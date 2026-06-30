import logging
import os
import re
import requests
import json
import validators
import csv
import io
from urllib.parse import urlparse
from bs4 import BeautifulSoup
from django.utils import timezone

from reNgine.definitions import *
from reNgine.settings import *
from reNgine.common_func import *
from django.db import transaction
import yaml
import subprocess
import signal


def _validate_hostname(value):
	if not re.fullmatch(r'[a-zA-Z0-9]([a-zA-Z0-9\-\.]{0,253}[a-zA-Z0-9])?', value):
		raise ValueError(f'Invalid hostname: {value!r}')
from reNgine.utils.task import save_subdomain, stream_command
from targetApp.models import Domain
from startScan.models import ScanHistory, Subdomain, EndPoint, MonitoringDiscovery
from scanEngine.models import EngineType
from reNgine.parsers import SpiderFootBatchParser
from redis import Redis

logger = logging.getLogger(__name__)


def generate_reconx_config(domain_name, reconx_dir):
	"""Generates a structured YAML configuration for ReconX."""
	targets_file = os.path.join(reconx_dir, "targets.txt")
	with open(targets_file, 'w') as f:
		f.write(domain_name)
	
	config = {
		'targets_file': targets_file,
		'data_dir': os.path.join(reconx_dir, "data"),
		'output_dir': os.path.join(reconx_dir, "output"),
		'findings_dir': os.path.join(reconx_dir, "findings"),
		'logs_dir': os.path.join(reconx_dir, "logs"),
		'recon': {
			'parallel_targets': 5,
			'subfinder_threads': 100
		},
		'pipeline': {
			'parallel_scans': 5,
			'cycle_delay': 60
		},
		'logging': {
			'level': 'info',
			'file': os.path.join(reconx_dir, "logs", "reconx.log")
		}
	}
	
	# Create directories
	for key in ['data_dir', 'output_dir', 'findings_dir', 'logs_dir']:
		os.makedirs(config[key], exist_ok=True)
		
	config_path = os.path.join(reconx_dir, "config.yaml")
	with open(config_path, 'w') as f:
		yaml.dump(config, f)
		
	return config_path, config['findings_dir']


def is_reconx_running(pid_file):
	"""Checks if a ReconX process is already running using a PID file."""
	if os.path.exists(pid_file):
		try:
			with open(pid_file, 'r') as f:
				pid = int(f.read().strip())
			os.kill(pid, 0)
			return True
		except (OSError, ValueError, ProcessLookupError):
			return False
	return False


def _process_monitor_spiderfoot_batch(batch, domain, scan_history, ctx, new_discoveries, existing_subs):
	"""Internal helper to process a batch of SpiderFoot findings for monitoring."""
	try:
		with transaction.atomic():
			for event in batch:
				e_type = event.get('type')
				e_data = event.get('data')
				
				if not e_type or not e_data:
					continue
				
				# SF types for hostnames/subdomains
				if e_type in ['DNS_NAME', 'INTERNET_NAME', 'AFFILIATE_INTERNET_NAME']:
					sub_name = e_data.lower()
					if sub_name and sub_name.endswith(domain.name) and sub_name not in existing_subs:
						sub_obj, created = save_subdomain(sub_name, ctx=ctx)
						if created:
							new_discoveries.append(f"Subdomain (SpiderFoot): {sub_name}")
							existing_subs.add(sub_name)
							MonitoringDiscovery.objects.create(
								domain=domain,
								discovery_type='subdomain',
								content={'name': sub_name, 'source': 'SpiderFoot'},
								scan_history=scan_history
							)
		logger.info(f"Processed monitoring batch of {len(batch)} SpiderFoot findings.")
	except Exception as e:
		logger.error(f"Error processing SpiderFoot monitoring batch: {str(e)}")


def monitor_target_task(domain_id):
	try:
		domain = Domain.objects.get(pk=domain_id)
	except Domain.DoesNotExist:
		logger.error(f"Domain with ID {domain_id} does not exist.")
		return

	logger.info(f"Starting monitoring for {domain.name}")

	# 1. Setup Scan History
	engine = domain.monitor_engine
	if not engine:
		engine = EngineType.objects.filter(default_engine=True).first()

	scan_history = ScanHistory.objects.create(
		domain=domain,
		scan_type=engine,
		start_scan_date=timezone.now(),
		scan_status=RUNNING_TASK,
		tasks=['monitoring_discovery']
	)

	results_dir = f"{RENGINE_RESULTS}/{domain.name}_monitor_{scan_history.id}"
	os.makedirs(results_dir, exist_ok=True)
	scan_history.results_dir = results_dir
	scan_history.save()

	# Context for save_subdomain and save_endpoint
	ctx = {
		'scan_history_id': scan_history.id,
		'domain_id': domain.id,
		'results_dir': results_dir,
	}

	new_discoveries = []

	try:
		# 2. Subdomain Discovery (Subfinder)
		subdomain_file = f"{results_dir}/subdomains_monitor.txt"
		_validate_hostname(domain.name)
		subprocess.run(['subfinder', '-d', domain.name, '-silent', '-o', subdomain_file], check=False)

		if os.path.exists(subdomain_file):
			with open(subdomain_file, 'r') as f:
				discovered_subs = [line.strip() for line in f if line.strip()]
			
			existing_subs = set(Subdomain.objects.filter(target_domain=domain).values_list('name', flat=True))
			
			# Check if subdomain discovery is enabled in tasks
			if 'subdomain_discovery' in scan_history.tasks:
				for sub_name in discovered_subs:
					if sub_name not in existing_subs:
						# Save new subdomain
						sub_obj, created = save_subdomain(sub_name, ctx=ctx)
					if created:
						new_discoveries.append(f"Subdomain: {sub_name}")
						MonitoringDiscovery.objects.create(
							domain=domain,
							discovery_type='subdomain',
							content={'name': sub_name},
							scan_history=scan_history
						)

		# 3. URL Discovery (GAU)
		url_file = f"{results_dir}/urls_monitor.txt"
		subprocess.run(['gau', domain.name, '--subs', '--silent', '-o', url_file], check=False)

		if os.path.exists(url_file):
			with open(url_file, 'r') as f:
				# Limit to 500 URLs to avoid overload in monitoring
				discovered_urls = [line.strip() for line in f if line.strip()][:500]
			
			existing_urls = set(EndPoint.objects.filter(target_domain=domain).values_list('http_url', flat=True))
			
			for url in discovered_urls:
				if url not in existing_urls:
					# Detect login and status
					status, title, is_login = detect_login_and_status(url)
					
					from reNgine.utils.task import save_endpoint
					endpoint_data = {
						'http_status': status,
						'page_title': title,
					}
					endpoint_obj, created = save_endpoint(url, ctx=ctx, **endpoint_data)
					
					if created:
						disc_type = 'login' if is_login else 'directory'
						new_discoveries.append(f"{disc_type.capitalize()}: {url}")
						MonitoringDiscovery.objects.create(
							domain=domain,
							discovery_type=disc_type,
							content={'url': url, 'status': status, 'title': title},
							scan_history=scan_history
						)

		# 4. ReconX Discovery (24/7 Monitoring)
		reconx_dir = os.path.join(RENGINE_RESULTS, f"{domain.name}_reconx")
		os.makedirs(reconx_dir, exist_ok=True)
		pid_file = os.path.join(reconx_dir, "reconx.pid")
		
		# Generate/Update Config
		config_path, findings_dir = generate_reconx_config(domain.name, reconx_dir)
		
		# Initiate 24/7 Monitoring if not already running
		if not is_reconx_running(pid_file):
			logger.info(f"Initiating 24/7 ReconX monitoring for {domain.name}")
			# Start reconx run in the background
			try:
				# Use nohup or setsid to ensure it stays alive. 
				# In Docker, we just need to detach it from the current shell.
				process = subprocess.Popen(
					["reconx", "run", "-config", config_path],
					stdout=subprocess.DEVNULL,
					stderr=subprocess.DEVNULL,
					start_new_session=True
				)
				with open(pid_file, 'w') as f:
					f.write(str(process.pid))
				logger.info(f"ReconX started with PID {process.pid} for {domain.name}")
			except Exception as e:
				logger.error(f"Failed to start ReconX for {domain.name}: {str(e)}")
		else:
			logger.info(f"ReconX is already running for {domain.name}")
		
		# Parse findings from the domain-specific findings directory
		if os.path.exists(findings_dir):
			for file in os.listdir(findings_dir):
				if file.endswith(".jsonl"):
					try:
						file_path = os.path.join(findings_dir, file)
						with open(file_path, 'r') as f:
							for line in f:
								finding = json.loads(line)
								if finding.get('type') == 'subdomain':
									sub_name = finding.get('data', {}).get('subdomain')
									if sub_name and sub_name.endswith(domain.name) and sub_name not in existing_subs:
										sub_obj, created = save_subdomain(sub_name, ctx=ctx)
										if created:
											new_discoveries.append(f"Subdomain (ReconX): {sub_name}")
											existing_subs.add(sub_name)
											MonitoringDiscovery.objects.create(
												domain=domain,
												discovery_type='subdomain',
												content={'name': sub_name, 'source': 'ReconX'},
												scan_history=scan_history
											)
								elif finding.get('type') == 'vulnerability':
									vuln_info = finding.get('data', {})
									new_discoveries.append(f"Vulnerability (ReconX): {vuln_info.get('template-id')}")
						# Optionally move or delete processed findings to avoid re-parsing
						# os.rename(file_path, file_path + ".processed")
					except Exception as e:
						logger.error(f"Error parsing ReconX findings for {domain.name}: {str(e)}")

		# 5. Attack Surface Intelligence (SpiderFoot)
		if 'spiderfoot_scan' in scan_history.tasks:
			sf_output = f"{results_dir}/spiderfoot_monitor.json"
			# Use global SF config
			sf_config_path = "/usr/src/github/spiderfoot/spiderfoot.cfg"
			
			# Use a focused set of modules for monitoring efficiency
			# Discovery modules + OSINT
			sf_modules = "snovio,hunterio,emailrep,intelx,shodan,sublist3r,threatcrowd,crtsh"
			# Use CSV output for streaming. -r includes source data, -n strips newlines.
			_validate_hostname(domain.name)
			sf_cmd = [
				'python3', '/usr/src/github/spiderfoot/sf.py',
				'-s', domain.name, '-m', sf_modules,
				'-q', '-o', 'csv', '-r', '-n', '-c', sf_config_path
			]

			# Initialize stateful parser with Redis dedup
			redis_client = Redis(host="redis", port=6379, decode_responses=True)
			parser = SpiderFootBatchParser(dedup_backend=redis_client, scan_id=scan_history.id)

			batch = []
			batch_size = 100

			try:
				for line in stream_command(sf_cmd, shell=False):
					event = parser.parse_line(line)
					if not event:
						continue
						
					batch.append(event)
					
					if len(batch) >= batch_size:
						_process_monitor_spiderfoot_batch(batch, domain, scan_history, ctx, new_discoveries, existing_subs)
						batch = []
				
				if batch:
					_process_monitor_spiderfoot_batch(batch, domain, scan_history, ctx, new_discoveries, existing_subs)
					
			except Exception as e:
				logger.error(f"SpiderFoot monitoring failed: {e}")


		# 5. Notifications
		if new_discoveries:
			message = f"🔍 Monitoring discovery for {domain.name}:\n" + "\n".join(new_discoveries[:10])
			if len(new_discoveries) > 10:
				message += f"\n... and {len(new_discoveries) - 10} more."
			
			send_telegram_message(message)
			send_slack_message(message)
			send_discord_message(message, title=f"Monitoring: {domain.name}", severity='info')
			
			# Create In-App Notification (Toast)
			create_inappnotification(
				title=f"Monitoring Discovery: {domain.name}",
				description=f"Found {len(new_discoveries)} new items.",
				notification_type=PROJECT_LEVEL_NOTIFICATION,
				status='info'
			)

		# 6. Follow-up Scan
		if domain.monitor_scan_scope != 'none' and new_discoveries:
			from reNgine.tasks import initiate_scan_temporal
			if domain.monitor_scan_scope == 'targeted':
				# Targeted scan for new subdomains
				new_subs = [d.split(": ")[1] for d in new_discoveries if d.startswith("Subdomain")]
				if new_subs:
					try:
						initiate_scan_temporal(
							scan_history_id=None,
							domain_id=domain.id,
							engine_id=engine.id,
							scan_type=SCHEDULED_SCAN,
							imported_subdomains=new_subs
						)
					except Exception as e:
						logger.warning(f"Failed to start targeted recovery scan for {domain.name}: {e}")
			elif domain.monitor_scan_scope == 'full':
				try:
					initiate_scan_temporal(
						scan_history_id=None,
						domain_id=domain.id,
						engine_id=engine.id,
						scan_type=SCHEDULED_SCAN
					)
				except Exception as e:
					logger.warning(f"Failed to start full recovery scan for {domain.name}: {e}")

		scan_history.scan_status = SUCCESS_TASK
		scan_history.stop_scan_date = timezone.now()
		scan_history.save()
		
		# Update domain's last monitored date
		domain.last_monitored = timezone.now()
		domain.save()

	except Exception as e:
		logger.error(f"Error in monitoring task for {domain.name}: {str(e)}")
		scan_history.scan_status = FAILED_TASK
		scan_history.error_message = str(e)
		scan_history.save()

def detect_login_and_status(url):
	try:
		# Use a random User-Agent from OpSec if possible, or just a default
		headers = {'User-Agent': 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/91.0.4472.124 Safari/537.36'}
		response = requests.get(url, timeout=5, verify=False, headers=headers)
		status = response.status_code
		soup = BeautifulSoup(response.text, 'html.parser')
		title = soup.title.string.strip() if soup.title and soup.title.string else ""
		
		is_login = False
		if soup.find('input', {'type': 'password'}):
			is_login = True
		elif any(keyword in title.lower() for keyword in ['login', 'signin', 'auth', 'portal']):
			is_login = True
			
		return status, title, is_login
	except Exception as e:
		# logger.debug(f"Probing failed for {url}: {str(e)}")
		return 0, "", False
