import logging
import subprocess
import json
import requests
import base64
import os
import yaml
from pathlib import Path

from reNgine.common_func import *
from reNgine.definitions import *
from reNgine.parsers import SpiderFootBatchParser
from reNgine.utils.task import run_command, stream_command, save_email, save_employee, save_subdomain, save_endpoint
from reNgine.utils.opsec import get_opsec_manager
from reNgine.tasks.persistence import save_metadata_info, save_ip_address, save_secret_leak
from reNgine.tasks.geo import query_whois
from reNgine.tasks.scan_init import finish_osint, finish_osint_discovery
from reNgine.tasks.vuln import semgrep_scan
from reNgine.osint_tasks import osint_orchestrator
from reNgine.osint.hibp_scraper import check_hibp_for_email_task
from reNgine.utils.graph import Neo4jManager
from redis import Redis
from startScan.models import *
from targetApp.models import Domain

logger = logging.getLogger(__name__)

def osint(self, host=None, ctx={}, description=None):
	"""Run Open-Source Intelligence tools on selected domain.

	Args:
		host (str): Hostname to scan.

	Returns:
		dict: Results from osint discovery and dorking.
	"""
	# Copy theHarvester api-keys.yaml to /root/.theHarvester/api-keys.yaml
	source_api_keys = '/usr/src/github/theHarvester/api-keys.yaml'
	target_dir = '/root/.theHarvester'
	target_api_keys = f'{target_dir}/api-keys.yaml'
	try:
		if os.path.exists(source_api_keys):
			os.makedirs(target_dir, exist_ok=True)
			shutil.copyfile(source_api_keys, target_api_keys)
			logger.info('Copied theHarvester api-keys.yaml to /root/.theHarvester/api-keys.yaml')
	except Exception as e:
		logger.error('Failed to copy theHarvester api-keys.yaml: %s', e)

	# Inject stored Hunter API key so theHarvester -b all uses Hunter as a source.
	try:
		hunter_key_obj = HunterIOAPIKey.objects.first()
		if hunter_key_obj and hunter_key_obj.key and os.path.exists(target_api_keys):
			with open(target_api_keys, 'r') as _f:
				_yaml_data = yaml.safe_load(_f)
			if not isinstance(_yaml_data, dict):
				_yaml_data = {}
			if not isinstance(_yaml_data.get('apikeys'), dict):
				_yaml_data['apikeys'] = {}
			if not isinstance(_yaml_data['apikeys'].get('hunter'), dict):
				_yaml_data['apikeys']['hunter'] = {}
			
			_yaml_data['apikeys']['hunter']['key'] = hunter_key_obj.key
			
			with open(target_api_keys, 'w') as _f:
				yaml.dump(_yaml_data, _f)
			logger.info('[HUNTER] Injected Hunter API key into theHarvester api-keys.yaml')
	except Exception as e:
		logger.error('Failed to inject Hunter key into theHarvester YAML: %s', e)

	config = self.yaml_configuration.get(OSINT) or OSINT_DEFAULT_CONFIG
	results = {}

	results = []

	if 'discover' in config:
		ctx['track'] = False
		results.append(osint_discovery(
			self,
			config=config,
			host=self.scan.domain.name,
			scan_history_id=self.scan.id,
			activity_id=self.activity_id,
			results_dir=self.results_dir,
			ctx=ctx
		))

	if OSINT_DORK in config or OSINT_CUSTOM_DORK in config or self.scan.cfg_custom_dorks:
		results.append(dorking(
			config=config,
			host=self.scan.domain.name,
			scan_history_id=self.scan.id,
			activity_id=self.activity_id,
			results_dir=self.results_dir,
			raw_dorks=self.scan.cfg_custom_dorks
		))

	if results:
		finish_osint(results, scan_history_id=self.scan.id)

	logger.info('Standard OSINT Tasks finished...')

	# Deep Pursuit OSINT Pipeline (holehe, maigret, LinkedInt)
	logger.info('Starting Deep Pursuit OSINT Pipeline...')
	osint_orchestrator(scan_history_id=self.scan.id)

	# Run h8mail after all OSINT tasks are finished
	osint_lookup = config.get(OSINT_DISCOVER, [])
	if 'emails' in osint_lookup:
		h8mail(
			self,
			config=config,
			host=self.scan.domain.name,
			scan_history_id=self.scan.id,
			activity_id=self.activity_id,
			results_dir=self.results_dir,
			ctx=ctx
		)
		
		# Run HaveIBeenPwned checks sequentially for all found emails
		logger.info('Starting HaveIBeenPwned playwright check for found emails...')
		from reNgine.osint.hibp_scraper import check_hibp_for_email_task
		for email_obj in self.scan.emails.all():
			check_hibp_for_email_task(email_obj.address, self.scan.id, email_obj.id)

	logger.info('OSINT Tasks finished...')
	return True

	# with open(self.output_path, 'w') as f:
	# 	json.dump(results, f, indent=4)
	#
	# return results


def osint_discovery(self, config, host, scan_history_id, activity_id, results_dir, ctx={}):
	"""Run OSINT discovery.

	Args:
		config (dict): yaml_configuration
		host (str): target name
		scan_history_id (startScan.ScanHistory): Scan History ID
		results_dir (str): Path to store scan results

	Returns:
		dict: osint metadat and theHarvester and h8mail results.
	"""
	scan_history = ScanHistory.objects.get(pk=scan_history_id)
	osint_lookup = config.get(OSINT_DISCOVER, [])
	osint_intensity = config.get(INTENSITY, 'normal')
	documents_limit = config.get(OSINT_DOCUMENTS_LIMIT, 50)
	results = {}
	meta_info = []
	emails = []
	creds = []

	# Get and save meta info
	if 'metainfo' in osint_lookup:
		if osint_intensity == 'normal':
			meta_dict = DottedDict({
				'osint_target': host,
				'domain': host,
				'scan_id': scan_history_id,
				'documents_limit': documents_limit
			})
			meta_info.append(save_metadata_info(meta_dict))

		# TODO: disabled for now
		# elif osint_intensity == 'deep':
		# 	subdomains = Subdomain.objects
		# 	if self.scan:
		# 		subdomains = subdomains.filter(scan_history=self.scan)
		# 	for subdomain in subdomains:
		# 		meta_dict = DottedDict({
		# 			'osint_target': subdomain.name,
		# 			'domain': self.domain,
		# 			'scan_id': self.scan_id,
		# 			'documents_limit': documents_limit
		# 		})
		# 		meta_info.append(save_metadata_info(meta_dict))

	if 'employees' in osint_lookup:
		ctx['track'] = False
		theHarvester(
			self,
			config=config,
			host=host,
			scan_history_id=scan_history_id,
			activity_id=activity_id,
			results_dir=results_dir,
			ctx=ctx
		)

	leaks_config = config.get(LEAKS_AND_SECRETS, {})
	if leaks_config:
		if leaks_config.get(LEAKLOOKUP):
			leaklookup(
				self,
				host=host,
				scan_history_id=scan_history_id,
				activity_id=activity_id,
				results_dir=results_dir,
				ctx=ctx
			)

		if leaks_config.get(GITLEAKS) or leaks_config.get(TRUFFLEHOG):
			secret_scanning(
				self,
				config=leaks_config,
				host=host,
				scan_history_id=scan_history_id,
				activity_id=activity_id,
				results_dir=results_dir,
				ctx=ctx
			)

	finish_osint_discovery([results], results_dir=results_dir)

	# Strip metadata from OSINT results
	opsec = get_opsec_manager()
	opsec.strip_directory(results_dir)

	return results


def dorking(config, host, scan_history_id, results_dir, activity_id=None, raw_dorks=None):
	"""Run Google dorks.

	Args:
		config (dict): yaml_configuration
		host (str): target name
		scan_history_id (startScan.ScanHistory): Scan History ID
		results_dir (str): Path to store scan results
		raw_dorks (str): Raw custom dorks list (one per line)

	Returns:
		list: Dorking results for each dork ran.
	"""
	# Some dork sources: https://github.com/six2dez/degoogle_hunter/blob/master/degoogle_hunter.sh
	scan_history = ScanHistory.objects.get(pk=scan_history_id)
	dorks = config.get(OSINT_DORK, [])
	custom_dorks = config.get(OSINT_CUSTOM_DORK, [])
	results = []
	# custom dorking has higher priority
	try:
		for custom_dork in custom_dorks:
			if isinstance(custom_dork, str):
				# Handle simple string query from YAML
				query = custom_dork.replace('_target_', host)
				logger.info(f'Processing YAML custom dork: {query}')
				get_and_save_dork_results(
					lookup_target=host,
					results_dir=results_dir,
					type='custom_dork_yaml',
					lookup_keywords=query,
					scan_history=scan_history,
					activity_id=activity_id
				)
			elif isinstance(custom_dork, dict):
				# Handle structured dict from YAML
				lookup_target = custom_dork.get('lookup_site')
				# replace with original host if _target_
				lookup_target = host if lookup_target == '_target_' else lookup_target
				if 'lookup_extensions' in custom_dork:
					results = get_and_save_dork_results(
						lookup_target=lookup_target,
						results_dir=results_dir,
						type='custom_dork',
						lookup_extensions=custom_dork.get('lookup_extensions'),
						scan_history=scan_history,
						activity_id=activity_id
					)
				elif 'lookup_keywords' in custom_dork:
					results = get_and_save_dork_results(
						lookup_target=lookup_target,
						results_dir=results_dir,
						type='custom_dork',
						lookup_keywords=custom_dork.get('lookup_keywords'),
						scan_history=scan_history,
						activity_id=activity_id
					)
	except Exception as e:
		logger.error(f'Error processing custom dorks from YAML: {str(e)}')
		logger.exception(e)

	# Process raw custom dorks from UI/ScanHistory
	if raw_dorks:
		logger.info('Processing raw custom dorks...')
		try:
			custom_dork_list = raw_dorks.split('\n')
			for dork_query in custom_dork_list:
				dork_query = dork_query.strip()
				if dork_query:
					# We use the raw query as keywords for GooFuzz
					# Note: If dork_query starts with site:{host}, we strip it.
					query_to_run = dork_query
					if dork_query.startswith(f'site:{host} '):
						query_to_run = dork_query.replace(f'site:{host} ', '', 1)
					elif dork_query.startswith(f'site:{host}'):
						query_to_run = dork_query.replace(f'site:{host}', '', 1)
					
					get_and_save_dork_results(
						lookup_target=host,
						results_dir=results_dir,
						type='custom_dork_ui',
						lookup_keywords=query_to_run,
						scan_history=scan_history,
						activity_id=activity_id
					)
		except Exception as e:
			logger.exception(e)

	# default dorking
	try:
		for dork in dorks:
			logger.info(f'Getting dork information for {dork}')
			if dork == 'stackoverflow':
				results = get_and_save_dork_results(
					lookup_target='stackoverflow.com',
					results_dir=results_dir,
					type=dork,
					lookup_keywords=host,
					scan_history=scan_history
				)

			elif dork == 'login_pages':
				results = get_and_save_dork_results(
					lookup_target=host,
					results_dir=results_dir,
					type=dork,
					lookup_keywords='/login/,login.html',
					page_count=5,
					scan_history=scan_history
				)

			elif dork == 'admin_panels':
				results = get_and_save_dork_results(
					lookup_target=host,
					results_dir=results_dir,
					type=dork,
					lookup_keywords='/admin/,admin.html',
					page_count=5,
					scan_history=scan_history
				)

			elif dork == 'dashboard_pages':
				results = get_and_save_dork_results(
					lookup_target=host,
					results_dir=results_dir,
					type=dork,
					lookup_keywords='/dashboard/,dashboard.html',
					page_count=5,
					scan_history=scan_history
				)

			elif dork == 'social_media' :
				social_websites = [
					'tiktok.com',
					'facebook.com',
					'twitter.com',
					'youtube.com',
					'reddit.com'
				]
				for site in social_websites:
					results = get_and_save_dork_results(
						lookup_target=site,
						results_dir=results_dir,
						type=dork,
						lookup_keywords=host,
						scan_history=scan_history
					)

			elif dork == 'project_management' :
				project_websites = [
					'trello.com',
					'atlassian.net'
				]
				for site in project_websites:
					results = get_and_save_dork_results(
						lookup_target=site,
						results_dir=results_dir,
						type=dork,
						lookup_keywords=host,
						scan_history=scan_history
					)

			elif dork == 'code_sharing' :
				project_websites = [
					'github.com',
					'gitlab.com',
					'bitbucket.org'
				]
				for site in project_websites:
					results = get_and_save_dork_results(
						lookup_target=site,
						results_dir=results_dir,
						type=dork,
						lookup_keywords=host,
						scan_history=scan_history
					)

			elif dork == 'config_files' :
				config_file_exts = [
					'env',
					'xml',
					'conf',
					'toml',
					'yml',
					'yaml',
					'cnf',
					'inf',
					'rdp',
					'ora',
					'txt',
					'cfg',
					'ini'
				]
				results = get_and_save_dork_results(
					lookup_target=host,
					results_dir=results_dir,
					type=dork,
					lookup_extensions=','.join(config_file_exts),
					page_count=4,
					scan_history=scan_history
				)

			elif dork == 'jenkins' :
				lookup_keyword = 'Jenkins'
				results = get_and_save_dork_results(
					lookup_target=host,
					results_dir=results_dir,
					type=dork,
					lookup_keywords=lookup_keyword,
					page_count=1,
					scan_history=scan_history
				)

			elif dork == 'wordpress_files' :
				lookup_keywords = [
					'/wp-content/',
					'/wp-includes/'
				]
				results = get_and_save_dork_results(
					lookup_target=host,
					results_dir=results_dir,
					type=dork,
					lookup_keywords=','.join(lookup_keywords),
					page_count=5,
					scan_history=scan_history
				)

			elif dork == 'php_error' :
				lookup_keywords = [
					'PHP Parse error',
					'PHP Warning',
					'PHP Error'
				]
				results = get_and_save_dork_results(
					lookup_target=host,
					results_dir=results_dir,
					type=dork,
					lookup_keywords=','.join(lookup_keywords),
					page_count=5,
					scan_history=scan_history
				)

			elif dork == 'jenkins' :
				lookup_keywords = [
					'PHP Parse error',
					'PHP Warning',
					'PHP Error'
				]
				results = get_and_save_dork_results(
					lookup_target=host,
					results_dir=results_dir,
					type=dork,
					lookup_keywords=','.join(lookup_keywords),
					page_count=5,
					scan_history=scan_history
				)

			elif dork == 'exposed_documents' :
				docs_file_ext = [
					'doc',
					'docx',
					'odt',
					'pdf',
					'rtf',
					'sxw',
					'psw',
					'ppt',
					'pptx',
					'pps',
					'csv'
				]
				results = get_and_save_dork_results(
					lookup_target=host,
					results_dir=results_dir,
					type=dork,
					lookup_extensions=','.join(docs_file_ext),
					page_count=7,
					scan_history=scan_history
				)

			elif dork == 'db_files' :
				file_ext = [
					'sql',
					'db',
					'dbf',
					'mdb'
				]
				results = get_and_save_dork_results(
					lookup_target=host,
					results_dir=results_dir,
					type=dork,
					lookup_extensions=','.join(file_ext),
					page_count=1,
					scan_history=scan_history
				)

			elif dork == 'git_exposed' :
				file_ext = [
					'git',
				]
				results = get_and_save_dork_results(
					lookup_target=host,
					results_dir=results_dir,
					type=dork,
					lookup_extensions=','.join(file_ext),
					page_count=1,
					scan_history=scan_history
				)

	except Exception as e:
		logger.exception(e)
	return results


def theHarvester(self, config, host, scan_history_id, activity_id, results_dir, ctx={}):
	"""Run theHarvester to get save emails, hosts, employees found in domain.

	Args:
		config (dict): yaml_configuration
		host (str): target name
		scan_history_id (startScan.ScanHistory): Scan History ID
		activity_id: ScanActivity ID
		results_dir (str): Path to store scan results
		ctx (dict): context of scan

	Returns:
		dict: Dict of emails, employees, hosts and ips found during crawling.
	"""
	scan_history = ScanHistory.objects.get(pk=scan_history_id)
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
	output_path_json = f'{results_dir}/theHarvester.json'
	theHarvester_dir = '/usr/src/github/theHarvester'
	history_file = f'{results_dir}/commands.txt'

	# Update proxies.yaml
	proxy_query = Proxy.objects.all()
	if proxy_query.exists():
		proxy = proxy_query.first()
		if proxy.use_proxy:
			proxy_list = proxy.proxies.splitlines()
			yaml_data = {'http' : proxy_list}
			with open(f'{theHarvester_dir}/proxies.yaml', 'w') as file:
				yaml.dump(yaml_data, file)

	# Run cmd
	logger.info('theHarvester started')
	cmd = f'uv run theHarvester -d {host} -b all -f {output_path_json}'
	logger.warning(f'TheHarvester command: {cmd}')
	run_command(
		cmd,
		shell=True,
		cwd=theHarvester_dir,
		history_file=history_file,
		scan_id=scan_history_id,
		activity_id=activity_id)

	# Get file location
	if not os.path.isfile(output_path_json):
		logger.error(f'Could not open {output_path_json}')
		return {}

	# Load theHarvester results
	with open(output_path_json, 'r') as f:
		data = json.load(f)

	# Re-indent theHarvester JSON
	with open(output_path_json, 'w') as f:
		json.dump(data, f, indent=4)

	emails = data.get('emails', [])
	for email_address in emails:
		email, _ = save_email(email_address, scan_history=scan_history)
		if email:
			self.notify(fields={'Emails': f'• `{email.address}`'})

	linkedin_people = data.get('linkedin_people', [])
	for people in linkedin_people:
		employee, _ = save_employee(
			people,
			designation='linkedin',
			scan_history=scan_history)
		if employee:
			self.notify(fields={'LinkedIn people': f'• {employee.name}'})

	twitter_people = data.get('twitter_people', [])
	for people in twitter_people:
		employee, _ = save_employee(
			people,
			designation='twitter',
			scan_history=scan_history)
		if employee:
			self.notify(fields={'Twitter people': f'• {employee.name}'})

	hosts = data.get('hosts', [])
	urls = []
	for host in hosts:
		split = tuple(host.split(':'))
		http_url = split[0]
		subdomain_name = get_subdomain_from_url(http_url)
		subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
		endpoint, _ = save_endpoint(
			http_url,
			crawl=False,
			ctx=ctx,
			subdomain=subdomain)
		if endpoint:
			urls.append(endpoint.http_url)
			self.notify(fields={'Hosts': f'• {endpoint.http_url}'})

	# if enable_http_crawl:
	# 	ctx['track'] = False
	# 	http_crawl(urls, ctx=ctx)

	# TODO: Lots of ips unrelated with our domain are found, disabling
	# this for now.
	# ips = data.get('ips', [])
	# for ip_address in ips:
	# 	ip, created = save_ip_address(
	# 		ip_address,
	# 		subscan=subscan)
	# 	if ip:
	# 		send_task_notif.delay(
	# 			'osint',
	# 			scan_history_id=scan_history_id,
	# 			subscan_id=subscan_id,
	# 			severity='success',
	# 			update_fields={'IPs': f'{ip.address}'})
	return data


def h8mail(self, config, host, scan_history_id, activity_id, results_dir, ctx={}):
	"""Run h8mail.

	Args:
		config (dict): yaml_configuration
		host (str): target name
		scan_history_id (startScan.ScanHistory): Scan History ID
		activity_id: ScanActivity ID
		results_dir (str): Path to store scan results
		ctx (dict): context of scan

	Returns:
		list[dict]: List of credentials info.
	"""
	logger.warning('Getting leaked credentials')
	scan_history = ScanHistory.objects.get(pk=scan_history_id)
	input_path = f'{results_dir}/emails.txt'
	output_file = f'{results_dir}/h8mail.json'

	# Retrieve all emails from DB and create emails.txt if not exists or update it
	emails = scan_history.emails.all()
	emails_list = [email.address for email in emails]
	
	target = ctx.get('target')
	if target and target not in emails_list:
		emails_list.append(target)
		
	if not emails_list:
		logger.warning('No emails found to run h8mail against. Skipping.')
		return []

	with open(input_path, 'w') as f:
		for email in set(emails_list):
			f.write(f'{email}\n')

	cmd = f'h8mail -t {input_path} --json {output_file}'
	history_file = f'{results_dir}/commands.txt'

	run_command(
		cmd,
		history_file=history_file,
		scan_id=scan_history_id,
		activity_id=activity_id)

	if os.path.exists(output_file):
		try:
			with open(output_file) as f:
				data = json.load(f)
				creds = data.get('targets', [])
		except Exception as e:
			logger.error(f"Error reading h8mail output: {e}")
			creds = []
	else:
		logger.warning(f"h8mail output file {output_file} not found.")
		creds = []

	# TODO: go through h8mail output and save emails to DB
	for cred in creds:
		logger.warning(cred)
		email_address = cred['target']
		pwn_num = cred['pwn_num']
		pwn_data = cred.get('data', [])
		email, created = save_email(email_address, scan_history=scan_history)
		# if email:
		# 	self.notify(fields={'Emails': f'• `{email.address}`'})
	return creds


def leaklookup(self, host=None, ctx=None, **kwargs):
	"""Run LeakLookup and ProjectDiscovery query."""
	leaklookup_api_key = get_leaklookup_key()
	chaos_api_key = get_chaos_api_key()

	if not leaklookup_api_key and not chaos_api_key:
		return "LeakLookup and ProjectDiscovery API keys not found. Skipping."

	results_summary = []

	# LeakLookup
	if leaklookup_api_key:
		try:
			url = "https://leak-lookup.com/api/search"
			params = {
				'key': leaklookup_api_key,
				'type': 'domain',
				'query': host
			}
			response = requests.post(url, data=params, timeout=30)
			if response.status_code == 200:
				data = response.json()
				if data.get('error') == 'false':
					leaks = data.get('message') or {}
					leak_count = 0
					for db_name, contents in leaks.items():
						for match in contents:
							save_secret_leak(
								scan_history=self.scan,
								tool_name=LEAKLOOKUP,
								secret_type="Data Leak",
								source_url=db_name,
								match_content=match,
								status='unverified'
							)
							leak_count += 1
					results_summary.append(f"LeakLookup: Found {leak_count} leaks in {len(leaks)} databases")
				else:
					results_summary.append(f"LeakLookup error: {data.get('message')}")
			else:
				results_summary.append(f"LeakLookup HTTP error: {response.status_code}")
		except Exception as e:
			logger.error(f"Error in LeakLookup: {e}")
			results_summary.append(f"LeakLookup error: {e}")

	# ProjectDiscovery
	if chaos_api_key:
		try:
			pd_url = f"https://api.projectdiscovery.io/v1/leaks?type=all&time_range=all_time&domain={host}"
			headers = {"X-API-Key": chaos_api_key}
			response = requests.get(pd_url, headers=headers, timeout=30)
			if response.status_code == 200:
				data = response.json()
				leaks = data.get('data') or []
				leak_count = 0
				for match in leaks:
					source_url = match.get('url') or match.get('url_domain') or 'Unknown'
					match_content = ""
					if match.get('username'):
						match_content += f"Username: {match.get('username')} "
					if match.get('password'):
						match_content += f"Password: {match.get('password')} "
					if match.get('device_ip'):
						match_content += f"IP: {match.get('device_ip')} "
					
					save_secret_leak(
						scan_history=self.scan,
						tool_name=PROJECTDISCOVERY,
						secret_type="Data Leak",
						source_url=source_url,
						match_content=match_content.strip(),
						status='unverified'
					)
					leak_count += 1
				results_summary.append(f"ProjectDiscovery: Found {leak_count} leaks")
			else:
				results_summary.append(f"ProjectDiscovery HTTP error: {response.status_code}")
		except Exception as e:
			logger.error(f"Error in ProjectDiscovery: {e}")
			results_summary.append(f"ProjectDiscovery error: {e}")

	return " | ".join(results_summary)


def secret_scanning(self, config=None, host=None, ctx=None, **kwargs):
	"""Scan for secrets in JS files and potentially other sources.

	Args:
		config (dict, optional): Leaks and secrets configuration dictionary.
		host (str, optional): Target hostname.
		ctx (dict, optional): Scan activity context.
	"""
	if not self.scan:
		return "No scan history found."

	if config is None:
		config = (
			self.yaml_configuration.get('secret_scanning') or
			self.yaml_configuration.get('leaks_and_secrets') or
			self.yaml_configuration.get('osint', {}).get('leaks_and_secrets') or
			{}
		)

	endpoints = EndPoint.objects.filter(scan_history=self.scan)
	# Sensitive extensions to scan
	SENSITIVE_EXTENSIONS = ('.js', '.env', '.php', '.asp', '.aspx', '.jsp', '.jspx', '.txt', '.log', '.conf', '.config', '.bak', '.old', '.json', '.yaml', '.yml')
	target_endpoints = [e for e in endpoints if e.http_url.lower().endswith(SENSITIVE_EXTENSIONS)]

	if not target_endpoints:
		return "No sensitive files found to scan."

	temp_dir = f"{self.results_dir}/secrets_temp"
	os.makedirs(temp_dir, exist_ok=True)

	# Download sensitive files
	for js in target_endpoints:
		try:
			filename = "".join([c if c.isalnum() else "_" for c in js.http_url]) + ".js"
			filepath = os.path.join(temp_dir, filename)
			resp = requests.get(js.http_url, timeout=10, verify=False)
			if resp.status_code == 200:
				with open(filepath, 'w') as f:
					f.write(resp.text)
		except Exception as e:
			logger.error(f"Failed to download {js.http_url}: {e}")

	findings_count = 0

	# Run Gitleaks
	if config.get(GITLEAKS):
		report_path = f"{temp_dir}/gitleaks_report.json"
		# Gitleaks v8+ detect command
		subprocess.run(
			['gitleaks', 'detect', '--source', temp_dir,
			 '--report-format', 'json', '--report-path', report_path, '--exit-code', '0'],
			check=False
		)
		
		if os.path.exists(report_path):
			try:
				with open(report_path, 'r') as f:
					findings = json.load(f)
					for finding in findings:
						# Map finding to SecretLeak
						save_secret_leak(
							scan_history=self.scan,
							tool_name=GITLEAKS,
							secret_type=finding.get('Description', 'Secret'),
							source_url=finding.get('File', 'Unknown'),
							match_content=finding.get('Secret', ''),
							status='unverified'
						)
						findings_count += 1
			except Exception as e:
				logger.error(f"Error parsing Gitleaks report: {e}")

	# Run Trufflehog
	if config.get(TRUFFLEHOG):
		# Trufflehog v3 filesystem command
		process = subprocess.Popen(
			['trufflehog', 'filesystem', temp_dir, '--json'],
			shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE
		)
		stdout, stderr = process.communicate()
		
		for line in stdout.decode().splitlines():
			if not line: continue
			try:
				finding = json.loads(line)
				# Trufflehog v3 output format varies, but usually has 'SourceMetadata' or 'DetectorName'
				save_secret_leak(
					scan_history=self.scan,
					tool_name=TRUFFLEHOG,
					secret_type=finding.get('DetectorName', 'Secret'),
					source_url=finding.get('SourceMetadata', {}).get('Data', {}).get('Filesystem', {}).get('file', 'Unknown'),
					match_content=finding.get('Raw', ''),
					status='unverified'
				)
				findings_count += 1
			except Exception as e:
				logger.error(f"Error parsing Trufflehog finding: {e}")

	# Run Betterleaks
	if config.get(BETTERLEAKS):
		# Betterleaks is typically run against files or a directory
		# It's good for finding secrets like API keys, passwords, etc.
		# Command: betterleaks -p {temp_dir}
		logger.info(f"Running Betterleaks on {temp_dir}")
		process = subprocess.Popen(
			['betterleaks', '-p', temp_dir],
			shell=False, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True
		)
		stdout, stderr = process.communicate()
		logger.info(f"Betterleaks output: {stdout}")
		for line in stdout.splitlines():
			if line.strip():
				# Assuming betterleaks outputs findings in a recognizable format
				# For now, let's just log it and save if it looks like a finding
				if any(keyword in line.lower() for keyword in ['key', 'password', 'secret', 'token', 'found']):
					save_secret_leak(
						scan_history=self.scan,
						tool_name=BETTERLEAKS,
						secret_type='Potential Secret',
						source_url='Discovered Files',
						match_content=line.strip(),
						status='unverified'
					)
					findings_count += 1

	# Run Semgrep Secret Scan (Default)
	try:
		logger.info('Running Semgrep Secret Scan...')
		semgrep_scan(self, ctx=ctx, mode='secret', description='Semgrep Secret Scan')
	except Exception as e:
		logger.error(f"Semgrep secret scan failed: {e}")

	# Cleanup
	shutil.rmtree(temp_dir, ignore_errors=True)

	return f"Secret scanning completed. Found {findings_count} findings."


def spiderfoot_scan(self, host=None, ctx={}, description=None):
	"""Run SpiderFoot scan on selected domain with real-time batch parsing.
	"""
	# host selection logic based on user rules
	if not host:
		if self.subscan_id and self.subdomain:
			host = self.subdomain.name
		else:
			host = self.domain.name
	
	logger.warning(f"[SPIDERFOOT] Starting scan for target: {host} (Scan ID: {self.scan_id}, Subscan ID: {self.subscan_id})")
	
	if not self.yaml_configuration:
		logger.error("[SPIDERFOOT] yaml_configuration is empty! Check engine config.")
	
	config = self.yaml_configuration.get(SPIDERFOOT_SCAN) or {}
	modules = config.get('modules', 'all')
	threads = config.get('threads') or self.yaml_configuration.get('threads', 5)
	intensity = config.get('intensity', 'normal') # normal, fast, deep

	# Spiderfoot CLI intensity mapping (profiles)
	profile_cmd = ""
	if intensity == 'fast':
		profile_cmd = "-u footprint"
	elif intensity == 'deep':
		profile_cmd = "-u all"
	
	if modules != 'all':
		profile_cmd = f"-m {modules}"
	elif not profile_cmd:
		profile_cmd = "-u investigate"
	
	# Use global SF config
	sf_config_path = "/usr/src/github/spiderfoot/spiderfoot.cfg"
	sf_exec_path = "/usr/src/github/spiderfoot/sf.py"
	
	if not os.path.exists(sf_exec_path):
		logger.error(f"[SPIDERFOOT] SpiderFoot executable not found at {sf_exec_path}!")
		return
		
	if not os.path.exists(sf_config_path):
		logger.error(f"[SPIDERFOOT] SpiderFoot config not found at {sf_config_path}. Task may fail or use defaults.")
	
	# Use CSV output for streaming. -r includes source data, -n strips newlines.
	cmd = f"python3 {sf_exec_path} -s {host} {profile_cmd} -max-threads {threads} -o csv -r -n"
	logger.warning(f"[SPIDERFOOT] Executing command: {cmd}")
	
	# Initialize stateful parser with Redis dedup
	from django.conf import settings
	redis_client = Redis(
		host=settings.REDIS_HOST,
		port=settings.REDIS_PORT,
		password=settings.REDIS_PASSWORD,
		decode_responses=True
	)
	parser = SpiderFootBatchParser(dedup_backend=redis_client, scan_id=self.scan_id, target_domain=self.domain.name)
	
	batch = []
	batch_size = 100
	
	for line in stream_command(
		cmd,
		shell=True,
		scan_id=self.scan_id,
		activity_id=self.activity_id):
		
		event = parser.parse_line(line)
		if not event:
			continue
			
		batch.append(event)
		
		if len(batch) >= batch_size:
			_process_spiderfoot_batch(self, batch, ctx, host)
			batch = []
	
	# Process remaining
	if batch:
		_process_spiderfoot_batch(self, batch, ctx, host)
		
	# Sync to Neo4j
	graph = Neo4jManager()
	graph.sync_scan_results(self.scan_id)
	graph.close()


def persist_osint_item(scan_history, domain, osint_type, e_data, confidence, source_data=None, event_type=None, ctx=None, activity_id=None):
	"""
	Core logic to persist an OSINT item into primary tables.
	Separated from tasks to allow manual promotion from UI.
	"""
	if osint_type == 'Subdomain':
		sub_name = e_data.lower()
		save_subdomain(sub_name, ctx=ctx)
	elif osint_type == 'Email':
		save_email(e_data.lower(), scan_history=scan_history)
	elif osint_type == 'Employee':
		save_employee(e_data, scan_history=scan_history)
	elif osint_type == 'URL':
		if is_valid_url(e_data):
			save_endpoint(e_data, ctx=ctx)
	elif osint_type == 'IP':
		save_ip_address(e_data, scan_id=scan_history.id, activity_id=activity_id)
	elif osint_type == 'Port':
		if ':' in e_data:
			ip_part, port_part = e_data.split(':', 1)
			if port_part.isdigit():
				port_num = int(port_part)
				res = get_port_service_description(port_num)
				port_obj, _ = update_or_create_port(port_num, service_name=res.get('service_name'), description=res.get('description'))
				ip_obj, _ = save_ip_address(ip_part, scan_id=scan_history.id, activity_id=activity_id)
				if ip_obj:
					ip_obj.ports.add(port_obj)
		elif e_data.isdigit():
			port_num = int(e_data)
			update_or_create_port(port_num)
	elif osint_type == 'Tech':
		from django.core.exceptions import MultipleObjectsReturned
		try:
			tech_obj, _ = Technology.objects.get_or_create(name=e_data)
		except MultipleObjectsReturned:
			tech_obj = Technology.objects.filter(name=e_data).first()
		if source_data:
			subdomain = Subdomain.objects.filter(name=source_data, scan_history=scan_history).first()
			if subdomain:
				subdomain.technologies.add(tech_obj)
	elif osint_type == 'Leak':
		save_secret_leak(
			scan_history=scan_history,
			tool_name='SpiderFoot',
			secret_type=event_type or 'Sensitive Data',
			source_url=source_data or 'SpiderFoot Findings',
			match_content=e_data
		)

def _process_spiderfoot_batch(self, batch, ctx, host):
	"""Internal helper to process a batch of SpiderFoot findings with tiered validation."""
	try:
		with transaction.atomic():
			for event in batch:
				e_type = event.get('type')
				e_data = event.get('data')
				osint_type = event.get('osint_type')
				confidence = event.get('confidence', 0)
				
				if not osint_type or not e_data:
					continue

				# Automated Persistence (High Confidence)
				if confidence > 80:
					persist_osint_item(
						scan_history=self.scan,
						domain=self.domain,
						osint_type=osint_type,
						e_data=e_data,
						confidence=confidence,
						source_data=event.get('source_data'),
						event_type=e_type,
						ctx=ctx,
						activity_id=self.activity_id
					)
				
				# Staging Area (Moderate Confidence: 50% -> 80%)
				elif 50 <= confidence <= 80:
					OsintStaging.objects.update_or_create(
						scan_history=self.scan,
						target_domain=self.domain,
						content=e_data,
						osint_type=osint_type,
						defaults={
							'source': event.get('source', 'SpiderFoot'),
							'confidence': confidence,
							'metadata': {
								'sf_type': e_type,
								'source_data': event.get('source_data'),
								'iocs': event.get('iocs')
							},
							'status': 'pending'
						}
					)
				else:
					# Discard low confidence noise
					logger.debug(f"[SPIDERFOOT] Discarding low confidence finding: {osint_type} - {e_data} ({confidence}%)")

		logger.warning(f"Processed batch of {len(batch)} SpiderFoot findings with validation.")
	except Exception as e:
		logger.error(f"Error processing SpiderFoot batch: {str(e)}")







def get_and_save_dork_results(lookup_target, results_dir, type, lookup_keywords=None, lookup_extensions=None, delay=3, page_count=2, scan_history=None, activity_id=None):
	"""
		Uses gofuzz to dork and store information

		Args:
			lookup_target (str): target to look into such as stackoverflow or even the target itself
			results_dir (str): Results directory
			type (str): Dork Type Title
			lookup_keywords (str): comma separated keywords or paths to look for
			lookup_extensions (str): comma separated extensions to look for
			delay (int): delay between each requests
			page_count (int): pages in google to extract information
			scan_history (startScan.ScanHistory): Scan History Object
	"""
	results = []
	# Use quotes around arguments to handle spaces and special characters safely in the shell
	gofuzz_command = f'{GOFUZZ_EXEC_PATH} -t "{lookup_target}" -d {delay} -p {page_count}'
	proxy = get_random_proxy()

	if lookup_extensions:
		gofuzz_command += f' -e "{lookup_extensions}"'
	elif lookup_keywords:
		# Double quote keywords to preserve complex dork queries, escaping any inner quotes
		escaped_keywords = lookup_keywords.replace('"', '\\"')
		gofuzz_command += f' -w "{escaped_keywords}"'

	if proxy:
		gofuzz_command += f' -r "{proxy}"'

	output_file = f'{results_dir}/gofuzz.txt'
	gofuzz_command += f' -o "{output_file}"'
	history_file = f'{results_dir}/commands.txt'

	try:
		# proxy already embedded via -r flag above; don't also pass proxy= kwarg
		# or run_command would double-wrap with proxychains when use_proxychains=True
		run_command(
			gofuzz_command,
			shell=True, # Use shell=True to handle quoted arguments correctly
			history_file=history_file,
			scan_id=scan_history.id if scan_history else None,
			activity_id=activity_id,
		)

		if not os.path.isfile(output_file):
			return

		with open(output_file) as f:
			for line in f.readlines():
				url = line.strip()
				if url:
					results.append(url)
					dork, created = Dork.objects.get_or_create(
						type=type,
						url=url
					)
					if scan_history:
						scan_history.dorks.add(dork)

		# remove output file
		os.remove(output_file)

	except Exception as e:
		logger.exception(e)

	return results

