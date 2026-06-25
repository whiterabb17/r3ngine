import os
import django
from django.apps import apps
if not apps.ready and not apps.loading:
    os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'reNgine.settings')
    django.setup()

import csv
import threading
import requests
import json
import pprint
import subprocess
import time
import validators
import xmltodict
import yaml
import tldextract
import concurrent.futures
import base64
import io
import shutil
from redis import Redis


from datetime import datetime
from pathlib import Path
from urllib.parse import urlparse, parse_qs
from api.serializers import SubdomainSerializer
import logging
from django.db import transaction
from django.db.models import Count
from dotted_dict import DottedDict
from django.utils import timezone
from django.shortcuts import get_object_or_404
from pycvesearch import CVESearch
from metafinder.extractor import extract_metadata_from_google_search

from django.core.cache import cache
from reNgine.common_func import *
from reNgine.definitions import *
from reNgine.settings import *
from reNgine.llm import *
from reNgine.utilities import *
from reNgine.utils.opsec import ProxychainsWrapper, get_opsec_manager
from reNgine.utils.waf import OriginDiscoveryManager, WafBypassOrchestrator
from scanEngine.models import (EngineType, InstalledExternalTool, Notification, Proxy, OpSec)
from startScan.models import *
from startScan.models import EndPoint, Subdomain, Vulnerability, Parameter
from targetApp.models import Domain, normalize_manual_subdomains
from dashboard.models import AcunetixAPIKey, HunterIOAPIKey
from reNgine.monitor_tasks import *
from reNgine.utils.graph import Neo4jManager
from reNgine.vulnerability_tasks import *
from reNgine.fuzzing_tasks import *
from reNgine.stress.testing_tasks import run_stress_testing
from reNgine.osint_tasks import *
from reNgine.utils.task import (
    run_command, run_command_with_retry, stream_command, save_email, save_employee, save_subdomain, save_endpoint, save_parameter,
    sanitize_command_for_db, get_tool_color, ensure_endpoints_crawled_and_execute, save_fuzzing_file,
    parse_custom_header_to_list, save_subdomain_metadata,
    bulk_persist_fetch_urls, bulk_apply_gf_pattern_from_file, activity_heartbeat_safe,
)
from reNgine.report_tasks import *
from reNgine.wpscan_tasks import wpscan_scan
from reNgine.parsers import SpiderFootBatchParser
from reNgine.tech_mapping import get_nuclei_tags_from_techs
try:
	from acunetix import Acunetix
except ImportError:
	Acunetix = None

from plugins.orchestrator import PluginOrchestrator
from reNgine.tasks.parsers import (
    parse_nuclei_result,
    parse_dalfox_result,
    parse_crlfuzz_result,
    parse_s3scanner_result,
)
from reNgine.tasks.acunetix import (
    map_acunetix_severity,
    _validate_subdomain_name,
    _build_vuln_detail_url,
    _normalize_acunetix_target_url,
    _find_acunetix_target,
    _get_acunetix_profile_id,
    _create_or_reuse_acunetix_target,
    _start_acunetix_scan_direct,
    _fetch_acunetix_vulnerabilities,
    acunetix_scan,
)
from reNgine.tasks.geo import (
    geo_localize,
    query_whois,
    query_reverse_whois,
    query_ip_history,
    fetch_related_tlds_and_domains,
    fetch_whois_data_using_netlas,
)
from reNgine.tasks.llm import (
    llm_vulnerability_description, pull_ollama_model,
    get_vulnerability_gpt_report, add_gpt_description_db,
)
from reNgine.tasks.proxies import fetch_proxies_task
from reNgine.tasks.waf import waf_detection, waf_bypass
from reNgine.tasks.screenshot import screenshot
from reNgine.tasks.notifications import (
    send_notif,
    send_scan_notif,
    generate_inapp_notification,
    send_task_notif,
    send_file_to_discord,
    send_hackerone_report,
)
from reNgine.tasks.persistence import (
    remove_duplicate_endpoints,
    process_httpx_response,
    extract_httpx_url,
    save_metadata_info,
    create_scan_activity,
    save_ip_address,
    save_secret_leak,
)
from reNgine.tasks.port_scan import (
    port_scan, nmap, firewall_vpn_scan,
    parse_nmap_results, parse_nmap_https_redirect_output,
    parse_nmap_http_server_header_output, parse_nmap_fingerprint_strings_output,
    parse_nmap_http_title_output, parse_nmap_generic_vuln_output,
    parse_nmap_http_csrf_output, parse_nmap_vulscan_output,
    parse_nmap_vulners_output, get_severity_from_cvss,
    cve_to_vuln, parse_sslscan_results,
)
from reNgine.tasks.crawl import (
    http_crawl, fetch_url, web_api_discovery, parse_curl_output,
)
from reNgine.tasks.vuln import (
    vulnerability_scan, nuclei_scan, dalfox_xss_scan, crlfuzz_scan, s3scanner,
)
from reNgine.tasks.osint import (
    osint, osint_discovery, dorking, theHarvester, h8mail,
    leaklookup, secret_scanning, spiderfoot_scan,
    persist_osint_item, _process_spiderfoot_batch,
    get_and_save_dork_results,
)
from reNgine.tasks.subdomain import (
    subdomain_discovery, amass_intel_discovery, save_imported_subdomains,
)
from reNgine.tasks.scan_init import (
    SCAN_PIPELINE_DEFINITION,
    sync_all_scans_to_graph,
    finish_osint,
    finish_osint_discovery,
    initiate_scan_temporal,
    initiate_subscan_temporal,
    report,
    resume_scan_temporal,
)

"""
Celery tasks.
"""

logger = get_task_logger(__name__)




def correlate_exposures(self, scan_history_id, ctx={}, description=None):
	"""Correlate exposures and attack surface assets.
	"""
	logger.warning("[TIER7][CORRELATE_EXPOSURES] Starting exposure correlation | scan_id=%s", scan_history_id)
	
	from startScan.models import ScanHistory
	from reNgine.exposure_correlation import ExposureCorrelationEngine
	try:
		history = ScanHistory.objects.get(id=scan_history_id)
		engine = ExposureCorrelationEngine(scan_history=history)
		engine.correlate_exposures()
		logger.info("[TIER7][CORRELATE_EXPOSURES] Completed exposure correlation for scan_id=%s", scan_history_id)
	except ScanHistory.DoesNotExist:
		logger.error("ScanHistory not found: %s", scan_history_id)
	except Exception as e:
		logger.error("Error correlating exposures: %s", e)


def correlate_vulnerabilities(self, scan_history_id, ctx={}, description=None):
	"""Correlate discovered technologies with known CVEs and update the graph database.

	Args:
		scan_history_id (int): Scan history ID.
		ctx (dict): Scan context.
	"""
	logger.warning("[TIER7][CORRELATE] Starting vulnerability correlation | scan_id=%s", scan_history_id)

	# Check if there are other scanning tasks still running
	from startScan.models import ScanActivity
	from reNgine.definitions import RUNNING_TASK, INITIATED_TASK
	post_processing_names = ['correlate_vulnerabilities', 'calculate_risk_scores', 'generate_impact_assessment', 'run_apme', 'report']

	if self.subscan:
		running_scans = ScanActivity.objects.filter(
			execution_id__in=self.subscan.workflow_ids,
			status__in=[RUNNING_TASK, INITIATED_TASK]
		).exclude(name__in=post_processing_names)
	else:
		running_scans = ScanActivity.objects.filter(
			scan_of_id=scan_history_id,
			status__in=[RUNNING_TASK, INITIATED_TASK]
		).exclude(name__in=post_processing_names)

	if running_scans.exists() and not getattr(self, '_is_temporal_proxy', False):
		running_names = list(running_scans.values_list('name', flat=True))
		logger.warning("[TIER7][CORRELATE] Scan tasks still running (%s) — rescheduling", running_names)
		raise self.retry(countdown=10, max_retries=1000)

	vuln_count = Vulnerability.objects.filter(scan_history_id=scan_history_id).count()
	logger.warning("[TIER7][CORRELATE] Syncing %d vulnerabilities to Neo4j graph | scan_id=%s", vuln_count, scan_history_id)

	nm = Neo4jManager()
	try:
		nm.sync_scan_results(scan_history_id)
		logger.warning("[TIER7][CORRELATE] Neo4j sync complete | scan_id=%s", scan_history_id)
	except Exception as e:
		logger.error("[TIER7][CORRELATE] Neo4j sync failed for scan_id=%s: %s", scan_history_id, e)
	finally:
		nm.close()

	logger.warning("[TIER7][CORRELATE] Vulnerability correlation complete | scan_id=%s", scan_history_id)


def calculate_risk_scores(self, scan_history_id, ctx={}, description=None):
	"""Calculate a weighted risk score for discovered vulnerabilities.

	Args:
		scan_history_id (int): Scan history ID.
		ctx (dict): Scan context.
	"""
	logger.warning("[TIER7][RISK] Starting risk score calculation | scan_id=%s", scan_history_id)

	# Check if there are other scanning tasks still running
	from startScan.models import ScanActivity
	from reNgine.definitions import RUNNING_TASK, INITIATED_TASK
	post_processing_names = ['correlate_vulnerabilities', 'calculate_risk_scores', 'generate_impact_assessment', 'run_apme', 'report']

	if self.subscan:
		running_scans = ScanActivity.objects.filter(
			execution_id__in=self.subscan.workflow_ids,
			status__in=[RUNNING_TASK, INITIATED_TASK]
		).exclude(name__in=post_processing_names)
	else:
		running_scans = ScanActivity.objects.filter(
			scan_of_id=scan_history_id,
			status__in=[RUNNING_TASK, INITIATED_TASK]
		).exclude(name__in=post_processing_names)

	if running_scans.exists() and not getattr(self, '_is_temporal_proxy', False):
		running_names = list(running_scans.values_list('name', flat=True))
		logger.warning("[TIER7][RISK] Scan tasks still running (%s) — rescheduling", running_names)
		raise self.retry(countdown=10, max_retries=1000)

	from reNgine.correlation import VulnerabilityCorrelationEngine
	scan_history = ScanHistory.objects.get(id=scan_history_id)

	vuln_count = Vulnerability.objects.filter(scan_history_id=scan_history_id).count()
	logger.warning("[TIER7][RISK] Running correlation engine on %d vulnerabilities | scan_id=%s", vuln_count, scan_history_id)

	correlator = VulnerabilityCorrelationEngine(scan_history=scan_history)
	try:
		correlator.correlate_findings()
		logger.warning("[TIER7][RISK] Risk score calculation complete | scan_id=%s", scan_history_id)
	except Exception as e:
		logger.error("[TIER7][RISK] Correlation engine failed for scan_id=%s: %s", scan_history_id, e, exc_info=True)
		raise


def generate_impact_assessment(self, scan_history_id=None, vulnerability_id=None, ctx={}, description=None):
	"""Generate an AI-powered impact assessment for vulnerabilities.

	Args:
		scan_history_id (int): Scan history ID.
		vulnerability_id (int): Specific vulnerability ID.
		ctx (dict): Scan context.
	"""
	logger.warning("[TIER7][IMPACT] Starting AI impact assessment | scan_id=%s vuln_id=%s", scan_history_id, vulnerability_id)

	from reNgine.llm import LLMImpactGenerator
	from reNgine.privacy import PIIGate

	# Cap the per-run vuln limit so the activity stays well inside start_to_close_timeout.
	# Single-vuln calls from the dashboard UI bypass this via vulnerability_id.
	_VULN_LIMIT = 100

	if vulnerability_id:
		vulns = Vulnerability.objects.filter(id=vulnerability_id).prefetch_related(
			'subdomain__technologies', 'cve_ids'
		)
		if not scan_history_id and vulns.exists():
			scan_history_id = vulns.first().scan_history_id
		logger.warning("[TIER7][IMPACT] Single-vuln mode | vuln_id=%s scan_id=%s", vulnerability_id, scan_history_id)
	elif scan_history_id:
		# Order critical→info so the most important findings are assessed first
		# if the run is interrupted; cap to avoid timeout on large scans.
		vulns = (
			Vulnerability.objects
			.filter(scan_history_id=scan_history_id)
			.prefetch_related('subdomain__technologies', 'cve_ids')
			.order_by('-severity')[:_VULN_LIMIT]
		)
		total_vulns = Vulnerability.objects.filter(scan_history_id=scan_history_id).count()
		logger.warning(
			"[TIER7][IMPACT] Bulk mode | %d total vulns | processing up to %d (capped) | scan_id=%s",
			total_vulns, _VULN_LIMIT, scan_history_id,
		)
	else:
		logger.error("[TIER7][IMPACT] Neither scan_history_id nor vulnerability_id provided — aborting.")
		return False

	# Check if there are other scanning tasks still running
	if scan_history_id:
		from startScan.models import ScanActivity
		from reNgine.definitions import RUNNING_TASK, INITIATED_TASK
		post_processing_names = ['correlate_vulnerabilities', 'calculate_risk_scores', 'generate_impact_assessment', 'run_apme', 'report']

		if self.subscan:
			running_scans = ScanActivity.objects.filter(
				execution_id__in=self.subscan.workflow_ids,
				status__in=[RUNNING_TASK, INITIATED_TASK]
			).exclude(name__in=post_processing_names)
		else:
			running_scans = ScanActivity.objects.filter(
				scan_of_id=scan_history_id,
				status__in=[RUNNING_TASK, INITIATED_TASK]
			).exclude(name__in=post_processing_names)

		if running_scans.exists() and not getattr(self, '_is_temporal_proxy', False):
			running_names = list(running_scans.values_list('name', flat=True))
			logger.warning("[TIER7][IMPACT] Scan tasks still running (%s) — rescheduling", running_names)
			raise self.retry(countdown=10, max_retries=1000)

	generator = LLMImpactGenerator(logger)
	assessed_count = 0
	suppressed_count = 0
	failed_count = 0
	vuln_list = list(vulns)
	total = len(vuln_list)

	logger.warning("[TIER7][IMPACT] Beginning per-vulnerability LLM loop | total=%d | scan_id=%s", total, scan_history_id)

	for idx, vuln in enumerate(vuln_list, start=1):
		if vuln.is_suppressed:
			suppressed_count += 1
			logger.warning("[TIER7][IMPACT] [%d/%d] Skipping suppressed vuln_id=%s", idx, total, vuln.id)
			continue

		asset = vuln.subdomain.name if vuln.subdomain else (vuln.endpoint.http_url if vuln.endpoint else 'Unknown')

		try:
			# Step 1 — populate structured description/impact/remediation/references if not already done
			if not vuln.is_gpt_used:
				logger.warning(
					"[TIER7][IMPACT] [%d/%d] Generating GPT vulnerability report | vuln_id=%s",
					idx, total, vuln.id,
				)
				gpt_report = get_vulnerability_gpt_report(
					(vuln.name, vuln.get_path()),
					vulnerability_id=vuln.id,
				)
				if gpt_report.get('status'):
					vuln.refresh_from_db()
					logger.warning(
						"[TIER7][IMPACT] [%d/%d] GPT report saved | vuln_id=%s",
						idx, total, vuln.id,
					)
				else:
					logger.warning(
						"[TIER7][IMPACT] [%d/%d] GPT report failed | vuln_id=%s error=%s",
						idx, total, vuln.id, gpt_report.get('error'),
					)

			# Step 2 — generate AI business-impact assessment (for ImpactAssessment record)
			logger.warning(
				"[TIER7][IMPACT] [%d/%d] Calling LLM impact generator | vuln_id=%s severity=%s asset=%s",
				idx, total, vuln.id, vuln.severity, asset,
			)

			existing_assessment = ImpactAssessment.objects.filter(
				vulnerability__name=vuln.name,
				is_ai_generated=True
			).first()

			if existing_assessment and existing_assessment.potential_impact:
				logger.warning(
					"[TIER7][IMPACT] [%d/%d] Reusing existing target-agnostic impact assessment for %s | vuln_id=%s",
					idx, total, vuln.name, vuln.id,
				)
				final_impact = existing_assessment.potential_impact
				elapsed = 0.0
			else:
				# Omit Asset to make context target-agnostic (PII masking is handled by generator)
				context = "Vulnerability: %s\n" % vuln.name
				context += "Description: %s\n" % (vuln.description or '')
				if vuln.subdomain:
					context += "Technologies: %s\n" % ', '.join([t.name for t in vuln.subdomain.technologies.all()])

				t_start = time.time()
				final_impact = generator.generate_impact_assessment(context)
				elapsed = time.time() - t_start

			logger.warning(
				"[TIER7][IMPACT] [%d/%d] LLM returned in %.1fs | vuln_id=%s impact_len=%d",
				idx, total, elapsed, vuln.id, len(final_impact) if final_impact else 0,
			)

			# Persist business-impact text to ImpactAssessment model
			ImpactAssessment.objects.update_or_create(
				vulnerability=vuln,
				defaults={
					'scan_history_id': scan_history_id,
					'subdomain': vuln.subdomain,
					'potential_impact': final_impact,
					'is_ai_generated': True
				}
			)

			# Only write back to Vulnerability.impact when the structured GPT report
			# has not already set it (avoid overwriting the richer structured content).
			if not vuln.is_gpt_used:
				vuln.impact = final_impact
				vuln.save()

			assessed_count += 1
			logger.warning("[TIER7][IMPACT] [%d/%d] Saved | vuln_id=%s", idx, total, vuln.id)

		except Exception as e:
			failed_count += 1
			logger.error(
				"[TIER7][IMPACT] [%d/%d] Failed for vuln_id=%s: %s",
				idx, total, vuln.id, e, exc_info=True,
			)

	logger.warning(
		"[TIER7][IMPACT] AI impact assessment complete | assessed=%d suppressed=%d failed=%d | scan_id=%s",
		assessed_count, suppressed_count, failed_count, scan_history_id,
	)


def sync_cisa_kev_catalog():
	"""
	Syncs CISA KEV catalog and updates CVE records.
	"""
	import requests
	from startScan.models import CveId
	url = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"
	try:
		response = requests.get(url, timeout=30)
		if response.status_code == 200:
			data = response.json()
			cve_list = [v.get("cveID") for v in data.get("vulnerabilities", [])]
			if cve_list:
				CveId.objects.filter(name__in=cve_list).update(is_cisa_kev=True)
				logger.info(f"Successfully synced CISA KEV catalog. Updated {len(cve_list)} records.")
	except Exception as e:
		logger.error(f"Error syncing CISA KEV catalog: {e}")


def sync_semgrep_rules():
	"""
	Synchronizes Semgrep rules from the public registry to the local filesystem.
	Runs at system startup and can be triggered manually.
	"""
	rules_dir = "/usr/src/github/semgrep_rules"
	if not os.path.exists(rules_dir):
		os.makedirs(rules_dir, exist_ok=True)
	
	# Rule sets to sync
	rule_sets = {
		"p/secrets": "secrets.yaml",
		"p/owasp-top-ten": "owasp-top-10.yaml",
		"p/ci": "ci.yaml",
		"p/javascript": "javascript.yaml",
		"p/python": "python.yaml"
	}
	
	for config, filename in rule_sets.items():
		target_path = os.path.join(rules_dir, filename)
		url = f"https://semgrep.dev/c/{config}"
		try:
			logger.info(f"Syncing Semgrep rule set: {config} -> {filename}")
			response = requests.get(url, timeout=60)
			if response.status_code == 200:
				with open(target_path, 'wb') as f:
					f.write(response.content)
				logger.info(f"Successfully synced Semgrep rule set: {config}")
			else:
				logger.error(f"Failed to download Semgrep rule set {config}: HTTP {response.status_code}")
		except Exception as e:
			logger.error(f"Failed to sync Semgrep rule set {config}: {e}")


def clean_and_validate_url(url, base_domain=None):
	"""Cleans and validates a URL by stripping metadata and enforcing domain matching.

	Args:
		url (str): The raw URL string to clean and validate.
		base_domain (str, optional): The target domain name to scope check against.

	Returns:
		str: The cleaned, fully qualified URL, or None if invalid/out-of-scope.
	"""
	from urllib.parse import urlparse
	
	url = url.strip()
	if not url:
		return None

	# Strip any trailing metadata often present in raw discovery tool outputs
	# (e.g. "url] - metadata", "url [javascript]", "url - text/html")
	if ' ' in url:
		parts = url.split()
		# Find the first part that looks like a URL or relative path
		for p in parts:
			if p.startswith('http://') or p.startswith('https://') or p.startswith('//') or '/' in p:
				url = p
				break
		else:
			url = parts[0]

	# Extract only the URL content before any trailing brackets or brackets metadata
	url = url.split(']')[0].split('[')[0].strip()

	if not url:
		return None

	# Normalize the scheme
	parsed = urlparse(url)
	if not parsed.scheme:
		if base_domain:
			if url.startswith('//'):
				url = f"https:{url}"
			else:
				url = f"https://{base_domain}/{url.lstrip('/')}"
		else:
			url = f"https://{url.lstrip('/')}"
		parsed = urlparse(url)

	hostname = parsed.hostname
	if not hostname:
		return None

	# Filter out external/third-party domains to maintain strict scan scoping
	if base_domain:
		base_domain_lower = base_domain.lower()
		hostname_lower = hostname.lower()
		if not (hostname_lower == base_domain_lower or hostname_lower.endswith('.' + base_domain_lower)):
			return None

	# Ensure it is a valid HTTP/HTTPS protocol URL
	if not (url.startswith('http://') or url.startswith('https://')):
		return None

	return url


def semgrep_scan(self, ctx={}, mode='vulnerability', description=None):
	"""
	Runs Semgrep static analysis on fetched files.
	mode: 'secret' or 'vulnerability'
	"""
	scan_id = ctx.get('scan_history_id')
	results_dir = ctx.get('results_dir')

	logger.warning("[SEMGREP] Starting %s scan | scan_id=%s", mode, scan_id)

	if not results_dir:
		logger.error("Results directory not provided. Semgrep scan aborted.")
		return

	# Create a directory for Semgrep to scan
	semgrep_dir = os.path.join(results_dir, f'semgrep_{mode}_temp')
	os.makedirs(semgrep_dir, exist_ok=True)

	# But to be robust, we'll download files ourselves if the directory is empty
	SENSITIVE_EXTENSIONS = ('.js', '.env', '.php', '.asp', '.aspx', '.jsp', '.jspx', '.txt', '.log', '.conf', '.config', '.bak', '.old', '.json', '.yaml', '.yml', '.html', '.htm')

	# Load URLs from fetch_url output files and tool-specific files
	urls_from_files = set()
	if os.path.exists(results_dir):
		for f in os.listdir(results_dir):
			if f.endswith('_fetch_url.txt') or (f.startswith('urls_') and f.endswith('.txt')):
				fpath = os.path.join(results_dir, f)
				try:
					with open(fpath, 'r', encoding='utf-8', errors='ignore') as f_in:
						for line in f_in:
							url_str = line.strip()
							if url_str:
								urls_from_files.add(url_str)
					logger.warning("[SEMGREP] Loaded %d URLs from file: %s", len(urls_from_files), fpath)
				except Exception as e:
					logger.error("[SEMGREP] Failed to read file %s: %s", fpath, e)

	endpoints = EndPoint.objects.filter(scan_history_id=scan_id)
	endpoint_urls = set(e.http_url for e in endpoints if e.http_url)
	logger.warning("[SEMGREP] Sources: %d endpoint URLs from DB, %d URLs from result files", len(endpoint_urls), len(urls_from_files))
	all_urls = endpoint_urls | urls_from_files
	logger.warning("[SEMGREP] Total combined URLs before extension filter: %d", len(all_urls))

	# Filter sensitive URLs robustly by parsing their path component
	target_urls = []
	for url in all_urls:
		try:
			path = urlparse(url).path.lower()
			if path.endswith(SENSITIVE_EXTENSIONS):
				target_urls.append(url)
		except Exception:
			if url.lower().endswith(SENSITIVE_EXTENSIONS):
				target_urls.append(url)

	logger.warning("[SEMGREP] URLs matching sensitive extensions: %d", len(target_urls))

	if not target_urls:
		logger.warning("[SEMGREP] No target files found for %s scan — aborting.", mode)
		return

	# Retrieve proxies configuration from database
	available_proxies = []
	use_proxy = False

	try:
		if Proxy.objects.all().exists():
			proxy_config = Proxy.objects.first()
			if proxy_config.use_proxy:
				use_proxy = True
				available_proxies = [p.strip() for p in proxy_config.proxies.splitlines() if p.strip()]
				# Shuffle the proxies to distribute traffic randomly
				random.shuffle(available_proxies)
				logger.warning("[SEMGREP] Proxy enabled with %d available proxies", len(available_proxies))
			else:
				logger.warning("[SEMGREP] Proxy configured but disabled — running direct")
	except Exception as e:
		logger.error("[SEMGREP] Failed to load proxies configuration: %s", e)

	# Convert custom headers list to dictionary
	headers_dict = {}
	custom_headers = self.yaml_configuration.get(CUSTOM_HEADERS, [])
	custom_header = self.yaml_configuration.get(CUSTOM_HEADER)
	if custom_header:
		custom_headers.append(custom_header)
	for h in custom_headers:
		if ':' in h:
			k, v = h.split(':', 1)
			headers_dict[k.strip()] = v.strip()
	if 'User-Agent' not in headers_dict:
		headers_dict['User-Agent'] = 'Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36'

	base_domain = self.domain.name if self.domain else None

	# Clean, validate, and deduplicate all URLs
	unique_targets = set()
	invalid_count = 0
	for url in target_urls:
		clean_url = clean_and_validate_url(url, base_domain)
		if clean_url:
			unique_targets.add(clean_url)
		else:
			invalid_count += 1
	unique_targets = list(unique_targets)
	logger.warning("[SEMGREP] After clean/dedup: %d valid unique targets (%d dropped as invalid/out-of-scope)", len(unique_targets), invalid_count)

	# Cap the maximum files to scan to prevent infinite stalls on huge targets
	MAX_SEMGREP_FILES = 500
	if len(unique_targets) > MAX_SEMGREP_FILES:
		logger.warning("[SEMGREP] Capping target URLs from %d to %d to prevent stalling.", len(unique_targets), MAX_SEMGREP_FILES)
		unique_targets = unique_targets[:MAX_SEMGREP_FILES]
	else:
		logger.warning("[SEMGREP] Target URL count %d is within cap limit (%d) — no capping applied.", len(unique_targets), MAX_SEMGREP_FILES)

	downloaded_count = 0

	# Define download worker function
	def download_file(full_url):
		# Create a safe filename from URL
		safe_name = "".join([c if c.isalnum() else "_" for c in full_url])
		ext = os.path.splitext(urlparse(full_url).path)[1]
		if not ext:
			ext = ".js"
		filename = f"{safe_name}{ext}"
		filepath = os.path.join(semgrep_dir, filename)

		if os.path.exists(filepath):
			return True, filepath # Already downloaded

		logger.warning("[SEMGREP] Downloading file: %s", full_url)

		# Try downloading the URL, with proxy cycling on failure (capped at max 5 to prevent stalls)
		max_retries = min(5, len(available_proxies)) if use_proxy and available_proxies else 1
		if max_retries < 1:
			max_retries = 1
		attempt = 0
		current_proxy_index = random.randint(0, len(available_proxies) - 1) if available_proxies else 0

		while attempt < max_retries:
			proxies = None
			current_proxy_name = None
			if use_proxy and available_proxies:
				current_proxy_name = available_proxies[current_proxy_index % len(available_proxies)]
				proxies = {
					'http': current_proxy_name,
					'https': current_proxy_name
				}

			try:
				# Stream response to enforce maximum download file size of 5MB
				resp = requests.get(full_url, headers=headers_dict, proxies=proxies, timeout=10, verify=False, stream=True)
				if resp.status_code == 200:
					content = b""
					max_bytes = 5 * 1024 * 1024  # 5MB
					for chunk in resp.iter_content(chunk_size=8192):
						if len(content) + len(chunk) > max_bytes:
							content += chunk[:max_bytes - len(content)]
							break
						content += chunk
					
					with open(filepath, 'wb') as f:
						f.write(content)
					logger.warning("[SEMGREP] Download complete: %s", full_url)
					return True, filepath
				elif resp.status_code in [407, 502, 503, 504]:
					# Proxy connection/auth issues, cycle and retry
					raise requests.exceptions.ProxyError(f"Proxy returned status code {resp.status_code}")
				else:
					logger.debug(f"Semgrep downloader got status {resp.status_code} for {full_url}")
					break
			except (requests.exceptions.ProxyError, requests.exceptions.ConnectionError, requests.exceptions.Timeout) as e:
				attempt += 1
				current_proxy_index += 1
			except Exception as e:
				logger.debug(f"Semgrep downloader got non-network error for {full_url}: {e}")
				break
		return False, None

	# Execute downloads in parallel using a ThreadPoolExecutor
	file_to_url_map = {}
	if unique_targets:
		from concurrent.futures import ThreadPoolExecutor, as_completed
		logger.warning("[SEMGREP] Downloading %d files in parallel (max_workers=10)...", len(unique_targets))
		with ThreadPoolExecutor(max_workers=10) as executor:
			futures = {executor.submit(download_file, url): url for url in unique_targets}
			for future in as_completed(futures):
				try:
					success, filepath = future.result()
					if success and filepath:
						downloaded_count += 1
						file_to_url_map[os.path.basename(filepath)] = futures[future]
				except Exception as e:
					logger.error("[SEMGREP] Error in download thread: %s", e)
		logger.warning("[SEMGREP] Download phase complete: %d / %d files downloaded successfully", downloaded_count, len(unique_targets))

	if downloaded_count == 0:
		logger.warning("[SEMGREP] No files could be downloaded — aborting %s scan.", mode)
		shutil.rmtree(semgrep_dir, ignore_errors=True)
		return

	rules_dir = "/usr/src/github/semgrep_rules"
	config_file = "owasp-top-10.yaml" if mode == 'vulnerability' else "secrets.yaml"
	rules_path = os.path.join(rules_dir, config_file)

	# Fallback if local sync failed
	if not os.path.exists(rules_path):
		logger.warning("[SEMGREP] Local rules not found at %s — falling back to remote registry.", rules_path)
		rules_path = "p/owasp-top-10" if mode == 'vulnerability' else "p/secrets"
	else:
		logger.warning("[SEMGREP] Using local rules: %s", rules_path)

	output_json = os.path.join(results_dir, f'semgrep_{mode}_{int(time.time())}.json')

	# Run Semgrep
	cmd = f"semgrep scan --config {rules_path} {semgrep_dir} --json --output {output_json} --timeout 600"
	logger.warning("[SEMGREP] Executing: %s", cmd)
	return_code, output = run_command(cmd, scan_id=scan_id)
	logger.warning("[SEMGREP] semgrep process exited with return code: %s", return_code)

	if os.path.exists(output_json):
		try:
			with open(output_json, 'r') as f:
				data = json.load(f)
				results = data.get('results', [])

				for result in results:
					if mode == 'secret':
						save_semgrep_secret_finding(result, ctx, semgrep_dir, file_to_url_map)
					else:
						save_semgrep_vulnerability_finding(result, ctx, semgrep_dir, file_to_url_map)

			logger.warning("[SEMGREP] %s scan complete — %d matches found.", mode, len(results))
		except Exception as e:
			logger.error("[SEMGREP] Error parsing output: %s", e)
	else:
		logger.warning("[SEMGREP] Output JSON not found at %s — semgrep may have failed silently.", output_json)

	# Cleanup
	shutil.rmtree(semgrep_dir, ignore_errors=True)

	return return_code


def save_semgrep_vulnerability_finding(result, ctx, base_dir, file_to_url_map=None):
	"""Saves a Semgrep finding as a Vulnerability.

	Args:
		result (dict): Semgrep finding match dictionary.
		ctx (dict): Scan context containing history and domain IDs.
		base_dir (str): Base directory path of the cloned repo.
		file_to_url_map (dict): Optional map from downloaded file basename to original URL.
	"""
	extra = result.get('extra', {})
	path = result.get('path', '')
	
	try:
		scan = ScanHistory.objects.get(id=ctx.get('scan_history_id'))
		domain = Domain.objects.get(id=ctx.get('domain_id'))
		
		check_id = result.get('check_id', '')
		cleaned_check_id = clean_semgrep_check_id(check_id)
		
		source_file = path.replace(base_dir, '').lstrip('/')
		mapped_url = file_to_url_map.get(os.path.basename(source_file)) if file_to_url_map else None
		final_url = mapped_url if mapped_url else source_file
		
		vuln_data = {
			'name': f"Semgrep: {cleaned_check_id}",
			'description': extra.get('message', ''),
			'severity': SEMGREP_SEVERITY_MAP.get(extra.get('severity', 'INFO'), 0),
			'http_url': final_url,
			'type': 'SAST',
			'request': f"File: {source_file}\nLine: {result.get('start', {}).get('line')}",
			'response': extra.get('lines', ''),
			'source': 'Semgrep',
		}
		save_vulnerability(vuln_data, scan_history=scan, target_domain=domain)
	except Exception as e:
		logger.error(f"Error saving Semgrep vulnerability: {e}")


def save_semgrep_secret_finding(result, ctx, base_dir, file_to_url_map=None):
	"""Saves a Semgrep finding as a SecretLeak.

	Args:
		result (dict): Semgrep finding match dictionary.
		ctx (dict): Scan context containing history and domain IDs.
		base_dir (str): Base directory path of the cloned repo.
		file_to_url_map (dict): Optional map from downloaded file basename to original URL.
	"""
	extra = result.get('extra', {})
	path = result.get('path', '')
	
	try:
		scan = ScanHistory.objects.get(id=ctx.get('scan_history_id'))
		
		check_id = result.get('check_id', '')
		cleaned_check_id = clean_semgrep_check_id(check_id)
		
		source_file = path.replace(base_dir, '').lstrip('/')
		mapped_url = file_to_url_map.get(os.path.basename(source_file)) if file_to_url_map else None
		final_url = mapped_url if mapped_url else source_file
		
		leak_data = {
			'scan_history': scan,
			'tool_name': 'Semgrep',
			'secret_type': cleaned_check_id or 'Secret',
			'source_url': final_url,
			'match_content': extra.get('lines', '').strip(),
			'status': 'unverified'
		}
		save_secret_leak(**leak_data)
	except Exception as e:
		logger.error(f"Error saving Semgrep secret: {e}")


def run_apme(self, scan_history_id, ctx={}, description=None):
	"""Run the Attack Path Modeling Engine (APME).

	Args:
		scan_history_id (int): Scan history ID.
		ctx (dict): Scan context.
	"""
	logger.warning("[TIER7][APME] Starting Attack Path Modeling Engine | scan_id=%s", scan_history_id)

	if not RENGINE_APME_ENABLED:
		logger.warning("[TIER7][APME] Disabled via RENGINE_APME_ENABLED=False — skipping | scan_id=%s", scan_history_id)
		return

	# Check if there are other scanning tasks still running
	from startScan.models import ScanActivity
	from reNgine.definitions import RUNNING_TASK, INITIATED_TASK
	post_processing_names = ['correlate_vulnerabilities', 'calculate_risk_scores', 'generate_impact_assessment', 'run_apme', 'report']

	if self.subscan:
		running_scans = ScanActivity.objects.filter(
			execution_id__in=self.subscan.workflow_ids,
			status__in=[RUNNING_TASK, INITIATED_TASK]
		).exclude(name__in=post_processing_names)
	else:
		running_scans = ScanActivity.objects.filter(
			scan_of_id=scan_history_id,
			status__in=[RUNNING_TASK, INITIATED_TASK]
		).exclude(name__in=post_processing_names)

	if running_scans.exists() and not getattr(self, '_is_temporal_proxy', False):
		running_names = list(running_scans.values_list('name', flat=True))
		logger.warning("[TIER7][APME] Scan tasks still running (%s) — rescheduling", running_names)
		raise self.retry(countdown=10, max_retries=1000)

	try:
		from apme.orchestrator import APMEOrchestrator
		from startScan.models import ScanHistory

		# Fetch configuration from engine
		scan = ScanHistory.objects.get(id=scan_history_id)
		config = yaml.safe_load(scan.scan_type.yaml_configuration) or {}
		apme_config = config.get(ATTACK_PATH_MODELING, {})
		top_n = apme_config.get('top_n', 5)

		logger.warning("[TIER7][APME] Running orchestrator | top_n=%d | scan_id=%s", top_n, scan_history_id)
		orchestrator = APMEOrchestrator(top_n=top_n)
		result = orchestrator.run(scan_history_id)

		logger.warning(
			"[TIER7][APME] Complete | total_paths=%d returned_paths=%d | scan_id=%s",
			result.get('total_paths', 0), result.get('returned_paths', 0), scan_history_id,
		)
		return result
	except Exception as exc:
		logger.error("[TIER7][APME] Failed for scan_id=%s: %s", scan_history_id, exc, exc_info=True)
		return {"error": str(exc), "total_paths": 0, "returned_paths": 0, "paths": []}