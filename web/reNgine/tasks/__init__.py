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

"""
Celery tasks.
"""

logger = get_task_logger(__name__)



SCAN_PIPELINE_DEFINITION = [
    {
        'tier': 1,
        'name': 'Discovery',
        'type': 'CONCURRENT',
        'tasks': ['amass_intel_discovery', 'subdomain_discovery', 'osint', 'spiderfoot_scan', 'firewall_vpn_scan']
    },
    {
        'tier': 2,
        'name': 'Enumeration',
        'type': 'CONCURRENT',
        'tasks': ['http_crawl', 'port_scan', 'screenshot']
    },
    {
        'tier': 3,
        'name': 'Fuzzing',
        'type': 'SEQUENTIAL',
        'tasks': ['dir_file_fuzz']
    },
    {
        'tier': 4,
        'name': 'URL Extraction',
        'type': 'SEQUENTIAL',
        'tasks': ['fetch_url']
    },
    {
        'tier': 5,
        'name': 'Analysis',
        'type': 'CONCURRENT',
        'tasks': ['web_api_discovery', 'waf_detection']
    },
    {
        'tier': 6,
        'name': 'Security Assessment',
        'type': 'CONCURRENT',
        'tasks': ['waf_bypass', 'vulnerability_scan']
    },
    {
        'tier': 7,
        'name': 'Finalization',
        'type': 'SEQUENTIAL',
        'tasks': [
            'correlate_vulnerabilities',
            'enrich_scan_cves',
            'calculate_risk_scores',
            'generate_impact_assessment',
            'stress_test',
            'run_apme'
        ]
    }
]


#----------------------#
# Scan / Subscan tasks #
#----------------------#


def sync_all_scans_to_graph(self, heartbeat_callback=None):
	"""Sync all pre-existing scan results to Neo4j graph."""
	logger.warning("Starting global graph synchronization...")
	nm = Neo4jManager()
	try:
		nm.sync_all_scans(heartbeat_callback=heartbeat_callback)
	finally:
		nm.close()
	logger.warning("Global graph synchronization completed.")

def finish_osint(results, scan_history_id):
    """Trigger the Deep Pursuit OSINT pipeline after standard OSINT tasks complete.

    Called synchronously from within the osint() Temporal activity. The
    activity's heartbeat thread (started by _run_task) keeps Temporal alive
    during the pipeline run.
    """
    from reNgine.osint_tasks import osint_orchestrator
    logger.info(f"[finish_osint] Starting Deep Pursuit pipeline for scan {scan_history_id}")
    osint_orchestrator(scan_history_id=scan_history_id)
    return results

def finish_osint_discovery(results, results_dir):
    """Callback for OSINT discovery tasks. Strips metadata from results."""
    opsec = get_opsec_manager()
    opsec.strip_directory(results_dir)
    logger.info(f"OSINT discovery completed and cleaned up in {results_dir}")
    return results


def initiate_scan_temporal(
		scan_history_id,
		domain_id,
		engine_id=None,
		scan_type=LIVE_SCAN,
		results_dir=RENGINE_RESULTS,
		imported_subdomains=[],
		out_of_scope_subdomains=[],
		initiated_by_id=None,
		starting_point_path='',
		excluded_paths=[],
		custom_dorks=None,
		enable_spiderfoot_scan=False,
		selected_plugin_slugs=None,
		profile_ctx=None,
		task_queue=None,
	):
	"""Initiate a new scan using Temporal durable workflow orchestration.

	This function performs the same scan setup as `initiate_scan` (creates the
	ScanHistory record, results directory, initial subdomain and endpoint objects)
	but delegates execution to a `MasterScanWorkflow` on the Temporal cluster
	instead of building a Celery chain.

	This is the production entrypoint for all new scans when Temporal is active.

	Args:
		scan_history_id (int): ScanHistory id.
		domain_id (int): Domain id.
		engine_id (int): Engine ID.
		scan_type (int): Scan type (periodic, live).
		results_dir (str): Results directory root.
		imported_subdomains (list): Pre-imported subdomains.
		out_of_scope_subdomains (list): Out-of-scope subdomains to skip.
		initiated_by_id (int): User ID initiating the scan.
		starting_point_path (str): URL path filter. Default: ''.
		excluded_paths (list): URL paths to exclude from scan.
		custom_dorks (str): Custom dorks to run. Default: None.
		enable_spiderfoot_scan (bool): Whether to enable SpiderFoot scan.

	Returns:
		dict: {'success': True, 'workflow_id': str} on success.
	"""
	import asyncio
	import uuid

	logger.info('Initiating scan via Temporal workflow orchestrator')
	scan = None
	try:
		# ---- Get scan objects ----
		if scan_history_id:
			scan = ScanHistory.objects.filter(pk=scan_history_id).first()

		if not engine_id and scan:
			engine_id = scan.scan_type.id
		engine = EngineType.objects.get(pk=engine_id)

		# ---- Parse engine YAML config ----
		config = yaml.safe_load(engine.yaml_configuration)
		enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
		gf_patterns = config.get(GF_PATTERNS, [])
		api_discovery_config = config.get(WEB_API_DISCOVERY, {})
		api_discovery_tools = api_discovery_config.get(USES_TOOLS, [])
		kr_wordlist = api_discovery_config.get(KITERUNNER_WORDLIST, 'routes-small.kite')

		# ---- Get domain ----
		domain = Domain.objects.get(pk=domain_id)
		domain.last_scan_date = timezone.now()
		domain.save()
		imported_subdomains = merge_imported_subdomains(domain, imported_subdomains)

		starting_point_path = starting_point_path.rstrip('/')

		if scan_type == SCHEDULED_SCAN:
			scan_history_id = create_scan_object(
				host_id=domain_id,
				engine_id=engine_id,
				initiated_by_id=initiated_by_id,
			)

		if not scan:
			scan = ScanHistory.objects.get(pk=scan_history_id)

		tasks = list(engine.tasks)

		# WAF Logic: If WAF Bypass is enabled, WAF Detection MUST also be enabled
		if 'waf_bypass' in tasks and 'waf_detection' not in tasks:
			tasks.insert(tasks.index('waf_bypass'), 'waf_detection')

		if enable_spiderfoot_scan and 'spiderfoot_scan' not in tasks:
			tasks.append('spiderfoot_scan')

		# ---- Update ScanHistory ----
		scan.scan_status = RUNNING_TASK
		scan.scan_type = engine
		scan.domain = domain
		scan.start_scan_date = timezone.now()
		scan.tasks = tasks
		scan.results_dir = f'{results_dir}/{domain.name}_{scan.id}'
		scan.cfg_starting_point_path = starting_point_path
		scan.cfg_excluded_paths = excluded_paths
		scan.cfg_out_of_scope_subdomains = out_of_scope_subdomains
		scan.cfg_imported_subdomains = imported_subdomains

		add_gf_patterns = gf_patterns and 'fetch_url' in tasks
		if add_gf_patterns:
			scan.used_gf_patterns = ','.join(gf_patterns)

		if custom_dorks:
			scan.cfg_custom_dorks = custom_dorks

		scan.save()

		from reNgine.utils.scan_cancellation import set_scan_stop_kill_switch
		set_scan_stop_kill_switch(scan.id, enabled=False)

		# ---- Create scan results directory ----
		os.makedirs(scan.results_dir, exist_ok=True)

		if custom_dorks:
			with open(f'{scan.results_dir}/custom_dorks.txt', 'w') as f:
				f.write(custom_dorks)

		# ---- Save imported subdomains ----
		save_imported_subdomains(imported_subdomains, ctx={
			'scan_history_id': scan.id,
			'domain_id': domain.id,
			'results_dir': scan.results_dir
		})

		# ---- Create initial root subdomain & endpoint ----
		ctx_bootstrap = {
			'scan_history_id': scan.id,
			'engine_id': engine_id,
			'domain_id': domain.id,
			'results_dir': scan.results_dir,
			'starting_point_path': starting_point_path,
			'out_of_scope_subdomains': out_of_scope_subdomains,
		}
		subdomain, _ = save_subdomain(domain.name, ctx=ctx_bootstrap)
		_root = f'{domain.name}{starting_point_path}' if starting_point_path else domain.name
		if not _root.startswith(('http://', 'https://')):
			_root = f'http://{_root}'
		endpoint, _ = save_endpoint(
			_root,
			ctx=ctx_bootstrap,
			crawl=enable_http_crawl,
			is_default=True,
			subdomain=subdomain
		)
		if endpoint and endpoint.is_alive:
			subdomain.http_url = endpoint.http_url
			subdomain.http_status = endpoint.http_status
			subdomain.response_time = endpoint.response_time
			subdomain.page_title = endpoint.page_title
			subdomain.content_type = endpoint.content_type
			subdomain.content_length = endpoint.content_length
			for tech in endpoint.techs.all():
				subdomain.technologies.add(tech)
			subdomain.save()

		# ---- Get Hardware Profile Details ----
		from scanEngine.models import HardwareProfile
		hardware_profile_ctx = None
		if scan.hardware_profile:
			profile = scan.hardware_profile
			hardware_profile_ctx = {
				'id': profile.id,
				'name': profile.name,
				'threads': profile.threads,
				'rate_limit': profile.rate_limit,
				'timeout': profile.timeout,
				'delay': profile.delay,
				'retries': profile.retries,
			}
		else:
			try:
				profile = HardwareProfile.objects.filter(is_default=True, is_active=True).first()
				if not profile:
					profile = HardwareProfile.objects.filter(is_active=True).first()
				if profile:
					hardware_profile_ctx = {
						'id': profile.id,
						'name': profile.name,
						'threads': profile.threads,
						'rate_limit': profile.rate_limit,
						'timeout': profile.timeout,
						'delay': profile.delay,
						'retries': profile.retries,
					}
			except Exception:
				pass

		# ---- Build Temporal workflow context (mirrors Celery ctx) ----
		_proxy = Proxy.objects.first()
		temporal_ctx = {
			'scan_history_id': scan.id,
			'engine_id': engine_id,
			'domain_id': domain.id,
			'results_dir': scan.results_dir,
			'starting_point_path': starting_point_path,
			'excluded_paths': excluded_paths,
			'yaml_configuration': config,
			'out_of_scope_subdomains': out_of_scope_subdomains,
			'custom_dorks': custom_dorks,
			'api_discovery_tools': api_discovery_tools,
			'kr_wordlist': kr_wordlist,
			'tasks': tasks,
			'use_tor': bool(_proxy and _proxy.use_tor),
			'selected_plugin_slugs': selected_plugin_slugs or [],
			'hardware_profile': hardware_profile_ctx,
			'profile': profile_ctx or {},
		}

		# ---- Start MasterScanWorkflow on Temporal ----
		from reNgine.temporal_client import TemporalClientProvider, run_and_close
		from datetime import timedelta
		from temporalio.exceptions import ServerError as TemporalServiceError

		workflow_id = f"scan-{scan.id}-{uuid.uuid4().hex[:8]}"
		max_retries = 3
		backoff_base = 2

		async def _start_workflow_with_retry():
			"""Async helper: connect to Temporal, start workflow, retry on transient errors."""
			for attempt in range(1, max_retries + 1):
				try:
					client = await TemporalClientProvider.get_client()
					logger.info(
						f'[initiate_scan_temporal] Starting MasterScanWorkflow '
						f'attempt {attempt}/{max_retries} workflow_id={workflow_id}'
					)
					handle = await client.start_workflow(
						"MasterScanWorkflow",
						args=[temporal_ctx],
						id=workflow_id,
						task_queue=task_queue or "python-orchestrator-queue",
						execution_timeout=timedelta(days=30),
						run_timeout=timedelta(days=30),
						task_timeout=timedelta(hours=1),
					)
					return handle.id
				except TemporalServiceError as e:
					if attempt == max_retries:
						logger.error(
							f'[initiate_scan_temporal] Failed after {max_retries} retries: {e}'
						)
						raise
					wait_time = backoff_base ** (attempt - 1)
					logger.warning(
						f'[initiate_scan_temporal] Attempt {attempt} failed, retrying in {wait_time}s: {e}'
					)
					await asyncio.sleep(wait_time)

		loop = asyncio.new_event_loop()
		asyncio.set_event_loop(loop)
		started_workflow_id = run_and_close(loop, _start_workflow_with_retry())

		logger.info(
			f'Started MasterScanWorkflow id={started_workflow_id} '
			f'for scan_history_id={scan.id}'
		)

		# Track workflow execution so cancel_workflow can find it
		from startScan.models import TemporalWorkflowExecution
		TemporalWorkflowExecution.objects.get_or_create(
			workflow_id=started_workflow_id,
			defaults={
				'scan_history': scan,
				'run_id': started_workflow_id,
				'workflow_type': 'MasterScanWorkflow',
				'status': 'RUNNING',
			}
		)
		scan.workflow_ids = [started_workflow_id]
		scan.save()

		# Send start notification
		try:
			send_scan_notif(
				scan.id,
				subscan_id=None,
				engine_id=engine_id,
				status=CELERY_TASK_STATUS_MAP.get(scan.scan_status, 'RUNNING')
			)
		except Exception as e:
			logger.warning(f"Could not send scan notification: {e}")

		return {
			'success': True,
			'workflow_id': started_workflow_id,
		}

	except Exception as e:
		logger.exception(e)
		if scan:
			scan.scan_status = FAILED_TASK
			scan.error_message = str(e)
			scan.save()
		return {
			'success': False,
			'error': str(e)
		}


def initiate_subscan_temporal(
		scan_history_id,
		subdomain_id,
		engine_id=None,
		scan_type=None,
		results_dir=RENGINE_RESULTS,
		starting_point_path='',
		excluded_paths=[],
		custom_dorks=None,
		selected_plugin_slugs=None,
		task_queue=None,
	):
	"""Initiate a new subscan using Temporal durable workflow orchestration.

	This function performs the subdomain scan setup (creates the SubScan records,
	results directory, and initial endpoint objects) and triggers a single
	`SubScanWorkflow` on the Temporal cluster to execute all requested tasks
	in tiered execution order.

	Args:
		scan_history_id (int): ScanHistory ID.
		subdomain_id (int): Target Subdomain ID.
		engine_id (int, optional): Engine ID.
		scan_type (str or list, optional): Subscan type or list of subscan types to run.
		results_dir (str, optional): Results directory root.
		starting_point_path (str, optional): URL path filter. Default: ''.
		excluded_paths (list, optional): URL paths to exclude. Default: [].
		custom_dorks (str, optional): Custom dorks to run. Default: None.

	Returns:
		dict: {'success': True, 'workflow_id': str} on success.
	"""
	import asyncio
	import uuid

	# Normalize scan_type to list of tasks
	if isinstance(scan_type, str):
		scan_types = [scan_type]
	else:
		scan_types = list(scan_type)

	logger.info(f"Initiating subdomain subscans '{scan_types}' via Temporal workflow orchestrator")
	created_subscans = []
	try:
		# ---- Get Subdomain, Domain and ScanHistory ----
		subdomain = Subdomain.objects.get(pk=subdomain_id)
		scan = ScanHistory.objects.get(pk=subdomain.scan_history.id)
		domain = Domain.objects.get(pk=subdomain.target_domain.id)

		# ---- Get EngineType ----
		engine_id = engine_id or scan.scan_type.id
		engine = EngineType.objects.get(pk=engine_id)

		# ---- Get YAML config ----
		config = yaml.safe_load(engine.yaml_configuration)
		enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
		
		# ---- Get web_api_discovery config ----
		api_discovery_config = config.get(WEB_API_DISCOVERY, {})
		api_discovery_tools = api_discovery_config.get(USES_TOOLS, [])
		kr_wordlist = api_discovery_config.get(KITERUNNER_WORDLIST, 'routes-small.kite')

		# ---- Skip subscan types that are already active for this subdomain ----
		active_statuses = [INITIATED_TASK, RUNNING_TASK, PAUSED_TASK]
		existing_active_subscans = (
			SubScan.objects
			.filter(
				scan_history=scan,
				subdomain=subdomain,
				type__in=scan_types,
				status__in=active_statuses,
			)
			.order_by('-start_scan_date')
		)
		existing_active_by_type = {subscan.type: subscan for subscan in existing_active_subscans}
		pending_scan_types = [stype for stype in scan_types if stype not in existing_active_by_type]

		if not pending_scan_types:
			existing_workflow_id = next(
				(
					workflow_id
					for subscan in existing_active_subscans
					for workflow_id in (subscan.workflow_ids or [])
					if workflow_id
				),
				None,
			)
			logger.info(
				f"Skipping duplicate subscan launch for subdomain_id={subdomain.id}. "
				f"Active types already exist: {scan_types}. existing_workflow_id={existing_workflow_id}"
			)
			return {
				'success': True,
				'workflow_id': existing_workflow_id,
				'skipped': True,
				'skipped_scan_types': scan_types,
			}

		# ---- Create scan activity records of SubScan Model ----
		subscans_info = []
		for stype in pending_scan_types:
			subscan = SubScan(
				start_scan_date=timezone.now(),
				workflow_ids=[],
				scan_history=scan,
				subdomain=subdomain,
				type=stype,
				status=RUNNING_TASK,
				engine=engine
			)
			subscan.save()
			created_subscans.append(subscan)
			subscans_info.append({
				'id': subscan.id,
				'type': stype
			})

		# ---- Create results directory ----
		# Anchor the directory to the first subscan record's ID
		first_subscan_id = created_subscans[0].id
		subscan_results_dir = f'{scan.results_dir}/subscans/{first_subscan_id}'
		os.makedirs(subscan_results_dir, exist_ok=True)

		# ---- Update scan's tasks list ----
		for stype in pending_scan_types:
			if stype not in scan.tasks:
				scan.tasks.append(stype)
		scan.save()

		# ---- Send start notification ----
		try:
			send_scan_notif(
				scan.id,
				subscan_id=first_subscan_id,
				engine_id=engine_id,
				status='RUNNING'
			)
		except Exception as notif_err:
			logger.warning(f"Could not send subscan start notification: {notif_err}")

		# ---- Get Hardware Profile Details ----
		from scanEngine.models import HardwareProfile
		hardware_profile_ctx = None
		if scan.hardware_profile:
			profile = scan.hardware_profile
			hardware_profile_ctx = {
				'id': profile.id,
				'name': profile.name,
				'threads': profile.threads,
				'rate_limit': profile.rate_limit,
				'timeout': profile.timeout,
				'delay': profile.delay,
				'retries': profile.retries,
			}
		else:
			try:
				profile = HardwareProfile.objects.filter(is_default=True, is_active=True).first()
				if not profile:
					profile = HardwareProfile.objects.filter(is_active=True).first()
				if profile:
					hardware_profile_ctx = {
						'id': profile.id,
						'name': profile.name,
						'threads': profile.threads,
						'rate_limit': profile.rate_limit,
						'timeout': profile.timeout,
						'delay': profile.delay,
						'retries': profile.retries,
					}
			except Exception:
				pass

		# ---- Build Temporal workflow context (mirrors Celery ctx) ----
		_proxy = Proxy.objects.first()
		temporal_ctx = {
			'scan_history_id': scan.id,
			'subscan_id': first_subscan_id,
			'subscans_info': subscans_info,
			'engine_id': engine_id,
			'domain_id': domain.id,
			'subdomain_id': subdomain.id,
			'subdomain_name': subdomain.name,
			'subdomain_http_url': subdomain.http_url,
			'yaml_configuration': config,
			'results_dir': subscan_results_dir,
			'starting_point_path': starting_point_path,
			'excluded_paths': excluded_paths,
			'api_discovery_tools': api_discovery_tools,
			'kr_wordlist': kr_wordlist,
			'use_tor': bool(_proxy and _proxy.use_tor),
			'selected_plugin_slugs': selected_plugin_slugs or [],
			'hardware_profile': hardware_profile_ctx,
		}

		# ---- Create initial endpoints in DB ----
		base_url = f'{subdomain.name}{starting_point_path}' if starting_point_path else subdomain.name
		endpoint, _ = save_endpoint(
			base_url,
			crawl=enable_http_crawl,
			ctx=temporal_ctx,
			subdomain=subdomain
		)
		if endpoint and endpoint.is_alive:
			logger.warning(f'Found subdomain root HTTP URL {endpoint.http_url}')
			subdomain.http_url = endpoint.http_url
			subdomain.http_status = endpoint.http_status
			subdomain.response_time = endpoint.response_time
			subdomain.page_title = endpoint.page_title
			subdomain.content_type = endpoint.content_type
			subdomain.content_length = endpoint.content_length
			for tech in endpoint.techs.all():
				subdomain.technologies.add(tech)
			subdomain.save()

			# Update context with new URL
			temporal_ctx['subdomain_http_url'] = subdomain.http_url

		# ---- Start SubScanWorkflow on Temporal ----
		from reNgine.temporal_client import TemporalClientProvider, run_and_close
		from datetime import timedelta
		from temporalio.exceptions import ServerError as TemporalServiceError
		from temporalio.common import RetryPolicy

		workflow_id = f"subscan-{first_subscan_id}-{uuid.uuid4().hex[:8]}"
		max_retries = 3
		backoff_base = 2

		async def _start_subscan_workflow_with_retry():
			"""Async helper: connect to Temporal, start SubScanWorkflow, retry on transient errors."""
			for attempt in range(1, max_retries + 1):
				try:
					client = await TemporalClientProvider.get_client()
					logger.info(
						f'[initiate_subscan_temporal] Starting SubScanWorkflow '
						f'attempt {attempt}/{max_retries} workflow_id={workflow_id}'
					)
					handle = await client.start_workflow(
						"SubScanWorkflow",
						args=[temporal_ctx, pending_scan_types],
						id=workflow_id,
						task_queue=task_queue or "python-orchestrator-queue",
						execution_timeout=timedelta(days=7),
						run_timeout=timedelta(days=7),
						task_timeout=timedelta(hours=1),
						retry_policy=RetryPolicy(maximum_attempts=1),
					)
					return handle.id
				except TemporalServiceError as e:
					if attempt == max_retries:
						logger.error(
							f'[initiate_subscan_temporal] Failed after {max_retries} retries: {e}'
						)
						raise
					wait_time = backoff_base ** (attempt - 1)
					logger.warning(
						f'[initiate_subscan_temporal] Attempt {attempt} failed, retrying in {wait_time}s: {e}'
					)
					await asyncio.sleep(wait_time)

		loop = asyncio.new_event_loop()
		asyncio.set_event_loop(loop)
		started_workflow_id = run_and_close(loop, _start_subscan_workflow_with_retry())

		logger.info(
			f"Started SubScanWorkflow id={started_workflow_id} "
			f"for subscan_id={first_subscan_id} (types={pending_scan_types})"
		)

		# Save workflow ID in all subscans' workflow_ids list
		for subscan in created_subscans:
			subscan.workflow_ids = [started_workflow_id]
			subscan.save()

		return {
			'success': True,
			'workflow_id': started_workflow_id,
			'started_scan_types': pending_scan_types,
		}

	except Exception as e:
		logger.exception(e)
		for subscan in created_subscans:
			subscan.status = FAILED_TASK
			subscan.save()
		return {
			'success': False,
			'error': str(e)
		}


def report(self, ctx={}, description=None):
	"""Report task running after all other tasks.
	Mark ScanHistory or SubScan object as completed and update with final
	status, log run details and send notification.

	Args:
		description (str, optional): Task description shown in UI.
	"""
	# Get objects
	subscan_id = ctx.get('subscan_id')
	scan_id = ctx.get('scan_history_id')

	# Check if there are other scanning tasks still running
	if scan_id:
		from startScan.models import ScanActivity
		from reNgine.definitions import RUNNING_TASK, INITIATED_TASK
		post_processing_names = ['correlate_vulnerabilities', 'calculate_risk_scores', 'generate_impact_assessment', 'run_apme', 'report']
		running_scans = ScanActivity.objects.filter(
			scan_of_id=scan_id,
			status__in=[RUNNING_TASK, INITIATED_TASK]
		).exclude(name__in=post_processing_names)
		if running_scans.exists() and not getattr(self, '_is_temporal_proxy', False):
			running_names = list(running_scans.values_list('name', flat=True))
			#logger.info(f"Scanning tasks are still running: {running_names}. Rescheduling report...")
			raise self.retry(countdown=10, max_retries=1000)

	engine_id = ctx.get('engine_id')
	scan = ScanHistory.objects.filter(pk=scan_id).first()
	subscan = SubScan.objects.filter(pk=subscan_id).first()

	# Get failed tasks
	tasks = ScanActivity.objects.filter(scan_of=scan).all()
	if subscan:
		tasks = tasks.filter(execution_id__in=subscan.workflow_ids)
	failed_tasks = tasks.filter(status__in=[FAILED_TASK, ABORTED_TASK])

	# Get task status
	failed_count = failed_tasks.count()

	if subscan:
		status = SUCCESS_TASK if failed_count == 0 else FAILED_TASK
		status_h = 'SUCCESS' if failed_count == 0 else 'FAILED'
		subscan.stop_scan_date = timezone.now()
		subscan.status = status
		subscan.save()
	else:
		# Main scan completion
		if failed_count == 0:
			status = SUCCESS_TASK
			status_h = 'SUCCESS'
		else:
			# If any subscans failed, mark as Partially Complete
			has_failed_subscans = SubScan.objects.filter(scan_history=scan, status__in=[FAILED_TASK, ABORTED_TASK]).exists()

			if has_failed_subscans:
				status = PARTIALLY_COMPLETE_TASK
				status_h = 'PARTIALLY COMPLETE'
			else:
				status = FAILED_TASK
				status_h = 'FAILED'

		scan.scan_status = status

	scan.stop_scan_date = timezone.now()
	scan.save()

	# Send scan status notif
	try:
		send_scan_notif(
			scan_history_id=scan_id,
			subscan_id=subscan_id,
			engine_id=engine_id,
			status=status_h)
	except Exception as e:
		logger.warning(f"Could not send scan notification: {e}")


#------------------------- #
# Tracked reNgine tasks    #
#--------------------------#

def amass_intel_discovery(self, host, ctx={}, description=None):
	"""Infrastructure discovery using Amass Intel.
	
	Args:
		host (str): Target domain to run intel on.
	"""
	config = self.yaml_configuration.get(SUBDOMAIN_DISCOVERY) or {}
	use_amass_config = config.get(USE_AMASS_CONFIG, False)
	
	output_path = f'{self.results_dir}/amass_intel.txt'
	
	cmd = f'amass intel -d {host} -whois -o {output_path}'
	cmd += ' -config /root/.config/amass.ini' if use_amass_config else ''
	
	#proxy = get_random_proxy()
	#if proxy:
	#	cmd = f"export HTTP_PROXY='{proxy}' HTTPS_PROXY='{proxy}' && {cmd}"

	run_command(
		cmd,
		shell=True,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id
	)
	
	# Process results: finding other root domains
	discovered_count = 0
	if os.path.exists(output_path):
		with open(output_path, 'r') as f:
			for line in f:
				domain_name = line.strip()
				if domain_name and domain_name != host:
					discovered_count += 1
					logger.info(f"Discovered associated domain: {domain_name}")
					
	if discovered_count > 0:
		self.notify(fields={'Infrastructure Discovery': f'Discovered {discovered_count} associated domains/assets via Amass Intel.'})
		
	return True


def subdomain_discovery(
		self,
		host=None,
		ctx=None,
		description=None):
	"""Uses a set of tools (see SUBDOMAIN_SCAN_DEFAULT_TOOLS) to scan all
	subdomains associated with a domain.

	Args:
		host (str): Hostname to scan.

	Returns:
		subdomains (list): List of subdomain names.
	"""
	if not host:
		host = self.subdomain.name if self.subdomain else self.domain.name

	if self.starting_point_path:
		logger.warning(f'Ignoring subdomains scan as an URL path filter was passed ({self.starting_point_path}).')
		return

	# Config
	config = self.yaml_configuration.get(SUBDOMAIN_DISCOVERY) or {}
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL) or self.yaml_configuration.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
	threads = config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
	timeout = config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT)
	tools = config.get(USES_TOOLS, SUBDOMAIN_SCAN_DEFAULT_TOOLS)
	default_subdomain_tools = [tool.name.lower() for tool in InstalledExternalTool.objects.filter(is_default=True).filter(is_subdomain_gathering=True)]
	custom_subdomain_tools = [tool.name.lower() for tool in InstalledExternalTool.objects.filter(is_default=False).filter(is_subdomain_gathering=True)]
	send_subdomain_changes, send_interesting = False, False
	notif = Notification.objects.first()
	subdomain_scope_checker = SubdomainScopeChecker(self.out_of_scope_subdomains)
	if notif:
		send_subdomain_changes = notif.send_subdomain_changes_notif
		send_interesting = notif.send_interesting_notif

	# Gather tools to run for subdomain scan
	if ALL in tools:
		tools = SUBDOMAIN_SCAN_DEFAULT_TOOLS + custom_subdomain_tools
	tools = [t.lower() for t in tools]

	# Make exception for amass since tool name is amass, but command is amass-active/passive
	default_subdomain_tools.append('amass-passive')
	default_subdomain_tools.append('amass-active')
	# Append baddns so it is always registered as a supported default subdomain discovery tool
	default_subdomain_tools.append('baddns')

	# Run tools
	opsec = get_opsec_manager()
	existing_subs = set(Subdomain.objects.filter(scan_history=self.scan).values_list('name', flat=True))
	new_discoveries = []

	for tool in tools:
		cmd = None
		results_file = None
		logger.info(f'Scanning subdomains for {host} with {tool}')
		proxy = get_random_proxy()
		if tool in default_subdomain_tools:
			if tool == 'amass-passive':
				use_amass_config = config.get(USE_AMASS_CONFIG, False)
				results_file = f'{self.results_dir}/subdomains_amass.txt'
				cmd = f'amass enum -passive -d {host} -o {results_file}'
				cmd += ' -config /root/.config/amass.ini' if use_amass_config else ''
				#if proxy:
				#	cmd = f"export HTTP_PROXY='{proxy}' HTTPS_PROXY='{proxy}' && {cmd}"

			elif tool == 'amass-active':
				use_amass_config = config.get(USE_AMASS_CONFIG, False)
				amass_wordlist_name = config.get(AMASS_WORDLIST, 'deepmagic.com-prefixes-top50000')
				wordlist_path = f'/usr/src/wordlist/{amass_wordlist_name}.txt'
				results_file = f'{self.results_dir}/subdomains_amass_active.txt'
				cmd = f'amass enum -active -d {host} -o {results_file}'
				cmd += ' -config /root/.config/amass.ini' if use_amass_config else ''
				cmd += f' -brute -w {wordlist_path}'
				#if proxy:
				#	cmd = f"export HTTP_PROXY='{proxy}' HTTPS_PROXY='{proxy}' && {cmd}"

			elif tool == 'sublist3r':
				results_file = f'{self.results_dir}/subdomains_sublister.txt'
				cmd = f'python3 /usr/src/github/Sublist3r/sublist3r.py -d {host} -t {threads} -o {results_file}'

			elif tool == 'subfinder':
				results_file = f'{self.results_dir}/subdomains_subfinder.txt'
				cmd = f'subfinder -d {host} -all -o {results_file}'
				use_subfinder_config = config.get(USE_SUBFINDER_CONFIG, False)
				cmd += ' -config /root/.config/subfinder/config.yaml' if use_subfinder_config else ''
				#cmd += f' -proxy {proxy}' if proxy else ''
				cmd += f' -timeout {timeout}' if timeout else ''
				cmd += f' -t {threads}' if threads else ''
				cmd += f' -silent'

			elif tool == 'oneforall':
				results_file = f'{self.results_dir}/subdomains_oneforall.txt'
				cmd = f'python3 /usr/src/github/OneForAll/oneforall.py --target {host} run'
				cmd_extract = f'cut -d\',\' -f6 /usr/src/github/OneForAll/results/{host}.csv | tail -n +2 > {results_file}'
				cmd_rm = f'rm -rf /usr/src/github/OneForAll/results/{host}.csv'
				cmd += f' && {cmd_extract} && {cmd_rm}'

			elif tool == 'ctfr':
				results_file = self.results_dir + '/subdomains_ctfr.txt'
				cmd = f'python3 /usr/src/github/ctfr/ctfr.py -d {host} -o {results_file}'
				cmd_extract = f"cat {results_file} | sed 's/\\*.//g' | tail -n +12 | uniq | sort > {results_file}_temp && mv {results_file}_temp {results_file}"
				cmd += f' && {cmd_extract}'

			elif tool == 'tlsx':
				results_file = self.results_dir + '/subdomains_tlsx.txt'
				cmd = f'tlsx -san -cn -silent -ro -host {host}'
				cmd += rf" | sed -n '/^\([a-zA-Z0-9]\([-a-zA-Z0-9]*[a-zA-Z0-9]\)\?\.\)\+{host}$/p' | uniq | sort"
				cmd += f' > {results_file}'

			elif tool == 'netlas':
				results_file = self.results_dir + '/subdomains_netlas.txt'
				cmd = f'netlas search -d domain -i domain domain:"*.{host}" -f json'
				netlas_key = get_netlas_key()
				cmd += f' -a {netlas_key}' if netlas_key else ''
				cmd_extract = rf"grep -oE '([a-zA-Z0-9]([-a-zA-Z0-9]*[a-zA-Z0-9])?\.)+{host}'"
				cmd += f' | {cmd_extract} > {results_file}'

			elif tool == 'chaos':
				# we need to find api key if not ignore
				chaos_key = get_chaos_key()
				if not chaos_key:
					logger.error('Chaos API key not found. Skipping.')
					continue
				results_file = self.results_dir + '/subdomains_chaos.txt'
				cmd = f'chaos -d {host} -silent -key {chaos_key} -o {results_file}'

			elif tool == 'baddns':
				results_file = self.results_dir + '/baddns_report.json'
				# Run baddns in silent mode (JSON format) and redirect stdout to results_file
				cmd = f'baddns -s {host} > {results_file}'


		elif tool in custom_subdomain_tools:
			tool_query = InstalledExternalTool.objects.filter(name__icontains=tool.lower())
			if not tool_query.exists():
				logger.error(f'{tool} configuration does not exists. Skipping.')
				continue
			custom_tool = tool_query.first()
			cmd = custom_tool.subdomain_gathering_command
			if '{TARGET}' not in cmd:
				logger.error(f'Missing {{TARGET}} placeholders in {tool} configuration. Skipping.')
				continue
			if '{OUTPUT}' not in cmd:
				logger.error(f'Missing {{OUTPUT}} placeholders in {tool} configuration. Skipping.')
				continue

			results_file = f'{self.results_dir}/subdomains_{tool}.txt'
			cmd = cmd.replace('{TARGET}', host)
			cmd = cmd.replace('{OUTPUT}', results_file)
			cmd = cmd.replace('{PATH}', custom_tool.github_clone_path) if '{PATH}' in cmd else cmd
		else:
			logger.warning(
				f'Subdomain discovery tool "{tool}" is not supported by reNgine. Skipping.')
			continue

		# Apply OpSec stealth
		cmd = opsec.apply_stealth(tool, cmd, proxy=proxy)

		# Run tool (with empty-file retry up to 3 attempts)
		try:
			logger.warning(f'Running {tool} with command: {cmd}')
			run_command_with_retry(
				cmd,
				results_file=results_file,
				shell=True,
				history_file=self.history_file,
				scan_id=self.scan_id,
				activity_id=self.activity_id,
				proxy=proxy if tool not in ['amass-passive', 'amass-active', 'subfinder'] else None)

			# If the tool is baddns, extract discovered subdomains from the JSON results
			if tool == 'baddns' and os.path.exists(results_file):
				import re
				extracted_file = self.results_dir + '/subdomains_baddns.txt'
				discovered_subs = set()
				try:
					with open(results_file, 'r') as f:
						for line in f:
							line = line.strip()
							if not line:
								continue
							try:
								data = json.loads(line)
								# Extract target and trigger fields which can contain subdomains/domains
								for key in ['target', 'trigger']:
									val = data.get(key)
									if val and isinstance(val, str):
										# Clean wildcard or prefix (like _dmarc.example.com -> example.com)
										val = re.sub(r'^_[\w\-]+\.', '', val)
										val = val.strip().lower()
										# Check if it's a valid domain/IP
										if validators.domain(val) or validators.ipv4(val) or validators.ipv6(val):
											# Ensure it belongs to the target domain scope (host)
											if host in val:
												discovered_subs.add(val)
							except json.JSONDecodeError:
								# Fallback: if not JSON, try to extract domain-like strings from plain text line
								for part in line.split():
									part = part.strip().lower()
									if host in part and (validators.domain(part) or validators.ipv4(part)):
										discovered_subs.add(part)
					
					if discovered_subs:
						with open(extracted_file, 'w') as f_out:
							for sub in sorted(discovered_subs):
								f_out.write(f'{sub}\n')
						logger.info(f"Extracted {len(discovered_subs)} subdomains from baddns output: {discovered_subs}")
				except Exception as parse_err:
					logger.error(f"Error parsing baddns output to extract subdomains: {parse_err}")
					logger.exception(parse_err)

		except Exception as e:
			logger.error(
				f'Subdomain discovery tool "{tool}" raised an exception')
			logger.exception(e)

	# Gather all the tools' results in one single file. Write subdomains into
	# separate files, and sort all subdomains.
	run_command(
		f'cat {self.results_dir}/subdomains_*.txt > {self.output_path}',
		shell=True,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)
	run_command(
		f'sort -u {self.output_path} -o {self.output_path}',
		shell=True,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)

	if not os.path.isfile(self.output_path):
		logger.warning('subdomain_discovery: output file not found at %s, no subdomains collected.', self.output_path)
		return

	with open(self.output_path) as f:
		lines = f.readlines()

	# Parse the output_file file and store Subdomain and EndPoint objects found
	# in db.
	subdomain_count = 0
	subdomains = []
	urls = []
	for line in lines:
		subdomain_name = line.strip()
		valid_url = bool(validators.url(subdomain_name))
		valid_domain = (
			bool(validators.domain(subdomain_name)) or
			bool(validators.ipv4(subdomain_name)) or
			bool(validators.ipv6(subdomain_name)) or
			valid_url
		)
		if not valid_domain:
			logger.error(f'Subdomain {subdomain_name} is not a valid domain, IP or URL. Skipping.')
			continue

		if valid_url:
			subdomain_name = urlparse(subdomain_name).netloc

		if subdomain_scope_checker.is_out_of_scope(subdomain_name):
			logger.error(f'Subdomain {subdomain_name} is out of scope. Skipping.')
			continue

		# Add subdomain
		subdomain, created = save_subdomain(subdomain_name, ctx=ctx)
		if subdomain:
			subdomain_count += 1
			# Special handling for baddns findings (if it was a takeover)
			# We'll check the baddns report file specifically for this subdomain
			baddns_report = f'{self.results_dir}/baddns_report.json'
			if os.path.exists(baddns_report):
				with open(baddns_report, 'r') as f:
					for b_line in f:
						b_line = b_line.strip()
						if not b_line:
							continue
						if subdomain_name in b_line:
							is_takeover = False
							# Try parsing as JSON first
							try:
								data = json.loads(b_line)
								desc = data.get('description', '').lower()
								sig = data.get('signature', '').lower()
								mod = data.get('module', '').lower()
								# Check if it's a takeover finding
								if 'takeover' in desc or 'takeover' in sig or mod in ['cname', 'ns', 'mx']:
									# Exclude non-takeover DNS findings like DMARC, SPF, etc.
									if not any(x in desc or x in sig for x in ['dmarc', 'spf', 'mta-sts', 'nsec', 'zonetransfer']):
										is_takeover = True
							except Exception:
								# Fallback to plain text check
								if '[takeover]' in b_line.lower() or 'takeover' in b_line.lower():
									is_takeover = True

							if is_takeover:
								subdomain.is_important = True
								subdomain.save()
								# Create Critical Vulnerability
								description_text = f"baddns detected a potential subdomain takeover on {subdomain_name}."
								try:
									data = json.loads(b_line)
									if data.get('description'):
										description_text = f"baddns: {data.get('description')}"
								except Exception:
									pass
								
								save_vulnerability(
									name=f"Subdomain Takeover on {subdomain_name}",
									description=f"{description_text} Line: {b_line}",
									severity='critical',
									type='Subdomain Takeover',
									subdomain=subdomain,
									scan_history=self.scan,
									target_domain=self.domain,
									validation_status='unverified',
									source='baddns'
								)
			subdomains.append(subdomain)
			urls.append(subdomain.name)

	# Bulk crawl subdomains - removed to avoid collisions; delegated to next stage in pipeline
	url_filter = ctx.get('url_filter')

	# Find root subdomain endpoints and save default endpoints.
	# save_endpoint requires a scheme — bare hostnames (no http://) are rejected
	# silently, which left http_crawl and fetch_url with nothing to process.
	for subdomain in subdomains:
		raw_url = f'{subdomain.name}{url_filter}' if url_filter else subdomain.name
		if not raw_url.startswith(('http://', 'https://')):
			raw_url = f'http://{raw_url}'
		endpoint, _ = save_endpoint(
			raw_url,
			ctx=ctx,
			is_default=True,
			subdomain=subdomain
		)
		if endpoint:
			save_subdomain_metadata(subdomain, endpoint)

	# Send notifications
	subdomains_str = '\n'.join([f'• `{subdomain.name}`' for subdomain in subdomains])
	self.notify(fields={
		'Subdomain count': len(subdomains),
		'Subdomains': subdomains_str,
	})
	if send_subdomain_changes and self.scan_id and self.domain_id:
		added = get_new_added_subdomain(self.scan_id, self.domain_id)
		removed = get_removed_subdomain(self.scan_id, self.domain_id)

		if added:
			subdomains_str = '\n'.join([f'• `{subdomain}`' for subdomain in added])
			self.notify(fields={'Added subdomains': subdomains_str})

		if removed:
			subdomains_str = '\n'.join([f'• `{subdomain}`' for subdomain in removed])
			self.notify(fields={'Removed subdomains': subdomains_str})

	if send_interesting and self.scan_id and self.domain_id:
		interesting_subdomains = get_interesting_subdomains(self.scan_id, self.domain_id)
		if interesting_subdomains:
			subdomains_str = '\n'.join([f'• `{subdomain}`' for subdomain in interesting_subdomains])
			self.notify(fields={'Interesting subdomains': subdomains_str})

	return SubdomainSerializer(subdomains, many=True).data



def save_imported_subdomains(subdomains, ctx={}):
	"""Take a list of subdomains imported and write them to from_imported.txt.

	Args:
		subdomains (list): List of subdomain names.
		scan_history (startScan.models.ScanHistory): ScanHistory instance.
		domain (startScan.models.Domain): Domain instance.
		results_dir (str): Results directory.
	"""
	domain_id = ctx['domain_id']
	domain = Domain.objects.get(pk=domain_id)
	results_dir = ctx.get('results_dir', RENGINE_RESULTS)

	# Validate each subdomain and de-duplicate entries
	subdomains = list(set([
		subdomain for subdomain in subdomains
		if validators.domain(subdomain) and domain.name == get_domain_from_subdomain(subdomain)
	]))
	if not subdomains:
		return

	logger.warning(f'Found {len(subdomains)} imported subdomains.')
	with open(f'{results_dir}/from_imported.txt', 'w+') as output_file:
		for name in subdomains:
			subdomain_name = name.strip()
			subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
			subdomain.is_imported_subdomain = True
			subdomain.save()
			output_file.write(f'{subdomain}\n')







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


def resume_scan_temporal(scan_id):
	"""Resume a scan from the last completed task.
	
	1. Identifies completed tasks by checking ScanActivity records.
	2. Spawns MasterScanWorkflow with only the remaining tasks.
	"""
	from reNgine.temporal_client import TemporalClientProvider, run_and_close
	import asyncio

	scan = ScanHistory.objects.get(id=scan_id)
	
	# Mark genuinely-running activities as failed; leave INITIATED rows intact so
	# run-2 can claim them — they were never started and are not real failures.
	scan.scanactivity_set.filter(status=RUNNING_TASK).update(status=FAILED_TASK)

	# Calculate completed tasks
	completed_activities = scan.scanactivity_set.filter(status=SUCCESS_TASK).values_list('name', flat=True)
	completed_tasks = set(completed_activities)

	# Filter the scan's original task list (tasks may be NULL for old/broken scans)
	remaining_tasks = [t for t in (scan.tasks or []) if t not in completed_tasks]

	# Reset FAILED rows for tasks that will be retried back to INITIATED so:
	# (a) _create_scan_activity can claim the existing row rather than creating
	#     a tier-less duplicate, and (b) the progress serializer no longer counts
	#     those tiers as completed, giving the UI an accurate picture immediately.
	if remaining_tasks:
		scan.scanactivity_set.filter(
			status=FAILED_TASK,
			name__in=remaining_tasks,
		).update(
			status=INITIATED_TASK,
			time_started=None,
			time_ended=None,
			error_message=None,
		)

	if not remaining_tasks:
		logger.info(f"Scan {scan_id} has no remaining tasks to resume.")
		scan.scan_status = SUCCESS_TASK
		scan.stop_scan_date = timezone.now()
		scan.save()
		return
		
	# Update scan status. Clear stop_scan_date and reset recovery_count so that
	# recover_stuck_scans can find this scan if the container crashes again — a
	# manually resumed scan is a fresh attempt, not a continuation of prior failures.
	scan.scan_status = RUNNING_TASK
	scan.error_message = None
	scan.stop_scan_date = None
	scan.recovery_count = 0
	scan.tasks = remaining_tasks
	scan.save()

	from reNgine.utils.scan_cancellation import set_scan_stop_kill_switch
	set_scan_stop_kill_switch(scan.id, enabled=False)
	
	# Rebuild ctx — tasks must be in ctx so TargetProfilingActivity does not
	# fall back to engine.tasks (the full original list) and reset the resume.
	yaml_config = yaml.safe_load(scan.scan_type.yaml_configuration)
	ctx = {
		'scan_history_id': scan.id,
		'engine_id': scan.scan_type.id,
		'domain_id': scan.domain.id,
		'results_dir': scan.results_dir,
		'yaml_configuration': yaml_config,
		'tasks': remaining_tasks,
	}
	
	workflow_id = f"master-scan-{scan.id}-run-{scan.recovery_count}"
	
	# Append the new workflow ID to the scan
	workflow_ids = scan.workflow_ids or []
	workflow_ids.append(workflow_id)
	scan.workflow_ids = workflow_ids
	scan.save()
	
	# Cancel any previously known workflows for this scan before spawning the new one.
	# This prevents double-execution when recovery fires while the old workflow
	# (or its nuclei child) is still alive — e.g. after a Temporal server blip.
	old_ids = [wid for wid in (scan.workflow_ids or []) if wid != workflow_id]

	async def _cancel_old_and_start():
		from datetime import timedelta
		from temporalio.service import RPCError, RPCStatusCode
		client = await TemporalClientProvider.get_client()

		for old_wf_id in old_ids:
			for candidate in [old_wf_id, f"{old_wf_id}-nuclei"]:
				try:
					handle = client.get_workflow_handle(candidate)
					await handle.cancel()
					logger.info(f"Cancelled old workflow before recovery: {candidate}")
				except RPCError as e:
					if e.status not in (RPCStatusCode.NOT_FOUND,):
						logger.warning(f"Could not cancel old workflow {candidate}: {e}")
				except Exception as e:
					logger.warning(f"Could not cancel old workflow {candidate}: {e}")

		await client.start_workflow(
			"MasterScanWorkflow",
			args=[ctx],
			id=workflow_id,
			task_queue="python-orchestrator-queue",
			execution_timeout=timedelta(days=30),
			run_timeout=timedelta(days=30),
			task_timeout=timedelta(hours=1),
		)

	loop = asyncio.new_event_loop()
	run_and_close(loop, _cancel_old_and_start())

	# Track workflow execution so cancel_workflow can find it
	from startScan.models import TemporalWorkflowExecution
	TemporalWorkflowExecution.objects.get_or_create(
		workflow_id=workflow_id,
		defaults={
			'scan_history': scan,
			'run_id': workflow_id,
			'workflow_type': 'MasterScanWorkflow',
			'status': 'RUNNING',
		}
	)
	
	logger.info(f"Resumed scan {scan_id} with remaining tasks: {remaining_tasks}")


def recover_stuck_scans():
	"""Recover scans stuck due to a crash or Temporal state loss.

	Called on orchestrator startup. Identifies RUNNING_TASK scans whose associated
	Temporal workflow no longer exists (e.g. after a container restart or crash),
	marks them as FAILED_TASK, and resumes them using the temporal orchestrator.
	Scans that are already in FAILED_TASK, ABORTED_TASK, or otherwise completed/stopped/paused
	states are not touched.

	Auto-recovery is capped at recovery_count < 3.
	"""
	import asyncio
	from startScan.models import ScanHistory, TemporalWorkflowExecution
	from reNgine.definitions import FAILED_TASK, RUNNING_TASK
	from reNgine.temporal_client import TemporalClientProvider, run_and_close

	logger.info("[RECOVERY] recover_stuck_scans triggered")

	async def _is_workflow_active(workflow_id):
		from temporalio.client import WorkflowExecutionStatus
		from temporalio.service import RPCError, RPCStatusCode
		try:
			client = await TemporalClientProvider.get_client()
			handle = client.get_workflow_handle(workflow_id)
			desc = await handle.describe()
			# Also check well-known child workflow IDs that outlive the master
			if desc.status == WorkflowExecutionStatus.RUNNING:
				return True
			# Master finished — check whether its nuclei child is still running
			nuclei_id = f"{workflow_id}-nuclei"
			try:
				nuclei_handle = client.get_workflow_handle(nuclei_id)
				nuclei_desc = await nuclei_handle.describe()
				if nuclei_desc.status == WorkflowExecutionStatus.RUNNING:
					return True
			except RPCError as e:
				if e.status != RPCStatusCode.NOT_FOUND:
					return True  # server error — assume running
			return False
		except RPCError as e:
			if e.status == RPCStatusCode.NOT_FOUND:
				return False  # workflow genuinely absent — safe to recover
			# Any other RPC error means Temporal itself is unavailable — do NOT recover
			logger.warning("[RECOVERY] Temporal RPC error checking workflow '%s': %s. Skipping recovery.", workflow_id, e)
			return True
		except Exception as e:
			logger.warning("[RECOVERY] Unexpected error checking workflow '%s': %s. Skipping recovery.", workflow_id, e)
			return True

	# --- Pass 2: RUNNING_TASK scans whose Temporal workflow is gone ---
	# Guard: skip scans whose stop_scan_date was set within the last 2 minutes —
	# that narrow window covers the abort race-condition where the orchestrator
	# restarts before abort_scan_history can flip scan_status to ABORTED_TASK.
	# Scans stopped longer ago (or never stopped) are safe to recover; in particular
	# a manually-resumed scan now clears stop_scan_date in resume_scan_temporal so
	# it will always appear here with stop_scan_date=None.
	from django.utils import timezone as _tz
	import datetime as _dt
	_abort_grace = _tz.now() - _dt.timedelta(minutes=2)
	candidates = list(ScanHistory.objects.filter(
		scan_status__in=[RUNNING_TASK, FAILED_TASK],
		recovery_count__lt=3,
	).exclude(
		stop_scan_date__gte=_abort_grace,
	))

	logger.info("[RECOVERY] Evaluating %d RUNNING/FAILED scan(s) for recovery", len(candidates))

	recovered = 0
	active = 0
	for scan in candidates:
		# Prefer the TemporalWorkflowExecution record; fall back to workflow_ids array.
		latest_exec = (
			TemporalWorkflowExecution.objects
			.filter(scan_history=scan, status='RUNNING')
			.order_by('-started_at')
			.first()
		)
		workflow_id = (
			latest_exec.workflow_id if latest_exec
			else (scan.workflow_ids[-1] if scan.workflow_ids else None)
		)

		loop = asyncio.new_event_loop()
		is_active = run_and_close(loop, _is_workflow_active(workflow_id)) if workflow_id else False

		if is_active:
			logger.info("[RECOVERY] Scan %d (%s) workflow '%s' is ACTIVE — skipping", scan.id, scan.domain, workflow_id)
			active += 1
			continue

		logger.info(
			"[RECOVERY] Scan %d (%s) workflow '%s' is DEAD — resuming (recovery_count=%d)",
			scan.id, scan.domain, workflow_id, scan.recovery_count
		)
		try:
			resume_scan_temporal(scan.id)
			recovered += 1
			logger.info("[RECOVERY] Scan %d resumed successfully", scan.id)
		except Exception as e:
			# Recovery failed — only now mark the scan permanently FAILED so the
			# user can see it and act on it. Doing this before the attempt would
			# leave the scan stuck in FAILED state whenever resume raises.
			scan.refresh_from_db(fields=['scan_status'])
			scan.scan_status = FAILED_TASK
			scan.save(update_fields=['scan_status'])
			logger.error("[RECOVERY] Failed to auto-recover stuck running scan %d: %s", scan.id, e)

	logger.info("[RECOVERY] recover_stuck_scans complete — active=%d recovered=%d", active, recovered)
