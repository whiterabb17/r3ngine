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
				_yaml_data = yaml.safe_load(_f) or {}
			_yaml_data.setdefault('apikeys', {}).setdefault('hunter', {})['key'] = hunter_key_obj.key
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





def fetch_url(self, urls=[], ctx={}, description=None):
	"""Fetch URLs using different tools like gauplus, gau, gospider, waybackurls ...

	Args:
		urls (list): List of URLs to start from.
		description (str, optional): Task description shown in UI.
	"""
	input_path = f'{self.results_dir}/input_endpoints_fetch_url.txt'

	# Config
	config = self.yaml_configuration.get(FETCH_URL) or {}
	should_remove_duplicate_endpoints = config.get(REMOVE_DUPLICATE_ENDPOINTS, True)
	duplicate_removal_fields = config.get(DUPLICATE_REMOVAL_FIELDS, ENDPOINT_SCAN_DEFAULT_DUPLICATE_FIELDS)
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
	gf_patterns = config.get(GF_PATTERNS, DEFAULT_GF_PATTERNS)
	ignore_file_extension = config.get(IGNORE_FILE_EXTENSION, DEFAULT_IGNORE_FILE_EXTENSIONS)
	tools = config.get(USES_TOOLS, ENDPOINT_SCAN_DEFAULT_TOOLS)
	threads = config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
	# domain_request_headers = self.domain.request_headers if self.domain else None
	custom_headers = self.yaml_configuration.get(CUSTOM_HEADERS, [])
	'''
	# TODO: Remove custom_header in next major release
		support for custom_header will be remove in next major release, 
		as of now it will be supported for backward compatibility
		only custom_headers will be supported
	'''
	custom_header = self.yaml_configuration.get(CUSTOM_HEADER)
	if custom_header:
		custom_headers.append(custom_header)
	exclude_subdomains = config.get(EXCLUDED_SUBDOMAINS, False)

	# Get URLs to scan and save to input file
	if urls:
		with open(input_path, 'w') as f:
			f.write('\n'.join(urls))
	else:
		urls = get_http_urls(
			is_alive=enable_http_crawl,
			write_filepath=input_path,
			exclude_subdomains=exclude_subdomains,
			get_only_default_urls=True,
			ctx=ctx
		)
		# When http_crawl found no alive endpoints, fall back to all default
		# seed URLs so passive tools (gau, waybackurls) can still query
		# historical data even if the target is currently unreachable.
		if not urls and enable_http_crawl:
			urls = get_http_urls(
				is_alive=False,
				write_filepath=input_path,
				exclude_subdomains=exclude_subdomains,
				get_only_default_urls=True,
				ctx=ctx
			)

	# Domain regex
	host = self.domain.name if self.domain else urlparse(urls[0]).netloc
	host_regex = f"\'https?://([a-zA-Z0-9_-]+[.])*{host}[^][[:space:]\\\"\\`><]*\'"

	# Tools cmds
	base_cmd_map = {
		'gau': f'gau',
		'hakrawler': 'hakrawler -subs -u',
		'waybackurls': 'waybackurls',
		'gospider': f'gospider -S {input_path} --js -d 2 --sitemap --robots -w -r',
		'katana': f'katana -list {input_path} -silent -jc -kf all -d 3 -fs rdn',
	}

	recon_run = False
	for tool in tools:
		if tool in base_cmd_map:
			p = get_random_proxy()

			# Build base command without proxy so we can reuse it for fallback
			base_tool_cmd = base_cmd_map[tool]
			if threads > 0:
				if tool == 'gau': base_tool_cmd += f' --threads {threads}'
				elif tool == 'gospider': base_tool_cmd += f' -t {threads}'
				elif tool == 'katana': base_tool_cmd += f' -c {threads}'
			if custom_headers:
				formatted_headers = ' '.join(f'-H "{header}"' for header in custom_headers)
				if tool == 'gospider': base_tool_cmd += f' {formatted_headers}'
				elif tool == 'hakrawler': base_tool_cmd += ';;'.join(header for header in custom_headers)
				elif tool == 'katana': base_tool_cmd += f' {formatted_headers}'

			# Add proxy for the primary attempts
			tool_cmd = base_tool_cmd
			if p:
				if tool == 'katana': tool_cmd += f' -proxy "{p}"'
				elif tool == 'gospider': tool_cmd += f' -p {p}'
				#elif tool == 'hakrawler': tool_cmd += f' -proxy {p}'
				elif tool == 'gau': tool_cmd += f' --proxy {p}'

			url_results_file = f'{self.results_dir}/urls_{tool}.txt'
			if os.path.exists(url_results_file) and os.path.getsize(url_results_file) > 0:
				logger.info(f'{tool}: reusing cached results in {url_results_file}')
				recon_run = True
				continue

			full_cmd = f'cat {input_path} | {tool_cmd} | grep -Eo {host_regex} | tee {url_results_file}'
			logger.info(f'Running {tool}')
			logger.warning(f'{tool} command: {full_cmd}')
			run_command_with_retry(
				full_cmd,
				results_file=url_results_file,
				shell=True,
				scan_id=self.scan_id,
				activity_id=self.activity_id
			)

			# If all 3 proxy attempts produced no results, retry once without proxy
			if p and (not os.path.exists(url_results_file) or os.path.getsize(url_results_file) == 0):
				logger.warning(f'{tool}: all proxy attempts failed, retrying once without proxy')
				full_no_proxy_cmd = f'cat {input_path} | {base_tool_cmd} | grep -Eo {host_regex} | tee {url_results_file}'
				logger.warning(f'{tool} no-proxy fallback: {full_no_proxy_cmd}')
				run_command(full_no_proxy_cmd, shell=True, scan_id=self.scan_id, activity_id=self.activity_id)

			recon_run = True

	# Vigolium spidering — runs ingestion+discovery phases to collect additional URLs.
	# Activated by adding 'vigolium' to fetch_url.uses_tools in the YAML config.
	if 'vigolium' in tools and os.path.isfile(input_path):
		from reNgine.vigolium_tasks import _ensure_duration as _ensure_vigolium_duration, _iter_jsonl

		vigolium_jsonl = f'{self.results_dir}/urls_vigolium.jsonl'
		vigolium_urls_file = f'{self.results_dir}/urls_vigolium.txt'

		vig_spider_config = config.get('vigolium_spider', {})
		vig_concurrency = vig_spider_config.get(VIGOLIUM_CONCURRENCY, 30)
		vig_rate_limit = vig_spider_config.get(VIGOLIUM_RATE_LIMIT, 80)
		vig_timeout = _ensure_vigolium_duration(vig_spider_config.get(VIGOLIUM_TIMEOUT, '20s'))
		vig_strategy = vig_spider_config.get(VIGOLIUM_STRATEGY, 'balanced')

		vig_cmd = (
			f"vigolium scan"
			f" -T {input_path}"
			f" --only ingestion,discovery"
			f" --stateless"
			f" --format jsonl"
			f" -o {vigolium_jsonl}"
			f" -c {vig_concurrency}"
			f" -r {vig_rate_limit}"
			f" --timeout {vig_timeout}"
			f" --strategy {vig_strategy}"
			f" --skip-dependency-check"
		)
		proxy = get_random_proxy()
		if proxy:
			vig_cmd += f" --proxy {proxy}"

		if os.path.exists(vigolium_jsonl) and os.path.getsize(vigolium_jsonl) > 0:
			logger.info(f'fetch_url: reusing cached vigolium results in {vigolium_jsonl}')
		else:
			logger.info("fetch_url: running vigolium spidering")
			logger.warning(f"vigolium spider command: {vig_cmd}")
			run_command_with_retry(
				vig_cmd,
				results_file=vigolium_jsonl,
				scan_id=self.scan_id,
				activity_id=self.activity_id
			)

		spider_urls = [
			record['data']['url']
			for record in _iter_jsonl(vigolium_jsonl)
			if record.get('type') == 'http_record' and record.get('data', {}).get('url')
		]
		if spider_urls:
			with open(vigolium_urls_file, 'w') as _vf:
				_vf.write('\n'.join(spider_urls))
			logger.info(f"fetch_url: vigolium spidering found {len(spider_urls)} URLs")
			recon_run = True

	if not recon_run:
		logger.warning('No reconnaissance tools enabled for fetch_url. Skipping.')
		return

	# Cleanup task — only merge plain-text url lists (exclude .jsonl artifacts)
	sort_output = [
		f'cat {self.results_dir}/urls_*.txt > {self.output_path} 2>/dev/null || true',
		f'cat {input_path} >> {self.output_path}',
		f'sort -u {self.output_path} -o {self.output_path}',
	]
	if ignore_file_extension:
		ignore_exts = '|'.join(ignore_file_extension)
		grep_ext_filtered_output = [
			f'cat {self.output_path} | grep -Eiv "\\.({ignore_exts}).*" > {self.results_dir}/urls_filtered.txt',
			f'mv {self.results_dir}/urls_filtered.txt {self.output_path}'
		]
		sort_output.extend(grep_ext_filtered_output)

	for cmd in sort_output:
		run_command(
			cmd,
			shell=True,
			scan_id=self.scan_id,
			activity_id=self.activity_id
		)

	# Store all the endpoints and run httpx
	if not os.path.isfile(self.output_path):
		logger.warning('fetch_url: output file not found at %s, no URLs to process.', self.output_path)
		return

	all_urls_set = set()
	raw_line_count = 0
	with open(self.output_path, encoding='utf-8', errors='replace') as f:
		for raw_line in f:
			raw_line_count += 1
			parsed = parse_fetched_url_line(raw_line, self.starting_point_path)
			if not parsed:
				continue
			if not validators.url(parsed):
				logger.warning(f'Invalid URL "{parsed}". Skipping.')
				continue
			all_urls_set.add(parsed)
			if raw_line_count % 25000 == 0:
				activity_heartbeat_safe(f'fetch_url parse {raw_line_count} lines')

	self.notify(fields={'Discovered URLs': len(all_urls_set)})

	all_urls = list(all_urls_set)

	# if exclude_paths is found, then remove urls matching those paths
	if self.excluded_paths:
		all_urls = exclude_urls_by_patterns(self.excluded_paths, all_urls)

	# Pass 1: URL signature dedup — collapse parametric variants (same path, different param values).
	if should_remove_duplicate_endpoints:
		pre_count = len(all_urls)
		seen_sigs = set()
		deduped = []
		for url in all_urls:
			sig = url_param_signature(url)
			if sig not in seen_sigs:
				seen_sigs.add(sig)
				deduped.append(url)
		all_urls = deduped
		logger.warning(
			f'fetch_url dedup: {pre_count} → {len(all_urls)} URLs '
			f'(removed {pre_count - len(all_urls)} parametric variants)'
		)

	# Write result to output path
	with open(self.output_path, 'w') as f:
		f.write('\n'.join(all_urls))
	logger.warning(f'Found {len(all_urls)} usable URLs')

	# Save discovered URLs immediately to database as skeleton endpoints (batched).
	created_count = bulk_persist_fetch_urls(all_urls, ctx)
	logger.warning(f'fetch_url persisted {created_count} new skeleton endpoints')

	# Pass 2: Content-based dedup — delete endpoints already enriched by http_crawl
	# whose (subdomain, content_length, page_title) signature matches a shorter sibling.
	# Skeleton endpoints added by fetch_url (no content_length/page_title yet) are skipped.
	if should_remove_duplicate_endpoints and duplicate_removal_fields:
		scan_obj = ScanHistory.objects.filter(pk=ctx.get('scan_history_id')).first()
		domain_obj = Domain.objects.filter(pk=ctx.get('domain_id')).first()
		if scan_obj and domain_obj:
			field_filter = {f'{f}__isnull': False for f in duplicate_removal_fields}
			field_filter.update(
				{f'{f}__gt': 0 for f in duplicate_removal_fields if f == 'content_length'}
			)
			crawled_eps = EndPoint.objects.filter(
				scan_history=scan_obj,
				target_domain=domain_obj,
				**field_filter
			).order_by('http_url')

			seen_content_sigs = {}
			to_delete = []
			for ep in crawled_eps.iterator(chunk_size=2000):
				sig = tuple(getattr(ep, f, None) for f in duplicate_removal_fields)
				subdomain_key = (ep.subdomain_id,) + sig
				if subdomain_key in seen_content_sigs:
					to_delete.append(ep.pk)
				else:
					seen_content_sigs[subdomain_key] = ep.pk

			if to_delete:
				deleted_count, _ = EndPoint.objects.filter(pk__in=to_delete).delete()
				logger.warning(
					f'fetch_url content dedup: removed {deleted_count} duplicate endpoints '
					f'(same {duplicate_removal_fields})'
				)



	#-------------------#
	# GF PATTERNS MATCH #
	#-------------------#

	# Combine old gf patterns with new ones
	if gf_patterns:
		self.scan.used_gf_patterns = ','.join(gf_patterns)
		self.scan.save()

	# Run gf patterns on saved endpoints
	# TODO: refactor to Celery task
	for gf_pattern in gf_patterns:
		# TODO: js var is causing issues, removing for now
		if gf_pattern == 'jsvar':
			logger.info('Ignoring jsvar as it is causing issues.')
			continue

		# Run gf on current pattern
		logger.warning(f'Running gf on pattern "{gf_pattern}"')
		gf_output_file = f'{self.results_dir}/gf_patterns_{gf_pattern}.txt'
		cmd = f'cat {self.output_path} | gf {gf_pattern} | grep -Eo {host_regex} | tee -a {gf_output_file}'
		run_command(
			cmd,
			shell=True,
			history_file=self.history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id)

		if not os.path.exists(gf_output_file):
			logger.error(f'Could not find GF output file {gf_output_file}. Skipping GF pattern "{gf_pattern}"')
			continue

		updated = bulk_apply_gf_pattern_from_file(gf_output_file, gf_pattern, ctx)
		logger.warning(f'GF pattern "{gf_pattern}" updated {updated} endpoints')

	return all_urls


def parse_curl_output(response):
	# TODO: Enrich from other cURL fields.
	CURL_REGEX_HTTP_STATUS = r'HTTP\/(?:(?:\d\.?)+)\s(\d+)\s(?:\w+)'
	http_status = 0
	if response:
		failed = False
		regex = re.compile(CURL_REGEX_HTTP_STATUS, re.MULTILINE)
		try:
			http_status = int(regex.findall(response)[0])
		except (KeyError, TypeError, IndexError):
			pass
	return {
		'http_status': http_status,
	}



def web_api_discovery(self, urls=[], ctx={}, description=None):
	"""Advanced Web App & API Discovery using Kiterunner, Arjun, LinkFinder, etc."""
	scan_id = ctx.get('scan_history_id')
	config = self.yaml_configuration.get(WEB_API_DISCOVERY) or {}
	uses_tools = ctx.get('api_discovery_tools') or config.get(USES_TOOLS, ['kiterunner', 'arjun', 'linkfinder', 'paramspider', 'semgrep'])
	kr_wordlist = ctx.get('kr_wordlist') or config.get(KITERUNNER_WORDLIST, 'routes-small.kite')
	scan_only_active = config.get(SCAN_ONLY_ACTIVE, True)
	threads = config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
	timeout = config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT)
	arjun_methods = config.get(ARJUN_METHODS, ARJUN_DEFAULT_METHODS)
	proxy = None
	kr_proxy = 'socks5://tor:9050' if ctx.get('use_tor') else None

	logger.warning("[WEB_API] Starting Web API Discovery | scan_id=%s | tools=%s", scan_id, uses_tools)

	# Get targets
	if not urls:
		urls = get_http_urls(
			is_alive=scan_only_active,
			write_filepath=None,
			ctx=ctx
		)

	if not urls:
		logger.warning('[WEB_API] No targets found for Web API Discovery — aborting.')
		return

	logger.warning('[WEB_API] Target URL count: %d | scan_only_active=%s', len(urls), scan_only_active)

	results_dir = f"{self.results_dir}/web_api_discovery"
	os.makedirs(results_dir, exist_ok=True)

	# ── Phase 1: Map URLs to subdomains ─────────────────────────────────────
	# Build subdomain_targets {name: (Subdomain, base_url)} for Kiterunner and
	# an ordered url_subdomain_map for per-URL tools (Arjun, LinkFinder, InQL).
	# URL pattern deduplication removes param-value variants that add no value
	# (e.g. locale=ar vs locale=cs share the same path+key signature).
	subdomain_targets = {}
	url_subdomain_map = []
	processed_url_patterns = set()
	skipped_no_subdomain = 0

	for url in urls:
		parsed = urlparse(url)
		query_keys = sorted(parse_qs(parsed.query).keys())
		url_pattern = f"{parsed.netloc}{parsed.path}?{'&'.join(query_keys)}"
		if url_pattern in processed_url_patterns:
			continue
		processed_url_patterns.add(url_pattern)

		subdomain_name = get_subdomain_from_url(url)
		subdomain = Subdomain.objects.filter(name=subdomain_name, scan_history=self.scan).first()
		if not subdomain:
			skipped_no_subdomain += 1
			continue

		if subdomain_name not in subdomain_targets:
			base_url = f"{parsed.scheme}://{parsed.netloc}/"
			subdomain_targets[subdomain_name] = (subdomain, base_url)

		url_subdomain_map.append((url, subdomain_name, subdomain))

	logger.warning(
		'[WEB_API] URL mapping complete: %d unique subdomains, %d deduplicated URLs queued, %d skipped (no subdomain record)',
		len(subdomain_targets), len(url_subdomain_map), skipped_no_subdomain,
	)

	# ── Kiterunner: batched scan across subdomains ───────────────────────────
	# Subdomains are batched in groups of `threads` and written to a hosts file
	# so that -j (max-parallel-hosts) is actually utilised rather than wasted
	# on a single host per call.
	# Per-subdomain .json files act as the idempotency guard for Temporal retries:
	# any subdomain with a non-empty file is skipped; the rest form the next batch.
	if 'kiterunner' in uses_tools:
		# Task 6: Validate wordlist path to prevent traversal (Rule 1.1/1.2)
		_kr_base_dir = Path('/usr/src/wordlist/kr').resolve()
		_kr_wordlist_path = (_kr_base_dir / kr_wordlist).resolve()
		if not str(_kr_wordlist_path).startswith(str(_kr_base_dir)):
			logger.error('[WEB_API] Kiterunner: wordlist path %s escapes base dir — skipping', kr_wordlist)
		else:
			logger.warning('[WEB_API] Kiterunner: scanning %d subdomains | wordlist=%s | batch_size=%d', len(subdomain_targets), kr_wordlist, threads)

			# Separate cached subdomains from those that still need scanning
			to_scan = {
				name: (sub, base_url)
				for name, (sub, base_url) in subdomain_targets.items()
				if not (os.path.exists(f"{results_dir}/kr_{name}.json") and os.path.getsize(f"{results_dir}/kr_{name}.json") > 0)
			}
			cached_count = len(subdomain_targets) - len(to_scan)
			if cached_count:
				logger.warning('[WEB_API] Kiterunner: %d subdomains cached, scanning %d new', cached_count, len(to_scan))

			# Scan phase: batch uncached subdomains so -j is utilised
			scan_items = list(to_scan.items())
			for batch_start in range(0, len(scan_items), threads):
				batch = dict(scan_items[batch_start:batch_start + threads])
				batch_idx = batch_start // threads

				hosts_file = f"{results_dir}/kr_hosts_batch_{batch_idx}.txt"
				with open(hosts_file, 'w') as hf:
					for _name, (_sub, _base_url) in batch.items():
						hf.write(_base_url + '\n')

				combined_output = f"{results_dir}/kr_batch_{batch_idx}.json"
				cmd = (
					f"kr scan {hosts_file}"
					f" -w {_kr_wordlist_path}"
					f" -j {threads}"
					f" --timeout {timeout}s"
					f" --fail-status-codes 404"
					f" -o json -q"
					f" | tee {combined_output}"
				)
				logger.warning('[WEB_API] Kiterunner: batch %d — %d hosts | cmd: %s', batch_idx, len(batch), cmd)
				run_command(cmd, shell=True, scan_id=self.scan_id, activity_id=self.activity_id, proxy=kr_proxy)
				logger.warning('[WEB_API] Kiterunner: batch %d finished', batch_idx)

				# Split combined JSON output into per-subdomain files for caching
				if os.path.exists(combined_output):
					subdomain_lines: dict = {name: [] for name in batch}
					with open(combined_output, 'r') as f:
						for line in f:
							line = line.strip()
							if not line:
								continue
							try:
								entry = json.loads(line)
								target_host = urlparse(entry.get('target', '')).hostname or ''
								if target_host in subdomain_lines:
									subdomain_lines[target_host].append(line)
							except (json.JSONDecodeError, Exception):
								continue
					for _name, lines in subdomain_lines.items():
						if lines:
							_kr_out = f"{results_dir}/kr_{_name}.json"
							with open(_kr_out, 'w') as f:
								f.write('\n'.join(lines) + '\n')
				else:
					logger.warning('[WEB_API] Kiterunner: combined output missing for batch %d', batch_idx)

			# Parse pass: read all per-subdomain files (cached + newly written)
			for subdomain_name, (subdomain, base_url) in subdomain_targets.items():
				kr_output = f"{results_dir}/kr_{subdomain_name}.json"
				if not os.path.exists(kr_output):
					logger.warning('[WEB_API] Kiterunner: output file missing for %s', subdomain_name)
					continue
				try:
					kr_parsed = urlparse(base_url)
					kr_endpoints = 0
					kr_params = 0
					with open(kr_output, 'r') as f:
						for line in f:
							if not line.strip():
								continue
							entry = json.loads(line)
							found_path = entry.get('path', '')
							if not found_path:
								continue
							# Use correct status field from responses array
							responses = entry.get('responses', [])
							http_status = responses[0].get('sc') if responses else None
							# Skip 404s as defence-in-depth (--fail-status-codes 404 handles most)
							if http_status == 404:
								continue
							full_url = f"{kr_parsed.scheme}://{kr_parsed.netloc}{found_path}"
							endpoint, _ = save_endpoint(full_url, ctx=ctx, subdomain=subdomain, http_status=http_status)
							kr_endpoints += 1
							if endpoint and '?' in full_url:
								params = extract_params_from_url(full_url)
								for p in params:
									save_parameter(endpoint, p['name'], param_type='Kiterunner', value=p['value'])
									kr_params += 1
					logger.warning('[WEB_API] Kiterunner: %s → %d endpoints, %d params saved', subdomain_name, kr_endpoints, kr_params)
				except Exception as e:
					logger.error('[WEB_API] Kiterunner: error parsing output for %s: %s', subdomain_name, e)
	else:
		logger.warning('[WEB_API] Kiterunner: skipped (not in uses_tools)')

	# ── Per-URL tools (Arjun, ParamSpider, LinkFinder, InQL) ─────────────────
	# Each tool uses a file-existence check so that Temporal retries skip work
	# that already completed in a previous attempt.
	processed_paramspider_subdomains = set()
	processed_arjun_subdomains = set()
	processed_linkfinder_subdomains = set()
	# Gate-check caches: has_graphql_endpoint probes up to 6 network paths with a
	# 5s timeout each, and has_jwt_tokens issues 2 DB queries — both return the
	# same result for every URL sharing a subdomain.  Evaluate each gate once per
	# subdomain and reuse the cached bool for subsequent URLs.
	_graphql_gate_cache: dict = {}  # subdomain_name -> bool
	_jwt_gate_cache: dict = {}      # subdomain_name -> bool
	logger.warning('[WEB_API] Starting per-URL tool phase for %d URLs', len(url_subdomain_map))

	for url, subdomain_name, subdomain in url_subdomain_map:

		# Arjun - Parameter discovery (once per subdomain; output is subdomain-scoped)
		if 'arjun' in uses_tools and subdomain_name not in processed_arjun_subdomains:
			processed_arjun_subdomains.add(subdomain_name)
			arjun_output = f"{results_dir}/arjun_{subdomain_name}.json"
			if os.path.exists(arjun_output) and os.path.getsize(arjun_output) > 0:
				logger.warning('[WEB_API] Arjun: cache hit for %s — loading existing results', subdomain_name)
			else:
				cmd = f"arjun -u {url} --passive -m {arjun_methods} -t {threads} -oJ {arjun_output}"
				logger.warning('[WEB_API] Arjun: running on %s | cmd: %s', subdomain_name, cmd)
				run_command(cmd, shell=True, scan_id=self.scan_id, activity_id=self.activity_id)
				logger.warning('[WEB_API] Arjun: finished on %s', subdomain_name)
			if os.path.exists(arjun_output):
				try:
					arjun_params = 0
					with open(arjun_output, 'r') as f:
						data = json.load(f)
						for target_url, details in data.items():
							endpoint, _ = save_endpoint(target_url, ctx=ctx, subdomain=subdomain)
							if endpoint:
								params = details.get('params', {})
								if isinstance(params, dict):
									for method, param_list in params.items():
										for p in param_list:
											save_parameter(endpoint, p, param_type=method)
											arjun_params += 1
								elif isinstance(params, list):
									method = details.get('method', 'unknown')
									for p in params:
										save_parameter(endpoint, p, param_type=method)
										arjun_params += 1
					logger.warning('[WEB_API] Arjun: %s → %d params saved', subdomain_name, arjun_params)
				except Exception as e:
					logger.error('[WEB_API] Arjun: error parsing output for %s: %s', subdomain_name, e)
			else:
				logger.warning('[WEB_API] Arjun: output file missing for %s', subdomain_name)

		# ParamSpider - once per subdomain
		if 'paramspider' in uses_tools and subdomain_name not in processed_paramspider_subdomains:
			processed_paramspider_subdomains.add(subdomain_name)
			ps_output = f"{results_dir}/ps_{subdomain_name}.txt"
			if os.path.exists(ps_output) and os.path.getsize(ps_output) > 0:
				logger.warning('[WEB_API] ParamSpider: cache hit for %s — loading existing results', subdomain_name)
			else:
				cmd = f"paramspider --domain {subdomain_name} | tee {ps_output}"
				proxy = get_random_proxy()
				if proxy:
					cmd = f"paramspider --domain {subdomain_name} --proxy {proxy} | tee {ps_output}"
				logger.warning('[WEB_API] ParamSpider: running on %s | cmd: %s', subdomain_name, cmd)
				run_command(cmd, shell=True, cwd=results_dir, scan_id=self.scan_id, activity_id=self.activity_id)
				logger.warning('[WEB_API] ParamSpider: finished on %s', subdomain_name)
			if os.path.exists(ps_output):
				try:
					ps_params = 0
					with open(ps_output, 'r') as f:
						for line in f:
							line = line.strip()
							if line and is_valid_url(line):
								endpoint, _ = save_endpoint(line, ctx=ctx, subdomain=subdomain)
								parsed = urlparse(line)
								if parsed.query:
									for q in parsed.query.split('&'):
										if '=' in q:
											p_name = q.split('=')[0]
											save_parameter(endpoint, p_name, param_type='URL Query')
											ps_params += 1
					logger.warning('[WEB_API] ParamSpider: %s → %d params saved', subdomain_name, ps_params)
				except Exception as e:
					logger.error('[WEB_API] ParamSpider: error parsing output for %s: %s', subdomain_name, e)
			else:
				logger.warning('[WEB_API] ParamSpider: output file missing for %s', subdomain_name)

		# LinkFinder - once per subdomain (JS endpoint and parameter extraction).
		# processed_linkfinder_subdomains is the primary dedup guard so the tool
		# runs at most once per subdomain regardless of whether its output file is
		# empty (empty output = no JS found, not an error requiring a retry).
		# os.path.exists is the Temporal retry guard: a file written by a prior
		# activity attempt is loaded directly without re-running the tool.
		if 'linkfinder' in uses_tools and subdomain_name not in processed_linkfinder_subdomains:
			processed_linkfinder_subdomains.add(subdomain_name)
			lf_output = f"{results_dir}/lf_{subdomain_name}.txt"
			if os.path.exists(lf_output):
				logger.warning('[WEB_API] LinkFinder: cache hit for %s — loading existing results', subdomain_name)
			else:
				cmd = f"python3 /usr/src/github/LinkFinder/linkfinder.py -d -i {url} -o cli | tee {lf_output}"
				logger.warning('[WEB_API] LinkFinder: running on %s | cmd: %s', subdomain_name, cmd)
				run_command(cmd, shell=True, cwd=results_dir, scan_id=self.scan_id, activity_id=self.activity_id)
				logger.warning('[WEB_API] LinkFinder: finished on %s', subdomain_name)
			if os.path.exists(lf_output):
				try:
					lf_endpoints = 0
					lf_params = 0
					with open(lf_output, 'r') as f:
						for line in f:
							line = line.strip()
							if line.startswith('/') or line.startswith('http'):
								if line.startswith('/'):
									parsed = urlparse(url)
									full_url = f"{parsed.scheme}://{parsed.netloc}{line}"
								else:
									full_url = line
								endpoint, _ = save_endpoint(full_url, ctx=ctx, subdomain=subdomain)
								lf_endpoints += 1
								if endpoint is not None and '?' in full_url:
									params = extract_params_from_url(full_url)
									for p in params:
										save_parameter(endpoint, p['name'], param_type='LinkFinder', value=p['value'])
										lf_params += 1
					logger.warning('[WEB_API] LinkFinder: %s → %d endpoints, %d params saved', subdomain_name, lf_endpoints, lf_params)
				except Exception as e:
					logger.error('[WEB_API] LinkFinder: error parsing output for %s: %s', subdomain_name, e)
			else:
				logger.warning('[WEB_API] LinkFinder: output file missing for %s', subdomain_name)

		# InQL - GraphQL Discovery (only when a GraphQL endpoint is detected).
		# _graphql_gate_cache[subdomain_name] is populated on first visit so that
		# has_graphql_endpoint (which issues a DB iregex query + up to 6 network
		# probes × 5 s each) is called at most once per subdomain, not per URL.
		if 'inql' in uses_tools:
			if subdomain_name not in _graphql_gate_cache:
				logger.warning('[WEB_API] InQL: checking GraphQL gate for %s (first visit)', subdomain_name)
				_graphql_gate_cache[subdomain_name] = has_graphql_endpoint(self.scan_id, url)
			if not _graphql_gate_cache[subdomain_name]:
				logger.warning('[WEB_API] InQL: no GraphQL endpoint detected, skipping %s', subdomain_name)
			else:
				inql_output = f"{results_dir}/inql_{subdomain_name}"
				cmd = f"inql -t {url} -o {inql_output}"
				proxy = get_random_proxy()
				if proxy:
					cmd += f" -p {proxy}"
				logger.warning('[WEB_API] InQL: running on %s | cmd: %s', subdomain_name, cmd)
				run_command(cmd, shell=True, scan_id=self.scan_id, activity_id=self.activity_id)
				if os.path.exists(inql_output):
					try:
						inql_findings = parse_inql_results(inql_output)
						for finding in inql_findings:
							save_endpoint(url, ctx=ctx, subdomain=subdomain, source='InQL (GraphQL Found)')
						from reNgine.cpde.graphql_enricher import enrich_graphql_params
						enrich_graphql_params(inql_output, url, subdomain, ctx)
						logger.warning('[WEB_API] InQL: %s → %d GraphQL findings saved', subdomain_name, len(inql_findings))
					except Exception as e:
						logger.error('[WEB_API] InQL: error parsing results for %s: %s', subdomain_name, e)
				else:
					logger.warning('[WEB_API] InQL: no output directory found for %s', subdomain_name)

		# jwt_tool - JWT security testing (only when JWT tokens have been found).
		# _jwt_gate_cache[subdomain_name] is populated on first visit so that
		# has_jwt_tokens (2 DB queries per call) runs at most once per subdomain.
		if JWT_TOOL in uses_tools:
			if subdomain_name not in _jwt_gate_cache:
				logger.warning('[WEB_API] jwt_tool: checking JWT gate for %s (first visit)', subdomain_name)
				_jwt_gate_cache[subdomain_name] = has_jwt_tokens(self.scan_id, subdomain=subdomain)
			if _jwt_gate_cache[subdomain_name]:
				logger.warning('[WEB_API] jwt_tool: JWT tokens found, running on %s', subdomain_name)
				from reNgine.api_tasks import run_jwt_scan
				run_jwt_scan(self, ctx, url, subdomain, results_dir)
				logger.warning('[WEB_API] jwt_tool: finished on %s', subdomain_name)
			else:
				logger.warning('[WEB_API] jwt_tool: no JWT tokens detected, skipping %s', subdomain_name)

		# graphql-cop - GraphQL security audit (only when a GraphQL endpoint is detected).
		# Shares _graphql_gate_cache with InQL — no second round of probes needed.
		if GRAPHQL_COP in uses_tools:
			if subdomain_name not in _graphql_gate_cache:
				logger.warning('[WEB_API] graphql-cop: checking GraphQL gate for %s (first visit)', subdomain_name)
				_graphql_gate_cache[subdomain_name] = has_graphql_endpoint(self.scan_id, url)
			if not _graphql_gate_cache[subdomain_name]:
				logger.warning('[WEB_API] graphql-cop: no GraphQL endpoint detected, skipping %s', subdomain_name)
			else:
				logger.warning('[WEB_API] graphql-cop: running on %s', subdomain_name)
				from reNgine.api_tasks import run_graphql_cop
				run_graphql_cop(self, ctx, url, subdomain)
				logger.warning('[WEB_API] graphql-cop: finished on %s', subdomain_name)

	# Semgrep - Post-discovery pattern matching
	if 'semgrep' in uses_tools:
		semgrep_output = f"{results_dir}/semgrep_results.json"
		cmd = f"semgrep scan --config auto --json --output {semgrep_output} {results_dir}"
		logger.warning('[WEB_API] Semgrep: running post-discovery scan | cmd: %s', cmd)
		run_command(cmd, shell=True, scan_id=self.scan_id, activity_id=self.activity_id)
		if os.path.exists(semgrep_output):
			try:
				with open(semgrep_output, 'r') as f:
					data = json.load(f)
					matches = data.get('results', [])
					for match in matches:
						vuln_data = parse_semgrep_result(match)
						save_vulnerability(vuln_data, self.scan, self.domain)
				logger.warning('[WEB_API] Semgrep: %d vulnerabilities saved', len(matches))
			except Exception as e:
				logger.error('[WEB_API] Semgrep: error parsing output: %s', e)
		else:
			logger.warning('[WEB_API] Semgrep: output file not found — may have failed silently')
	else:
		logger.warning('[WEB_API] Semgrep: skipped (not in uses_tools)')

	# Retire.js - JS Library vulnerability scan
	if 'retire' in uses_tools:
		retire_output = f"{results_dir}/retire_results.json"
		cmd = f"npx -y retire --path {results_dir} --outputformat json --outputpath {retire_output}"
		logger.warning('[WEB_API] Retire.js: running | cmd: %s', cmd)
		run_command(cmd, shell=True, scan_id=self.scan_id, activity_id=self.activity_id)
		if os.path.exists(retire_output):
			try:
				retire_vulns = 0
				with open(retire_output, 'r') as f:
					data = json.load(f)

					# Retire.js results can be either a list of file results or a dictionary wrapper
					results_list = []
					if isinstance(data, list):
						results_list = data
					elif isinstance(data, dict):
						# Check standard Retire.js dictionary output keys
						if 'data' in data and isinstance(data['data'], list):
							results_list = data['data']
						elif 'results' in data and isinstance(data['results'], list):
							results_list = data['results']
						else:
							results_list = [data]

				for result in results_list:
					if not isinstance(result, dict):
						continue
					for component in result.get('results', []):
						if not isinstance(component, dict):
							continue
						for vuln in component.get('vulnerabilities', []):
							if not isinstance(vuln, dict):
								continue
							vuln_data = parse_retire_result({
								'component': component.get('component'),
								'version': component.get('version'),
								'info': vuln.get('info'),
								'file': result.get('file')
							})
							save_vulnerability(vuln_data, self.scan, self.domain)
							retire_vulns += 1
				logger.warning('[WEB_API] Retire.js: %d vulnerabilities saved', retire_vulns)
			except Exception as e:
				logger.error('[WEB_API] Retire.js: error parsing output: %s', e)
		else:
			logger.warning('[WEB_API] Retire.js: output file not found — may have failed silently')
	else:
		logger.warning('[WEB_API] Retire.js: skipped (not in uses_tools)')

	# Aquatone - visual inspection of discovered URLs
	if 'aquatone' in uses_tools and urls:
		aquatone_out = f"{results_dir}/aquatone"
		os.makedirs(aquatone_out, exist_ok=True)
		targets_file = f"{aquatone_out}/targets.txt"
		with open(targets_file, 'w') as _f:
			_f.write('\n'.join(urls))
		cmd = f"cat {targets_file} | aquatone -out {aquatone_out} -threads {threads} -silent"
		logger.warning('[WEB_API] Aquatone: running on %d URLs | cmd: %s', len(urls), cmd)
		run_command(cmd, shell=True, cwd=aquatone_out, scan_id=self.scan_id, activity_id=self.activity_id)
		logger.warning('[WEB_API] Aquatone: finished')
	elif 'aquatone' in uses_tools:
		logger.warning('[WEB_API] Aquatone: skipped (no URLs)')

	# Sync to Graph
	if Neo4jManager:
		logger.warning('[WEB_API] Syncing results to Neo4j graph...')
		nm = Neo4jManager()
		nm.sync_scan_results(self.scan_id)
		nm.close()
		logger.warning('[WEB_API] Neo4j sync complete')

	# Trigger Intelligent Auth Candidate Extraction
	logger.warning('[WEB_API] Running auth candidate extraction...')
	from reNgine.auth_discovery_tasks import extract_auth_candidates
	extract_auth_candidates(self, ctx=ctx)
	logger.warning('[WEB_API] Web API Discovery complete | scan_id=%s', scan_id)


def vulnerability_scan(self, urls=[], ctx={}, description=None):
	"""This task serves as the entrypoint for vulnerability scans, spawning all enabled scanners.

	Args:
		urls (list): Target URLs to scan.
		ctx (dict): Scan context.
		description (str): Task description.
	"""
	logger.info('Running Vulnerability Scan Queue')
	config = self.yaml_configuration
	
	# Note: vulnerability_scan is bypassed by RunVulnerabilityScanActivity in Temporal.
	# This path handles any direct calls by dispatching each scanner sequentially.
	vuln_config = config.get(VULNERABILITY_SCAN) or {}
	from reNgine.definitions import RUN_NUCLEI, RUN_CRLFUZZ, RUN_DALFOX, RUN_S3SCANNER, RUN_ACUNETIX, RUN_WPSCAN, RUN_CPANEL2SHELL, RUN_REACT2SHELL
	from reNgine.vulnerability_tasks import cpanel_scan, react2shell_scan
	from reNgine.wpscan_tasks import wpscan_scan

	if vuln_config.get(RUN_NUCLEI, True):
		nuclei_scan(self, urls=urls, ctx=ctx, description='Nuclei Scan')
	if vuln_config.get(RUN_CRLFUZZ, False):
		crlfuzz_scan(self, urls=urls, ctx=ctx, description='CRLFuzz Scan')
	if vuln_config.get(RUN_DALFOX, False):
		dalfox_xss_scan(self, urls=urls, ctx=ctx, description='Dalfox XSS Scan')
	if vuln_config.get(RUN_S3SCANNER, True):
		s3scanner(self, ctx=ctx, description='S3 Bucket Scanner')
	if vuln_config.get(RUN_ACUNETIX, False):
		from dashboard.models import AcunetixAPIKey
		creds = AcunetixAPIKey.objects.first()
		if creds and creds.server_url and creds.api_key:
			acunetix_scan(self, domain_id=ctx.get('domain_id'), scan_history_id=ctx.get('scan_history_id'), ctx=ctx)
	cpanel_cfg = vuln_config.get('cpanel_scanner', {})
	if cpanel_cfg.get(RUN_CPANEL2SHELL, True):
		cpanel_scan(self, ctx=ctx, description='cPanel Vulnerability Scan')
	if vuln_config.get(RUN_WPSCAN, True):
		wpscan_scan(self, urls=urls, ctx=ctx, description='WPScan')
	react_cfg = vuln_config.get('react_scanner', {})
	if react_cfg.get(RUN_REACT2SHELL, True):
		react2shell_scan(self, ctx=ctx, description='React Vulnerability Scan')
	semgrep_scan(self, ctx=ctx, mode='vulnerability', description='Semgrep Vulnerability Scan')
	logger.info("Primary vulnerability scan tasks (Stage 1) completed.")
	logger.info("Additional vulnerability scan tasks (Stage 2) completed.")

	logger.info('Vulnerability scan completed...')
	return None






def nuclei_scan(self, urls=[], ctx={}, description=None, prepare_only=False, parse_only=None, severity=None, tags_override=None, proxies_file_path=None):
	"""HTTP vulnerability scan using Nuclei

	Args:
		urls (list, optional): List of HTTP URLs to scan.
		ctx (dict, optional): Task execution context dictionary containing settings.
		description (str, optional): Task description shown in the UI activity.
		prepare_only (bool, optional): If True, only write target files and skip tool run.
		parse_only (str, optional): Path to output file to parse results from.
		severity (str, optional): Nuclei severity to scan (e.g. info, low, medium, high, critical).

	Notes:
	Unfurl the urls to keep only domain and path, will be sent to vuln scan and
	ignore certain file extensions. Thanks: https://github.com/six2dez/reconftw
	"""
	# Config
	config = self.yaml_configuration.get(VULNERABILITY_SCAN) or {}
	severity_filter = severity or ctx.get('nuclei_severity_filter')
	severity_suffix = f"_{severity_filter}" if severity_filter else ""
	input_path = f'{self.results_dir}/input_endpoints_vulnerability_scan{severity_suffix}.txt'
	enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
	concurrency = config.get(NUCLEI_CONCURRENCY) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
	intensity = config.get(INTENSITY) or self.yaml_configuration.get(INTENSITY, DEFAULT_SCAN_INTENSITY)
	rate_limit = config.get(RATE_LIMIT) or self.yaml_configuration.get(RATE_LIMIT, DEFAULT_RATE_LIMIT)
	# Cap concurrency and rate when routing through a proxy file.
	# nuclei v3.9.0 AdaptiveWaitGroup deadlocks at high concurrency under proxy
	# error rates of 60%+. See: scan 37 post-mortem / nuclei-stacktrace-*.dump.
	if proxies_file_path and os.path.exists(proxies_file_path):
		if concurrency > NUCLEI_PROXY_MAX_CONCURRENCY:
			logger.warning(
				'nuclei proxy mode: capping concurrency %s -> %s to prevent semaphore deadlock',
				concurrency, NUCLEI_PROXY_MAX_CONCURRENCY,
			)
			concurrency = NUCLEI_PROXY_MAX_CONCURRENCY
		if rate_limit > NUCLEI_PROXY_MAX_RATE_LIMIT:
			logger.warning(
				'nuclei proxy mode: capping rate_limit %s -> %s req/s',
				rate_limit, NUCLEI_PROXY_MAX_RATE_LIMIT,
			)
			rate_limit = NUCLEI_PROXY_MAX_RATE_LIMIT
	retries = config.get(RETRIES) or self.yaml_configuration.get(RETRIES, DEFAULT_RETRIES)
	timeout = config.get(TIMEOUT) or self.yaml_configuration.get(TIMEOUT, DEFAULT_HTTP_TIMEOUT)
	custom_headers = self.yaml_configuration.get(CUSTOM_HEADERS, [])
	'''
	# TODO: Remove custom_header in next major release
		support for custom_header will be remove in next major release, 
		as of now it will be supported for backward compatibility
		only custom_headers will be supported
	'''
	custom_header = self.yaml_configuration.get(CUSTOM_HEADER)
	if custom_header:
		custom_headers.append(custom_header)
	should_fetch_gpt_report = config.get(FETCH_GPT_REPORT, DEFAULT_GET_GPT_REPORT)
	nuclei_specific_config = config.get('nuclei', {})
	use_nuclei_conf = nuclei_specific_config.get(USE_NUCLEI_CONFIG, False)
	auto_update_templates = nuclei_specific_config.get('auto_update_templates', True)
	if severity_filter:
		severities = [severity_filter]
	else:
		severities = nuclei_specific_config.get(NUCLEI_SEVERITY, NUCLEI_DEFAULT_SEVERITIES)
	if tags_override is not None:
		# Tags were pre-computed and batched by NucleiPlannerWorkflow via
		# GatherNucleiTagsActivity.  Use them directly; skip the tech-detection
		# block so we don't re-query the DB on every batch call.
		tags = ','.join(tags_override) if tags_override else ''
		all_techs = set()
	else:
		tags = nuclei_specific_config.get(NUCLEI_TAGS, [])

		# Intelligence-Driven Scanning: Inject tags based on detected technologies
		tech_tags = []
		all_techs = set()
		if self.scan:
			# Get all technologies discovered for this scan
			subdomains = Subdomain.objects.filter(scan_history=self.scan)
			all_techs = set()
			for sub in subdomains:
				# assuming technologies is a many-to-many field with 'name' attribute
				all_techs.update(sub.technologies.values_list('name', flat=True))

			if all_techs:
				tech_tags = get_nuclei_tags_from_techs(list(all_techs))
				logger.info('Detected technologies: %s. Adding targeted Nuclei tags: %s', list(all_techs), tech_tags)

		if tech_tags:
			# Combine user tags with tech tags
			from reNgine.nuclei_batch_utils import build_tag_batches
			user_tags = set(tags if isinstance(tags, list) else tags.split(',') if tags else [])
			user_tags.update(tech_tags)
			all_combined = sorted(user_tags)
			batches = build_tag_batches(all_combined, {}, max_tags=3)
			if len(batches) > 1:
				logger.warning(
					'nuclei_scan: %d tags detected outside Temporal batching; '
					'running first batch of %d only. Use NucleiPlannerWorkflow for full coverage.',
					len(all_combined), len(batches[0]),
				)
			tags = ','.join(batches[0]) if batches else ''
		else:
			tags = ','.join(tags) if isinstance(tags, list) else tags

	nuclei_templates = nuclei_specific_config.get(NUCLEI_TEMPLATE)
	custom_nuclei_templates = nuclei_specific_config.get(NUCLEI_CUSTOM_TEMPLATE)
	severities_str = ','.join(severities)

	# Collect all URLs: DB endpoints (no alive-only filter) + spidering result files
	if urls:
		combined = list(set(urls))
	else:
		combined = collect_all_scan_urls(
			ctx=ctx,
			results_dir=self.results_dir,
			ignore_files=True,
		)
	with open(input_path, 'w') as f:
		f.write('\n'.join(combined))

	if intensity == 'normal': # reduce number of endpoints to scan
		unfurl_filter = f'{self.results_dir}/urls_unfurled{severity_suffix}.txt'
		run_command(
			f"cat {input_path} | unfurl -u format %s://%d%p |uro > {unfurl_filter}",
			shell=True,
			history_file=self.history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id)
		run_command(
			f'sort -u {unfurl_filter} -o  {unfurl_filter}',
			shell=True,
			history_file=self.history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id)
		if os.path.isfile(unfurl_filter) and os.path.getsize(unfurl_filter) > 0:
			input_path = unfurl_filter
		else:
			logger.warning('nuclei_scan: unfurl produced no output, using original endpoint list.')

	# Build templates
	logger.info('Updating Nuclei templates ...')
	# Wordfence Templates integration — 70k+ WordPress CVE templates, daily-updated
	# When tags_override is used, all_techs is empty; check the batch tags instead.
	if tags_override is not None:
		is_wordpress_detected = any(
			'wordpress' in t.lower() or 'wp-' in t.lower()
			for t in (tags_override or [])
		)
	else:
		is_wordpress_detected = any(
			'wordpress' in t.lower() or 'wp-' in t.lower()
			for t in all_techs
		) if all_techs else False
	wordfence_exists = False
	if is_wordpress_detected:
		wordfence_dir = '/root/nuclei-templates/wordfence'
		if os.path.isdir(wordfence_dir) and os.listdir(wordfence_dir):
			logger.info('WordPress detected; Wordfence templates present at %s', wordfence_dir)
			wordfence_exists = True
		else:
			logger.warning(
				'WordPress detected but Wordfence templates missing at %s; '
				'templates should be pre-loaded at container startup', wordfence_dir
			)

	if auto_update_templates:
		run_command(
			'nuclei -update-templates',
			shell=True,
			history_file=self.history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id)
	templates = []
	if not (nuclei_templates or custom_nuclei_templates):
		templates.append(NUCLEI_DEFAULT_TEMPLATES_PATH)

	if nuclei_templates:
		if ALL in nuclei_templates:
			template = NUCLEI_DEFAULT_TEMPLATES_PATH
			templates.append(template)
		else:
			templates.extend(nuclei_templates)

	if custom_nuclei_templates:
		custom_nuclei_template_paths = []
		for elem in custom_nuclei_templates:
			if str(elem).endswith(('.yaml', '.yml')) or str(elem).endswith('/'):
				custom_nuclei_template_paths.append(str(elem))
			else:
				custom_nuclei_template_paths.append(f'{str(elem)}.yaml')
		templates.extend(custom_nuclei_template_paths)

	# Build CMD
	cmd = 'nuclei -j -hang-monitor -stats'
	cmd += ' -config /root/.config/nuclei/config.yaml' if use_nuclei_conf else ''
	cmd += f' -irr'

	# Apply OpSec stealth
	proxy = get_random_proxy()
	opsec = get_opsec_manager()
	cmd = opsec.apply_stealth('nuclei', cmd, proxy=proxy)
	formatted_headers = ' '.join(f'-H "{header}"' for header in custom_headers)
	if formatted_headers:
		cmd += f' {formatted_headers}'
	cmd += f' '
	
	if proxies_file_path and os.path.exists(proxies_file_path):
		cmd += f' -proxy {proxies_file_path}'
	elif proxy:
		cmd += f' -proxy {proxy}' 
	cmd += f' -l {input_path}'
	cmd += f' -c {str(concurrency)}' if concurrency > 0 else ''

	cmd += f' -retries {retries}' if retries > 0 else ''
	cmd += f' -rl {rate_limit}' if rate_limit > 0 else ''
	if severities_str:
		cmd += f' -severity {severities_str}'
	#cmd += f' -timeout {str(timeout)}' if timeout and timeout > 0 else ''
	if tags:
		cmd += f" -tags '{tags}'"
	#cmd += f' -silent'
	for tpl in templates:
		cmd += f' -t {tpl}'
	
	if is_wordpress_detected and wordfence_exists:
		# Wordfence templates live at /root/nuclei-templates/wordfence — already included
		# in the default -t /root/nuclei-templates recursive scan; no extra -t needed.
		logger.info(f'[nuclei] WordPress detected; Wordfence templates active at /root/nuclei-templates/wordfence')
	logger.info("Running Nuclei vulnerabilities scan")
	if hasattr(self, 'activity') and self.activity:
		self.activity.title = "Nuclei Scan"
		self.activity.save()
	
	logger.warning(f'cmd: {cmd}')
	
	results = []
	notif = Notification.objects.first()
	send_status = notif.send_scan_status_notif if notif else False

	import json
	line_source = stream_command(
		cmd,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)

	for line in line_source:
		if not isinstance(line, dict):
			continue

		results.append(line)

		# Gather nuclei results
		vuln_data = parse_nuclei_result(line)

		# Get corresponding subdomain
		http_url = sanitize_url(line.get('matched-at'))
		subdomain_name = get_subdomain_from_url(http_url)

		subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
		if not subdomain:
			continue

		severity_value = line['info'].get('severity', 'unknown')

		# Get or create EndPoint object
		response = line.get('response')
		httpx_crawl = False if response else enable_http_crawl # avoid yet another httpx crawl
		endpoint, _ = save_endpoint(
			http_url,
			crawl=httpx_crawl,
			subdomain=subdomain,
			ctx=ctx)
		if endpoint:
			http_url = endpoint.http_url
			if not httpx_crawl:
				output = parse_curl_output(response)
				endpoint.http_status = output['http_status']
				endpoint.save()

		# Register Auth Candidate if Nuclei flagged it as login or auth
		tags_list = line.get('info', {}).get('tags', []) or []
		if any(tag in tags_list for tag in ['login', 'auth', 'admin', 'default-login', 'bruteforce', 'panel']):
			from reNgine.utilities import save_auth_candidate
			save_auth_candidate(
				scan_history=self.scan,
				target=http_url,
				protocol='http',
				port=int(urlparse(http_url).port or (443 if 'https' in http_url else 80)),
				source_tool='Nuclei',
				metadata={'tags': tags_list, 'template_id': line.get('template-id')},
				subdomain=subdomain,
				endpoint=endpoint
			)

		# Get or create Vulnerability object
		vuln, created = save_vulnerability(
			target_domain=self.domain,
			http_url=http_url,
			scan_history=self.scan,
			subscan=self.subscan,
			subdomain=subdomain,
			**vuln_data)
		if not vuln or not created:
			continue

		# Print vuln
		logger.warning(str(vuln))

		# Send notification for all vulnerabilities except info
		url = vuln.http_url or vuln.subdomain
		send_vuln = (
			notif and
			notif.send_vuln_notif and
			vuln and
			severity_value in ['low', 'medium', 'high', 'critical'])
		if send_vuln:
			fields = {
				'Severity': f'**{severity_value.upper()}**',
				'URL': http_url,
				'Subdomain': subdomain_name,
				'Name': vuln.name,
				'Type': vuln.type,
				'Description': vuln.description,
				'Template': vuln.template_url,
				'Tags': vuln.get_tags_str() or "N/A",
				'CVEs': vuln.get_cve_str(),
				'CWEs': vuln.get_cwe_str(),
				'References': vuln.get_refs_str()
			}
			severity_map = {
				'low': 'info',
				'medium': 'warning',
				'high': 'error',
				'critical': 'error'
			}
			self.notify(
				f'vulnerability_scan_#{vuln.id}',
				severity_map[severity_value],
				fields,
				add_meta_info=False)

		# Send report to hackerone
		hackerone_query = Hackerone.objects.filter(send_report=True)
		api_key_check_query = HackerOneAPIKey.objects.filter(
			Q(username__isnull=False) & Q(key__isnull=False)
		)

		send_report = (
			hackerone_query.exists() and
			api_key_check_query.exists() and
			severity_value not in ('info', 'low') and
			vuln.target_domain.h1_team_handle
		)

		if send_report:
			hackerone = hackerone_query.first()
			try:
				if hackerone.send_critical and severity_value == 'critical':
					send_hackerone_report(vuln.id)
				elif hackerone.send_high and severity_value == 'high':
					send_hackerone_report(vuln.id)
				elif hackerone.send_medium and severity_value == 'medium':
					send_hackerone_report(vuln.id)
			except Exception as e:
				logger.warning(f"HackerOne report send failed for vuln {vuln.id}: {e}")

	# Write results to JSON file
	with open(self.output_path, 'w') as f:
		json.dump(results, f, indent=4)

	# Send finish notif
	if send_status:
		vulns = Vulnerability.objects.filter(scan_history__id=self.scan_id)
		info_count = vulns.filter(severity=0).count()
		low_count = vulns.filter(severity=1).count()
		medium_count = vulns.filter(severity=2).count()
		high_count = vulns.filter(severity=3).count()
		critical_count = vulns.filter(severity=4).count()
		unknown_count = vulns.filter(severity=-1).count()
		vulnerability_count = info_count + low_count + medium_count + high_count + critical_count + unknown_count
		fields = {
			'Total': vulnerability_count,
			'Critical': critical_count,
			'High': high_count,
			'Medium': medium_count,
			'Low': low_count,
			'Info': info_count,
			'Unknown': unknown_count
		}
		self.notify(fields=fields)

	if should_fetch_gpt_report and OpenAiAPIKey.objects.all().first():
		logger.info('Getting Vulnerability GPT Report')
		vulns = Vulnerability.objects.filter(
			scan_history__id=self.scan_id
		).filter(
			source=NUCLEI
		).exclude(
			severity=0
		)
		unique_vulns = set()
		for vuln in vulns:
			unique_vulns.add((vuln.name, vuln.get_path()))

		unique_vulns = list(unique_vulns)

		import concurrent.futures
		with concurrent.futures.ThreadPoolExecutor(max_workers=DEFAULT_THREADS) as executor:
			future_to_gpt = {executor.submit(get_vulnerability_gpt_report, vuln): vuln for vuln in unique_vulns}
			for future in concurrent.futures.as_completed(future_to_gpt):
				gpt = future_to_gpt[future]
				try:
					future.result()
				except Exception as e:
					logger.error(f"Exception for Vulnerability {gpt}: {e}")

	logger.info('Vulnerability scan completed...')
	return None

def dalfox_xss_scan(self, urls=[], ctx={}, description=None):
	"""XSS Scan using dalfox

	Args:
		urls (list, optional): If passed, filter on those URLs.
		description (str, optional): Task description shown in UI.
	"""
	vuln_config = self.yaml_configuration.get(VULNERABILITY_SCAN) or {}
	should_fetch_gpt_report = vuln_config.get(FETCH_GPT_REPORT, DEFAULT_GET_GPT_REPORT)
	dalfox_config = vuln_config.get(DALFOX) or {}
	custom_headers = self.yaml_configuration.get(CUSTOM_HEADERS, [])
	'''
	# TODO: Remove custom_header in next major release
		support for custom_header will be remove in next major release, 
		as of now it will be supported for backward compatibility
		only custom_headers will be supported
	'''
	custom_header = self.yaml_configuration.get(CUSTOM_HEADER)
	if custom_header:
		custom_headers.append(custom_header)
	is_waf_evasion = dalfox_config.get(WAF_EVASION, False)
	use_deep_scan = dalfox_config.get('DEEP_SCAN', False)
	use_remote_payloads = dalfox_config.get('REMOTE_PAYLOADS', False)
	use_remote_wordlists = dalfox_config.get('REMOTE_WORDLISTS', False)
	scan_timeout = dalfox_config.get('SCAN_TIMEOUT', 300)
	blind_xss_server = dalfox_config.get(BLIND_XSS_SERVER)
	user_agent = dalfox_config.get(USER_AGENT) or self.yaml_configuration.get(USER_AGENT)
	timeout = dalfox_config.get(TIMEOUT)
	delay = dalfox_config.get(DELAY)
	threads = dalfox_config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
	input_path = f'{self.results_dir}/input_endpoints_dalfox_xss.txt'

	if urls:
		with open(input_path, 'w') as f:
			f.write('\n'.join(urls))
	else:
		get_http_urls(
			is_alive=False,
			ignore_files=False,
			write_filepath=input_path,
			ctx=ctx
		)

	notif = Notification.objects.first()
	send_status = notif.send_scan_status_notif if notif else False

	# command builder
	proxy = get_random_proxy()
	opsec = get_opsec_manager()
	cmd = 'dalfox scan --no-color'
	cmd += f' --only-poc v,r'
	cmd += f' --ignore-return 302,404,403'
	
	cmd = opsec.apply_stealth('dalfox', cmd, proxy=proxy)
	cmd += f' file {input_path}'
	cmd += f' --proxy {proxy}' if proxy and '--proxy' not in cmd else ''
	cmd += f' --waf-evasion' if is_waf_evasion else ''
	cmd += f' --waf-bypass auto'
	cmd += f' --deep-scan' if use_deep_scan else ''
	cmd += f' --remote-payloads portswigger,payloadbox' if use_remote_payloads else ''
	cmd += f' --remote-wordlists burp,assetnote' if use_remote_wordlists else ''
	cmd += f' -b {blind_xss_server}' if blind_xss_server else ''
	cmd += f' --delay {delay}' if delay else ''
	cmd += f' --timeout {timeout}' if timeout else ''
	cmd += f' --scan-timeout {scan_timeout}' if scan_timeout else ''
	formatted_headers = ' '.join(f'-H "{header}"' for header in custom_headers)
	if formatted_headers:
		cmd += f' {formatted_headers}'
	cmd += f' --user-agent {user_agent}' if user_agent else ''
	cmd += f' --workers {threads}' if threads else ''
	cmd += f' --format json'

	results = []
	for line in stream_command(
			cmd,
			history_file=self.history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id,
			trunc_char=','
		):
		if not isinstance(line, dict):
			continue

		results.append(line)

		vuln_data = parse_dalfox_result(line)

		http_url = sanitize_url(line.get('data'))
		subdomain_name = get_subdomain_from_url(http_url)

		subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
		if not subdomain:
			continue
		endpoint, _ = save_endpoint(
			http_url,
			crawl=False,
			subdomain=subdomain,
			ctx=ctx
		)
		if endpoint:
			http_url = endpoint.http_url
			endpoint.save()

		vuln, _ = save_vulnerability(
			target_domain=self.domain,
			http_url=http_url,
			scan_history=self.scan,
			subscan=self.subscan,
			**vuln_data
		)

		if not vuln:
			continue

	# after vulnerability scan is done, we need to run gpt if
	# should_fetch_gpt_report and openapi key exists

	if should_fetch_gpt_report and OpenAiAPIKey.objects.all().first():
		logger.info('Getting Dalfox Vulnerability GPT Report')
		vulns = Vulnerability.objects.filter(
			scan_history__id=self.scan_id
		).filter(
			source=DALFOX
		).exclude(
			severity=0
		)

		_vulns = []
		for vuln in vulns:
			_vulns.append((vuln.name, vuln.http_url))

		with concurrent.futures.ThreadPoolExecutor(max_workers=DEFAULT_THREADS) as executor:
			future_to_gpt = {executor.submit(get_vulnerability_gpt_report, vuln): vuln for vuln in _vulns}

			# Wait for all tasks to complete
			for future in concurrent.futures.as_completed(future_to_gpt):
				gpt = future_to_gpt[future]
				try:
					future.result()
				except Exception as e:
					logger.error(f"Exception for Vulnerability {gpt}: {e}")
	return results


def crlfuzz_scan(self, urls=[], ctx={}, description=None):
	"""CRLF Fuzzing with CRLFuzz

	Args:
		urls (list, optional): If passed, filter on those URLs.
		description (str, optional): Task description shown in UI.
	"""
	vuln_config = self.yaml_configuration.get(VULNERABILITY_SCAN) or {}
	should_fetch_gpt_report = vuln_config.get(FETCH_GPT_REPORT, DEFAULT_GET_GPT_REPORT)
	custom_headers = self.yaml_configuration.get(CUSTOM_HEADERS, [])
	'''
	# TODO: Remove custom_header in next major release
		support for custom_header will be remove in next major release, 
		as of now it will be supported for backward compatibility
		only custom_headers will be supported
	'''
	custom_header = self.yaml_configuration.get(CUSTOM_HEADER)
	if custom_header:
		custom_headers.append(custom_header)
	user_agent = vuln_config.get(USER_AGENT) or self.yaml_configuration.get(USER_AGENT)
	threads = vuln_config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
	input_path = f'{self.results_dir}/input_endpoints_crlf.txt'
	output_path = f'{self.results_dir}/{self.filename}'

	urls = [u for u in urls if u and u.strip()]

	if urls:
		with open(input_path, 'w') as f:
			f.write('\n'.join(urls))
	else:
		get_http_urls(
			is_alive=False,
			ignore_files=True,
			write_filepath=input_path,
			ctx=ctx
		)

	if not os.path.isfile(input_path) or os.path.getsize(input_path) == 0:
		logger.warning('crlfuzz: no endpoints to scan at %s, skipping.', input_path)
		return

	notif = Notification.objects.first()
	send_status = notif.send_scan_status_notif if notif else False

	# command builder
	proxy = get_random_proxy()
	cmd = 'crlfuzz ' # -s
	cmd += f' -l {input_path}'
	cmd += f' -x {proxy}' if proxy else ''
	formatted_headers = ' '.join(f'-H "{header}"' for header in custom_headers)
	if formatted_headers:
		cmd += f' {formatted_headers}'
	cmd += f' -o {output_path}'

	run_command(
		cmd,
		shell=True,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id
	)

	if not os.path.isfile(output_path):
		logger.info('No Results from CRLFuzz')
		return

	crlfs = []
	results = []
	with open(output_path, 'r') as file:
		crlfs = file.readlines()

	for crlf in crlfs:
		url = crlf.strip()
		if not url:
			continue

		vuln_data = parse_crlfuzz_result(url)

		http_url = sanitize_url(url)
		subdomain_name = get_subdomain_from_url(http_url)

		subdomain, _ = save_subdomain(subdomain_name, ctx=ctx)
		if not subdomain:
			continue

		endpoint, _ = save_endpoint(
			http_url,
			crawl=False,
			subdomain=subdomain,
			ctx=ctx
		)
		if endpoint:
			http_url = endpoint.http_url
			endpoint.save()

		vuln, _ = save_vulnerability(
			target_domain=self.domain,
			http_url=http_url,
			scan_history=self.scan,
			subscan=self.subscan,
			**vuln_data
		)

		if not vuln:
			continue

	# after vulnerability scan is done, we need to run gpt if
	# should_fetch_gpt_report and openapi key exists

	if should_fetch_gpt_report and OpenAiAPIKey.objects.all().first():
		logger.info('Getting CRLFuzz Vulnerability GPT Report')
		vulns = Vulnerability.objects.filter(
			scan_history__id=self.scan_id
		).filter(
			source=CRLFUZZ
		).exclude(
			severity=0
		)

		_vulns = []
		for vuln in vulns:
			_vulns.append((vuln.name, vuln.http_url))

		with concurrent.futures.ThreadPoolExecutor(max_workers=DEFAULT_THREADS) as executor:
			future_to_gpt = {executor.submit(get_vulnerability_gpt_report, vuln): vuln for vuln in _vulns}

			# Wait for all tasks to complete
			for future in concurrent.futures.as_completed(future_to_gpt):
				gpt = future_to_gpt[future]
				try:
					future.result()
				except Exception as e:
					logger.error(f"Exception for Vulnerability {gpt}: {e}")

	return results


def s3scanner(self, ctx={}, description=None):
	"""Bucket Scanner

	Args:
		ctx (dict): Context
		description (str, optional): Task description shown in UI.
	"""
	input_path = f'{self.results_dir}/subdomain_discovery.txt'
	if not os.path.isfile(input_path):
		logger.warning(f's3scanner: subdomain list not found at {input_path}, skipping.')
		return
	vuln_config = self.yaml_configuration.get(VULNERABILITY_SCAN) or {}
	s3_config = vuln_config.get(S3SCANNER) or {}
	threads = s3_config.get(THREADS) or self.yaml_configuration.get(THREADS, DEFAULT_THREADS)
	providers = s3_config.get(PROVIDERS, S3SCANNER_DEFAULT_PROVIDERS)
	scan_history = ScanHistory.objects.filter(pk=self.scan_id).first()
	for provider in providers:
		cmd = f's3scanner -bucket-file {input_path} -enumerate -provider {provider} -threads {threads} -json'
		for line in stream_command(
				cmd,
				history_file=self.history_file,
				scan_id=self.scan_id,
				activity_id=self.activity_id):

			if not isinstance(line, dict):
				continue

			if line.get('bucket', {}).get('exists', 0) == 1:
				result = parse_s3scanner_result(line)
				s3bucket, created = S3Bucket.objects.get_or_create(**result)
				scan_history.buckets.add(s3bucket)
				logger.info(f"s3 bucket added {result['provider']}-{result['name']}-{result['region']}")


def http_crawl(
		self,
		urls=[],
		method=None,
		recrawl=False,
		ctx={},
		track=True,
		description=None,
		is_ran_from_subdomain_scan=False,
		should_remove_duplicate_endpoints=True,
		duplicate_removal_fields=[]):
	"""Use httpx to query HTTP URLs for important info like page titles, http
	status, etc...

	Args:
		urls (list, optional): A set of URLs to check. Overrides default
			behavior which queries all endpoints related to this scan.
		method (str): HTTP method to use (GET, HEAD, POST, PUT, DELETE).
		recrawl (bool, optional): If False, filter out URLs that have already
			been crawled.
		should_remove_duplicate_endpoints (bool): Whether to remove duplicate endpoints
		duplicate_removal_fields (list): List of Endpoint model fields to check for duplicates

	Returns:
		list: httpx results.
	"""
	logger.info('Initiating HTTP Crawl')
	if is_ran_from_subdomain_scan:
		logger.info('Running From Subdomain Scan...')
	cmd = '/usr/local/bin/httpx'
	cfg = self.yaml_configuration.get(HTTP_CRAWL) or {}
	custom_headers = self.yaml_configuration.get(CUSTOM_HEADERS, [])
	'''
	# TODO: Remove custom_header in next major release
		support for custom_header will be remove in next major release, 
		as of now it will be supported for backward compatibility
		only custom_headers will be supported
	'''
	custom_header = self.yaml_configuration.get(CUSTOM_HEADER)
	if custom_header:
		custom_headers.append(custom_header)
	threads = cfg.get(THREADS, DEFAULT_THREADS)
	follow_redirect = cfg.get(FOLLOW_REDIRECT, True)
	self.output_path = None
	input_path = f'{self.results_dir}/httpx_input.txt'
	history_file = f'{self.results_dir}/commands.txt'
	if urls: # direct passing URLs to check
		if self.starting_point_path:
			urls = [u for u in urls if self.starting_point_path in u]

		with open(input_path, 'w') as f:
			f.write('\n'.join(urls))
	else:
		urls = get_http_urls(
			is_uncrawled=not recrawl,
			write_filepath=input_path,
			ctx=ctx
		)
		# logger.debug(urls)

	# exclude urls by pattern
	if self.excluded_paths:
		urls = exclude_urls_by_patterns(self.excluded_paths, urls)

	# If no URLs found, skip it
	if not urls:
		return

	# Re-adjust thread number if few URLs to avoid spinning up a monster to
	# kill a fly.
	if len(urls) < threads:
		threads = len(urls)

	# projectdiscovery tools like naabu and httpx seem to fail when proxies are used
	# ensuring that proxies are never used for httpx
	proxy = ''

	# Run command
	cmd += f' -cl -ct -rt -location -td -websocket -cname -asn -cdn -probe -random-agent'
	cmd += f' -t {threads}' if threads > 0 else ''
	cmd += f' --http-proxy {proxy}' if proxy else ''
	formatted_headers = ' '.join(f'-H "{header}"' for header in custom_headers)
	if formatted_headers:
		cmd += f' {formatted_headers}'
	cmd += f' -json'
	cmd += f' -u {urls[0]}' if len(urls) == 1 else f' -l {input_path}'
	cmd += f' -x {method}' if method else ''
	if follow_redirect:
		cmd += ' --follow-redirects'
	
	# Apply OpSec stealth
	opsec = get_opsec_manager()
	cmd = opsec.apply_stealth('httpx', cmd, proxy=proxy)

	results = []
	endpoint_ids = []
	for line in stream_command(
			cmd,
			history_file=history_file,
			scan_id=self.scan_id,
			activity_id=self.activity_id):

		if not line or not isinstance(line, dict):
			continue

		logger.debug(line)

		# No response from endpoint
		if line.get('failed', False):
			continue

		httpx_result = process_httpx_response(line, ctx=ctx, is_ran_from_subdomain_scan=is_ran_from_subdomain_scan)
		if not httpx_result:
			continue

		endpoint, created = httpx_result

		if not endpoint:
			continue

		endpoint_str = f'{endpoint.http_url} [{endpoint.http_status}] `{endpoint.content_length}B` `{endpoint.webserver}` `{line.get("time")}`'
		logger.warning(endpoint_str)
		if endpoint.is_alive and endpoint.http_status != 403:
			self.notify(
				fields={'Alive endpoint': f'• {endpoint_str}'},
				add_meta_info=False)

		# Add endpoint to results for UI tabs
		line['_cmd'] = cmd
		line['final_url'] = endpoint.http_url
		line['endpoint_id'] = endpoint.id
		line['endpoint_created'] = created
		line['is_redirect'] = endpoint.is_redirect
		line['status_code'] = endpoint.http_status
		line['title'] = endpoint.page_title
		line['content_length'] = endpoint.content_length
		line['webserver'] = endpoint.webserver
		line['content_type'] = endpoint.content_type
		line['response_time'] = endpoint.response_time
		
		results.append(line)

		techs = line.get('tech', [])
		subdomain = endpoint.subdomain

		# Add technology objects to DB
		for technology in techs:
			from django.core.exceptions import MultipleObjectsReturned
			try:
				tech, _ = Technology.objects.get_or_create(name=technology)
			except MultipleObjectsReturned:
				tech = Technology.objects.filter(name=technology).first()
			endpoint.techs.add(tech)
			if subdomain:
				subdomain.technologies.add(tech)
				subdomain.save()
			endpoint.save()
		techs_str = ', '.join([f'`{tech}`' for tech in techs])
		self.notify(
			fields={'Technologies': techs_str},
			add_meta_info=False)

		# Add IP objects for 'a' records to DB
		a_records = line.get('a', [])
		cdn = line.get('cdn', False)
		for ip_address in a_records:
			ip, _ = save_ip_address(
				ip_address,
				subdomain,
				subscan=self.subscan,
				scan_id=self.scan_id,
				activity_id=self.activity_id,
				cdn=cdn)
		
		if a_records:
			ips_str = '• ' + '\n• '.join([f'`{ip}`' for ip in a_records])
			self.notify(
				fields={'IPs': ips_str},
				add_meta_info=False)

		# Update subdomain status attributes if this is the default endpoint
		if endpoint.is_default and subdomain:
			subdomain.http_url = endpoint.http_url
			subdomain.http_status = endpoint.http_status
			subdomain.page_title = endpoint.page_title
			subdomain.content_length = endpoint.content_length
			subdomain.webserver = endpoint.webserver
			subdomain.response_time = endpoint.response_time
			subdomain.content_type = endpoint.content_type
			
			cnames = line.get('cnames', [])
			if cnames:
				subdomain.cname = ','.join(cnames)
			
			subdomain.is_cdn = cdn
			if cdn:
				subdomain.cdn_name = line.get('cdn_name')
			subdomain.save()
		endpoint.save()
		endpoint_ids.append(endpoint.id)

	if should_remove_duplicate_endpoints:
		# Remove 'fake' alive endpoints that are just redirects to the same page
		remove_duplicate_endpoints(
			self.scan_id,
			self.domain_id,
			self.subdomain_id,
			filter_ids=endpoint_ids
		)

	# Remove input file
	run_command(
		f'rm {input_path}',
		shell=True,
		history_file=self.history_file,
		scan_id=self.scan_id,
		activity_id=self.activity_id)

	return results


#---------------------#
# Notifications tasks #
#---------------------#

#-------------#
# Utils tasks #
#-------------#


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
