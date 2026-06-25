import logging
import os
import json
import yaml
import uuid
import asyncio
from datetime import datetime
from pathlib import Path

from reNgine.common_func import *
from reNgine.definitions import *
from reNgine.utils.graph import Neo4jManager
from reNgine.utils.task import save_endpoint, save_subdomain
from reNgine.tasks.notifications import send_scan_notif
from reNgine.tasks.persistence import create_scan_activity
from reNgine.tasks.subdomain import save_imported_subdomains
from startScan.models import *
from targetApp.models import Domain
from scanEngine.models import EngineType

logger = logging.getLogger(__name__)


def _make_json_safe(value):
    """Recursively ensure a value is JSON-serializable for Temporal workflow args.

    Converts Django model instances to their PKs, datetimes to ISO strings,
    and any other non-primitive to its string representation so Temporal's
    data converter never hits a TypeError.
    """
    from django.db.models import Model
    from datetime import datetime, date
    if value is None or isinstance(value, (bool, int, float, str)):
        return value
    if isinstance(value, Model):
        return value.pk
    if isinstance(value, (datetime, date)):
        return value.isoformat()
    if isinstance(value, dict):
        return {k: _make_json_safe(v) for k, v in value.items()}
    if isinstance(value, (list, tuple)):
        return [_make_json_safe(v) for v in value]
    try:
        json.dumps(value)
        return value
    except (TypeError, ValueError):
        return str(value)


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
						args=[_make_json_safe(temporal_ctx)],
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
						args=[_make_json_safe(temporal_ctx), pending_scan_types],
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
