"""
Background maintenance activities: startup sync, domain monitoring, scheduled
scan setup and HackerOne program synchronisation.
"""

from temporalio import activity
from reNgine.temporal.heartbeat import keep_alive

from reNgine.utils.logger import get_module_logger, format_exception_for_log
from reNgine.common_func import merge_imported_subdomains, resolve_api_discovery_tools

logger = get_module_logger(__name__)


@activity.defn(name="RunStartupSyncActivity")
def run_startup_sync_activity(task_name: str) -> None:
    """Execute a named startup sync task. Called once per orchestrator start via StartupSyncWorkflow.

    Supported task_name values:
      'sync_all_scans_to_graph' — syncs all scan results to Neo4j
      'sync_cisa_kev_catalog'   — downloads CISA KEV catalog and marks CVEs
      'sync_semgrep_rules'      — syncs Semgrep rule sets to local filesystem
      'sync_cve_data'           — full CVE enrichment (KEV catalog + unenriched CVEs)
    """
    logger.log_line("[TEMPORAL]", "START", "task=run_startup_sync task_name=%s" % task_name)
    activity.logger.info("[RunStartupSyncActivity] Starting: %s", task_name)
    if task_name == 'sync_all_scans_to_graph':
        from reNgine.tasks import sync_all_scans_to_graph
        from reNgine.utils.graph import _graph_heartbeat
        activity.heartbeat("startup graph sync starting")
        sync_all_scans_to_graph(None, heartbeat_callback=_graph_heartbeat)
    elif task_name == 'sync_cisa_kev_catalog':
        from reNgine.tasks import sync_cisa_kev_catalog
        sync_cisa_kev_catalog()
    elif task_name == 'sync_semgrep_rules':
        from reNgine.tasks import sync_semgrep_rules
        sync_semgrep_rules()
    elif task_name == 'recover_stuck_scans':
        from reNgine.tasks import recover_stuck_scans
        recover_stuck_scans()
    elif task_name == 'sync_cve_data':
        from reNgine.cve_enrichment import CVEEnrichmentService, CVEBatchEnricher
        service = CVEEnrichmentService()
        enricher = CVEBatchEnricher()
        service.sync_cisa_kev_catalog()
        enricher.enrich_unenriched_cves()
    elif task_name == 'sync_epss_data':
        from reNgine.cve_enrichment import CVEEnrichmentService
        service = CVEEnrichmentService()
        service.sync_epss_catalog()
    else:
        raise ValueError(f"[RunStartupSyncActivity] Unknown task: {task_name}")
    activity.logger.info("[RunStartupSyncActivity] Completed: %s", task_name)
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=run_startup_sync task_name=%s" % task_name)


@activity.defn(name="ToolProbeActivity")
@keep_alive
def tool_probe_activity(op: str, payload: dict) -> dict:
    """Run a tool inventory probe on this worker (see ``reNgine.tool_workers``).

    The web container has no Docker socket and cannot exec into this
    container, so it asks through ToolProbeWorkflow instead. ``op`` selects
    resolve / version / help / summary / sync; ``payload`` carries the op's
    arguments and the result is the op's JSON-serialisable answer.
    """
    from reNgine.tool_workers import run_probe_op

    logger.log_line("[TEMPORAL]", "START", "task=tool_probe op=%s" % op)
    try:
        result = run_probe_op(op, payload)
    except Exception as exc:
        logger.log_line("[TEMPORAL]", "ERROR", "task=tool_probe op=%s %s" % (op, format_exception_for_log(exc)),
                        level="error", exc_info=True)
        raise
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=tool_probe op=%s" % op)
    return result


@activity.defn(name="RunMonitoringCheckActivity")
@keep_alive
def run_monitoring_check_activity(domain_id: int) -> None:
    """Execute a monitoring check for a domain. Called by MonitoringWorkflow on schedule.

    Delegates to monitor_target_task which handles subdomain discovery, change
    detection, notifications, and conditional scan initiation.
    """
    logger.log_line("[TEMPORAL]", "START", "task=run_monitoring_check domain_id=%s" % domain_id)
    activity.logger.info("[RunMonitoringCheckActivity] Checking domain_id=%s", domain_id)
    from reNgine.tasks.monitor import monitor_target_task
    monitor_target_task(domain_id)
    activity.logger.info("[RunMonitoringCheckActivity] Completed domain_id=%s", domain_id)
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=run_monitoring_check domain_id=%s" % domain_id)


@activity.defn(name="SetupScheduledScanActivity")
@keep_alive
def setup_scheduled_scan_activity(params: dict) -> dict:
    """Create a ScanHistory record and build a full workflow ctx for a scheduled scan.

    Mirrors the setup portion of initiate_scan_temporal (DB record creation,
    directory setup, initial subdomain/endpoint) without starting any workflow.
    The returned ctx is passed directly to MasterScanWorkflow as a child workflow.

    Args:
        params: Dict with keys: domain_id, engine_id, scan_type, initiated_by_id,
                imported_subdomains, out_of_scope_subdomains, starting_point_path,
                excluded_paths, enable_spiderfoot_scan.

    Returns:
        dict: Complete Temporal workflow ctx ready for MasterScanWorkflow.
    """
    import os
    import yaml
    from django.utils import timezone
    from reNgine.common_func import (
        create_scan_object, save_imported_subdomains, save_subdomain, save_endpoint
    )
    from reNgine.definitions import (
        RUNNING_TASK, SCHEDULED_SCAN,
        ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL,
        GF_PATTERNS, WEB_API_DISCOVERY, USES_TOOLS, KITERUNNER_WORDLIST,
    )
    from reNgine.settings import RENGINE_RESULTS
    from scanEngine.models import EngineType
    from startScan.models import ScanHistory
    from targetApp.models import Domain

    domain_id = params['domain_id']
    engine_id = params['engine_id']
    initiated_by_id = params.get('initiated_by_id')
    logger.log_line("[TEMPORAL]", "START", "task=setup_scheduled_scan domain_id=%s engine_id=%s" % (domain_id, engine_id))
    imported_subdomains = params.get('imported_subdomains') or []
    out_of_scope_subdomains = params.get('out_of_scope_subdomains') or []
    starting_point_path = (params.get('starting_point_path') or '').rstrip('/')
    excluded_paths = params.get('excluded_paths') or []
    enable_spiderfoot_scan = params.get('enable_spiderfoot_scan', False)

    engine = EngineType.objects.get(pk=engine_id)
    domain = Domain.objects.get(pk=domain_id)
    imported_subdomains = merge_imported_subdomains(domain, imported_subdomains)
    config = yaml.safe_load(engine.yaml_configuration) or {}

    scan_history_id = create_scan_object(
        host_id=domain_id,
        engine_id=engine_id,
        initiated_by_id=initiated_by_id,
    )
    scan = ScanHistory.objects.get(pk=scan_history_id)

    tasks = list(engine.tasks)
    if 'waf_bypass' in tasks and 'waf_detection' not in tasks:
        tasks.insert(tasks.index('waf_bypass'), 'waf_detection')
    if enable_spiderfoot_scan and 'spiderfoot_scan' not in tasks:
        tasks.append('spiderfoot_scan')

    scan.scan_status = RUNNING_TASK
    scan.scan_type = engine
    scan.domain = domain
    scan.start_scan_date = timezone.now()
    scan.tasks = tasks
    scan.results_dir = f'{RENGINE_RESULTS}/{domain.name}_{scan.id}'
    scan.cfg_starting_point_path = starting_point_path
    scan.cfg_excluded_paths = excluded_paths
    scan.cfg_out_of_scope_subdomains = out_of_scope_subdomains
    scan.cfg_imported_subdomains = imported_subdomains
    scan.save()

    os.makedirs(scan.results_dir, exist_ok=True)

    ctx_bootstrap = {
        'scan_history_id': scan.id,
        'engine_id': engine_id,
        'domain_id': domain.id,
        'results_dir': scan.results_dir,
        'starting_point_path': starting_point_path,
        'out_of_scope_subdomains': out_of_scope_subdomains,
    }
    save_imported_subdomains(imported_subdomains, ctx=ctx_bootstrap)

    enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
    subdomain, _ = save_subdomain(domain.name, ctx=ctx_bootstrap)
    _root = f'{domain.name}{starting_point_path}' if starting_point_path else domain.name
    if not _root.startswith(('http://', 'https://')):
        _root = f'http://{_root}'
    endpoint, _ = save_endpoint(
        _root,
        ctx=ctx_bootstrap,
        crawl=enable_http_crawl,
        is_default=True,
        subdomain=subdomain,
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

    gf_patterns = config.get(GF_PATTERNS, [])
    api_discovery_config = config.get(WEB_API_DISCOVERY, {})
    api_discovery_tools = resolve_api_discovery_tools(api_discovery_config)
    kr_wordlist = api_discovery_config.get(KITERUNNER_WORDLIST, 'routes-small.kite')

    if gf_patterns and 'fetch_url' in tasks:
        scan.used_gf_patterns = ','.join(gf_patterns)
        scan.save(update_fields=['used_gf_patterns'])

    activity.logger.info(
        "[SetupScheduledScanActivity] Created scan_id=%s for domain=%s", scan.id, domain.name
    )
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=setup_scheduled_scan scan_id=%s domain_id=%s" % (scan.id, domain_id))
    return {
        'scan_history_id': scan.id,
        'engine_id': engine_id,
        'domain_id': domain.id,
        'results_dir': scan.results_dir,
        'starting_point_path': starting_point_path,
        'excluded_paths': excluded_paths,
        'yaml_configuration': config,
        'out_of_scope_subdomains': out_of_scope_subdomains,
        'api_discovery_tools': api_discovery_tools,
        'kr_wordlist': kr_wordlist,
        'tasks': tasks,
    }


@activity.defn(name="ImportHackerOneProgramsActivity")
@keep_alive
def import_hackerone_programs_activity(handles: list, project_slug: str, is_sync: bool = False) -> None:
    from api.shared_api_tasks import import_hackerone_programs_task
    logger.log_line("[TEMPORAL]", "START", "task=import_hackerone_programs project=%s count=%d" % (project_slug, len(handles)))
    activity.logger.info("[ImportHackerOneProgramsActivity] project=%s handles_count=%s", project_slug, len(handles))
    import_hackerone_programs_task(handles, project_slug, is_sync=is_sync)
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=import_hackerone_programs project=%s" % project_slug)


@activity.defn(name="SyncBookmarkedProgramsActivity")
@keep_alive
def sync_bookmarked_programs_activity(project_slug: str) -> None:
    from api.shared_api_tasks import sync_bookmarked_programs_task
    logger.log_line("[TEMPORAL]", "START", "task=sync_bookmarked_programs project=%s" % project_slug)
    activity.logger.info("[SyncBookmarkedProgramsActivity] project=%s", project_slug)
    sync_bookmarked_programs_task(project_slug)
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=sync_bookmarked_programs project=%s" % project_slug)
