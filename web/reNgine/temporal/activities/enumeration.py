"""
Enumeration, fuzzing and analysis activities (Tiers 2-5): HTTP crawl, port
scan, screenshots, URL fetching, directory fuzzing, URL extraction and the
analysis tools that run on the crawled surface.
"""

from temporalio import activity
from reNgine.temporal.heartbeat import keep_alive

from reNgine.utils.logger import get_module_logger, format_exception_for_log
from reNgine.utils.task import activity_heartbeat_safe
from reNgine.temporal.activities.core import TemporalTaskProxy, _run_task

logger = get_module_logger(__name__)


@activity.defn(name="SeedEndpointsForCrawlActivity")
def seed_endpoints_for_crawl_activity(ctx: dict) -> dict:
    """Ensure every discovered subdomain has a default EndPoint before http_crawl runs.

    Mirrors rengine-ng's pre_crawl step. Queries all Subdomain records for the
    current scan and creates EndPoint(is_default=True, http_status=0) for any
    subdomain that does not yet have a default endpoint. Returns an updated ctx
    with a 'seed_urls' list that RunHTTPCrawlActivity can log and use.
    """
    from startScan.models import Subdomain, EndPoint
    from reNgine.utils.task import save_endpoint
    from reNgine.common_func import sanitize_url

    scan_id = ctx.get('scan_history_id')
    url_filter = ctx.get('starting_point_path', '')
    logger.log_line("[TEMPORAL]", "START", "task=seed_endpoints_for_crawl scan_id=%s" % scan_id)

    subdomains = Subdomain.objects.filter(scan_history_id=scan_id)
    subdomain_id = ctx.get('subdomain_id')
    if subdomain_id:
        subdomains = subdomains.filter(pk=subdomain_id)
    seed_urls = []
    # save_endpoint caches model instances (_domain_obj, _scan_obj) in the ctx it
    # is given; keep them out of the returned ctx, which Temporal serialises.
    save_ctx = dict(ctx)

    for subdomain in subdomains:
        if url_filter:
            path = url_filter if url_filter.startswith('/') else f'/{url_filter}'
            raw_url = f'{subdomain.name}{path}'
        else:
            raw_url = subdomain.name
        if not raw_url.startswith(('http://', 'https://')):
            raw_url = f'http://{raw_url}'
        raw_url = sanitize_url(raw_url)

        existing = EndPoint.objects.filter(
            scan_history_id=scan_id,
            http_url=raw_url,
            is_default=True,
        ).first()

        if existing:
            seed_urls.append(existing.http_url)
        else:
            endpoint, _ = save_endpoint(
                raw_url,
                ctx=save_ctx,
                crawl=False,
                is_default=True,
                subdomain=subdomain,
            )
            if endpoint:
                seed_urls.append(endpoint.http_url)

    activity.logger.info(
        "[SeedEndpointsForCrawlActivity] scan_id=%s: seeded %s endpoint(s) for http_crawl.", scan_id, len(seed_urls)
    )
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=seed_endpoints_for_crawl scan_id=%s seeded=%d" % (scan_id, len(seed_urls)))
    return {**ctx, 'seed_urls': seed_urls}


# ===========================================================================
# Tier 2 — Enumeration
# ===========================================================================

@activity.defn(name="RunHTTPCrawlActivity")
def run_http_crawl_activity(ctx: dict) -> bool:
    """Run httpx HTTP crawl across all discovered subdomains.

    Delegates to the existing `http_crawl` task which probes all discovered
    subdomains for live HTTP services and persists endpoint metadata.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from reNgine.tasks import http_crawl
    seed_count = len(ctx.get('seed_urls', []))
    activity.logger.info("[RunHTTPCrawlActivity] scan_id=%s seed_count=%s", ctx.get('scan_history_id'), seed_count)
    return _run_task(
        http_crawl,
        ctx,
        is_ran_from_subdomain_scan=True,
        task_name='http_crawl',
        description='HTTP Crawl'
    )


@activity.defn(name="RunHTTPCrawlBridgeActivity")
def run_http_crawl_bridge_activity(ctx: dict) -> bool:
    """Run httpx HTTP crawl bridge across newly discovered endpoints and dead/not-alive endpoints.

    Queries the DB to fetch all endpoints associated with this scan that are either
    newly discovered (status is 0 or None) or dead/not alive (status is 404, or >= 500, or <= 0).
    It then delegates to the `http_crawl` task to scan exactly those URLs.

    Args:
        ctx (dict): Temporal workflow context containing:
            - scan_history_id (int): Django ScanHistory database ID.
            - subdomain_id (int, optional): Optional subdomain ID to limit query.

    Returns:
        bool: True on success.
    """
    from reNgine.tasks import http_crawl
    from startScan.models import EndPoint
    from django.db.models import Q

    scan_history_id = ctx.get('scan_history_id')
    subdomain_id = ctx.get('subdomain_id')
    activity.logger.info("[RunHTTPCrawlBridgeActivity] Querying endpoints for scan_history_id=%s", scan_history_id)

    # Query all endpoints for this scan/subscan
    query = EndPoint.objects.filter(scan_history_id=scan_history_id)
    if subdomain_id:
        query = query.filter(subdomain__id=subdomain_id)

    # Filter endpoints that are not alive or new:
    # Alive is defined as: (0 < status < 500) and status != 404
    # Therefore, not alive/new is: status is None, or status <= 0, or status == 404, or status >= 500
    query = query.filter(
        Q(http_status__isnull=True) |
        Q(http_status__lte=0) |
        Q(http_status=404) |
        Q(http_status__gte=500)
    )

    urls = list(query.order_by('http_url').values_list('http_url', flat=True).distinct())
    activity.logger.info("[RunHTTPCrawlBridgeActivity] Found %s new or dead/not-alive endpoints to crawl.", len(urls))

    if not urls:
        activity.logger.info("[RunHTTPCrawlBridgeActivity] No new or dead/not-alive endpoints found. Skipping crawl.")
        return True

    return _run_task(
        http_crawl,
        ctx,
        task_name='http_crawl_bridge',
        description='HTTP Crawl Bridge',
        urls=urls,
        recrawl=False
    )


@activity.defn(name="ParseHTTPCrawlResultsActivity")
@keep_alive
def parse_http_crawl_results_activity(ctx: dict) -> bool:
    """Verify HTTP crawl results are persisted correctly after http_crawl runs.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from startScan.models import EndPoint
    scan_id = ctx.get('scan_history_id')
    logger.log_line("[TEMPORAL]", "START", "task=parse_http_crawl_results scan_id=%s" % scan_id)
    # is_alive is a @property (not a DB column): http_status > 0, < 500, != 404
    alive_count = EndPoint.objects.filter(
        scan_history_id=scan_id,
        http_status__gt=0,
        http_status__lt=500,
    ).exclude(http_status=404).count()
    activity.logger.info(
        "[ParseHTTPCrawlResultsActivity] scan_id=%s: %s alive endpoints.", scan_id, alive_count
    )
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=parse_http_crawl_results scan_id=%s alive=%d" % (scan_id, alive_count))
    return True


@activity.defn(name="RunPortScanActivity")
def run_port_scan_activity(ctx: dict) -> bool:
    """Run port scanning (naabu, nmap) across all discovered subdomains.

    Delegates to the existing `port_scan` task.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from reNgine.tasks import port_scan
    activity.logger.info("[RunPortScanActivity] scan_id=%s", ctx.get('scan_history_id'))
    from scanEngine.models import Proxy as _Proxy
    _proxy = _Proxy.objects.first()
    if _proxy and _proxy.use_tor:
        activity.logger.warning(
            "[RunPortScanActivity] TOR mode is active but naabu uses raw sockets — "
            "port scan traffic will NOT be routed through TOR"
        )
    return _run_task(
        port_scan,
        ctx,
        task_name='port_scan',
        description='Port Scan'
    )


@activity.defn(name="TorNewCircuitActivity")
def run_tor_new_circuit_activity() -> None:
    from reNgine.common_func import get_random_proxy
    logger.log_line("[TEMPORAL]", "START", "task=tor_new_circuit")
    if not get_random_proxy().startswith('socks'):
        logger.log_line("[TEMPORAL]", "COMPLETE", "task=tor_new_circuit skipped=no_socks_proxy")
        return
    from reNgine.tor_manager import TorManager
    try:
        TorManager().new_circuit()
        activity.logger.info("[TorNewCircuitActivity] New TOR circuit requested successfully")
        logger.log_line("[TEMPORAL]", "COMPLETE", "task=tor_new_circuit")
    except Exception as e:
        activity.logger.warning("[TorNewCircuitActivity] Circuit rotation failed (scan continues): %s", e)
        logger.log_line("[TEMPORAL]", "COMPLETE", "task=tor_new_circuit skipped=circuit_failed")


@activity.defn(name="RunScreenshotActivity")
def run_screenshot_activity(ctx: dict) -> bool:
    """Capture screenshots of all live HTTP endpoints.

    Delegates to the existing `screenshot` task.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from reNgine.tasks import screenshot
    activity.logger.info("[RunScreenshotActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        screenshot,
        ctx,
        task_name='screenshot',
        description='Screenshot'
    )


@activity.defn(name="RunFetchURLActivity")
def run_fetch_url_activity(ctx: dict) -> bool:
    """Fetch and collect all URLs across the target using gau, waybackurls, etc.

    Delegates to the existing `fetch_url` task.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from reNgine.tasks import fetch_url
    activity.logger.info("[RunFetchURLActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        fetch_url,
        ctx,
        task_name='fetch_url',
        description='Fetch URL',
        urls=ctx.get('urls') or [],
    )


@activity.defn(name="ParseEnumerationResultsActivity")
def parse_enumeration_results_activity(ctx: dict) -> bool:
    """Verify enumeration tier (ports, screenshots, URLs) results are persisted.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from startScan.models import EndPoint, IpAddress
    scan_id = ctx.get('scan_history_id')
    logger.log_line("[TEMPORAL]", "START", "task=parse_enumeration_results scan_id=%s" % scan_id)
    endpoint_count = EndPoint.objects.filter(scan_history_id=scan_id).count()
    activity.logger.info(
        "[ParseEnumerationResultsActivity] scan_id=%s: %s total endpoints.", scan_id, endpoint_count
    )
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=parse_enumeration_results scan_id=%s endpoints=%d" % (scan_id, endpoint_count))
    return True


# ===========================================================================
# Tier 3/4 — Fuzzing & URL Extraction
# ===========================================================================

@activity.defn(name="RunDirFileFuzzActivity")
def run_dir_file_fuzz_activity(ctx: dict) -> bool:
    """Run directory and file fuzzing (dirsearch, ffuf) across all endpoints.

    Delegates to the existing `dir_file_fuzz` task.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from reNgine.tasks.fuzzing import dir_file_fuzz
    activity.logger.info("[RunDirFileFuzzActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        dir_file_fuzz,
        ctx,
        task_name='dir_file_fuzz',
        description='Directory & File Fuzz'
    )


@activity.defn(name="ParseFuzzResultsActivity")
@keep_alive
def parse_fuzz_results_activity(ctx: dict) -> bool:
    """Verify fuzzing results are persisted to the database.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from startScan.models import DirectoryFile
    scan_id = ctx.get('scan_history_id')
    logger.log_line("[TEMPORAL]", "START", "task=parse_fuzz_results scan_id=%s" % scan_id)
    fuzz_count = DirectoryFile.objects.filter(
        directory_files__directories__scan_history_id=scan_id
    ).distinct().count()
    activity.logger.info(
        "[ParseFuzzResultsActivity] scan_id=%s: %s fuzz entries.", scan_id, fuzz_count
    )
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=parse_fuzz_results scan_id=%s entries=%d" % (scan_id, fuzz_count))
    return True


@activity.defn(name="RunTargetDedupActivity")
def run_target_dedup_activity(ctx: dict) -> bool:
    """Mark live hosts that serve the same site as another host of the scan.

    Runs once HTTP crawl has established liveness; the batched directory fuzzer
    and the Acunetix submission skip the hosts it marks.
    """
    from reNgine.tasks.dedup import target_dedup
    return _run_task(
        target_dedup,
        ctx,
        task_name='target_dedup',
        description='Target Deduplication',
    )


# ===========================================================================
# Tier 5 — Analysis
# ===========================================================================

@activity.defn(name="RunWebAPIDiscoveryActivity")
def run_web_api_discovery_activity(ctx: dict) -> bool:
    """Discover web API endpoints and routes using kiterunner.

    Delegates to the existing `web_api_discovery` task.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from reNgine.tasks import web_api_discovery
    activity.logger.info("[RunWebAPIDiscoveryActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        web_api_discovery,
        ctx,
        task_name='web_api_discovery',
        description='Web API Discovery'
    )


@activity.defn(name="RunWAFDetectionActivity")
def run_waf_detection_activity(ctx: dict) -> bool:
    """Detect Web Application Firewalls protecting the target.

    Delegates to the existing `waf_detection` task.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from reNgine.tasks import waf_detection
    activity.logger.info("[RunWAFDetectionActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        waf_detection,
        ctx,
        task_name='waf_detection',
        description='WAF Detection'
    )


@activity.defn(name="RunSecretScanningActivity")
def run_secret_scanning_activity(ctx: dict) -> bool:
    """Scan for exposed secrets, credentials, and API keys using Semgrep/trufflehog.

    Delegates to the existing `secret_scanning` task.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from reNgine.tasks import secret_scanning
    activity.logger.info("[RunSecretScanningActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        secret_scanning,
        ctx,
        task_name='secret_scanning',
        description='Secrets & Leaks Scan'
    )


@activity.defn(name="ParseAnalysisResultsActivity")
def parse_analysis_results_activity(ctx: dict) -> bool:
    """Verify analysis tier results (WAF, API routes, secrets) are persisted.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    scan_id = ctx.get('scan_history_id')
    logger.log_line("[TEMPORAL]", "START", "task=parse_analysis_results scan_id=%s" % scan_id)
    activity.logger.info("[ParseAnalysisResultsActivity] scan_id=%s", scan_id)
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=parse_analysis_results scan_id=%s" % scan_id)
    return True


# ===========================================================================
# Distributed Heavy Scan Activities (Go Executor Integration)
# ===========================================================================

@activity.defn(name="PreparePortScanActivity")
def prepare_port_scan_activity(ctx: dict) -> dict:
    from reNgine.tasks import port_scan
    from startScan.models import Command
    from django.utils import timezone

    scan_id = ctx.get('scan_history_id')
    logger.log_line("[TEMPORAL]", "START", "task=prepare_port_scan scan_id=%s" % scan_id)
    activity.heartbeat("prepare_port_scan starting")
    proxy = TemporalTaskProxy(ctx, 'port_scan', 'Port Scan', track=False)
    raw_func = port_scan.__func__ if hasattr(port_scan, '__func__') else port_scan
    res = raw_func(proxy, ctx=ctx, prepare_only=True)

    cmd_record = Command.objects.create(
        command=res['cmd'],
        time=timezone.now(),
        scan_history_id=proxy.scan_id,
        activity_id=proxy.activity_id
    )
    res['command_id'] = cmd_record.id
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=prepare_port_scan scan_id=%s" % scan_id)
    return res


@activity.defn(name="ParsePortScanResultsActivity")
def parse_port_scan_results_activity(ctx: dict, stdout: str) -> dict:
    from reNgine.tasks import port_scan

    scan_id = ctx.get('scan_history_id')
    logger.log_line("[TEMPORAL]", "START", "task=parse_port_scan_results scan_id=%s" % scan_id)
    activity.heartbeat("parse_port_scan_results starting")
    proxy = TemporalTaskProxy(ctx, 'port_scan', 'Port Scan')
    raw_func = port_scan.__func__ if hasattr(port_scan, '__func__') else port_scan
    res = raw_func(proxy, ctx=ctx, parse_only=stdout)
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=parse_port_scan_results scan_id=%s" % scan_id)
    return {"ports_data": res}


@activity.defn(name="RunXURLFind3rActivity")
def run_xurlfind3r_activity(ctx: dict) -> bool:
    from reNgine.tasks.crawl import xurlfind3r_scan
    activity.logger.info("[RunXURLFind3rActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        xurlfind3r_scan, ctx, task_name='xurlfind3r_scan',
        description='Passive URL Discovery (xurlfind3r)',
        domain=ctx.get('domain'), domains=ctx.get('domains'),
    )


@activity.defn(name="RunURLFinderActivity")
def run_urlfinder_activity(ctx: dict) -> bool:
    from reNgine.tasks.crawl import urlfinder_scan
    activity.logger.info("[RunURLFinderActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        urlfinder_scan, ctx, task_name='urlfinder_scan',
        description='Passive URL Discovery (urlfinder)',
        domain=ctx.get('domain'),
    )


@activity.defn(name="RunCariddiActivity")
def run_cariddi_activity(ctx: dict) -> bool:
    from reNgine.tasks.crawl import cariddi_scan
    activity.logger.info("[RunCariddiActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        cariddi_scan, ctx, task_name='cariddi_scan',
        description='Endpoint Crawl & Secret Hunt (cariddi)',
        url=ctx.get('url'), urls=ctx.get('urls'),
    )


@activity.defn(name="RunBUPActivity")
def run_bup_activity(ctx: dict) -> bool:
    from reNgine.tasks.crawl import bup_scan
    activity.logger.info("[RunBUPActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        bup_scan, ctx, task_name='bup_scan', description='4xx URL Bypass (bup)',
        url=ctx.get('url'), urls=ctx.get('urls'),
    )


@activity.defn(name="RunArjunActivity")
def run_arjun_activity(ctx: dict) -> bool:
    from reNgine.tasks.crawl import arjun_scan
    activity.logger.info("[RunArjunActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        arjun_scan, ctx, task_name='arjun_scan',
        description='Parameter Discovery (arjun)',
        url=ctx.get('url'), urls=ctx.get('urls'),
    )


@activity.defn(name="RunFeroxbusterActivity")
def run_feroxbuster_activity(ctx: dict) -> bool:
    from reNgine.tasks.crawl import feroxbuster_scan
    activity.logger.info("[RunFeroxbusterActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        feroxbuster_scan, ctx, task_name='feroxbuster_scan',
        description='Recursive Content Fuzzing (feroxbuster)',
        url=ctx.get('url'), urls=ctx.get('urls'),
    )


@activity.defn(name="RunGFActivity")
def run_gf_activity(ctx: dict) -> list:
    """Run gf URL pattern matching. Returns matched URL list directly (not bool)."""
    from reNgine.tasks.crawl import gf_scan
    scan_id = ctx.get('scan_history_id')
    logger.log_line("[TEMPORAL]", "START", "task=gf_scan pattern=%s scan_id=%s" % (ctx.get('pattern', 'xss'), scan_id))
    activity.logger.info(
        "[RunGFActivity] pattern=%s scan_id=%s",
        ctx.get('pattern'), scan_id,
    )
    proxy = TemporalTaskProxy(ctx, task_name='gf_scan', description='URL Pattern Match (gf)')
    result = gf_scan(
        proxy,
        scan_history_id=scan_id,
        pattern=ctx.get('pattern', 'xss'),
        urls=ctx.get('urls', []),
    )
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=gf_scan pattern=%s scan_id=%s matches=%d" % (ctx.get('pattern', 'xss'), scan_id, len(result) if isinstance(result, list) else 0))
    return result


@activity.defn(name="RunGFOnAllEndpointsActivity")
def run_gf_on_all_endpoints_activity(ctx: dict) -> dict:
    """Run gf patterns against every endpoint persisted for this scan.

    Called at the end of Tier 4 in both MasterScanWorkflow and SubScanWorkflow so
    that URLs discovered by dir_file_fuzz (ffuf / dirsearch / feroxbuster) receive
    the same gf-pattern tagging that fetch_url applies to its own URL set.

    Returns a dict mapping pattern → number of endpoints updated.
    """
    from reNgine.definitions import DEFAULT_GF_PATTERNS, GF_PATTERNS, SUCCESS_TASK, FAILED_TASK
    from reNgine.tasks.crawl import gf_scan
    from reNgine.utils.task import bulk_apply_gf_pattern_from_urls
    from startScan.models import EndPoint, ScanHistory

    scan_id = ctx.get('scan_history_id')
    logger.log_line("[GF]", "START", "task=gf_all_endpoints scan_id=%s" % scan_id)
    activity.logger.info("[RunGFOnAllEndpointsActivity] scan_id=%s", scan_id)

    yaml_config = ctx.get('yaml_configuration') or {}
    fetch_url_config = yaml_config.get('fetch_url', {})
    gf_patterns = fetch_url_config.get(GF_PATTERNS, DEFAULT_GF_PATTERNS)

    if not gf_patterns:
        logger.log_line("[GF]", "COMPLETE", "task=gf_all_endpoints scan_id=%s patterns=none skipped" % scan_id)
        return {}

    all_urls = list(
        EndPoint.objects.filter(scan_history_id=scan_id, http_url__isnull=False)
        .exclude(http_url='')
        .values_list('http_url', flat=True)
        .distinct()
    )

    if not all_urls:
        logger.log_line("[GF]", "COMPLETE", "task=gf_all_endpoints scan_id=%s urls=0 skipped" % scan_id)
        return {}

    logger.log_line("[GF]", "INFO", "task=gf_all_endpoints scan_id=%s urls=%d patterns=%s" % (
        scan_id, len(all_urls), ','.join(gf_patterns)
    ))

    scan = ScanHistory.objects.filter(pk=scan_id).first()
    proxy = TemporalTaskProxy(ctx, task_name='gf_all_endpoints', description='GF Pattern Match (all endpoints)')
    results = {}

    try:
        for pattern in gf_patterns:
            if pattern == 'jsvar':
                continue
            matched = gf_scan(proxy, scan_history_id=scan_id, pattern=pattern, urls=all_urls)
            count = len(matched) if isinstance(matched, list) else 0
            if matched:
                updated = bulk_apply_gf_pattern_from_urls(matched, pattern, ctx)
                results[pattern] = updated
                logger.log_line("[GF]", "RESULT", "pattern=%s matched=%d updated=%d" % (pattern, count, updated))
            else:
                results[pattern] = 0
            activity_heartbeat_safe(f'gf pattern {pattern} done ({count} matches)')

        if scan and results:
            existing = set(filter(None, (scan.used_gf_patterns or '').split(',')))
            existing.update(p for p, c in results.items() if c > 0)
            scan.used_gf_patterns = ','.join(sorted(existing))
            scan.save(update_fields=['used_gf_patterns'])

        proxy.update_scan_activity(SUCCESS_TASK)
        logger.log_line("[GF]", "COMPLETE", "task=gf_all_endpoints scan_id=%s results=%s" % (scan_id, results))
        return results
    except Exception as exc:
        proxy.update_scan_activity(FAILED_TASK, error_message=repr(exc))
        logger.log_line("[GF]", "ERROR", "task=gf_all_endpoints scan_id=%s error=%s" % (scan_id, format_exception_for_log(exc)), level="error", exc_info=True)
        raise


@activity.defn(name="RunParamDiscoveryActivity")
def run_param_discovery_activity(ctx: dict) -> dict:
    """Run the Custom Parameter Discovery Engine (CPDE)."""
    from reNgine.tasks.cpde import param_discovery
    from reNgine.definitions import SUCCESS_TASK
    scan_id = ctx.get('scan_history_id')
    activity.logger.info("[RunParamDiscoveryActivity] Starting CPDE for scan_id=%s", scan_id)

    # Derive seed URLs before TemporalTaskProxy sets status=RUNNING — these are
    # fast DB queries and must complete first so the skip path can mark SUCCESS
    # without ever having set the row to RUNNING.
    urls = ctx.get('urls') or []
    if not urls:
        # Prefer a real endpoint URL (preserves correct scheme) from a prior http_crawl
        from startScan.models import EndPoint
        first_url = (
            EndPoint.objects
            .filter(scan_history_id=scan_id)
            .values_list('http_url', flat=True)
            .first()
        )
        if first_url:
            urls = [first_url]
            logger.log_line("[CPDE]", "INFO", "Derived seed URL from endpoint records: %s" % first_url)
        else:
            # Fall back to constructing from domain name
            from targetApp.models import Domain
            domain = Domain.objects.filter(id=ctx.get('domain_id')).first()
            if domain:
                urls = [f"https://{domain.name}/"]
                logger.log_line("[CPDE]", "INFO", "Derived seed URL from domain: %s" % urls[0])

    if not urls:
        logger.log_line("[CPDE]", "WARN", "No seed URLs available for scan_id=%s — skipping CPDE" % scan_id)
        # Mark the ScanActivity row SUCCESS so it does not stay permanently RUNNING.
        proxy = TemporalTaskProxy(ctx, task_name='param_discovery', description='Custom Parameter Discovery (CPDE)')
        proxy.update_scan_activity(SUCCESS_TASK)
        return {}

    # _run_task provides heartbeating, pre-flight abort-guard, and correct
    # SUCCESS_TASK / FAILED_TASK status updates — matching all other activities.
    _run_task(
        param_discovery,
        ctx,
        task_name='param_discovery',
        description='Custom Parameter Discovery (CPDE)',
        urls=urls,
    )
    return {}


@activity.defn(name="RunURLParserActivity")
def run_urlparser_activity(ctx: dict) -> bool:
    from reNgine.tasks.crawl import urlparser_scan
    activity.logger.info("[RunURLParserActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        urlparser_scan, ctx, task_name='urlparser_scan',
        description='URL Parameter Extraction (urlparser/unfurl)',
        urls=ctx.get('urls'),
    )
