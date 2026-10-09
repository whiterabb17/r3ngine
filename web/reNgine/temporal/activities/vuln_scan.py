"""
Vulnerability scanning activities (Tier 6 assessment): nuclei, DAST, the
per-tool scanners (dalfox, crlfuzz, acunetix, wpscan, semgrep, vigolium, ...)
and the bookkeeping that closes the vulnerability phase.
"""

import os

from temporalio import activity

from reNgine.utils.logger import get_module_logger
from reNgine.temporal.activities.core import _run_task, resolve_target_host
from startScan.models import Subdomain

logger = get_module_logger(__name__)


@activity.defn(name="GatherNucleiTagsActivity")
def gather_nuclei_tags_activity(ctx: dict) -> dict:
    """Pre-compute Nuclei tags and build template-count-aware batches.

    Counts templates per detected tag via ``nuclei -tl`` so the workflow can
    dispatch bounded nuclei invocations without violating Temporal determinism.

    Returns:
        dict with keys:
          - ``tags``: sorted deduplicated list of all detected tag strings
          - ``batches``: list of tag-lists, each batch's total template count
                         <= max_templates_per_batch; empty list when no tags
                         detected (caller falls back to unfiltered scan).
    """
    from reNgine.tech_mapping import get_nuclei_tags_from_techs
    from reNgine.nuclei_batch_utils import count_templates_for_tag, build_tag_batches, get_template_counts_for_tags
    from reNgine.definitions import (
        NUCLEI_MAX_TEMPLATES_PER_BATCH, NUCLEI_DEFAULT_TEMPLATES_PATH,
        NUCLEI_TEMPLATE, NUCLEI_CUSTOM_TEMPLATE, ALL
    )

    scan_id = ctx.get('scan_history_id')
    subdomain_id = ctx.get('subdomain_id')

    logger.log_line("[TEMPORAL]", "START", "task=gather_nuclei_tags scan_id=%s subdomain_id=%s" % (scan_id, subdomain_id))

    yaml_config = ctx.get('yaml_configuration', {})
    nuclei_cfg = yaml_config.get('vulnerability_scan', {}).get('nuclei', {})
    user_tags = nuclei_cfg.get('tags', [])
    if isinstance(user_tags, str):
        user_tags = [t.strip() for t in user_tags.split(',') if t.strip()]

    max_per_batch = int(nuclei_cfg.get(NUCLEI_MAX_TEMPLATES_PER_BATCH) or 100)

    qs = Subdomain.objects.filter(scan_history_id=scan_id)
    if subdomain_id:
        qs = qs.filter(pk=subdomain_id)

    all_techs: set = set()
    for sub in qs:
        all_techs.update(sub.technologies.values_list('name', flat=True))

    tech_tags = get_nuclei_tags_from_techs(list(all_techs)) if all_techs else []
    merged_set = set(user_tags) | set(tech_tags)

    # Intelligence: Append specific Nuclei tags if previously discovered vulnerabilities warrant it.
    from startScan.models import Vulnerability, ScanHistory
    scan = ScanHistory.objects.filter(pk=scan_id).first()
    if scan and scan.domain:
        vulns_qs = Vulnerability.objects.filter(target_domain=scan.domain)
        if subdomain_id:
            vulns_qs = vulns_qs.filter(subdomain_id=subdomain_id)
        
        # We only need to check names and whether it has CVE relations
        # Fetching names instead of iterating objects avoids memory overhead
        vuln_names = ' '.join(vulns_qs.values_list('name', flat=True)).lower()
        has_cve = vulns_qs.filter(cve_ids__isnull=False).exists() or 'cve-' in vuln_names
        
        if 'xss' in vuln_names or 'cross site' in vuln_names:
            merged_set.add('xss')
        if 'lfi' in vuln_names or 'local file inclusion' in vuln_names:
            merged_set.add('lfi')
        if 'idor' in vuln_names:
            merged_set.add('idor')
        if has_cve:
            merged_set.add('cve')
            
    # Tag splitter disabled — wp_* / cve_* slice expansion temporarily turned off.
    # import json
    # import os
    # import subprocess
    # import sys
    # if nuclei_cfg.get('auto_update_templates', True):
    #     try:
    #         subprocess.run(
    #             ['nuclei', '-update-templates'],
    #             timeout=120,
    #             capture_output=True,
    #         )
    #         logger.log_line("[TEMPORAL]", "INFO", "task=gather_nuclei_tags nuclei templates updated")
    #     except Exception as _upd_exc:
    #         logger.log_line("[TEMPORAL]", "WARN", "task=gather_nuclei_tags template update failed: %s" % _upd_exc)
    #     splitter_script = '/usr/src/scripts/nuclei_tag_splitter.py'
    #     if os.path.exists(splitter_script):
    #         try:
    #             subprocess.run(
    #                 [sys.executable, splitter_script],
    #                 timeout=300,
    #                 capture_output=True,
    #             )
    #             logger.log_line("[TEMPORAL]", "INFO", "task=gather_nuclei_tags tag splitter complete")
    #         except Exception as _spl_exc:
    #             logger.log_line("[TEMPORAL]", "WARN", "task=gather_nuclei_tags tag splitter failed: %s" % _spl_exc)
    # manifest_path = os.getenv("NUCLEI_SPLIT_TAGS_MANIFEST", "/root/nuclei-templates/split_tags.json")
    # if os.path.exists(manifest_path):
    #     try:
    #         with open(manifest_path, 'r', encoding='utf-8') as f:
    #             manifest = json.load(f)
    #         expanded_set = set()
    #         for tag in merged_set:
    #             if tag in manifest and manifest[tag]:
    #                 for split_tag in manifest[tag]:
    #                     expanded_set.add(split_tag)
    #             else:
    #                 expanded_set.add(tag)
    #         merged_set = expanded_set
    #     except Exception as e:
    #         logger.log_line("[TEMPORAL]", "ERROR", f"Failed to load tag split manifest: {e}")

    merged = sorted(merged_set)

    # Build the full list of template directories to scan for tag counts
    template_dirs = []
    nuclei_templates = nuclei_cfg.get(NUCLEI_TEMPLATE)
    custom_nuclei_templates = nuclei_cfg.get(NUCLEI_CUSTOM_TEMPLATE)

    if not (nuclei_templates or custom_nuclei_templates):
        template_dirs.append(NUCLEI_DEFAULT_TEMPLATES_PATH)

    if nuclei_templates:
        if ALL in nuclei_templates:
            template_dirs.append(NUCLEI_DEFAULT_TEMPLATES_PATH)
        else:
            template_dirs.extend(nuclei_templates)

    if custom_nuclei_templates:
        for elem in custom_nuclei_templates:
            if str(elem).endswith(('.yaml', '.yml')) or str(elem).endswith('/'):
                template_dirs.append(str(elem))
            else:
                template_dirs.append(f'{str(elem)}.yaml')

    # Count templates per tag so batches are bounded by template count not tag count.
    tag_counts = get_template_counts_for_tags(merged, template_dirs)
    for tag in merged:
        logger.log_line(
            "[TEMPORAL]", "INFO",
            "task=gather_nuclei_tags scan_id=%s tag=%s templates=%d" % (scan_id, tag, tag_counts.get(tag, 0))
        )

    # max_tags is the fallback guard for when template counts are unavailable and
    # every tag looks free. get_template_counts_for_tags() reads the counts
    # directly from the template files, so max_per_batch is the real bound here
    # and a ceiling of 3 only inflated the batch count — on a host with a rich
    # technology fingerprint that meant dozens of nuclei runs where a handful
    # would do.
    max_tags = int(os.environ.get('NUCLEI_MAX_TAGS_PER_BATCH', 10))
    batches = build_tag_batches(
        merged, tag_counts, max_per_batch=max_per_batch, max_tags=max_tags
    )

    activity.logger.info(
        "[GatherNucleiTagsActivity] scan_id=%s tags=%s batches=%d max_per_batch=%d",
        scan_id, merged, len(batches), max_per_batch,
    )
    logger.log_line(
        "[TEMPORAL]", "COMPLETE",
        "task=gather_nuclei_tags scan_id=%s tags=%d batches=%d" % (scan_id, len(merged), len(batches))
    )
    return {'tags': merged, 'batches': batches}


@activity.defn(name="RunNucleiActivity")
def run_nuclei_activity(ctx: dict, severity: str = None, tag_batch: list = None) -> bool:
    """Run Nuclei vulnerability scan against all live endpoints discovered for this scan.

    Performs a pre-flight check against the EndPoint table before invoking nuclei_scan.
    If no endpoints have been crawled yet (e.g. http_crawl was not in the task list or
    found no alive hosts), falls back to the root domain URL so Nuclei has at least one
    target rather than silently writing an empty input file and producing zero results.

    Args:
        ctx (dict): Temporal workflow context containing scan_history_id and engine config.
        severity (str, optional): The target severity level to filter the scan.
        tag_batch (list, optional): Pre-computed tag batch from GatherNucleiTagsActivity.
            None or empty list means no -tags flag is passed to Nuclei.

    Returns:
        bool: True on success (including graceful skip when no domain is found).
    """
    from reNgine.tasks import nuclei_scan
    from startScan.models import EndPoint, ScanHistory

    scan_id = ctx.get('scan_history_id')
    severity = severity or ctx.get('nuclei_severity_filter')
    proxies_file_path = ctx.get('nuclei_proxies_path')
    activity.logger.info(
        "[RunNucleiActivity] scan_id=%s severity=%s tags=%s proxies_file=%s",
        scan_id, severity, tag_batch, proxies_file_path
    )

    # Pre-flight: count endpoints in DB for this scan
    endpoint_qs = EndPoint.objects.filter(scan_history_id=scan_id)
    subdomain_id = ctx.get('subdomain_id')
    if subdomain_id:
        endpoint_qs = endpoint_qs.filter(subdomain_id=subdomain_id)
    endpoint_count = endpoint_qs.count()

    # Singular runs: prefer explicit urls only when not subdomain-scoped.
    # A subdomain singular run always seeds ctx['urls'] with the root http_url;
    # scanning only that would skip crawled endpoints for the same host.
    singular_urls = list(ctx.get('urls') or []) if ctx.get('singular_tool_run') else []

    if subdomain_id and endpoint_count > 0:
        # Let nuclei_scan collect via get_http_urls / collect_all_scan_urls (ctx-scoped).
        urls = []
        activity.logger.info(
            "[RunNucleiActivity] subdomain-scoped scan_id=%s subdomain_id=%s endpoints=%d",
            scan_id, subdomain_id, endpoint_count,
        )
    elif singular_urls:
        urls = singular_urls
    elif endpoint_count == 0:
        # No endpoints from http_crawl — prefer scoped host, then singular urls, then apex.
        scan = ScanHistory.objects.filter(pk=scan_id).first()
        scoped = (
            (ctx.get('subdomain_http_url') or '').strip()
            or (singular_urls[0] if singular_urls else '')
            or (
                f"https://{ctx.get('subdomain_name')}"
                if ctx.get('subdomain_name') else ''
            )
        )
        if scoped:
            urls = [scoped]
            activity.logger.warning(
                "[RunNucleiActivity] No endpoints for scan_id=%s subdomain_id=%s. "
                "Falling back to scoped URL: %s",
                scan_id, subdomain_id, scoped,
            )
        elif scan and scan.domain and not subdomain_id:
            root_url = f"https://{scan.domain.name}"
            activity.logger.warning(
                "[RunNucleiActivity] No endpoints found in DB for scan_id=%s. "
                "Falling back to root URL: %s",
                scan_id, root_url,
            )
            urls = [root_url]
        else:
            activity.logger.error(
                "[RunNucleiActivity] No endpoints and no scoped target for scan_id=%s. "
                "Skipping Nuclei scan.",
                scan_id,
            )
            return True
    else:
        activity.logger.info(
            "[RunNucleiActivity] %d endpoints in DB for scan_id=%s. "
            "Nuclei will query get_http_urls() from DB.",
            endpoint_count, scan_id,
        )
        # Let nuclei_scan call get_http_urls() to filter alive endpoints from DB
        urls = []

    tag_label = ','.join(tag_batch) if tag_batch else ''
    task_desc = f'Nuclei Scan ({severity}{" [" + tag_label + "]" if tag_label else ""})' if severity else 'Nuclei Scan'

    return _run_task(
        nuclei_scan, ctx,
        task_name='nuclei_scan',
        description=task_desc,
        urls=urls,
        severity=severity,
        tags_override=tag_batch if tag_batch else None,
        proxies_file_path=proxies_file_path,
    )


@activity.defn(name="RunSmugglexActivity")
def run_smugglex_activity(ctx: dict) -> bool:
    from reNgine.tasks import smugglex_scan
    return _run_task(smugglex_scan, ctx, task_name='smugglex_scan', description='Smugglex Scan', urls=ctx.get('urls', []))


@activity.defn(name="RunSecondOrderActivity")
def run_second_order_activity(ctx: dict) -> bool:
    from reNgine.tasks import second_order_scan
    return _run_task(second_order_scan, ctx, task_name='second_order_scan', description='Second Order Scan', urls=ctx.get('urls', []))


@activity.defn(name="RunNucleiDASTActivity")
def run_nuclei_dast_activity(ctx: dict) -> bool:
    from reNgine.tasks import nuclei_dast_scan
    return _run_task(nuclei_dast_scan, ctx, task_name='nuclei_dast_scan', description='Nuclei DAST Scan', urls=ctx.get('urls', []))


@activity.defn(name="RunCRLFuzzActivity")
def run_crlfuzz_activity(ctx: dict) -> bool:
    from reNgine.tasks import crlfuzz_scan
    activity.logger.info("[RunCRLFuzzActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(crlfuzz_scan, ctx, task_name='crlfuzz_scan', description='CRLFuzz Scan', urls=ctx.get('urls', []))


@activity.defn(name="RunDalfoxActivity")
def run_dalfox_activity(ctx: dict) -> bool:
    from reNgine.tasks import dalfox_xss_scan
    activity.logger.info("[RunDalfoxActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(dalfox_xss_scan, ctx, task_name='dalfox_xss_scan', description='Dalfox XSS Scan', urls=ctx.get('urls', []))


@activity.defn(name="RunS3ScannerActivity")
def run_s3scanner_activity(ctx: dict) -> bool:
    from reNgine.tasks import s3scanner
    activity.logger.info("[RunS3ScannerActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(s3scanner, ctx, task_name='s3scanner', description='S3 Bucket Scanner')


@activity.defn(name="RunAcunetixActivity")
def run_acunetix_activity(ctx: dict) -> bool:
    from reNgine.tasks import acunetix_scan
    activity.logger.info("[RunAcunetixActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        acunetix_scan,
        ctx,
        task_name='acunetix_scan',
        description='Acunetix Scan',
        domain_id=ctx.get('domain_id'),
        scan_history_id=ctx.get('scan_history_id'),
        subdomain_id=ctx.get('subdomain_id'),
        subdomain_name=ctx.get('subdomain_name'),
        subdomain_http_url=ctx.get('subdomain_http_url'),
    )


@activity.defn(name="SubmitLiveSubdomainsToAcunetixActivity")
def submit_live_subdomains_to_acunetix_activity(ctx: dict) -> bool:
    """Register every live, externally reachable subdomain as an Acunetix target.

    Runs right after the HTTP crawl, which is the first point where liveness is
    known. Hosts sent within the configured window are skipped, and every
    decision is recorded as a Command row on this activity's timeline entry.
    """
    from reNgine.tasks import acunetix_submit_live_subdomains
    activity.logger.info(
        "[SubmitLiveSubdomainsToAcunetixActivity] scan_id=%s", ctx.get('scan_history_id')
    )
    return _run_task(
        acunetix_submit_live_subdomains,
        ctx,
        task_name='acunetix_submit',
        description='Acunetix Target Submission',
        scan_history_id=ctx.get('scan_history_id'),
    )


@activity.defn(name="RunCpanelScanActivity")
def run_cpanel_scan_activity(ctx: dict) -> bool:
    from reNgine.tasks.vulnerability import cpanel_scan
    activity.logger.info("[RunCpanelScanActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(cpanel_scan, ctx, task_name='cpanel_scan', description='cPanel Vulnerability Scan')


@activity.defn(name="RunWpscanActivity")
def run_wpscan_activity(ctx: dict) -> bool:
    from reNgine.tasks.wpscan import wpscan_scan
    activity.logger.info("[RunWpscanActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(wpscan_scan, ctx, task_name='wpscan_scan', description='WPScan', urls=ctx.get('urls', []))


@activity.defn(name="RunWPTaintScanActivity")
def run_wptaint_scan_activity(ctx: dict) -> bool:
    from reNgine.tasks.wptaint import wptaint_scan
    activity.logger.info("[RunWPTaintScanActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(wptaint_scan, ctx, task_name='wptaint_scan', description='WP Taint Scan', urls=ctx.get('urls', []))


@activity.defn(name="RunReact2ShellActivity")
def run_react2shell_activity(ctx: dict) -> bool:
    from reNgine.tasks.vulnerability import react2shell_scan
    activity.logger.info("[RunReact2ShellActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(react2shell_scan, ctx, task_name='react2shell_scan', description='React Vulnerability Scan')


@activity.defn(name="RunSemgrepActivity")
def run_semgrep_activity(ctx: dict) -> bool:
    from reNgine.tasks import semgrep_scan
    activity.logger.info("[RunSemgrepActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(semgrep_scan, ctx, task_name='semgrep_scan', description='Semgrep Vulnerability Scan', mode='vulnerability')


@activity.defn(name="RunVigoliumScanActivity")
def run_vigolium_scan_activity(ctx: dict) -> bool:
    """Run Vigolium known-issue + dynamic-assessment scan against live endpoints.

    Runs inside NucleiPlannerWorkflow at Tier 6 alongside Nuclei. Default-enabled
    via vulnerability_scan.run_vigolium: true in the engine YAML config.
    """
    from reNgine.tasks.vigolium import vigolium_scan
    activity.logger.info("[RunVigoliumScanActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(vigolium_scan, ctx, task_name='vigolium_scan', description='Vigolium Vulnerability Scan')


@activity.defn(name="RunVigoliumHarvestActivity")
def run_vigolium_harvest_activity(ctx: dict) -> bool:
    """Run Vigolium passive ingestion harvest at Tier 1.

    Collects passively harvested endpoints (wayback, CT logs, passive DNS) before
    active crawling begins. Works with just the root domain — falls back gracefully
    when no subdomains have been enumerated yet.
    Controlled by vigolium_harvest.run_vigolium_harvest in engine YAML.
    """
    from reNgine.tasks.vigolium import vigolium_harvest
    activity.logger.info("[RunVigoliumHarvestActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(vigolium_harvest, ctx, task_name='vigolium_harvest', description='Vigolium Passive Harvest')


@activity.defn(name="RunVigoliumDiscoveryActivity")
def run_vigolium_discovery_activity(ctx: dict) -> bool:
    """Run Vigolium active discovery phase at Tier 1.

    Runs in parallel with subdomain enumeration. Populates EndPoint records
    via vigolium's active discovery phase; falls back to the root domain when
    no subdomains are in the DB yet.
    Controlled by vigolium_discovery.run_vigolium_discovery in engine YAML.
    """
    from reNgine.tasks.vigolium import vigolium_discovery
    activity.logger.info("[RunVigoliumDiscoveryActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(vigolium_discovery, ctx, task_name='vigolium_discovery', description='Vigolium Endpoint Discovery')


@activity.defn(name="RunVigoliumAnalysisActivity")
def run_vigolium_analysis_activity(ctx: dict) -> bool:
    """Run Vigolium dynamic-assessment phase at Tier 5.

    Runs in parallel with web_api_discovery. Executes vigolium's 251-module
    passive + active scanning suite and saves findings as Vulnerability records.
    Controlled by vigolium_analysis.run_vigolium_analysis in engine YAML.
    """
    from reNgine.tasks.vigolium import vigolium_analysis
    activity.logger.info("[RunVigoliumAnalysisActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(vigolium_analysis, ctx, task_name='vigolium_analysis', description='Vigolium Dynamic Analysis')


@activity.defn(name="PostScanProcessingActivity")
def post_scan_processing_activity(ctx: dict) -> bool:
    """Run post-scan processing after all Tier 6 tools complete.

    Performs endpoint deduplication, OpenAPI spec extraction from
    Vigolium/Nuclei-discovered swagger endpoints (including Swagger UI HTML
    page scraping to resolve embedded spec URLs), and GraphQL tool dispatch
    for any GraphQL endpoints found after web_api_discovery ran.

    Controlled by vulnerability_scan.run_post_scan_processing (default True).
    """
    from reNgine.post_scan_processing import post_scan_processing
    activity.logger.info("[PostScanProcessingActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        post_scan_processing, ctx,
        task_name='post_scan_processing',
        description='Post-Scan Processing (dedup, OpenAPI, GraphQL)',
    )


@activity.defn(name="MarkVulnerabilityScanCompleteActivity")
def mark_vulnerability_scan_complete_activity(ctx: dict) -> None:
    """Write a SUCCESS ScanActivity with name='vulnerability_scan'.

    NucleiPlannerWorkflow runs as a child workflow whose internal activities
    use names like 'nuclei_scan', 'crlfuzz_scan', etc. — never 'vulnerability_scan'.
    Without this record, resume_scan_temporal always considers vulnerability_scan
    incomplete and re-runs it from scratch on crash recovery.
    """
    from startScan.models import ScanHistory, ScanActivity
    from reNgine.definitions import SUCCESS_TASK
    from reNgine.task_plan import get_task_tier
    from django.utils import timezone

    scan_id = ctx.get('scan_history_id')
    logger.log_line("[TEMPORAL]", "START", "task=mark_vulnerability_scan_complete scan_id=%s" % scan_id)
    if ctx.get('singular_tool_run'):
        # Never upsert the pipeline vulnerability_scan row from a singular run —
        # resume_scan_temporal would treat the master scan's vuln tier as done.
        # The singular parent (single_tool_vulnerability_scan) is closed via activity_id.
        logger.log_line(
            "[TEMPORAL]", "COMPLETE",
            "task=mark_vulnerability_scan_complete scan_id=%s skipped=singular" % scan_id,
        )
        return
    scan = ScanHistory.objects.filter(pk=scan_id).first()
    if not scan:
        logger.log_line("[TEMPORAL]", "COMPLETE", "task=mark_vulnerability_scan_complete scan_id=%s skipped=no_scan" % scan_id)
        return
    ScanActivity.objects.update_or_create(
        scan_of=scan,
        name='vulnerability_scan',
        defaults={
            'title': 'Vulnerability Scan',
            'tier': get_task_tier('vulnerability_scan'),
            'target_host': resolve_target_host(ctx, domain=scan.domain),
            'time': timezone.now(),
            'status': SUCCESS_TASK,
        }
    )
    activity.logger.info("[MarkVulnerabilityScanCompleteActivity] scan_id=%s marked complete", scan_id)
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=mark_vulnerability_scan_complete scan_id=%s" % scan_id)


@activity.defn(name="RunWAFBypassActivity")
def run_waf_bypass_activity(ctx: dict) -> bool:
    """Attempt to bypass detected WAF protections to find unprotected origins.

    Delegates to the existing `waf_bypass` task.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from reNgine.tasks import waf_bypass
    activity.logger.info("[RunWAFBypassActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        waf_bypass,
        ctx,
        task_name='waf_bypass',
        description='WAF Bypass'
    )


@activity.defn(name="ParseAssessmentResultsActivity")
def parse_assessment_results_activity(ctx: dict) -> bool:
    """Verify assessment tier (vulnerability) results are persisted.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from startScan.models import Vulnerability
    scan_id = ctx.get('scan_history_id')
    logger.log_line("[TEMPORAL]", "START", "task=parse_assessment_results scan_id=%s" % scan_id)
    vuln_count = Vulnerability.objects.filter(scan_history_id=scan_id).count()
    activity.logger.info(
        "[ParseAssessmentResultsActivity] scan_id=%s: %s vulnerabilities found.", scan_id, vuln_count
    )
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=parse_assessment_results scan_id=%s vulns=%d" % (scan_id, vuln_count))
    return True


@activity.defn(name="RunWPProbeActivity")
def run_wpprobe_activity(ctx: dict) -> bool:
    from reNgine.tasks.recon import wpprobe_scan
    activity.logger.info("[RunWPProbeActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        wpprobe_scan, ctx, task_name='wpprobe_scan',
        description='WordPress Plugin Scan (wpprobe)',
        url=ctx.get('url', ''),
    )


@activity.defn(name="RunSearchVulnsActivity")
def run_search_vulns_activity(ctx: dict) -> bool:
    """Query vulners.com for CVEs/exploits for a single service+version.

    Designed to be fanned out concurrently — one instance per discovered service
    from RunPortScanActivity. Called from _fan_out_search_vulns in
    MasterScanWorkflow Tier 2 after port scan returns.
    """
    from reNgine.tasks.recon import search_vulns_scan
    activity.logger.info(
        "[RunSearchVulnsActivity] service=%s host=%s scan_id=%s",
        ctx.get('service'), ctx.get('host'), ctx.get('scan_history_id'),
    )
    # _run_task provides heartbeating, pre-flight abort-guard, and correct
    # SUCCESS_TASK / FAILED_TASK status updates — matching all other activities.
    return _run_task(
        search_vulns_scan,
        ctx,
        task_name='search_vulns_scan',
        description='Per-service CVE Lookup (vulners.com)',
        scan_history_id=ctx.get('scan_history_id'),
        service=ctx.get('service', ''),
        version=ctx.get('version'),
        host=ctx.get('host', ''),
        port=ctx.get('port', 0),
        subdomain_id=ctx.get('subdomain_id'),
        domain_id=ctx.get('domain_id'),
    )


@activity.defn(name="RunGrypeScanActivity")
def run_grype_scan_activity(ctx: dict) -> bool:
    from reNgine.tasks.vulnerability import grype_scan
    activity.logger.info("[RunGrypeScanActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        grype_scan, ctx, task_name='grype_scan',
        description='CVE Scan (grype)', code_path=ctx.get('starting_point_path'),
    )


@activity.defn(name="RunTrivySecretScanActivity")
def run_trivy_secret_scan_activity(ctx: dict) -> bool:
    from reNgine.tasks.vulnerability import trivy_secret_scan
    activity.logger.info("[RunTrivySecretScanActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        trivy_secret_scan, ctx, task_name='trivy_secret_scan',
        description='Secret Scan (trivy v0.69.3)', code_path=ctx.get('starting_point_path'),
    )


@activity.defn(name="RunVigoliumAuditActivity")
def run_vigolium_audit_activity(ctx: dict) -> bool:
    from reNgine.tasks.vigolium import vigolium_audit_scan
    activity.logger.info("[RunVigoliumAuditActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        vigolium_audit_scan, ctx, task_name='vigolium_audit_scan',
        description='Source Code Security Audit (vigolium)',
        code_path=ctx.get('starting_point_path'),
        ctx=ctx,
    )
