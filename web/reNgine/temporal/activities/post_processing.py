"""
Post-processing and intelligence activities (Tier 7): correlation, CVE
enrichment, risk scoring, impact assessment, graph sync, notifications and the
LLM/APME passes.
"""

from temporalio import activity
from reNgine.temporal.heartbeat import keep_alive
from django.utils import timezone

from reNgine.utils.logger import get_module_logger, format_exception_for_log
from reNgine.temporal.activities.core import TemporalTaskProxy, _run_task

logger = get_module_logger(__name__)


# ===========================================================================
# Tier 7 — Post-Processing & Intelligence
# ===========================================================================

@activity.defn(name="CorrelateVulnerabilitiesActivity")
def correlate_vulnerabilities_activity(ctx: dict) -> bool:
    """Correlate discovered vulnerabilities with CVE databases and Neo4j graph.

    Delegates to the existing `correlate_vulnerabilities` task which syncs
    the graph and links technology findings to CVE records.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from reNgine.tasks import correlate_vulnerabilities
    scan_id = ctx.get('scan_history_id')
    activity.logger.warning("[TIER7][CORRELATE] Activity starting | scan_id=%s", scan_id)
    result = _run_task(
        correlate_vulnerabilities,
        ctx,
        task_name='correlate_vulnerabilities',
        description='Correlate Vulnerabilities',
        scan_history_id=scan_id
    )
    activity.logger.warning("[TIER7][CORRELATE] Activity complete | scan_id=%s result=%s", scan_id, result)
    return result


@activity.defn(name="CorrelateExposuresActivity")
def correlate_exposures_activity(ctx: dict) -> bool:
    """Correlate endpoints, subdomains, and screenshots into Exposure assets.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from reNgine.tasks import correlate_exposures
    scan_id = ctx.get('scan_history_id')
    activity.logger.warning("[TIER7][CORRELATE_EXPOSURES] Activity starting | scan_id=%s", scan_id)
    result = _run_task(
        correlate_exposures,
        ctx,
        task_name='correlate_exposures',
        description='Correlate Exposures',
        scan_history_id=scan_id
    )
    activity.logger.warning("[TIER7][CORRELATE_EXPOSURES] Activity complete | scan_id=%s result=%s", scan_id, result)
    return result


@activity.defn(name="EnrichScanCVEsActivity")
def enrich_scan_cves_activity(ctx: dict) -> bool:
    """Enrich CVE records linked to vulnerabilities discovered in this scan.

    Queries all CveId objects linked to findings from this scan and fetches
    NVD CVSS v3.1, FIRST EPSS, and CISA KEV metadata for any that have not
    yet been enriched (or were enriched more than 7 days ago).

    Runs after CorrelateVulnerabilitiesActivity so all CVE links are committed
    and before CalculateRiskScoresActivity so risk scores can use the enriched
    CVSS/EPSS values. Failures on individual CVEs are non-fatal — the activity
    always returns True to keep the pipeline moving.

    Args:
        ctx (dict): Temporal workflow context containing scan_history_id.

    Returns:
        bool: True in all cases (enrichment failures are logged, not raised).
    """
    from datetime import timedelta
    from django.db.models import Q
    from django.utils import timezone
    from startScan.models import CveId
    from reNgine.cve_enrichment import CVEEnrichmentService

    scan_id = ctx.get('scan_history_id')
    logger.log_line("[TEMPORAL]", "START", "task=enrich_scan_cves scan_id=%s" % scan_id)
    activity.logger.warning("[TIER7][CVE_ENRICH] Activity starting | scan_id=%s", scan_id)

    # Only process CVEs that still need work. Skipping already-fresh rows keeps
    # this under the Temporal heartbeat budget when retries fire.
    cutoff = timezone.now() - timedelta(days=7)
    cve_names = list(
        CveId.objects
        .filter(cve_ids__scan_history_id=scan_id)
        .filter(
            Q(cvss_v31_base_score__isnull=True)
            | Q(last_enriched_at__isnull=True)
            | Q(last_enriched_at__lt=cutoff)
        )
        .values_list('name', flat=True)
        .distinct()
    )

    if not cve_names:
        activity.logger.warning("[TIER7][CVE_ENRICH] No CVEs need enrichment for this scan | scan_id=%s", scan_id)
        logger.log_line("[TEMPORAL]", "COMPLETE", "task=enrich_scan_cves scan_id=%s enriched=0/0 skipped=already_fresh" % scan_id)
        return True

    activity.logger.warning("[TIER7][CVE_ENRICH] Enriching %d CVE(s) | scan_id=%s", len(cve_names), scan_id)
    service = CVEEnrichmentService()
    enriched = 0

    for idx, cve_name in enumerate(cve_names, start=1):
        try:
            activity.heartbeat(f"enriching {idx}/{len(cve_names)} {cve_name}")
            if service.enrich_cve(cve_name):
                enriched += 1
        except Exception as exc:
            activity.logger.warning("[TIER7][CVE_ENRICH] Skipping %s: %s", cve_name, exc)

    activity.logger.warning(
        "[TIER7][CVE_ENRICH] Complete | scan_id=%s enriched=%d/%d",
        scan_id, enriched, len(cve_names),
    )
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=enrich_scan_cves scan_id=%s enriched=%d/%d" % (scan_id, enriched, len(cve_names)))
    return True


@activity.defn(name="CalculateRiskScoresActivity")
def calculate_risk_scores_activity(ctx: dict) -> bool:
    """Calculate weighted risk scores for all discovered vulnerabilities.

    Delegates to the existing `calculate_risk_scores` task.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from reNgine.tasks import calculate_risk_scores
    scan_id = ctx.get('scan_history_id')
    activity.logger.warning("[TIER7][RISK] Activity starting | scan_id=%s", scan_id)
    result = _run_task(
        calculate_risk_scores,
        ctx,
        task_name='calculate_risk_scores',
        description='Calculate Risk Scores',
        scan_history_id=scan_id
    )
    activity.logger.warning("[TIER7][RISK] Activity complete | scan_id=%s result=%s", scan_id, result)
    return result


@activity.defn(name="GenerateImpactAssessmentActivity")
def generate_impact_assessment_activity(ctx: dict) -> bool:
    """Run AI-powered vulnerability impact assessment (if enabled in config).

    Delegates to the existing `generate_impact_assessment` task.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from reNgine.tasks import generate_impact_assessment
    scan_id = ctx.get('scan_history_id')
    activity.logger.warning("[TIER7][IMPACT] Activity starting | scan_id=%s", scan_id)
    result = _run_task(
        generate_impact_assessment,
        ctx,
        task_name='generate_impact_assessment',
        description='AI Impact Assessment',
        scan_history_id=scan_id
    )
    activity.logger.warning("[TIER7][IMPACT] Activity complete | scan_id=%s result=%s", scan_id, result)
    return result


@activity.defn(name="SyncGraphActivity")
def sync_graph_activity(ctx: dict) -> bool:
    """Synchronize all scan results to the Neo4j Attack Path Modeling graph.

    Delegates to `run_apme` task and additionally runs `Neo4jManager.sync_scan_results`.
    Sends a heartbeat before the sync so Temporal knows the activity is alive even
    if Neo4j is slow to accept the initial connection.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from reNgine.utils.graph import Neo4jManager
    from reNgine.definitions import SUCCESS_TASK, FAILED_TASK

    scan_id = ctx.get('scan_history_id')
    proxy = TemporalTaskProxy(ctx, 'sync_graph', 'Graph Sync (Neo4j)')

    from reNgine.utils.graph import _graph_heartbeat

    logger.log_line("[TEMPORAL]", "START", "task=sync_graph scan_id=%s" % scan_id)
    activity.logger.warning("[TIER7][GRAPH] SyncGraphActivity starting | scan_id=%s", scan_id)
    _graph_heartbeat("SyncGraphActivity starting neo4j sync for scan_id=%s" % scan_id)

    nm = Neo4jManager()
    try:
        nm.sync_scan_results(scan_id, heartbeat_callback=_graph_heartbeat)
        activity.logger.warning("[TIER7][GRAPH] Neo4j sync complete | scan_id=%s", scan_id)
        proxy.update_scan_activity(SUCCESS_TASK)
        logger.log_line("[TEMPORAL]", "COMPLETE", "task=sync_graph scan_id=%s" % scan_id)
        return True
    except Exception as e:
        activity.logger.error("[TIER7][GRAPH] Neo4j sync failed | scan_id=%s: %s", scan_id, e)
        logger.log_line("[TEMPORAL]", "ERROR", "task=sync_graph scan_id=%s error=%s" % (scan_id, format_exception_for_log(e)), level="error")
        proxy.update_scan_activity(FAILED_TASK, error_message=str(e))
        return False
    finally:
        nm.close()


@activity.defn(name="SendScanNotificationActivity")
def send_scan_notification_activity(ctx: dict) -> bool:
    """Mark the scan as completed and send the final scan status notification.

    Calls the `report` task function to update ScanHistory.scan_status to
    SUCCESS/FAILED and dispatch the completion webhook/notification.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from startScan.models import ScanHistory, ScanActivity
    from reNgine.definitions import SUCCESS_TASK, FAILED_TASK
    from reNgine.tasks import send_scan_notif

    scan_id = ctx.get('scan_history_id')
    engine_id = ctx.get('engine_id')
    proxy = TemporalTaskProxy(ctx, 'scan_notification', 'Send Scan Notification')

    logger.log_line("[TEMPORAL]", "START", "task=send_scan_notification scan_id=%s" % scan_id)
    activity.logger.warning("[SCAN_COMPLETE] SendScanNotificationActivity starting | scan_id=%s", scan_id)

    scan = ScanHistory.objects.filter(pk=scan_id).first()
    if not scan:
        activity.logger.error("[SCAN_COMPLETE] ScanHistory not found | scan_id=%s", scan_id)
        proxy.update_scan_activity(FAILED_TASK, error_message="ScanHistory not found.")
        return False

    # Determine overall scan status from ScanActivity records.
    # A task that failed on an early Temporal retry attempt but succeeded on a later
    # attempt will have both a FAILED_TASK and a SUCCESS_TASK record with the same
    # name. We only treat a task as truly failed if it NEVER produced a SUCCESS record.
    # Only count activities that actually started (time_started set).
    # Pre-populated INITIATED rows that were never claimed have time_started=None
    # and must not be treated as failures even if their status was set to FAILED.
    failed_names = set(
        ScanActivity.objects.filter(scan_of=scan, status=FAILED_TASK, time_started__isnull=False)
        .exclude(name='scan_notification')
        .values_list('name', flat=True)
    )
    success_names = set(
        ScanActivity.objects.filter(scan_of=scan, status=SUCCESS_TASK)
        .exclude(name='scan_notification')
        .values_list('name', flat=True)
    )
    true_failures = failed_names - success_names  # failed and never recovered

    if true_failures:
        activity.logger.warning(
            "[SCAN_COMPLETE] True task failures detected (failed and never recovered): %s | scan_id=%s",
            sorted(true_failures), scan_id,
        )
    else:
        activity.logger.warning(
            "[SCAN_COMPLETE] All tasks completed successfully (%d succeeded) | scan_id=%s",
            len(success_names), scan_id,
        )

    status = SUCCESS_TASK if not true_failures else FAILED_TASK
    status_h = 'SUCCESS' if not true_failures else 'FAILED'
    te_status = 'COMPLETED' if not true_failures else 'FAILED'

    scan.scan_status = status
    scan.stop_scan_date = timezone.now()
    scan.save()

    for te in scan.temporal_executions.filter(status='RUNNING'):
        te.status = te_status
        te.ended_at = scan.stop_scan_date
        te.save()

    # Clean up orphaned RUNNING rows left by crashed worker first attempts.
    # When a Temporal activity worker crashes mid-execution, its ScanActivity row
    # stays at RUNNING_TASK (time_started set, time_ended None). The retry creates
    # a new row and completes it. Reconcile these orphans against their later SUCCESS
    # counterparts so the timeline shows only clean state.
    if status == SUCCESS_TASK:
        from reNgine.definitions import RUNNING_TASK as _RUNNING, ABORTED_TASK as _ABORTED
        success_row_ids = dict(
            ScanActivity.objects.filter(scan_of=scan, status=SUCCESS_TASK)
            .values_list('name', 'id')
        )
        orphans = ScanActivity.objects.filter(
            scan_of=scan, status=_RUNNING, time_started__isnull=False
        )
        orphan_ids = [
            r.id for r in orphans
            if r.name in success_row_ids and r.id < success_row_ids[r.name]
        ]
        if orphan_ids:
            ScanActivity.objects.filter(id__in=orphan_ids).update(status=SUCCESS_TASK)
            activity.logger.warning(
                "[SCAN_COMPLETE] Reconciled %d orphaned RUNNING rows to SUCCESS | scan_id=%s ids=%s",
                len(orphan_ids), scan_id, orphan_ids,
            )

        # Mark any remaining RUNNING tasks as ABORTED — these are zombie tasks
        # (e.g. subscan or plugin rows) that were still running when the scan
        # completed. They never finished but the scan succeeded; ABORTED conveys
        # "the scan ended before this task could complete" without marking the
        # overall scan as failed.
        zombie_ids = list(
            ScanActivity.objects.filter(
                scan_of=scan, status=_RUNNING, time_started__isnull=False
            ).values_list('id', flat=True)
        )
        if zombie_ids:
            ScanActivity.objects.filter(id__in=zombie_ids).update(status=_ABORTED)
            activity.logger.warning(
                "[SCAN_COMPLETE] Marked %d zombie RUNNING tasks as ABORTED | scan_id=%s ids=%s",
                len(zombie_ids), scan_id, zombie_ids,
            )

        # Delete 'Scan Aborted' sentinel rows — empty-name placeholder entries
        # written when a previous attempt or subscan was cancelled. They are noise
        # on a successfully completed scan timeline.
        deleted_count, _ = ScanActivity.objects.filter(
            scan_of=scan, name='', title='Scan aborted'
        ).delete()
        if deleted_count:
            activity.logger.warning(
                "[SCAN_COMPLETE] Deleted %d 'Scan aborted' sentinel rows | scan_id=%s",
                deleted_count, scan_id,
            )

    # Log scan summary stats
    try:
        from startScan.models import Subdomain, EndPoint, Vulnerability
        subdomain_count = Subdomain.objects.filter(scan_history_id=scan_id).count()
        endpoint_count = EndPoint.objects.filter(scan_history_id=scan_id).count()
        vuln_count = Vulnerability.objects.filter(scan_history_id=scan_id).count()
        activity.logger.warning(
            "[SCAN_COMPLETE] Scan summary | scan_id=%s status=%s | subdomains=%d endpoints=%d vulnerabilities=%d",
            scan_id, status_h, subdomain_count, endpoint_count, vuln_count,
        )
    except Exception as stats_e:
        activity.logger.warning("[SCAN_COMPLETE] Could not gather scan summary stats: %s", stats_e)

    proxy.update_scan_activity(SUCCESS_TASK)

    # Send notification directly (no Celery)
    try:
        activity.logger.warning("[SCAN_COMPLETE] Dispatching scan notification | scan_id=%s status=%s", scan_id, status_h)
        send_scan_notif(
            scan_history_id=scan_id,
            subscan_id=None,
            engine_id=engine_id,
            status=status_h
        )
        activity.logger.warning("[SCAN_COMPLETE] Notification dispatched | scan_id=%s", scan_id)
    except Exception as e:
        # Non-fatal: log and continue
        logger.warning("[SCAN_COMPLETE] Could not send scan notification for scan_id=%s: %s", scan_id, e)

    activity.logger.warning("[SCAN_COMPLETE] SendScanNotificationActivity complete | scan_id=%s status=%s", scan_id, status_h)
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=send_scan_notification scan_id=%s status=%s" % (scan_id, status_h))
    return True


@activity.defn(name="RunLlmApmeActivity")
@keep_alive
def run_llm_apme_activity(scan_history_id: int, job_id: str = None) -> dict:
    from apme.apme_tasks import run_llm_apme
    from reNgine.job_tracker import update_job

    logger.log_line("[TEMPORAL]", "START", "task=run_llm_apme scan_id=%s" % scan_history_id)
    activity.logger.info("[RunLlmApmeActivity] scan_id=%s", scan_history_id)
    update_job(job_id, "RUNNING", 10, "Initializing LLM Attack Path modeling...") if job_id else None
    try:
        result = run_llm_apme(None, scan_history_id)
        if result.get("status") == "success":
            update_job(job_id, "SUCCESS", 100, "Attack Path Modeling completed.", result) if job_id else None
        else:
            update_job(job_id, "FAILED", 100, f"Failed: {result.get('error')}", result) if job_id else None
        logger.log_line("[TEMPORAL]", "COMPLETE", "task=run_llm_apme scan_id=%s status=%s" % (scan_history_id, result.get('status', 'unknown')))
        return result
    except Exception as e:
        update_job(job_id, "FAILED", 100, f"Error: {str(e)}") if job_id else None
        logger.log_line("[TEMPORAL]", "ERROR", "task=run_llm_apme scan_id=%s error=%s" % (scan_history_id, format_exception_for_log(e)), level="error")
        raise


@activity.defn(name="RecalculateApmeActivity")
def recalculate_apme_activity(scan_history_id: int, job_id: str = None) -> dict:
    from apme.orchestrator import APMEOrchestrator
    from startScan.models import ScanHistory
    import yaml
    from reNgine.definitions import ATTACK_PATH_MODELING
    from reNgine.job_tracker import update_job

    logger.log_line("[TEMPORAL]", "START", "task=recalculate_apme scan_id=%s" % scan_history_id)
    activity.logger.info("[RecalculateApmeActivity] scan_id=%s", scan_history_id)
    update_job(job_id, "RUNNING", 10, "Recalculating attack paths...") if job_id else None
    
    try:
        scan = ScanHistory.objects.get(id=scan_history_id)
        config = yaml.safe_load(scan.scan_type.yaml_configuration) or {}
        apme_config = config.get(ATTACK_PATH_MODELING, {})
        top_n = apme_config.get('top_n', 5)

        orchestrator = APMEOrchestrator(top_n=top_n)
        result = orchestrator.run(scan_history_id, heartbeat_fn=activity.heartbeat)

        if "error" in result:
            update_job(job_id, "FAILED", 100, f"Failed: {result.get('error')}", result) if job_id else None
            logger.log_line("[TEMPORAL]", "ERROR", "task=recalculate_apme scan_id=%s error=%s" % (scan_history_id, result.get('error')), level="error")
        else:
            update_job(job_id, "SUCCESS", 100, "Attack path recalculation completed.", result) if job_id else None
            logger.log_line("[TEMPORAL]", "COMPLETE", "task=recalculate_apme scan_id=%s status=success" % scan_history_id)
        return result
    except Exception as e:
        update_job(job_id, "FAILED", 100, f"Error: {str(e)}") if job_id else None
        logger.log_line("[TEMPORAL]", "ERROR", "task=recalculate_apme scan_id=%s error=%s" % (scan_history_id, format_exception_for_log(e)), level="error")
        raise
