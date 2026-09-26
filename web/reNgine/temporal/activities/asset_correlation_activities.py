"""Temporal activity that runs AssetCorrelationService for an assessment.

Feature-flag-gated by settings.ASSESSMENT_ASSET_CORRELATION_ENABLED.
"""
from django.conf import settings
from temporalio import activity
# channels' wrapper, not asgiref's: it refreshes the thread's database connection
# around each call. The plain one left a dead cached connection in place for
# good — see check_scan_queue_status_activity for the incident.
from channels.db import database_sync_to_async

from reNgine.utils.logger import get_module_logger, format_exception_for_log
from reNgine.asset_correlation import AssetCorrelationService

logger = get_module_logger(__name__)


@activity.defn
async def run_asset_correlation_activity(assessment_id: str) -> dict:
    """Roll up per-scan Exposure records into canonical assessment Assets."""
    if not getattr(settings, 'ASSESSMENT_ASSET_CORRELATION_ENABLED', False):
        logger.log_line(
            "[CORRELATION]", "SKIP",
            "feature flag disabled for assessment %s" % assessment_id,
        )
        return {"status": "skipped_flag_off"}

    logger.log_line("[CORRELATION]", "START", "assessment %s" % assessment_id)
    try:
        result = await database_sync_to_async(_run_sync)(assessment_id)
    except Exception as exc:
        logger.log_line(
            "[CORRELATION]", "ERROR", format_exception_for_log(exc),
            level="error", exc_info=True,
        )
        raise

    logger.log_line(
        "[CORRELATION]", "COMPLETE",
        "assessment %s: new=%d updated=%d sources=%d scans=%d" % (
            assessment_id,
            result['new_assets'], result['updated_assets'],
            result['new_sources'], result['scans_processed'],
        ),
    )
    return result


def _run_sync(assessment_id: str) -> dict:
    """Synchronous inner — runs in a thread via database_sync_to_async."""
    from engagements.models import Assessment, AssessmentEvent

    assessment = Assessment.objects.get(uuid=assessment_id)
    service_result = AssetCorrelationService(assessment).correlate()
    payload = {
        "status": "ok",
        "new_assets": service_result.new_assets,
        "updated_assets": service_result.updated_assets,
        "new_sources": service_result.new_sources,
        "scans_processed": service_result.scans_processed,
    }
    AssessmentEvent.objects.create(
        assessment=assessment,
        event_type='assets_correlated',
        event_data=payload,
    )
    return payload
