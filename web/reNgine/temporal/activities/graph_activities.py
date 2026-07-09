"""Phase 5 — sync an Assessment's live Findings and Evidence to Neo4j.

Gated by settings.ASSESSMENT_GRAPH_SYNC_ENABLED. Findings with
validation_status in {new, false_positive, resolved} are intentionally
excluded from the graph.
"""
from django.conf import settings
from temporalio import activity
from asgiref.sync import sync_to_async

from apme.graph.builder import GraphBuilder
from reNgine.utils.logger import get_module_logger, format_exception_for_log

logger = get_module_logger(__name__)


_LIVE_STATUSES = ('verified', 'needs_review', 'accepted_risk')


@activity.defn
async def sync_assessment_graph_activity(assessment_id: str) -> dict:
    """Sync validated Findings + Evidence to Neo4j for an Assessment."""
    if not getattr(settings, 'ASSESSMENT_GRAPH_SYNC_ENABLED', False):
        logger.log_line(
            "[GRAPH]", "SKIP",
            "feature flag disabled for assessment %s" % assessment_id,
        )
        return {"status": "skipped_flag_off"}

    logger.log_line("[GRAPH]", "START", "sync assessment %s" % assessment_id)
    try:
        result = await sync_to_async(_run_sync, thread_sensitive=True)(assessment_id)
    except Exception as exc:
        logger.log_line(
            "[GRAPH]", "ERROR", format_exception_for_log(exc),
            level="error", exc_info=True,
        )
        raise

    logger.log_line(
        "[GRAPH]", "COMPLETE",
        "assessment %s: findings=%d evidence=%d" % (
            assessment_id, result['finding_count'], result['evidence_count'],
        ),
    )
    return result


def _run_sync(assessment_id: str) -> dict:
    from engagements.models import Assessment, AssessmentEvent
    from evidence.models import Evidence
    from startScan.models import Vulnerability

    assessment = Assessment.objects.get(uuid=assessment_id)
    findings = list(
        Vulnerability.objects
        .filter(scan_history__assessment=assessment,
                validation_status__in=_LIVE_STATUSES)
    )
    finding_ids = {v.id for v in findings}
    evidence_items = Evidence.objects.filter(collection__assessment=assessment) \
                                     .prefetch_related('vulnerabilities')
    evidences_with_findings = []
    for ev in evidence_items:
        linked = [vid for vid in ev.vulnerabilities.values_list('id', flat=True)
                  if vid in finding_ids]
        evidences_with_findings.append((ev, linked))

    builder = GraphBuilder()
    try:
        builder.merge_assessment_node(assessment)
        finding_count = builder.merge_finding_nodes(findings, assessment=assessment)
        evidence_count = builder.merge_evidence_nodes(evidences_with_findings)
    finally:
        builder.close()

    payload = {
        "status": "ok",
        "finding_count": finding_count,
        "evidence_count": evidence_count,
    }
    AssessmentEvent.objects.create(
        assessment=assessment,
        event_type='graph_synced',
        event_data=payload,
    )
    return payload
