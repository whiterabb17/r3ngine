"""SAFE PoC Temporal activities."""
from __future__ import annotations

import logging

from temporalio import activity
from django.utils import timezone

logger = logging.getLogger(__name__)


@activity.defn(name="SafePocCheckAbortActivity")
def safe_poc_check_abort_activity(attempt_id: int) -> bool:
    from mcp.models import SafePocAttempt

    attempt = SafePocAttempt.objects.filter(pk=attempt_id).first()
    return bool(attempt and attempt.status == SafePocAttempt.STATUS_ABORTED)


def _mark_attempt_failed(attempt_id: int, error: str) -> dict:
    from django.db import transaction

    from mcp.models import SafePocAttempt

    with transaction.atomic():
        attempt = (
            SafePocAttempt.objects
            .select_for_update()
            .filter(pk=attempt_id)
            .first()
        )
        if not attempt:
            logger.error('safe_poc mark_failed: attempt %s missing err=%s', attempt_id, error)
            return {'status': 'failed', 'error': error}
        if attempt.status == SafePocAttempt.STATUS_ABORTED:
            logger.info('safe_poc mark_failed skipped id=%s (aborted)', attempt_id)
            return {'status': attempt.status, 'aborted': True}
        if attempt.status in (
            SafePocAttempt.STATUS_SUCCEEDED,
            SafePocAttempt.STATUS_FAILED,
            SafePocAttempt.STATUS_REJECTED,
        ):
            logger.info(
                'safe_poc mark_failed idempotent id=%s status=%s',
                attempt_id,
                attempt.status,
            )
            return {'status': attempt.status, 'error': error}
        attempt.status = SafePocAttempt.STATUS_FAILED
        attempt.result = {
            'matched': False,
            'confidence': 0.0,
            'summary': error[:500],
            'error': 'execute_error',
        }
        attempt.completed_at = timezone.now()
        attempt.save(update_fields=['status', 'result', 'completed_at', 'updated_at'])
        template_id = attempt.template_id
        status = attempt.status

    logger.error(
        'safe_poc attempt marked failed id=%s template=%s err=%s',
        attempt_id,
        template_id,
        error[:300],
    )
    return {'status': status, 'error': error}


@activity.defn(name="SafePocExecuteActivity")
def safe_poc_execute_activity(attempt_id: int) -> dict:
    from mcp.safe_poc import SafePocError, execute_attempt

    logger.info('SafePocExecuteActivity start attempt_id=%s', attempt_id)
    try:
        result = execute_attempt(attempt_id)
        logger.info(
            'SafePocExecuteActivity success attempt_id=%s status=%s',
            attempt_id,
            result.get('status'),
        )
        return result
    except SafePocError as exc:
        logger.warning(
            'SafePocExecuteActivity SafePocError attempt_id=%s: %s',
            attempt_id,
            exc,
        )
        return _mark_attempt_failed(attempt_id, str(exc))
    except Exception as exc:
        logger.exception(
            'SafePocExecuteActivity unexpected error attempt_id=%s',
            attempt_id,
        )
        return _mark_attempt_failed(attempt_id, f'unexpected: {exc.__class__.__name__}: {exc}')
