"""Metasploit auxiliary/post Temporal activities (operator-gated)."""
from __future__ import annotations

import logging

from temporalio import activity
from django.utils import timezone

logger = logging.getLogger(__name__)


@activity.defn(name="MsfAuxCheckAbortActivity")
def msf_aux_check_abort_activity(attempt_id: int) -> bool:
    from copilot.models import MsfAuxAttempt

    attempt = MsfAuxAttempt.objects.filter(pk=attempt_id).first()
    return bool(attempt and attempt.status == MsfAuxAttempt.STATUS_ABORTED)


def _mark_attempt_failed(attempt_id: int, error: str) -> dict:
    from django.db import transaction

    from copilot.models import MsfAuxAttempt

    with transaction.atomic():
        attempt = (
            MsfAuxAttempt.objects
            .select_for_update()
            .filter(pk=attempt_id)
            .first()
        )
        if not attempt:
            return {'status': 'failed', 'error': error}
        if attempt.status == MsfAuxAttempt.STATUS_ABORTED:
            return {'status': attempt.status, 'aborted': True}
        if attempt.status in (
            MsfAuxAttempt.STATUS_SUCCEEDED,
            MsfAuxAttempt.STATUS_FAILED,
            MsfAuxAttempt.STATUS_REJECTED,
        ):
            return {'status': attempt.status, 'error': error}
        attempt.status = MsfAuxAttempt.STATUS_FAILED
        attempt.error = error[:2000]
        attempt.result = {'error': error[:500]}
        attempt.completed_at = timezone.now()
        attempt.save(update_fields=['status', 'error', 'result', 'completed_at', 'updated_at'])
        status = attempt.status
    return {'status': status, 'error': error}


@activity.defn(name="MsfAuxMarkFailedActivity")
def msf_aux_mark_failed_activity(attempt_id: int, error: str) -> dict:
    """Reconcile attempts left RUNNING after execute timeout/cancel."""
    return _mark_attempt_failed(attempt_id, error or 'execute interrupted')


@activity.defn(name="MsfAuxExecuteActivity")
def msf_aux_execute_activity(attempt_id: int) -> dict:
    from copilot.msf_aux import MsfAuxError, execute_attempt

    logger.info('MsfAuxExecuteActivity start attempt_id=%s', attempt_id)
    try:
        result = execute_attempt(attempt_id)
        logger.info(
            'MsfAuxExecuteActivity done attempt_id=%s status=%s',
            attempt_id,
            result.get('status'),
        )
        return result
    except MsfAuxError as exc:
        logger.warning('MsfAuxExecuteActivity MsfAuxError id=%s: %s', attempt_id, exc)
        return _mark_attempt_failed(attempt_id, str(exc))
    except Exception as exc:
        logger.exception('MsfAuxExecuteActivity unexpected id=%s', attempt_id)
        return _mark_attempt_failed(attempt_id, f'unexpected: {exc.__class__.__name__}: {exc}')
