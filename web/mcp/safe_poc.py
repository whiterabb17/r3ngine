"""SAFE PoC attempt service — propose, edit, approve (Temporal), abort, execute.

Propose never sends HTTP. Approve starts SafePocWorkflow. Execution is catalog-only.
Never writes ValidationResult.payload. Results nest under Vulnerability.agent_enrichment.poc.
"""
from __future__ import annotations

import asyncio
import logging
import re
from datetime import timezone as dt_timezone
from typing import Any, Optional
from urllib.parse import urlparse

from django.db import transaction
from django.utils import timezone

from mcp.models import SafePocAttempt
from mcp.safe_poc_catalog import (
    TEMPLATE_IDS,
    CatalogError,
    normalize_params,
    run_template,
)
from startScan.models import ScanHistory, Subdomain, Vulnerability

logger = logging.getLogger(__name__)

MAX_RATIONALE = 4000
PROPOSE_APPROVE_MSG = (
    'SAFE PoC requires propose → operator approve. '
    'Use r3ngine_propose_safe_poc then r3ngine_approve_safe_poc.'
)

_FORBIDDEN_KEY_RE = re.compile(
    r'(payload|exploit_code|exploit_body|shellcode|metasploit|msfvenom|'
    r'reverse_shell|bind_shell|weaponiz)',
    re.I,
)


class SafePocError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _utc_now_iso() -> str:
    return timezone.now().astimezone(dt_timezone.utc).isoformat()


def _reject_forbidden_keys(obj: Any, path: str = '') -> str | None:
    if isinstance(obj, dict):
        for key, value in obj.items():
            key_s = str(key)
            if _FORBIDDEN_KEY_RE.search(key_s):
                return f'forbidden field: {path + key_s}'
            err = _reject_forbidden_keys(value, path + key_s + '.')
            if err:
                return err
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            err = _reject_forbidden_keys(item, f'{path}{i}.')
            if err:
                return err
    return None


def _load_vuln(vulnerability_id: int) -> Vulnerability:
    vuln = (
        Vulnerability.objects
        .select_related('scan_history', 'scan_history__domain', 'target_domain', 'subdomain')
        .filter(pk=vulnerability_id)
        .first()
    )
    if not vuln:
        raise SafePocError('vulnerability not found', 404)
    return vuln


def _project_slug_for_vuln(vuln: Vulnerability) -> str:
    domain = vuln.target_domain or (vuln.scan_history.domain if vuln.scan_history_id else None)
    if domain is None:
        raise SafePocError('vulnerability has no target domain')
    project = getattr(domain, 'project', None)
    if project is None or not getattr(project, 'slug', None):
        raise SafePocError('vulnerability domain has no project')
    return project.slug


def _allowed_hosts_for_vuln(vuln: Vulnerability) -> set[str]:
    hosts: set[str] = set()
    domain = vuln.target_domain or (vuln.scan_history.domain if vuln.scan_history_id else None)
    if domain and domain.name:
        hosts.add(domain.name.lower())
    if vuln.subdomain_id and getattr(vuln.subdomain, 'name', None):
        hosts.add(vuln.subdomain.name.lower())
    scan_id = vuln.scan_history_id
    if scan_id:
        for name in Subdomain.objects.filter(scan_history_id=scan_id).values_list('name', flat=True):
            if name:
                hosts.add(str(name).lower())
    if vuln.http_url:
        host = urlparse(vuln.http_url).hostname
        if host:
            hosts.add(host.lower())
    return hosts


def serialize_attempt(attempt: SafePocAttempt) -> dict[str, Any]:
    # Never return cookie_value in API responses.
    params = dict(attempt.params or {})
    if 'cookie_value' in params:
        params['cookie_value'] = '***' if params.get('cookie_value') else None
    return {
        'id': attempt.id,
        'project_slug': attempt.project_slug,
        'scan_id': attempt.scan_id,
        'vulnerability_id': attempt.vulnerability_id,
        'status': attempt.status,
        'template_id': attempt.template_id,
        'params': params,
        'rationale': attempt.rationale,
        'agent_id': attempt.agent_id,
        'result': attempt.result,
        'operator_edited': attempt.operator_edited,
        'temporal_workflow_id': attempt.temporal_workflow_id or None,
        'created_at': attempt.created_at.isoformat() if attempt.created_at else None,
        'updated_at': attempt.updated_at.isoformat() if attempt.updated_at else None,
        'approved_at': attempt.approved_at.isoformat() if attempt.approved_at else None,
        'completed_at': attempt.completed_at.isoformat() if attempt.completed_at else None,
    }


def list_attempts(
    *,
    project_slug: Optional[str] = None,
    scan_id: Optional[int] = None,
    vulnerability_id: Optional[int] = None,
    status: Optional[str] = None,
    limit: int = 50,
) -> list[SafePocAttempt]:
    qs = SafePocAttempt.objects.all().order_by('-created_at')
    if project_slug:
        qs = qs.filter(project_slug=project_slug)
    if scan_id is not None:
        qs = qs.filter(scan_id=scan_id)
    if vulnerability_id is not None:
        qs = qs.filter(vulnerability_id=vulnerability_id)
    if status:
        qs = qs.filter(status=status)
    limit = max(1, min(int(limit or 50), 100))
    return list(qs[:limit])


def propose_attempt(
    *,
    vulnerability_id: int,
    template_id: str,
    params: Any = None,
    rationale: str = '',
    project_slug: str = '',
    scan_id: Optional[int] = None,
    agent_id: str = '',
    user=None,
) -> SafePocAttempt:
    forbidden = _reject_forbidden_keys({'params': params or {}, 'rationale': rationale})
    if forbidden:
        raise SafePocError(forbidden)

    template_id = str(template_id or '').strip()
    if template_id not in TEMPLATE_IDS:
        raise SafePocError(f'template_id must be one of {sorted(TEMPLATE_IDS)}')

    try:
        vulnerability_id = int(vulnerability_id)
    except (TypeError, ValueError) as exc:
        raise SafePocError('vulnerability_id must be an integer') from exc

    vuln = _load_vuln(vulnerability_id)
    resolved_slug = _project_slug_for_vuln(vuln)
    if project_slug and project_slug != resolved_slug:
        raise SafePocError('project_slug does not match vulnerability project', 403)
    project_slug = resolved_slug

    vuln_scan_id = vuln.scan_history_id
    if scan_id is not None and vuln_scan_id and int(scan_id) != int(vuln_scan_id):
        raise SafePocError('scan_id does not match vulnerability scan', 400)
    scan_id = vuln_scan_id

    if not vuln.http_url:
        raise SafePocError('vulnerability has no http_url')

    try:
        clean_params = normalize_params(template_id, params, vuln_url=vuln.http_url)
    except CatalogError as exc:
        raise SafePocError(str(exc), exc.status) from exc

    # Scope check at propose time
    allowed = _allowed_hosts_for_vuln(vuln)
    from mcp.safe_poc_catalog import assert_host_in_scope, assert_url_not_denied
    try:
        for key in ('base_url', 'url_a', 'url_b'):
            if clean_params.get(key):
                assert_url_not_denied(clean_params[key])
                assert_host_in_scope(clean_params[key], allowed)
    except CatalogError as exc:
        raise SafePocError(str(exc), exc.status) from exc

    attempt = SafePocAttempt.objects.create(
        project_slug=project_slug,
        scan_id=scan_id,
        vulnerability_id=vuln.id,
        status=SafePocAttempt.STATUS_PROPOSED,
        template_id=template_id,
        params=clean_params,
        rationale=(rationale or '')[:MAX_RATIONALE],
        agent_id=(agent_id or '')[:128],
        created_by=user if getattr(user, 'pk', None) else None,
        updated_by=user if getattr(user, 'pk', None) else None,
    )
    logger.info(
        'safe_poc propose ok id=%s vuln=%s template=%s project=%s scan=%s agent=%s',
        attempt.id,
        attempt.vulnerability_id,
        attempt.template_id,
        attempt.project_slug,
        attempt.scan_id,
        attempt.agent_id or None,
    )
    return attempt


def update_attempt(
    attempt: SafePocAttempt,
    *,
    template_id: Optional[str] = None,
    params: Any = None,
    rationale: Optional[str] = None,
    user=None,
    is_operator: bool = False,
) -> SafePocAttempt:
    if attempt.status != SafePocAttempt.STATUS_PROPOSED:
        logger.warning(
            'safe_poc update rejected id=%s status=%s (not proposed)',
            attempt.id,
            attempt.status,
        )
        raise SafePocError('only proposed attempts can be edited')
    if attempt.operator_edited and not is_operator:
        logger.warning(
            'safe_poc update rejected id=%s operator_edited lock is_operator=%s',
            attempt.id,
            is_operator,
        )
        raise SafePocError(
            'attempt was edited by an operator; agent cannot overwrite',
            403,
        )

    forbidden = _reject_forbidden_keys({
        'params': params if params is not None else {},
        'rationale': rationale or '',
    })
    if forbidden:
        raise SafePocError(forbidden)

    vuln = _load_vuln(attempt.vulnerability_id)
    new_template = str(template_id or attempt.template_id).strip()
    if new_template not in TEMPLATE_IDS:
        raise SafePocError(f'template_id must be one of {sorted(TEMPLATE_IDS)}')

    if params is not None or template_id is not None:
        try:
            clean_params = normalize_params(
                new_template,
                params if params is not None else attempt.params,
                vuln_url=vuln.http_url or '',
            )
        except CatalogError as exc:
            raise SafePocError(str(exc), exc.status) from exc
        allowed = _allowed_hosts_for_vuln(vuln)
        from mcp.safe_poc_catalog import assert_host_in_scope, assert_url_not_denied
        try:
            for key in ('base_url', 'url_a', 'url_b'):
                if clean_params.get(key):
                    assert_url_not_denied(clean_params[key])
                    assert_host_in_scope(clean_params[key], allowed)
        except CatalogError as exc:
            raise SafePocError(str(exc), exc.status) from exc
        attempt.template_id = new_template
        attempt.params = clean_params

    if rationale is not None:
        attempt.rationale = rationale[:MAX_RATIONALE]
    if is_operator:
        attempt.operator_edited = True
    if user and getattr(user, 'pk', None):
        attempt.updated_by = user
    attempt.save()
    logger.info(
        'safe_poc update ok id=%s template=%s is_operator=%s operator_edited=%s',
        attempt.id,
        attempt.template_id,
        is_operator,
        attempt.operator_edited,
    )
    return attempt


def _start_safe_poc_workflow(attempt_id: int) -> str:
    from reNgine.temporal_client import TemporalClientProvider, run_and_close

    # Stable id per attempt — concurrent starts collide instead of double-running.
    workflow_id = f'safe-poc-{attempt_id}'

    async def _start():
        client = await TemporalClientProvider.get_client()
        await client.start_workflow(
            'SafePocWorkflow',
            args=[{'attempt_id': attempt_id}],
            id=workflow_id,
            task_queue='python-orchestrator-queue',
        )

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    run_and_close(loop, _start())
    logger.info('safe_poc workflow started attempt_id=%s workflow_id=%s', attempt_id, workflow_id)
    return workflow_id


def approve_attempt(attempt: SafePocAttempt, *, user=None) -> SafePocAttempt:
    """Approve proposed attempt and start Temporal workflow.

    Uses ``select_for_update`` so concurrent approve calls cannot both start
    workflows / probes.
    """
    with transaction.atomic():
        locked = (
            SafePocAttempt.objects
            .select_for_update()
            .filter(pk=attempt.pk)
            .first()
        )
        if not locked:
            raise SafePocError('attempt not found', 404)
        if locked.status != SafePocAttempt.STATUS_PROPOSED:
            logger.warning(
                'safe_poc approve rejected id=%s status=%s',
                locked.id,
                locked.status,
            )
            raise SafePocError(
                f'cannot approve attempt in status={locked.status}',
                409,
            )
        locked.status = SafePocAttempt.STATUS_RUNNING
        locked.approved_at = timezone.now()
        if user and getattr(user, 'pk', None):
            locked.updated_by = user
        locked.save(update_fields=['status', 'approved_at', 'updated_by', 'updated_at'])
        attempt_id = locked.id
        template_id = locked.template_id

    logger.info(
        'safe_poc approve starting workflow id=%s template=%s user=%s',
        attempt_id,
        template_id,
        getattr(user, 'pk', None),
    )

    try:
        # Deterministic workflow id: Temporal rejects duplicates if a race slips past.
        wf_id = _start_safe_poc_workflow(attempt_id)
    except Exception as exc:
        logger.exception(
            'safe_poc Failed to start SafePocWorkflow id=%s template=%s',
            attempt_id,
            template_id,
        )
        with transaction.atomic():
            locked = (
                SafePocAttempt.objects
                .select_for_update()
                .filter(pk=attempt_id)
                .first()
            )
            if locked and locked.status == SafePocAttempt.STATUS_ABORTED:
                logger.info(
                    'safe_poc workflow start failed but abort wins id=%s',
                    attempt_id,
                )
                raise SafePocError(f'failed to start PoC workflow: {exc}', 502) from exc
            if locked and locked.status == SafePocAttempt.STATUS_RUNNING:
                locked.status = SafePocAttempt.STATUS_FAILED
                locked.result = {
                    'matched': False,
                    'confidence': 0.0,
                    'summary': f'failed to start workflow: {exc}',
                    'error': 'workflow_start_failed',
                }
                locked.completed_at = timezone.now()
                locked.save(
                    update_fields=['status', 'result', 'completed_at', 'updated_at']
                )
        raise SafePocError(f'failed to start PoC workflow: {exc}', 502) from exc

    with transaction.atomic():
        locked = (
            SafePocAttempt.objects
            .select_for_update()
            .filter(pk=attempt_id)
            .first()
        )
        if not locked:
            raise SafePocError('attempt not found', 404)
        if locked.status == SafePocAttempt.STATUS_ABORTED:
            logger.info(
                'safe_poc approve aborted after workflow start id=%s wf=%s',
                attempt_id,
                wf_id,
            )
            # Cancel the just-started workflow; abort already won on the row.
            _cancel_workflow(wf_id)
            return locked
        locked.temporal_workflow_id = wf_id
        locked.save(update_fields=['temporal_workflow_id', 'updated_at'])
    return locked


def abort_attempt(attempt: SafePocAttempt, *, user=None) -> SafePocAttempt:
    """Abort proposed/approved/running attempt; wins over in-flight execute."""
    workflow_id = None
    with transaction.atomic():
        locked = (
            SafePocAttempt.objects
            .select_for_update()
            .filter(pk=attempt.pk)
            .first()
        )
        if not locked:
            raise SafePocError('attempt not found', 404)
        if locked.status in (
            SafePocAttempt.STATUS_SUCCEEDED,
            SafePocAttempt.STATUS_FAILED,
            SafePocAttempt.STATUS_ABORTED,
            SafePocAttempt.STATUS_REJECTED,
        ):
            logger.info(
                'safe_poc abort idempotent id=%s status=%s',
                locked.id,
                locked.status,
            )
            return locked
        if locked.status not in (
            SafePocAttempt.STATUS_PROPOSED,
            SafePocAttempt.STATUS_APPROVED,
            SafePocAttempt.STATUS_RUNNING,
        ):
            logger.warning(
                'safe_poc abort rejected id=%s status=%s',
                locked.id,
                locked.status,
            )
            raise SafePocError(f'cannot abort attempt in status={locked.status}')

        locked.status = SafePocAttempt.STATUS_ABORTED
        locked.completed_at = timezone.now()
        if user and getattr(user, 'pk', None):
            locked.updated_by = user
        locked.save(update_fields=['status', 'completed_at', 'updated_by', 'updated_at'])
        workflow_id = locked.temporal_workflow_id or None
        attempt = locked

    logger.info(
        'safe_poc aborted id=%s workflow=%s user=%s',
        attempt.id,
        workflow_id,
        getattr(user, 'pk', None),
    )

    if workflow_id:
        _cancel_workflow(workflow_id)
    return attempt


def _cancel_workflow(workflow_id: str) -> None:
    from reNgine.temporal_client import TemporalClientProvider, run_and_close

    async def _cancel():
        client = await TemporalClientProvider.get_client()
        try:
            handle = client.get_workflow_handle(workflow_id)
            await handle.cancel()
            logger.info('safe_poc workflow cancel requested workflow_id=%s', workflow_id)
        except Exception:
            logger.warning('Could not cancel workflow %s', workflow_id, exc_info=True)

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        run_and_close(loop, _cancel())
    except Exception:
        logger.exception('Temporal cancel failed for %s', workflow_id)


def execute_attempt(attempt_id: int) -> dict[str, Any]:
    """Run catalog template and persist result + agent_enrichment.poc.

    Called by Temporal activity (and unit tests). Honors abort via
    ``select_for_update`` / conditional updates so a concurrent abort cannot
    be overwritten by a stale succeed/fail write.
    """
    with transaction.atomic():
        attempt = (
            SafePocAttempt.objects
            .select_for_update()
            .filter(pk=attempt_id)
            .first()
        )
        if not attempt:
            logger.error('safe_poc execute: attempt %s not found', attempt_id)
            raise SafePocError(f'SafePocAttempt {attempt_id} not found', 404)

        if attempt.status == SafePocAttempt.STATUS_ABORTED:
            logger.info('safe_poc execute skipped id=%s (already aborted)', attempt_id)
            return {'status': attempt.status, 'aborted': True}

        if attempt.status not in (
            SafePocAttempt.STATUS_APPROVED,
            SafePocAttempt.STATUS_RUNNING,
        ):
            if attempt.status in (
                SafePocAttempt.STATUS_SUCCEEDED,
                SafePocAttempt.STATUS_FAILED,
            ):
                logger.info(
                    'safe_poc execute idempotent id=%s status=%s',
                    attempt_id,
                    attempt.status,
                )
                return {'status': attempt.status, 'result': attempt.result}
            logger.warning(
                'safe_poc execute rejected id=%s status=%s',
                attempt_id,
                attempt.status,
            )
            raise SafePocError(f'cannot execute attempt in status={attempt.status}')

        attempt.status = SafePocAttempt.STATUS_RUNNING
        attempt.save(update_fields=['status', 'updated_at'])
        template_id = attempt.template_id
        vulnerability_id = attempt.vulnerability_id
        params = dict(attempt.params or {})

    logger.info(
        'safe_poc execute start id=%s template=%s vuln=%s',
        attempt_id,
        template_id,
        vulnerability_id,
    )

    # Abort may land between releasing the lock and starting the probe.
    if (
        SafePocAttempt.objects.filter(
            pk=attempt_id, status=SafePocAttempt.STATUS_ABORTED
        ).exists()
    ):
        logger.info('safe_poc execute aborted mid-flight id=%s', attempt_id)
        return {'status': SafePocAttempt.STATUS_ABORTED, 'aborted': True}

    vuln = _load_vuln(vulnerability_id)
    allowed = _allowed_hosts_for_vuln(vuln)
    # Cookie values stay in params for the HTTP client only; never log them.
    result = run_template(template_id, params, allowed_hosts=allowed)

    matched = bool(result.get('matched'))
    new_status = (
        SafePocAttempt.STATUS_SUCCEEDED if matched else SafePocAttempt.STATUS_FAILED
    )
    completed_at = timezone.now()

    with transaction.atomic():
        locked = (
            SafePocAttempt.objects
            .select_for_update()
            .filter(pk=attempt_id)
            .first()
        )
        if not locked:
            raise SafePocError(f'SafePocAttempt {attempt_id} not found', 404)
        if locked.status == SafePocAttempt.STATUS_ABORTED:
            logger.info('safe_poc execute aborted after probe id=%s', attempt_id)
            return {'status': locked.status, 'aborted': True}
        if locked.status != SafePocAttempt.STATUS_RUNNING:
            logger.warning(
                'safe_poc execute result skipped id=%s status=%s',
                attempt_id,
                locked.status,
            )
            return {'status': locked.status, 'result': locked.result}
        locked.status = new_status
        locked.result = result
        locked.completed_at = completed_at
        locked.save(update_fields=['status', 'result', 'completed_at', 'updated_at'])
        attempt = locked

    _nest_enrichment(vuln, attempt, result)
    log_fn = logger.info if matched else logger.warning
    log_fn(
        'safe_poc execute done id=%s status=%s matched=%s confidence=%s summary=%s error=%s',
        attempt.id,
        attempt.status,
        matched,
        result.get('confidence'),
        str(result.get('summary') or '')[:200],
        result.get('error'),
    )
    return {'status': attempt.status, 'result': result}


def _nest_enrichment(vuln: Vulnerability, attempt: SafePocAttempt, result: dict) -> None:
    enrichment = dict(vuln.agent_enrichment or {})
    enrichment['poc'] = {
        'last_attempt_id': attempt.id,
        'template_id': attempt.template_id,
        'outcome': attempt.status,
        'confidence': float(result.get('confidence') or 0.0),
        'summary': str(result.get('summary') or '')[:500],
        'attempted_at': _utc_now_iso(),
    }
    vuln.agent_enrichment = enrichment
    vuln.save(update_fields=['agent_enrichment'])
    logger.info(
        'safe_poc enrichment nested vuln=%s attempt=%s outcome=%s',
        vuln.id,
        attempt.id,
        attempt.status,
    )
