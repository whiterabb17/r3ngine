"""Gated Metasploit auxiliary/post attempts — propose → approve → Temporal → MSFRPC."""
from __future__ import annotations

import asyncio
import logging
from datetime import timezone as dt_timezone
from typing import Any

from django.db import transaction
from django.utils import timezone

from copilot.msf_aux_catalog import (
    MsfCatalogError,
    extract_rhosts,
    validate_module_options,
)
from copilot.msf_rpc import MsfrpcClient, MsfrpcError
from startScan.models import Subdomain

logger = logging.getLogger(__name__)

MAX_OUTPUT = 8000


class MsfAuxError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _utc_now_iso() -> str:
    return timezone.now().astimezone(dt_timezone.utc).isoformat()


def _allowed_hosts_for_project(project_slug: str, scan_id: int | None = None) -> set[str]:
    from targetApp.models import Domain

    hosts: set[str] = set()
    domains = Domain.objects.filter(project__slug=project_slug).values_list('name', flat=True)
    for name in domains:
        if name:
            hosts.add(str(name).lower())
    qs = Subdomain.objects.filter(target_domain__project__slug=project_slug)
    if scan_id:
        qs = qs.filter(scan_history_id=scan_id)
    for name in qs.values_list('name', flat=True)[:5000]:
        if name:
            hosts.add(str(name).lower())
    return hosts


def assert_rhosts_in_scope(
    options: dict[str, str],
    *,
    project_slug: str,
    scan_id: int | None = None,
    vulnerability_id: int | None = None,
) -> None:
    from copilot.service import CopilotError, _vuln_for_project

    hosts = extract_rhosts(options)
    if not hosts:
        raise MsfAuxError('RHOSTS/RHOST is required for scoped execution')
    allowed = _allowed_hosts_for_project(project_slug, scan_id=scan_id)
    if vulnerability_id:
        try:
            vuln = _vuln_for_project(int(vulnerability_id), project_slug)
        except CopilotError as exc:
            raise MsfAuxError(str(exc), status=exc.status) from exc
        domain = vuln.target_domain or (vuln.scan_history.domain if vuln.scan_history_id else None)
        if domain and domain.name:
            allowed.add(domain.name.lower())
        if vuln.subdomain_id and getattr(vuln.subdomain, 'name', None):
            allowed.add(vuln.subdomain.name.lower())
    if not allowed:
        raise MsfAuxError('no in-scope hosts found for project', status=403)
    for host in hosts:
        ok = host in allowed or any(host.endswith('.' + a) for a in allowed)
        if not ok:
            raise MsfAuxError(f'RHOSTS host out of scope: {host}', status=403)


def propose_attempt(
    *,
    project_slug: str,
    module: str,
    options: dict[str, Any] | None = None,
    vulnerability_id: int | None = None,
    scan_id: int | None = None,
    rationale: str = '',
    user=None,
):
    from copilot.models import MsfAuxAttempt

    try:
        entry, opts = validate_module_options(module, options)
    except MsfCatalogError as exc:
        raise MsfAuxError(str(exc), status=exc.status) from exc
    assert_rhosts_in_scope(
        opts,
        project_slug=project_slug,
        scan_id=scan_id,
        vulnerability_id=vulnerability_id,
    )
    attempt = MsfAuxAttempt.objects.create(
        project_slug=project_slug,
        scan_id=scan_id,
        vulnerability_id=vulnerability_id,
        module=str(entry['module']),
        options=opts,
        rationale=(rationale or '')[:4000],
        status=MsfAuxAttempt.STATUS_PROPOSED,
        created_by=user if getattr(user, 'is_authenticated', False) else None,
    )
    logger.info('msf_aux proposed id=%s module=%s', attempt.id, attempt.module)
    return attempt


def _start_msf_aux_workflow(attempt_id: int) -> str:
    from reNgine.temporal_client import TemporalClientProvider, run_and_close

    workflow_id = f'msf-aux-{attempt_id}'

    async def _start():
        client = await TemporalClientProvider.get_client()
        await client.start_workflow(
            'MsfAuxWorkflow',
            args=[{'attempt_id': attempt_id}],
            id=workflow_id,
            task_queue='python-orchestrator-queue',
        )

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    run_and_close(loop, _start())
    return workflow_id


def approve_and_start(attempt, *, user=None):
    from copilot.models import MsfAuxAttempt
    from copilot.trace import emit_trace

    with transaction.atomic():
        locked = (
            MsfAuxAttempt.objects
            .select_for_update()
            .filter(pk=attempt.pk)
            .first()
        )
        if not locked:
            raise MsfAuxError('attempt not found', 404)
        if locked.status != MsfAuxAttempt.STATUS_PROPOSED:
            raise MsfAuxError(f'cannot approve status={locked.status}', 409)
        locked.status = MsfAuxAttempt.STATUS_RUNNING
        locked.approved_at = timezone.now()
        locked.decided_by = user if getattr(user, 'is_authenticated', False) else None
        locked.save(update_fields=['status', 'approved_at', 'decided_by', 'updated_at'])
        attempt_id = locked.id
        module = locked.module

    try:
        wf_id = _start_msf_aux_workflow(attempt_id)
    except Exception as exc:
        logger.exception('msf_aux workflow start failed id=%s', attempt_id)
        with transaction.atomic():
            locked = (
                MsfAuxAttempt.objects
                .select_for_update()
                .filter(pk=attempt_id)
                .first()
            )
            if locked and locked.status == MsfAuxAttempt.STATUS_RUNNING:
                locked.status = MsfAuxAttempt.STATUS_FAILED
                locked.error = f'workflow_start_failed: {exc}'[:2000]
                locked.completed_at = timezone.now()
                locked.save(update_fields=['status', 'error', 'completed_at', 'updated_at'])
        raise MsfAuxError(f'failed to start Temporal workflow: {exc}', status=502) from exc

    with transaction.atomic():
        locked = MsfAuxAttempt.objects.select_for_update().filter(pk=attempt_id).first()
        if locked and locked.status == MsfAuxAttempt.STATUS_ABORTED:
            _cancel_workflow(wf_id)
            return locked
        if locked:
            locked.temporal_workflow_id = wf_id
            locked.save(update_fields=['temporal_workflow_id', 'updated_at'])
    emit_trace(
        project_slug=locked.project_slug if locked else '',
        event_type='msf_aux',
        summary=f'MSF aux run started: {module}',
        payload={'attempt_id': attempt_id, 'module': module, 'workflow_id': wf_id},
        msf_aux_attempt_id=attempt_id,
    )
    return locked or attempt


def _cancel_workflow(workflow_id: str) -> None:
    from reNgine.temporal_client import TemporalClientProvider, run_and_close

    async def _cancel():
        client = await TemporalClientProvider.get_client()
        try:
            handle = client.get_workflow_handle(workflow_id)
            await handle.cancel()
            logger.info('msf_aux workflow cancel requested workflow_id=%s', workflow_id)
        except Exception:
            logger.warning('Could not cancel msf_aux workflow %s', workflow_id, exc_info=True)

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        run_and_close(loop, _cancel())
    except Exception:
        logger.exception('Temporal cancel failed for msf_aux %s', workflow_id)


def abort_attempt(attempt, *, user=None):
    from copilot.models import MsfAuxAttempt

    workflow_id = None
    with transaction.atomic():
        locked = (
            MsfAuxAttempt.objects
            .select_for_update()
            .filter(pk=attempt.pk)
            .first()
        )
        if not locked:
            raise MsfAuxError('attempt not found', 404)
        if locked.status in (
            MsfAuxAttempt.STATUS_SUCCEEDED,
            MsfAuxAttempt.STATUS_FAILED,
            MsfAuxAttempt.STATUS_REJECTED,
            MsfAuxAttempt.STATUS_ABORTED,
        ):
            return locked
        locked.status = MsfAuxAttempt.STATUS_ABORTED
        locked.decided_by = user if getattr(user, 'is_authenticated', False) else None
        locked.completed_at = timezone.now()
        locked.save(update_fields=['status', 'decided_by', 'completed_at', 'updated_at'])
        workflow_id = locked.temporal_workflow_id or None
        attempt = locked
    if workflow_id:
        _cancel_workflow(workflow_id)
    return attempt


def _nest_enrichment(attempt, result: dict[str, Any]) -> None:
    if not attempt.vulnerability_id:
        return
    from copilot.service import CopilotError, _vuln_for_project

    try:
        vuln = _vuln_for_project(int(attempt.vulnerability_id), attempt.project_slug)
    except CopilotError:
        return
    enrichment = dict(vuln.agent_enrichment or {})
    enrichment['msf_aux'] = {
        'attempt_id': attempt.id,
        'module': attempt.module,
        'options': attempt.options,
        'status': attempt.status,
        'result': result,
        'agent_id': 'assessment-copilot',
        'updated_at': _utc_now_iso(),
    }
    vuln.agent_enrichment = enrichment
    vuln.save(update_fields=['agent_enrichment'])


def execute_attempt(attempt_id: int) -> dict[str, Any]:
    """Run allowlisted module via MSFRPC. Never sets validation_status=verified."""
    from copilot.models import MsfAuxAttempt
    from copilot.trace import emit_trace

    with transaction.atomic():
        attempt = (
            MsfAuxAttempt.objects
            .select_for_update()
            .filter(pk=attempt_id)
            .first()
        )
        if not attempt:
            raise MsfAuxError('attempt not found', 404)
        if attempt.status == MsfAuxAttempt.STATUS_ABORTED:
            return {'status': 'aborted', 'aborted': True}
        if attempt.status in (
            MsfAuxAttempt.STATUS_SUCCEEDED,
            MsfAuxAttempt.STATUS_FAILED,
            MsfAuxAttempt.STATUS_REJECTED,
        ):
            return {'status': attempt.status, 'result': attempt.result}
        module = attempt.module
        options = dict(attempt.options or {})
        project_slug = attempt.project_slug

    try:
        validate_module_options(module, options)
        assert_rhosts_in_scope(
            options,
            project_slug=project_slug,
            scan_id=attempt.scan_id,
            vulnerability_id=attempt.vulnerability_id,
        )
    except (MsfCatalogError, MsfAuxError) as exc:
        with transaction.atomic():
            locked = MsfAuxAttempt.objects.select_for_update().filter(pk=attempt_id).first()
            if locked and locked.status not in (
                MsfAuxAttempt.STATUS_ABORTED,
                MsfAuxAttempt.STATUS_SUCCEEDED,
            ):
                locked.status = MsfAuxAttempt.STATUS_FAILED
                locked.error = str(exc)[:2000]
                locked.completed_at = timezone.now()
                locked.save(update_fields=['status', 'error', 'completed_at', 'updated_at'])
        return {'status': 'failed', 'error': str(exc)}

    # Claim before any MSFRPC traffic so Temporal retries never re-run the module.
    with transaction.atomic():
        locked = MsfAuxAttempt.objects.select_for_update().filter(pk=attempt_id).first()
        if not locked:
            raise MsfAuxError('attempt not found', 404)
        if locked.status == MsfAuxAttempt.STATUS_ABORTED:
            return {'status': 'aborted', 'aborted': True}
        if locked.status in (
            MsfAuxAttempt.STATUS_SUCCEEDED,
            MsfAuxAttempt.STATUS_FAILED,
            MsfAuxAttempt.STATUS_REJECTED,
        ):
            return {'status': locked.status, 'result': locked.result}
        prior = locked.result if isinstance(locked.result, dict) else {}
        if prior.get('execution_claimed'):
            locked.status = MsfAuxAttempt.STATUS_FAILED
            locked.error = (
                'Previous MSF execution was interrupted before completion; '
                'not retried to avoid duplicate module traffic. Inspect MSF '
                'manually or propose a new attempt.'
            )
            locked.completed_at = timezone.now()
            locked.save(update_fields=['status', 'error', 'completed_at', 'updated_at'])
            emit_trace(
                project_slug=locked.project_slug,
                event_type='msf_aux',
                summary=f'MSF aux interrupted (no retry): {locked.module}',
                payload={'attempt_id': locked.id, 'error': locked.error[:500]},
                msf_aux_attempt_id=locked.id,
            )
            return {'status': 'failed', 'error': locked.error}
        locked.result = {
            'execution_claimed': True,
            'claimed_at': _utc_now_iso(),
        }
        locked.save(update_fields=['result', 'updated_at'])

    def _abort_check() -> bool:
        return MsfAuxAttempt.objects.filter(
            pk=attempt_id,
            status=MsfAuxAttempt.STATUS_ABORTED,
        ).exists()

    output = ''
    try:
        with MsfrpcClient() as client:
            # Console-only: captures aux/post text without a second module.execute.
            lines = [
                f'use {module}',
                *[f'set {k} {v}' for k, v in options.items()],
                'run',
            ]
            output = client.console_create_and_run(lines, abort_check=_abort_check)
    except MsfrpcError as exc:
        if 'aborted' in str(exc).lower():
            return {'status': 'aborted', 'aborted': True}
        with transaction.atomic():
            locked = MsfAuxAttempt.objects.select_for_update().filter(pk=attempt_id).first()
            if locked and locked.status == MsfAuxAttempt.STATUS_ABORTED:
                return {'status': 'aborted', 'aborted': True}
            if locked:
                locked.status = MsfAuxAttempt.STATUS_FAILED
                locked.error = str(exc)[:2000]
                locked.completed_at = timezone.now()
                locked.result = {'error': str(exc)}
                locked.save(update_fields=['status', 'error', 'result', 'completed_at', 'updated_at'])
                _nest_enrichment(locked, locked.result or {})
                emit_trace(
                    project_slug=locked.project_slug,
                    event_type='msf_aux',
                    summary=f'MSF aux failed: {locked.module}',
                    payload={'attempt_id': locked.id, 'error': str(exc)[:500]},
                    msf_aux_attempt_id=locked.id,
                )
        return {'status': 'failed', 'error': str(exc)}

    result = {
        'output': (output or '')[:MAX_OUTPUT],
        'truncated': len(output or '') > MAX_OUTPUT,
        'completed_at': _utc_now_iso(),
    }
    with transaction.atomic():
        locked = MsfAuxAttempt.objects.select_for_update().filter(pk=attempt_id).first()
        if not locked:
            return {'status': 'failed', 'error': 'attempt missing'}
        if locked.status == MsfAuxAttempt.STATUS_ABORTED:
            return {'status': 'aborted', 'aborted': True}
        locked.status = MsfAuxAttempt.STATUS_SUCCEEDED
        locked.result = result
        locked.error = ''
        locked.completed_at = timezone.now()
        locked.save(update_fields=['status', 'result', 'error', 'completed_at', 'updated_at'])
        _nest_enrichment(locked, result)
        emit_trace(
            project_slug=locked.project_slug,
            event_type='msf_aux',
            summary=f'MSF aux succeeded: {locked.module}',
            payload={'attempt_id': locked.id, 'module': locked.module},
            msf_aux_attempt_id=locked.id,
        )
        return {'status': locked.status, 'result': result}


def nest_recommend_on_vuln(
    *,
    vulnerability_id: int,
    project_slug: str,
    module: str,
    options: dict[str, str],
    rationale: str = '',
) -> dict[str, Any]:
    """Persist a recommendation-only blob under agent_enrichment.msf_aux (no Temporal)."""
    from copilot.service import _vuln_for_project

    vuln = _vuln_for_project(int(vulnerability_id), project_slug)
    enrichment = dict(vuln.agent_enrichment or {})
    blob = {
        'mode': 'recommend',
        'module': module,
        'options': options,
        'rationale': (rationale or '')[:2000],
        'agent_id': 'assessment-copilot',
        'updated_at': _utc_now_iso(),
    }
    enrichment['msf_aux'] = blob
    vuln.agent_enrichment = enrichment
    vuln.save(update_fields=['agent_enrichment'])
    return blob
