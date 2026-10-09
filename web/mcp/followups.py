"""Follow-up plan service — propose, edit, approve, abort, retry."""
from __future__ import annotations

import asyncio
import logging
import uuid
from typing import Any, Optional

from django.utils import timezone

from mcp.models import FollowupPlan
from reNgine.capabilities import (
    get_pipeline_tool,
    get_workflow_tool,
)
from reNgine.definitions import RUNNING_TASK
from startScan.models import EndPoint, ScanActivity, ScanHistory, Subdomain

logger = logging.getLogger(__name__)

MAX_STEPS = 5
STEP_KINDS = frozenset({'run_tool', 'start_subscan', 'start_workflow', 'retry_task'})


class FollowupError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _new_step_id() -> str:
    return uuid.uuid4().hex[:12]


def _normalize_step(raw: dict, index: int) -> dict:
    if not isinstance(raw, dict):
        raise FollowupError(f'step[{index}] must be an object')
    kind = raw.get('kind') or raw.get('step_kind') or 'run_tool'
    if kind not in STEP_KINDS:
        raise FollowupError(f'step[{index}]: unknown kind {kind}')

    step = {
        'id': raw.get('id') or _new_step_id(),
        'kind': kind,
        'status': raw.get('status') or 'pending',
        'error': raw.get('error') or None,
        'attempt': int(raw.get('attempt') or 0),
        'continue_on_error': bool(raw.get('continue_on_error', False)),
        'workflow_id': raw.get('workflow_id'),
        'activity_id': raw.get('activity_id'),
        'rationale': (raw.get('rationale') or raw.get('reason') or '')[:500],
    }

    if kind == 'run_tool':
        tool = raw.get('tool')
        if not tool:
            raise FollowupError(f'step[{index}]: tool is required')
        asset_type = raw.get('asset_type')
        if not asset_type:
            raise FollowupError(f'step[{index}]: asset_type is required')
        pipeline = get_pipeline_tool(tool)
        workflow = get_workflow_tool(tool)
        if pipeline:
            if asset_type not in pipeline['asset_kinds']:
                raise FollowupError(
                    f'step[{index}]: tool {tool} does not support asset_type={asset_type}'
                )
            step['tool'] = tool
            step['tool_kind'] = 'pipeline'
        elif workflow:
            if asset_type not in workflow['asset_kinds']:
                raise FollowupError(
                    f'step[{index}]: workflow {tool} does not support asset_type={asset_type}'
                )
            step['tool'] = tool
            step['tool_kind'] = 'workflow'
        else:
            raise FollowupError(f'step[{index}]: unknown tool {tool}')
        step['asset_type'] = asset_type
        step['asset_id'] = raw.get('asset_id')
        step['url'] = raw.get('url')
        step['scan_history_id'] = raw.get('scan_history_id') or raw.get('scan_id')
        if not step['asset_id'] and not step['url']:
            raise FollowupError(f'step[{index}]: asset_id or url required')
        if not step['scan_history_id'] and step['tool_kind'] == 'pipeline':
            raise FollowupError(f'step[{index}]: scan_history_id required for pipeline tools')
        raw_args = raw.get('tool_args')
        if raw_args is not None:
            if not isinstance(raw_args, dict):
                raise FollowupError(f'step[{index}]: tool_args must be an object')
            if step['tool_kind'] == 'pipeline':
                from reNgine.tool_args import ToolArgsError, validate_tool_args
                try:
                    validated = validate_tool_args(tool, raw_args)
                except ToolArgsError as exc:
                    raise FollowupError(f'step[{index}]: {exc}') from exc
                step['tool_args'] = validated.get('sanitized') or {}
            else:
                step['tool_args'] = raw_args

    elif kind == 'start_subscan':
        subdomain_ids = raw.get('subdomain_ids') or []
        if raw.get('subdomain_id'):
            subdomain_ids = list(subdomain_ids) + [raw['subdomain_id']]
        subdomain_ids = [int(x) for x in subdomain_ids]
        tasks = raw.get('tasks') or []
        if not subdomain_ids or not tasks:
            raise FollowupError(f'step[{index}]: subdomain_ids and tasks required')
        if len(subdomain_ids) > 5:
            raise FollowupError(f'step[{index}]: max 5 subdomains per step')
        for t in tasks:
            if not get_pipeline_tool(t):
                # Soft allow unknown task names that engines may still run
                pass
        step['subdomain_ids'] = subdomain_ids
        step['tasks'] = list(tasks)
        step['engine_id'] = raw.get('engine_id')

    elif kind == 'start_workflow':
        slug = raw.get('workflow_slug') or raw.get('tool')
        if not slug or not get_workflow_tool(slug):
            # Allow registry workflows even if not in soft catalog
            from api.views.tools import _WORKFLOW_REGISTRY
            if not slug or slug not in _WORKFLOW_REGISTRY:
                raise FollowupError(f'step[{index}]: unknown workflow_slug')
        step['workflow_slug'] = slug
        step['urls'] = raw.get('urls') or ([raw['url']] if raw.get('url') else [])
        step['domain'] = raw.get('domain')
        step['target'] = raw.get('target')
        step['target_type'] = raw.get('target_type')
        step['scan_history_id'] = raw.get('scan_history_id') or raw.get('scan_id')

    elif kind == 'retry_task':
        task_id = raw.get('task_id') or raw.get('activity_id')
        if not task_id:
            raise FollowupError(f'step[{index}]: task_id required')
        step['task_id'] = int(task_id)

    return step


def _hostname_in_domain(hostname: str, domain_name: str) -> bool:
    host = (hostname or '').lower().rstrip('.')
    base = (domain_name or '').lower().rstrip('.')
    if not host or not base:
        return False
    return host == base or host.endswith('.' + base)


def _validate_url_against_domains(url: str, allowed_domain_names: set[str]) -> None:
    from urllib.parse import urlparse

    raw = (url or '').strip()
    if not raw:
        raise FollowupError('url is required for url/host asset steps')
    parsed = urlparse(raw if '://' in raw else f'https://{raw}')
    host = parsed.hostname or (raw if '://' not in raw else None)
    if not host:
        raise FollowupError(f'could not parse host from url: {url}')
    if not any(_hostname_in_domain(host, name) for name in allowed_domain_names):
        raise FollowupError(f'url host {host} is outside plan domain scope')


def _validate_scope(steps: list[dict], project_slug: str, scan_id: Optional[int]) -> None:
    """Reject mixed out-of-scope assets across steps."""
    from targetApp.models import Domain

    domain_ids = set()
    if scan_id:
        scan = ScanHistory.objects.select_related('domain').filter(pk=scan_id).first()
        if not scan:
            raise FollowupError('scan_id not found', 404)
        if scan.domain.project.slug != project_slug:
            raise FollowupError('scan_id is outside project_slug')
        domain_ids.add(scan.domain_id)

    for step in steps:
        if step['kind'] == 'run_tool':
            sid = step.get('scan_history_id')
            if sid:
                scan = ScanHistory.objects.select_related('domain__project').filter(pk=sid).first()
                if not scan:
                    raise FollowupError(f'scan_history_id {sid} not found', 404)
                if scan.domain.project.slug != project_slug:
                    raise FollowupError('step scan is outside project_slug')
                domain_ids.add(scan.domain_id)
            aid = step.get('asset_id')
            if aid and step.get('asset_type') == 'subdomain':
                sub = Subdomain.objects.select_related('target_domain__project').filter(pk=aid).first()
                if sub and sub.target_domain_id:
                    if sub.target_domain.project.slug != project_slug:
                        raise FollowupError(f'subdomain {aid} outside project')
                    domain_ids.add(sub.target_domain_id)
            if aid and step.get('asset_type') == 'endpoint':
                ep = EndPoint.objects.select_related('target_domain__project').filter(pk=aid).first()
                if ep and ep.target_domain_id:
                    if ep.target_domain.project.slug != project_slug:
                        raise FollowupError(f'endpoint {aid} outside project')
                    domain_ids.add(ep.target_domain_id)
            if step.get('asset_type') in ('url', 'host') and step.get('url'):
                if not domain_ids and not sid and not scan_id:
                    raise FollowupError('url/host steps require scan_history_id or plan scan_id')
                names = set(
                    Domain.objects.filter(pk__in=domain_ids).values_list('name', flat=True)
                )
                if not names and sid:
                    scan = ScanHistory.objects.select_related('domain').filter(pk=sid).first()
                    if scan and scan.domain_id:
                        names.add(scan.domain.name)
                if not names:
                    raise FollowupError('url/host steps require a scoped scan domain')
                _validate_url_against_domains(step['url'], names)
        elif step['kind'] == 'start_subscan':
            for sid in step['subdomain_ids']:
                sub = Subdomain.objects.select_related('target_domain__project').filter(pk=sid).first()
                if not sub:
                    raise FollowupError(f'subdomain {sid} not found', 404)
                if sub.target_domain.project.slug != project_slug:
                    raise FollowupError(f'subdomain {sid} outside project')
                domain_ids.add(sub.target_domain_id)
        elif step['kind'] == 'retry_task':
            act = ScanActivity.objects.select_related('scan_of__domain__project').filter(
                pk=step['task_id']
            ).first()
            if not act or not act.scan_of_id:
                raise FollowupError(f'task {step["task_id"]} not found', 404)
            if act.scan_of.domain.project.slug != project_slug:
                raise FollowupError('retry task outside project')
            domain_ids.add(act.scan_of.domain_id)

    if len(domain_ids) > 1:
        raise FollowupError('mixed out-of-scope assets: all steps must target one domain')


def normalize_steps(raw_steps: list) -> list[dict]:
    if not isinstance(raw_steps, list) or not raw_steps:
        raise FollowupError('steps must be a non-empty list')
    if len(raw_steps) > MAX_STEPS:
        raise FollowupError(f'max {MAX_STEPS} steps per plan')
    return [_normalize_step(s, i) for i, s in enumerate(raw_steps)]


def serialize_plan(plan: FollowupPlan) -> dict[str, Any]:
    return {
        'id': plan.id,
        'project_slug': plan.project_slug,
        'scan_id': plan.scan_id,
        'assessment_id': plan.assessment_id,
        'status': plan.status,
        'rationale': plan.rationale,
        'steps': plan.steps or [],
        'temporal_workflow_ids': plan.temporal_workflow_ids or [],
        'retry_count': plan.retry_count,
        'operator_edited': plan.operator_edited,
        'created_by_id': plan.created_by_id,
        'updated_by_id': plan.updated_by_id,
        'created_at': plan.created_at.isoformat() if plan.created_at else None,
        'updated_at': plan.updated_at.isoformat() if plan.updated_at else None,
        'approved_at': plan.approved_at.isoformat() if plan.approved_at else None,
        'completed_at': plan.completed_at.isoformat() if plan.completed_at else None,
    }


def propose_plan(
    *,
    project_slug: str,
    steps: list,
    rationale: str = '',
    scan_id: Optional[int] = None,
    assessment_id: Optional[int] = None,
    user=None,
) -> FollowupPlan:
    from dashboard.models import Project
    if not project_slug:
        raise FollowupError('project_slug is required')
    if not Project.objects.filter(slug=project_slug).exists():
        raise FollowupError('project_slug not found', 404)
    normalized = normalize_steps(steps)
    _validate_scope(normalized, project_slug, scan_id)
    plan = FollowupPlan.objects.create(
        project_slug=project_slug,
        scan_id=scan_id,
        assessment_id=assessment_id,
        status=FollowupPlan.STATUS_PROPOSED,
        rationale=(rationale or '')[:2000],
        steps=normalized,
        created_by=user if getattr(user, 'pk', None) else None,
        updated_by=user if getattr(user, 'pk', None) else None,
    )
    return plan


def update_plan_steps(
    plan: FollowupPlan,
    steps: list,
    *,
    user=None,
    is_operator: bool = False,
) -> FollowupPlan:
    if plan.status != FollowupPlan.STATUS_PROPOSED:
        raise FollowupError('only proposed plans can be edited')
    if plan.operator_edited and not is_operator:
        raise FollowupError(
            'plan was edited by an operator; agent cannot overwrite',
            403,
        )
    normalized = normalize_steps(steps)
    _validate_scope(normalized, plan.project_slug, plan.scan_id)
    plan.steps = normalized
    if is_operator:
        plan.operator_edited = True
    if user and getattr(user, 'pk', None):
        plan.updated_by = user
    plan.save(update_fields=['steps', 'operator_edited', 'updated_by', 'updated_at'])
    return plan


def _start_plan_workflow(plan_id: int, step_ids: Optional[list[str]] = None) -> str:
    from reNgine.temporal_client import TemporalClientProvider, run_and_close

    workflow_id = f"followup-plan-{plan_id}-{int(timezone.now().timestamp())}"

    async def _start():
        client = await TemporalClientProvider.get_client()
        await client.start_workflow(
            'FollowupPlanWorkflow',
            args=[{'plan_id': plan_id, 'step_ids': step_ids}],
            id=workflow_id,
            task_queue='python-orchestrator-queue',
        )

    loop = asyncio.new_event_loop()
    asyncio.set_event_loop(loop)
    run_and_close(loop, _start())
    return workflow_id


def approve_plan(
    plan: FollowupPlan,
    *,
    steps: Optional[list] = None,
    user=None,
) -> FollowupPlan:
    if plan.status not in (FollowupPlan.STATUS_PROPOSED, FollowupPlan.STATUS_APPROVED):
        raise FollowupError(f'cannot approve plan in status={plan.status}')
    if steps is not None:
        update_plan_steps(plan, steps, user=user, is_operator=True)
        plan.refresh_from_db()

    plan.status = FollowupPlan.STATUS_RUNNING
    plan.approved_at = timezone.now()
    if user and getattr(user, 'pk', None):
        plan.updated_by = user
    # Reset pending steps
    new_steps = []
    for s in plan.steps or []:
        s = dict(s)
        if s.get('status') in (None, 'pending', 'proposed'):
            s['status'] = 'pending'
        new_steps.append(s)
    plan.steps = new_steps
    plan.save()

    try:
        wf_id = _start_plan_workflow(plan.id)
        ids = list(plan.temporal_workflow_ids or [])
        ids.append(wf_id)
        plan.temporal_workflow_ids = ids
        plan.save(update_fields=['temporal_workflow_ids', 'updated_at'])
    except Exception as exc:
        logger.exception('Failed to start FollowupPlanWorkflow')
        plan.status = FollowupPlan.STATUS_FAILED
        plan.save(update_fields=['status', 'updated_at'])
        raise FollowupError(f'failed to start plan workflow: {exc}', 502) from exc
    return plan


def abort_plan(plan: FollowupPlan, *, user=None) -> FollowupPlan:
    if plan.status in (
        FollowupPlan.STATUS_DONE,
        FollowupPlan.STATUS_ABORTED,
        FollowupPlan.STATUS_REJECTED,
    ):
        return plan  # idempotent
    if plan.status not in (
        FollowupPlan.STATUS_APPROVED,
        FollowupPlan.STATUS_RUNNING,
    ):
        raise FollowupError(f'cannot abort plan in status={plan.status}')

    plan.status = FollowupPlan.STATUS_ABORTED
    plan.completed_at = timezone.now()
    if user and getattr(user, 'pk', None):
        plan.updated_by = user
    steps = []
    for s in plan.steps or []:
        s = dict(s)
        if s.get('status') in ('pending', 'running'):
            s['status'] = 'skipped' if s.get('status') == 'pending' else 'aborted'
        steps.append(s)
    plan.steps = steps
    plan.save()

    _cancel_plan_workflows(plan)
    return plan


def _cancel_plan_workflows(plan: FollowupPlan) -> None:
    """Cancel plan/step Temporal workflows only — never abort the parent ScanHistory.

    Singular ``run_tool`` steps may temporarily flip a finished scan to RUNNING;
    aborting the scan would mark a completed assessment ABORTED. Cancel the tool
    workflows instead and restore SUCCESS when no master-scan activities remain.
    """
    from reNgine.definitions import SUCCESS_TASK
    from reNgine.temporal_client import TemporalClientProvider, run_and_close

    async def _cancel_all():
        client = await TemporalClientProvider.get_client()
        for wf_id in plan.temporal_workflow_ids or []:
            try:
                handle = client.get_workflow_handle(wf_id)
                await handle.cancel()
            except Exception:
                logger.warning('Could not cancel workflow %s', wf_id, exc_info=True)
        for step in plan.steps or []:
            wid = step.get('workflow_id')
            if not wid:
                continue
            try:
                handle = client.get_workflow_handle(wid)
                await handle.cancel()
            except Exception:
                logger.warning('Could not cancel step workflow %s', wid, exc_info=True)
            for extra in step.get('workflow_ids') or []:
                if not extra or extra == wid:
                    continue
                try:
                    handle = client.get_workflow_handle(extra)
                    await handle.cancel()
                except Exception:
                    logger.warning('Could not cancel step workflow %s', extra, exc_info=True)

    try:
        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        run_and_close(loop, _cancel_all())
    except Exception:
        logger.exception('Temporal cancel failed for plan %s', plan.id)

    if not plan.scan_id:
        return
    scan = ScanHistory.objects.filter(pk=plan.scan_id).first()
    if not scan or scan.scan_status != RUNNING_TASK:
        return
    had_singular = any(s.get('kind') == 'run_tool' for s in (plan.steps or []))
    if not had_singular:
        return
    # Leave a true master scan alone; only unwind singular-tool RUNNING flips.
    live_master = ScanActivity.objects.filter(
        scan_of_id=scan.id,
        status=RUNNING_TASK,
    ).exclude(title__endswith='(singular)').exists()
    if live_master:
        return
    scan.scan_status = SUCCESS_TASK
    scan.save(update_fields=['scan_status'])


def retry_plan(
    plan: FollowupPlan,
    *,
    step_ids: Optional[list[str]] = None,
    include_succeeded: bool = False,
    user=None,
) -> FollowupPlan:
    if plan.status not in (FollowupPlan.STATUS_FAILED, FollowupPlan.STATUS_ABORTED):
        raise FollowupError(
            f'retry only allowed for failed/aborted plans (got {plan.status})'
        )

    selected = set(step_ids or [])
    new_steps = []
    for s in plan.steps or []:
        s = dict(s)
        should = False
        if selected:
            should = s.get('id') in selected
        elif include_succeeded:
            should = True
        else:
            should = s.get('status') in ('failed', 'aborted', 'skipped', 'pending')
        if should:
            if s.get('status') == 'succeeded' and not include_succeeded and not selected:
                pass
            else:
                s['status'] = 'pending'
                s['error'] = None
                s['attempt'] = int(s.get('attempt') or 0) + 1
                s['workflow_id'] = None
        new_steps.append(s)

    plan.steps = new_steps
    plan.status = FollowupPlan.STATUS_RUNNING
    plan.retry_count = (plan.retry_count or 0) + 1
    plan.completed_at = None
    if user and getattr(user, 'pk', None):
        plan.updated_by = user
    plan.save()

    retry_ids = [
        s['id'] for s in new_steps
        if s.get('status') == 'pending'
    ]
    try:
        wf_id = _start_plan_workflow(plan.id, step_ids=retry_ids or None)
        ids = list(plan.temporal_workflow_ids or [])
        ids.append(wf_id)
        plan.temporal_workflow_ids = ids
        plan.save(update_fields=['temporal_workflow_ids', 'updated_at'])
    except Exception as exc:
        logger.exception('Failed to start retry FollowupPlanWorkflow')
        plan.status = FollowupPlan.STATUS_FAILED
        plan.save(update_fields=['status', 'updated_at'])
        raise FollowupError(f'failed to start retry workflow: {exc}', 502) from exc
    return plan


def followup_metrics() -> dict[str, Any]:
    """Aggregate follow-up plan metrics for operators."""
    qs = FollowupPlan.objects.all()
    by_status = {}
    for status, _ in FollowupPlan.STATUS_CHOICES:
        by_status[status] = qs.filter(status=status).count()
    total = qs.count()
    approved_or_beyond = qs.exclude(
        status__in=[FollowupPlan.STATUS_PROPOSED, FollowupPlan.STATUS_REJECTED]
    ).count()
    acceptance_rate = (approved_or_beyond / total) if total else 0.0
    return {
        'total_plans': total,
        'by_status': by_status,
        'acceptance_rate': round(acceptance_rate, 3),
        'avg_retry_count': (
            qs.exclude(retry_count=0).count()
        ),
        'plans_with_retries': qs.filter(retry_count__gt=0).count(),
    }
