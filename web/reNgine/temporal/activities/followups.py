"""Follow-up plan Temporal activities — dispatch and status updates."""
from __future__ import annotations

import logging
from typing import Any, Optional

from temporalio import activity

logger = logging.getLogger(__name__)


@activity.defn(name="FollowupLoadPlanActivity")
def followup_load_plan_activity(plan_id: int) -> dict:
    from mcp.models import FollowupPlan
    from mcp.followups import serialize_plan

    plan = FollowupPlan.objects.filter(pk=plan_id).first()
    if not plan:
        raise ValueError(f'FollowupPlan {plan_id} not found')
    return serialize_plan(plan)


@activity.defn(name="FollowupUpdateStepActivity")
def followup_update_step_activity(
    plan_id: int,
    step_id: str,
    status: str,
    error: Optional[str] = None,
    workflow_id: Optional[str] = None,
    activity_id: Optional[int] = None,
) -> dict:
    from mcp.models import FollowupPlan
    from django.utils import timezone

    plan = FollowupPlan.objects.filter(pk=plan_id).first()
    if not plan:
        raise ValueError(f'FollowupPlan {plan_id} not found')
    if plan.status == FollowupPlan.STATUS_ABORTED:
        return {'aborted': True, 'plan_status': plan.status}

    steps = []
    for s in plan.steps or []:
        s = dict(s)
        if s.get('id') == step_id:
            s['status'] = status
            if error is not None:
                s['error'] = error
            if workflow_id is not None:
                s['workflow_id'] = workflow_id
            if activity_id is not None:
                s['activity_id'] = activity_id
        steps.append(s)
    plan.steps = steps
    plan.save(update_fields=['steps', 'updated_at'])
    return {'ok': True, 'plan_status': plan.status}


@activity.defn(name="FollowupFinalizePlanActivity")
def followup_finalize_plan_activity(plan_id: int, success: bool) -> dict:
    from mcp.models import FollowupPlan
    from django.utils import timezone

    plan = FollowupPlan.objects.filter(pk=plan_id).first()
    if not plan:
        raise ValueError(f'FollowupPlan {plan_id} not found')
    if plan.status == FollowupPlan.STATUS_ABORTED:
        return {'status': plan.status}

    # Derive final status from steps if any failed
    statuses = [s.get('status') for s in (plan.steps or [])]
    if plan.status == FollowupPlan.STATUS_ABORTED:
        final = FollowupPlan.STATUS_ABORTED
    elif any(st == 'failed' for st in statuses):
        final = FollowupPlan.STATUS_FAILED
    elif success and all(st in ('succeeded', 'skipped') for st in statuses if st):
        final = FollowupPlan.STATUS_DONE
    elif success:
        final = FollowupPlan.STATUS_DONE
    else:
        final = FollowupPlan.STATUS_FAILED
    plan.status = final
    plan.completed_at = timezone.now()
    plan.save(update_fields=['status', 'completed_at', 'updated_at'])
    return {'status': final}


@activity.defn(name="FollowupCheckAbortActivity")
def followup_check_abort_activity(plan_id: int) -> bool:
    from mcp.models import FollowupPlan
    plan = FollowupPlan.objects.filter(pk=plan_id).first()
    return bool(plan and plan.status == FollowupPlan.STATUS_ABORTED)


@activity.defn(name="FollowupDispatchStepActivity")
def followup_dispatch_step_activity(plan_id: int, step: dict) -> dict:
    """Start the work for one plan step and return workflow/activity ids.

    Does not wait for completion — the FollowupPlanWorkflow waits on child
    workflows when a workflow_id is returned.
    """
    from api.tool_run import ToolRunError, start_pipeline_tool_run, start_workflow_tool_run
    from reNgine.tasks import initiate_subscan_temporal
    import asyncio
    from reNgine.temporal_client import TemporalClientProvider, run_and_close
    from django.utils import timezone

    kind = step.get('kind')
    try:
        if kind == 'run_tool':
            tool_kind = step.get('tool_kind') or 'pipeline'
            if tool_kind == 'workflow':
                result = start_workflow_tool_run(
                    workflow_slug=step['tool'],
                    scan_id=step.get('scan_history_id'),
                    url=step.get('url'),
                    asset_id=step.get('asset_id'),
                )
                return {
                    'ok': True,
                    'workflow_id': result.get('workflow_id'),
                    'wait': False,  # standalone workflows — fire and mark succeeded after start
                }
            result = start_pipeline_tool_run(
                tool=step['tool'],
                asset_type=step['asset_type'],
                scan_id=int(step['scan_history_id']),
                asset_id=step.get('asset_id'),
                url=step.get('url'),
                tool_args=step.get('tool_args'),
            )
            return {
                'ok': True,
                'workflow_id': result.get('workflow_id'),
                'activity_id': result.get('activity_id'),
                'wait': True,
            }

        if kind == 'start_subscan':
            errors = []
            wf_ids = []
            for sub_id in step.get('subdomain_ids') or []:
                res = initiate_subscan_temporal(
                    scan_history_id=None,
                    subdomain_id=sub_id,
                    engine_id=step.get('engine_id'),
                    scan_type=step.get('tasks'),
                )
                if not res.get('success'):
                    errors.append(res.get('error') or f'subscan failed for {sub_id}')
                    # Cancel already-started siblings so a failed step does not leave orphans.
                    if wf_ids:
                        async def _cancel_started(ids=list(wf_ids)):
                            client = await TemporalClientProvider.get_client()
                            for wid in ids:
                                if not wid:
                                    continue
                                try:
                                    await client.get_workflow_handle(wid).cancel()
                                except Exception:
                                    logger.warning(
                                        'Could not cancel orphan subscan workflow %s',
                                        wid,
                                        exc_info=True,
                                    )

                        try:
                            loop = asyncio.new_event_loop()
                            run_and_close(loop, _cancel_started())
                        except Exception:
                            logger.exception(
                                'Failed cancelling orphan subscans for plan %s step %s',
                                plan_id,
                                step.get('id'),
                            )
                    return {
                        'ok': False,
                        'error': '; '.join(errors),
                        'workflow_ids': wf_ids,
                    }
                else:
                    wf_ids.append(res.get('workflow_id'))
            return {
                'ok': True,
                'workflow_id': wf_ids[0] if wf_ids else None,
                'workflow_ids': wf_ids,
                'wait': True,
            }

        if kind == 'start_workflow':
            from api.views.tools import _WORKFLOW_REGISTRY
            slug = step['workflow_slug']
            workflow_name, required = _WORKFLOW_REGISTRY[slug]
            data: dict[str, Any] = {'yaml_configuration': {}}
            if 'urls' in required:
                data['urls'] = step.get('urls') or []
            if 'domain' in required:
                data['domain'] = step.get('domain')
            if 'target' in required:
                data['target'] = step.get('target')
                data['target_type'] = step.get('target_type') or 'host'
            if step.get('scan_history_id'):
                data['scan_history_id'] = step['scan_history_id']
            wf_id = f"followup-wf-{slug}-{plan_id}-{step.get('id')}-{int(timezone.now().timestamp())}"

            async def _start():
                client = await TemporalClientProvider.get_client()
                handle = await client.start_workflow(
                    workflow_name,
                    data,
                    id=wf_id,
                    task_queue='python-orchestrator-queue',
                )
                return handle.id

            loop = asyncio.new_event_loop()
            started = run_and_close(loop, _start())
            return {'ok': True, 'workflow_id': started or wf_id, 'wait': False}

        if kind == 'retry_task':
            from startScan.models import ScanActivity
            from reNgine.definitions import (
                FAILED_TASK, ABORTED_TASK, INITIATED_TASK, RUNNING_TASK, SUCCESS_TASK, PAUSED_TASK,
            )
            import yaml
            from django.db import transaction
            from startScan.models import ScanHistory
            from reNgine.utils.scan_cancellation import set_scan_stop_kill_switch

            activity_obj = ScanActivity.objects.filter(pk=step['task_id']).first()
            if not activity_obj or not activity_obj.scan_of_id:
                return {'ok': False, 'error': 'task not found'}
            scan = activity_obj.scan_of
            if scan.scan_status in (RUNNING_TASK, PAUSED_TASK):
                return {'ok': False, 'error': 'scan is running or paused'}
            original = scan.scan_status
            with transaction.atomic():
                ScanActivity.objects.filter(pk=activity_obj.pk).update(
                    status=INITIATED_TASK,
                    time_ended=None,
                    error_message=None,
                    traceback=None,
                    time=timezone.now(),
                )
                scan.scan_status = RUNNING_TASK
                scan.error_message = None
                scan.stop_scan_date = None
                scan.save(update_fields=['scan_status', 'error_message', 'stop_scan_date'])
            set_scan_stop_kill_switch(scan.id, enabled=False)
            yaml_config = yaml.safe_load(scan.scan_type.yaml_configuration or '') or {}
            ctx = {
                'scan_history_id': scan.id,
                'engine_id': scan.scan_type_id,
                'domain_id': scan.domain_id,
                'results_dir': scan.results_dir,
                'yaml_configuration': yaml_config,
                'tasks': [activity_obj.name],
                'original_scan_status': original,
            }
            if activity_obj.subscan_id:
                ctx['subscan_id'] = activity_obj.subscan_id
                subscan = activity_obj.subscan
                if subscan and subscan.subdomain_id:
                    ctx['subdomain_id'] = subscan.subdomain_id
                    ctx['subdomain_name'] = subscan.subdomain.name
            wf_id = f"retry-{activity_obj.name}-{scan.id}-{int(timezone.now().timestamp())}"

            async def _start_retry():
                client = await TemporalClientProvider.get_client()
                await client.start_workflow(
                    'SingleTaskRetryWorkflow',
                    args=[ctx, activity_obj.name],
                    id=wf_id,
                    task_queue='python-orchestrator-queue',
                )

            loop = asyncio.new_event_loop()
            run_and_close(loop, _start_retry())
            return {
                'ok': True,
                'workflow_id': wf_id,
                'activity_id': activity_obj.id,
                'wait': True,
            }

        return {'ok': False, 'error': f'unknown step kind {kind}'}
    except ToolRunError as exc:
        return {'ok': False, 'error': str(exc)}
    except Exception as exc:
        logger.exception('FollowupDispatchStepActivity failed')
        return {'ok': False, 'error': str(exc)}


@activity.defn(name="FollowupWaitWorkflowActivity")
def followup_wait_workflow_activity(workflow_id: str, timeout_hours: int = 24) -> dict:
    """Block until a Temporal workflow completes (used for sequential plan steps)."""
    import asyncio
    from datetime import timedelta
    from reNgine.temporal_client import TemporalClientProvider, run_and_close

    async def _wait():
        client = await TemporalClientProvider.get_client()
        handle = client.get_workflow_handle(workflow_id)
        try:
            await asyncio.wait_for(
                handle.result(),
                timeout=timeout_hours * 3600,
            )
            return {'ok': True}
        except asyncio.TimeoutError:
            return {'ok': False, 'error': 'workflow wait timed out'}
        except Exception as exc:
            return {'ok': False, 'error': str(exc)}

    loop = asyncio.new_event_loop()
    return run_and_close(loop, _wait())
