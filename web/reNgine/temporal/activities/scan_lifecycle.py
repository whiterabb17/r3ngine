"""
Scan lifecycle activities: initialisation, checkpoints, liveness guards, status
updates, generic task dispatch and scan/subscan finalisation.
"""

import os
import yaml

from temporalio import activity
from django.utils import timezone

from reNgine.utils.logger import get_module_logger, format_exception_for_log
from reNgine.temporal.activities.core import TemporalTaskProxy, _run_task

logger = get_module_logger(__name__)


# ===========================================================================
# Step 0 — Target Profiling & Checkpoint Management
# ===========================================================================

@activity.defn(name="LoadCheckpointActivity")
def load_checkpoint_activity(ctx: dict) -> dict:
    """Backward-compat no-op. Temporal's event history is the durable checkpoint."""
    return {}


@activity.defn(name="SaveCheckpointActivity")
def save_checkpoint_activity(ctx: dict) -> None:
    """Backward-compat no-op. Temporal's event history is the durable checkpoint."""
    return


@activity.defn(name="InitializeScanTasksActivity")
def initialize_scan_tasks_activity(ctx: dict) -> dict:
    """
    Pre-populates ScanActivity rows for every planned task so the
    timeline is visible immediately when the scan starts.
    Idempotent: uses get_or_create so retries are safe.
    """
    from django.utils import timezone as tz
    from startScan.models import ScanActivity, ScanHistory, SubScan
    from reNgine.definitions import INITIATED_TASK
    from reNgine.task_plan import build_scan_task_plan

    scan_id = ctx.get('scan_history_id')
    subscan_id = ctx.get('subscan_id')
    tasks = ctx.get('tasks', [])
    yaml_configuration = ctx.get('yaml_configuration', {})

    logger.log_line("[TEMPORAL]", "START", "task=initialize_scan_tasks scan_id=%s task_count=%d" % (scan_id, len(tasks)))

    try:
        scan = ScanHistory.objects.get(pk=scan_id)
    except ScanHistory.DoesNotExist:
        logger.warning("InitializeScanTasksActivity: ScanHistory %s not found", scan_id)
        return {'created': 0, 'existing': 0}

    subscan = None
    if subscan_id:
        try:
            subscan = SubScan.objects.get(pk=subscan_id)
        except SubScan.DoesNotExist:
            pass

    plan = build_scan_task_plan(tasks, yaml_configuration, is_subscan=bool(subscan_id))
    created_count = 0
    existing_count = 0
    now = tz.now()

    for entry in plan:
        existing = ScanActivity.objects.filter(
            scan_of=scan,
            name=entry['name'],
        ).first()
        if existing:
            updates = []
            if existing.tier != entry['tier']:
                existing.tier = entry['tier']
                updates.append('tier')
            # When a subscan reuses a parent-scan row, attach the subscan FK
            # so detail tools can scope activities to this subscan.
            if subscan and existing.subscan_id is None:
                existing.subscan = subscan
                updates.append('subscan')
            if updates:
                existing.save(update_fields=updates)
            existing_count += 1
        else:
            ScanActivity.objects.create(
                scan_of=scan,
                name=entry['name'],
                title=entry['title'],
                tier=entry['tier'],
                subscan=subscan,
                time=now,
                status=INITIATED_TASK,
            )
            created_count += 1

    logger.log_line("[TEMPORAL]", "COMPLETE", "task=initialize_scan_tasks scan_id=%s created=%d existing=%d" % (scan_id, created_count, existing_count))
    return {'created': created_count, 'existing': existing_count}


@activity.defn(name="UpdateScanStatusActivity")
def update_scan_status_activity(scan_id: int, status: int) -> None:
    """Update scan status in DB (used by pause/resume signals)."""
    from startScan.models import ScanHistory
    try:
        scan = ScanHistory.objects.get(id=scan_id)
        scan.scan_status = status
        scan.save(update_fields=["scan_status"])
        logger.log_line("[TEMPORAL]", "STATUS_UPDATE", "scan_id=%d status=%d" % (scan_id, status))
    except ScanHistory.DoesNotExist:
        logger.warning("UpdateScanStatusActivity: ScanHistory %d not found" % scan_id)


@activity.defn(name="TargetProfilingActivity")
def target_profiling_activity(ctx: dict) -> dict:
    """Validate the scan target and populate baseline scan context.

    Reads the ScanHistory record, resolves the domain, loads and caches the
    engine YAML configuration into ctx, and creates the scan results directory.

    This activity is the first real activity every scan workflow executes. It
    acts as the primary lifecycle guard: if the scan has been deleted or aborted
    in Django's DB (e.g. the user aborted/deleted the scan and the container
    restarted with Temporal replaying the workflow from its own history), this
    activity raises a non-retryable ApplicationError to permanently terminate
    the workflow without further retries.

    Args:
        ctx (dict): Temporal workflow context. Must contain 'scan_history_id'
                    and 'engine_id'.

    Returns:
        dict: Enriched ctx with 'yaml_configuration', 'results_dir', and
              'domain_name' populated.
    """
    from startScan.models import ScanHistory
    from scanEngine.models import EngineType
    from reNgine.settings import RENGINE_RESULTS
    from reNgine.definitions import RUNNING_TASK, SUCCESS_TASK, FAILED_TASK, ABORTED_TASK
    from temporalio.exceptions import ApplicationError

    scan_id = ctx.get('scan_history_id')
    activity.logger.info("[TargetProfilingActivity] Profiling scan_history_id=%s", scan_id)
    logger.log_line("[TEMPORAL]", "START", "task=target_profiling scan_id=%s" % scan_id)

    # ---------------------------------------------------------------------------
    # Lifecycle guard — abort/delete check
    # Temporal replays workflows from its own durable history after a container
    # restart, independently of Django's DB state. If the scan was deleted or
    # aborted while the container was down, we must terminate the workflow here
    # (the earliest possible point) rather than letting it run and crash later
    # with FK violations or silently overwrite the ABORTED status.
    # ApplicationError(non_retryable=True) tells Temporal to mark this activity
    # as permanently failed and propagate to the workflow without retrying.
    # ---------------------------------------------------------------------------
    scan = ScanHistory.objects.filter(pk=scan_id).first()
    if not scan:
        raise ApplicationError(
            f"[TargetProfilingActivity] ScanHistory {scan_id} no longer exists — "
            f"scan was deleted. Workflow cancelled.",
            non_retryable=True,
        )
    if scan.scan_status == ABORTED_TASK:
        raise ApplicationError(
            f"[TargetProfilingActivity] Scan {scan_id} was aborted by the user. "
            f"Workflow cancelled.",
            non_retryable=True,
        )

    proxy = TemporalTaskProxy(ctx, 'target_profiling', 'Target Profiling')
    try:
        engine_id = ctx.get('engine_id') or (scan.scan_type.id if scan.scan_type else None)
        engine = EngineType.objects.filter(pk=engine_id).first()
        if not engine:
            raise ValueError(f"EngineType with id={engine_id} not found.")

        # Re-arm status to RUNNING so the Django DB reflects reality when a
        # workflow is restarted after a prior run set it to FAILED.
        # Note: ABORTED_TASK is already blocked above — only FAILED/other non-running
        # states reach here (e.g. a legitimately failed scan being re-tried).
        if scan.scan_status != RUNNING_TASK:
            scan.scan_status = RUNNING_TASK
            scan.save(update_fields=['scan_status'])

        # Parse YAML configuration if not already done
        if 'yaml_configuration' not in ctx or not ctx['yaml_configuration']:
            ctx['yaml_configuration'] = yaml.safe_load(engine.yaml_configuration) or {}

        # Set task list from engine
        if 'tasks' not in ctx:
            ctx['tasks'] = engine.tasks or []

        # Ensure results dir exists
        results_dir = ctx.get('results_dir')
        if not results_dir:
            results_dir = f'{RENGINE_RESULTS}/{scan.domain.name}_{scan_id}'
            ctx['results_dir'] = results_dir
        os.makedirs(results_dir, exist_ok=True)

        # Enrich ctx with domain information
        ctx['domain_name'] = scan.domain.name
        ctx['engine_id'] = engine_id

        activity.logger.info(
            "[TargetProfilingActivity] Profiled target %s, tasks=%s", scan.domain.name, ctx.get('tasks')
        )
        proxy.update_scan_activity(SUCCESS_TASK)
        logger.log_line("[TEMPORAL]", "COMPLETE", "task=target_profiling scan_id=%s domain=%s" % (scan_id, scan.domain.name))
        return ctx
    except Exception as exc:
        logger.log_line("[TEMPORAL]", "ERROR", "task=target_profiling scan_id=%s error=%s" % (scan_id, format_exception_for_log(exc)), level="error")
        proxy.update_scan_activity(FAILED_TASK, error_message=repr(exc))
        raise


# ===========================================================================
# Child Workflow Lifecycle Guard
# ===========================================================================

@activity.defn(name="CheckScanAliveActivity")
def check_scan_alive_activity(scan_id: int, subscan_id: int = None) -> bool:
    """Entry-point lifecycle guard for child workflows (NucleiPlannerWorkflow, SubScanWorkflow).

    Child workflows are launched after TargetProfilingActivity has already
    completed in the parent MasterScanWorkflow. When Temporal replays a child
    workflow after a container restart, it skips the parent's TargetProfiling
    guard entirely and begins executing inside the child workflow directly.
    This activity acts as a matching guard at the start of every child workflow.

    Raises ApplicationError(non_retryable=True) if:
      - ScanHistory with scan_id no longer exists (scan was deleted by the user)
      - ScanHistory.scan_status is ABORTED_TASK (scan was aborted by the user)

    Using non_retryable=True ensures Temporal permanently marks the activity
    as failed and propagates the failure to the child workflow without any
    retry loop, which in turn cancels the child workflow cleanly.

    Args:
        scan_id (int): ScanHistory PK to check.
        subscan_id (int, optional): SubScan PK — used only for richer log context.

    Returns:
        bool: True if the scan is alive and the child workflow may proceed.

    Raises:
        ApplicationError: non_retryable if the scan is deleted or aborted.
    """
    from startScan.models import ScanHistory
    from reNgine.definitions import ABORTED_TASK
    from temporalio.exceptions import ApplicationError

    logger.log_line("[TEMPORAL]", "START", "task=check_scan_alive scan_id=%s subscan_id=%s" % (scan_id, subscan_id or ""))

    # -------------------------------------------------------------------------
    # Guard 1 — Deleted scan: ScanHistory no longer exists
    # -------------------------------------------------------------------------
    scan = ScanHistory.objects.filter(pk=scan_id).first()
    if not scan:
        activity.logger.warning(
            "[CheckScanAliveActivity] scan_id=%s — ScanHistory not found (scan deleted). "
            "Raising non-retryable error to terminate child workflow.", scan_id
        )
        raise ApplicationError(
            "[CheckScanAliveActivity] ScanHistory %s no longer exists — "
            "scan was deleted. Child workflow cancelled." % scan_id,
            non_retryable=True,
        )

    # -------------------------------------------------------------------------
    # Guard 2 — Aborted scan: user explicitly aborted this scan
    # -------------------------------------------------------------------------
    if scan.scan_status == ABORTED_TASK:
        activity.logger.warning(
            "[CheckScanAliveActivity] scan_id=%s — scan is ABORTED. "
            "Raising non-retryable error to terminate child workflow.", scan_id
        )
        raise ApplicationError(
            "[CheckScanAliveActivity] Scan %s was aborted by the user. "
            "Child workflow cancelled." % scan_id,
            non_retryable=True,
        )

    activity.logger.info(
        "[CheckScanAliveActivity] scan_id=%s — scan is alive (status=%s). Child workflow may proceed.",
        scan_id, scan.scan_status,
    )
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=check_scan_alive scan_id=%s alive=True" % scan_id)
    return True


_PERMITTED_GENERIC_TASKS = frozenset({
    "subdomain_discovery", "amass_intel_discovery", "firewall_vpn_scan",
    "dns_security", "osint", "spiderfoot_scan", "http_crawl", "port_scan", "screenshot",
    "fetch_url", "dir_file_fuzz", "web_api_discovery", "waf_detection",
    "secret_scanning", "vulnerability_scan", "waf_bypass",
    "nuclei_scan", "crlfuzz_scan", "dalfox_xss_scan", "s3scanner",
    "acunetix_scan", "cpanel_scan", "wpscan_scan", "react2shell_scan",
    "semgrep_scan", "correlate_vulnerabilities", "calculate_risk_scores",
    "generate_impact_assessment", "run_apme", "attack_path_modeling",
    "post_crawl_osint",
})


@activity.defn(name="RunGenericTaskActivity")
def run_generic_task_activity(ctx: dict, task_name: str, description: str = None, extra_args: dict = None, db_task_name: str = None) -> bool:
    """Execute any permitted task function dynamically in a Temporal activity.

    Only tasks in _PERMITTED_GENERIC_TASKS may be dispatched. This prevents
    arbitrary function execution from replayed workflow history events.
    """
    if task_name not in _PERMITTED_GENERIC_TASKS:
        raise ValueError(
            f"[RunGenericTaskActivity] '{task_name}' is not in the permitted task list. "
            f"Add it to _PERMITTED_GENERIC_TASKS to allow dispatch."
        )
    import importlib
    activity.logger.info("[RunGenericTaskActivity] task=%s scan_id=%s", task_name, ctx.get('scan_history_id'))

    tasks_module = importlib.import_module("reNgine.tasks")
    task_func = getattr(tasks_module, task_name, None)

    if not task_func:
        raise ValueError(f"Task function '{task_name}' not found in reNgine.tasks.")

    run_args = extra_args or {}
    return _run_task(
        task_func,
        ctx,
        task_name=task_name,
        description=description or ' '.join(task_name.split('_')).capitalize(),
        db_task_name=db_task_name,
        **run_args
    )


@activity.defn(name="FinalizeSubScanActivity")
def finalize_subscan_activity(ctx: dict, success: bool, subscan_id: int = None) -> bool:
    """Mark the subscan as completed and update its status.

    Args:
        ctx (dict): Temporal workflow context.
        success (bool): True if all subscan steps succeeded, False otherwise.
        subscan_id (int, optional): Specific subscan ID to finalize.
    """
    from startScan.models import SubScan
    from reNgine.definitions import SUCCESS_TASK, FAILED_TASK
    from reNgine.tasks import send_scan_notif

    if subscan_id is None:
        subscan_id = ctx.get('subscan_id')
    scan_id = ctx.get('scan_history_id')
    engine_id = ctx.get('engine_id')

    logger.log_line("[TEMPORAL]", "START", "task=finalize_subscan scan_id=%s subscan_id=%s" % (scan_id, subscan_id))

    subscan = SubScan.objects.filter(pk=subscan_id).first()
    if not subscan:
        activity.logger.error("[FinalizeSubScanActivity] SubScan %s not found.", subscan_id)
        return False

    status = SUCCESS_TASK if success else FAILED_TASK
    status_h = 'SUCCESS' if success else 'FAILED'

    subscan.status = status
    subscan.stop_scan_date = timezone.now()
    subscan.save()

    activity.logger.info(
        "[FinalizeSubScanActivity] subscan_id=%s finished with status=%s", subscan_id, status_h
    )
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=finalize_subscan scan_id=%s subscan_id=%s status=%s" % (scan_id, subscan_id, status_h))

    # Send notification directly (no Celery)
    try:
        send_scan_notif(
            scan_history_id=scan_id,
            subscan_id=subscan_id,
            engine_id=engine_id,
            status=status_h
        )
    except Exception as e:
        logger.warning("Could not send subscan notification: %s", e)

    return True


@activity.defn(name="FinalizeFailedScanActivity")
def finalize_failed_scan_activity(ctx: dict, error_msg: str) -> None:
    """Mark a scan as FAILED_TASK due to a workflow crash or unhandled exception.
    
    This ensures that the Django database reflects the crash and allows the user
    to manually resume the scan later.
    """
    from startScan.models import ScanHistory
    from reNgine.definitions import FAILED_TASK
    
    scan_id = ctx.get('scan_history_id')
    if not scan_id:
        return

    logger.log_line("[TEMPORAL]", "START", "task=finalize_failed_scan scan_id=%s" % scan_id)
    logger.log_line("[TEMPORAL]", "ERROR", "task=finalize_failed_scan scan_id=%s error=%s" % (scan_id, error_msg[:200] if error_msg else "workflow crash"), level="error")

    try:
        from reNgine.definitions import ABORTED_TASK, RUNNING_TASK, INITIATED_TASK
        scan = ScanHistory.objects.get(pk=scan_id)
        if scan.scan_status == ABORTED_TASK:
            logger.info(
                "Scan %s already ABORTED by user — not overwriting to FAILED_TASK.", scan_id
            )
            return
        scan.scan_status = FAILED_TASK
        scan.error_message = error_msg[:300] if error_msg else "Scan workflow crashed."
        scan.stop_scan_date = timezone.now()
        scan.save()
        logger.info("Scan %s marked as FAILED_TASK due to workflow crash.", scan_id)

        for te in scan.temporal_executions.filter(status='RUNNING'):
            te.status = 'FAILED'
            te.ended_at = scan.stop_scan_date
            te.save()

        # Mark any activities still in RUNNING or INITIATED state as FAILED
        # (previously filtered status=0 which is FAILED_TASK itself — a no-op)
        err = scan.error_message
        scan.scanactivity_set.filter(
            status__in=[RUNNING_TASK, INITIATED_TASK]
        ).update(status=FAILED_TASK, error_message=err)
        logger.log_line("[TEMPORAL]", "COMPLETE", "task=finalize_failed_scan scan_id=%s" % scan_id)
    except Exception as e:
        logger.error("Failed to finalize crashed scan %s: %s", scan_id, e)


@activity.defn(name="CheckScanQueueStatusActivity")
async def check_scan_queue_status_activity(scan_id: int, queue_type: str) -> bool:
    """Check if the given scan is allowed to proceed based on the queue settings.
    
    Args:
        scan_id (int): ScanHistory ID (for main) or SubScan ID (for subscan).
        queue_type (str): 'main' or 'subscan'.
    
    Returns:
        bool: True if it is allowed to proceed (queueing is off, or it's first in line).
    """
    # database_sync_to_async, not asgiref's sync_to_async: async activity ORM
    # calls run in an asgiref thread that DjangoAwareThreadPoolExecutor never
    # touches. Nothing refreshed that thread's cached connection, and once
    # Postgres closed it (idle timeout / restart) every later call raised
    # "connection already closed" — CheckScanQueueStatusActivity is the first
    # step of MasterScanWorkflow, so scans sat at 0% while reading RUNNING.
    # The channels wrapper runs close_old_connections() around each call, which
    # with CONN_HEALTH_CHECKS drops a dead connection and opens a fresh one.
    from channels.db import database_sync_to_async
    from reNgine.temporal_client import TemporalClientProvider
    from temporalio.client import WorkflowExecutionStatus
    from temporalio.service import RPCError, RPCStatusCode

    @database_sync_to_async
    def _get_queue_state():
        from dashboard.models import UserPreferences
        from startScan.models import ScanHistory, SubScan
        from reNgine.definitions import RUNNING_TASK
        
        prefs = UserPreferences.objects.first()
        if not prefs or not getattr(prefs, 'enable_scan_queueing', False):
            return {"queueing_enabled": False}

        if queue_type == "main":
            running = list(ScanHistory.objects.filter(
                scan_status=RUNNING_TASK
            ).order_by('start_scan_date').values_list('id', flat=True))
        else:
            running = list(SubScan.objects.filter(
                status=RUNNING_TASK
            ).order_by('start_scan_date').values_list('id', flat=True))
            
        return {"queueing_enabled": True, "running": running}

    @database_sync_to_async
    def _get_workflow_id(sid, qtype):
        from startScan.models import ScanHistory, SubScan, TemporalWorkflowExecution
        if qtype == "main":
            scan_obj = ScanHistory.objects.filter(id=sid).first()
            if not scan_obj: return None
            latest_exec = (
                TemporalWorkflowExecution.objects
                .filter(scan_history=scan_obj, status='RUNNING')
                .order_by('-started_at')
                .first()
            )
            return latest_exec.workflow_id if latest_exec else (scan_obj.workflow_ids[-1] if scan_obj.workflow_ids else None)
        else:
            # TemporalWorkflowExecution rows are only ever created for ScanHistory
            # (see reNgine.tasks.scan_init) — there is no subscan-scoped relation,
            # so the only source of truth for a subscan's workflow id is the
            # SubScan.workflow_ids array itself.
            scan_obj = SubScan.objects.filter(id=sid).first()
            if not scan_obj: return None
            return scan_obj.workflow_ids[-1] if getattr(scan_obj, 'workflow_ids', None) else None

    logger.log_line("[TEMPORAL]", "START", "task=check_scan_queue_status scan_id=%s queue_type=%s" % (scan_id, queue_type))
    activity.logger.info("[CheckScanQueueStatusActivity] scan_id=%s queue_type=%s", scan_id, queue_type)
    
    state = await _get_queue_state()
    if not state.get("queueing_enabled"):
        logger.log_line("[TEMPORAL]", "COMPLETE", "task=check_scan_queue_status scan_id=%s result=allowed_queueing_off" % scan_id)
        return True

    client = await TemporalClientProvider.get_client()

    async def is_workflow_active(sid, qtype):
        """Check if scan sid is actually running in Temporal."""
        workflow_id = await _get_workflow_id(sid, qtype)
        if not workflow_id:
            return False

        try:
            handle = client.get_workflow_handle(workflow_id)
            desc = await handle.describe()
            if desc.status == WorkflowExecutionStatus.RUNNING:
                return True
            
            # Master finished — check whether its nuclei child is still running (for main scans)
            if qtype == "main":
                nuclei_id = f"{workflow_id}-nuclei"
                try:
                    nuclei_handle = client.get_workflow_handle(nuclei_id)
                    nuclei_desc = await nuclei_handle.describe()
                    if nuclei_desc.status == WorkflowExecutionStatus.RUNNING:
                        return True
                except RPCError as e:
                    if e.status != RPCStatusCode.NOT_FOUND:
                        return True  # server error — assume running
            return False
        except RPCError as e:
            if e.status == RPCStatusCode.NOT_FOUND:
                return False  # workflow genuinely absent
            return True  # Any other RPC error means Temporal itself is unavailable — assume running
        except Exception as e:
            activity.logger.warning("[CheckScanQueueStatusActivity] Unexpected error checking workflow '%s': %s", workflow_id, e)
            return True

    running_scans = state.get("running", [])
    active_scans = []
    
    for sid in running_scans:
        if await is_workflow_active(sid, queue_type):
            active_scans.append(sid)
        else:
            activity.logger.warning("[CheckScanQueueStatusActivity] Ignoring DEAD %s %s blocking queue.", queue_type, sid)
            
    result = not active_scans or active_scans[0] == scan_id

    logger.log_line("[TEMPORAL]", "COMPLETE", "task=check_scan_queue_status scan_id=%s queue_type=%s allowed=%s" % (scan_id, queue_type, result))
    return result


@activity.defn(name="GetScanFinalStatusActivity")
def get_scan_final_status_activity(
    scan_id: int,
    task_succeeded: bool,
    in_flight_names: list | None = None,
    failed_task_name: str | None = None,
    activity_id: int | None = None,
) -> int:
    """Return the scan status after a single-task retry.

    If other names in this retry batch are still INITIATED/RUNNING, keep the
    scan RUNNING so a parallel sibling retry cannot mark SUCCESS early.
    Otherwise SUCCESS when this task succeeded and no other activities truly
    failed or remain aborted; FAILED otherwise.

    When this retry failed before the activity claimed its row, flip that
    INITIATED row back to FAILED so the timeline and retry button recover.
    Singular runs pass activity_id so only that pre-created row is closed —
    never every INITIATED sibling with the same task name.
    """
    from django.utils import timezone as _tz
    from startScan.models import ScanActivity
    from reNgine.definitions import (
        SUCCESS_TASK, FAILED_TASK, RUNNING_TASK, INITIATED_TASK, ABORTED_TASK,
    )
    from reNgine.task_plan import RETRY_TASK_ALIASES

    # Dispatch name plus any timeline row names that alias to it (e.g.
    # acunetix_scan → run_acunetix). Used when activity_id is missing.
    close_names = []
    if failed_task_name:
        close_names = [failed_task_name] + [
            timeline for timeline, dispatch in RETRY_TASK_ALIASES.items()
            if dispatch == failed_task_name
        ]

    pending_names = [n for n in (in_flight_names or []) if n]
    if close_names:
        pending_names = [n for n in pending_names if n not in close_names]

    if activity_id:
        row_qs = ScanActivity.objects.filter(
            pk=activity_id,
            scan_of_id=scan_id,
            status__in=[INITIATED_TASK, RUNNING_TASK],
        )
        if task_succeeded:
            row_qs.update(status=SUCCESS_TASK, time_ended=_tz.now())
        else:
            row_qs.update(
                status=FAILED_TASK,
                error_message="Retry workflow failed before the task completed",
                time_ended=_tz.now(),
            )
    elif not task_succeeded and close_names:
        # Only the in-flight retry row (INITIATED, time_started kept) — not
        # pre-seeded ghost rows with time_started=None. Match dispatch name and
        # reverse aliases so acunetix_scan rows close when dispatch is run_acunetix.
        ScanActivity.objects.filter(
            scan_of_id=scan_id,
            name__in=close_names,
            status=INITIATED_TASK,
            time_started__isnull=False,
        ).update(
            status=FAILED_TASK,
            error_message="Retry workflow failed before the task completed",
            time_ended=_tz.now(),
        )

    if pending_names:
        # Every retry path keeps time_started on the row it re-queues. A planned
        # row that never started has none and never will, so counting it would
        # keep the scan RUNNING for good.
        still_running = ScanActivity.objects.filter(
            scan_of_id=scan_id,
            name__in=pending_names,
            status__in=[INITIATED_TASK, RUNNING_TASK],
            time_started__isnull=False,
        ).exists()
        if still_running:
            return RUNNING_TASK

    if not task_succeeded:
        return FAILED_TASK

    # ABORTED counts as unsuccessful the same way FAILED does: a stop left
    # sibling rows cancelled, and a single successful retry must not erase that.
    unsuccessful_names = set(
        ScanActivity.objects.filter(
            scan_of_id=scan_id,
            status__in=[FAILED_TASK, ABORTED_TASK],
            time_started__isnull=False,
        ).values_list("name", flat=True)
    )
    success_names = set(
        ScanActivity.objects.filter(
            scan_of_id=scan_id,
            status=SUCCESS_TASK,
        ).values_list("name", flat=True)
    )
    true_failures = unsuccessful_names - success_names
    return FAILED_TASK if true_failures else SUCCESS_TASK
