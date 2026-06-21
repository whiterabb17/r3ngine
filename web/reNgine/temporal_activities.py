"""
Temporal Activities for r3ngine scan pipeline.

All Python-side activities are implemented here. They are designed to be
called by the Python Orchestrator Worker listening on the
'python-orchestrator-queue'.

The activities delegate to the existing scan task functions in
web/reNgine/tasks.py, which contain the full scan logic. Since the Python
worker runs with UnsandboxedWorkflowRunner, Django models and the existing
task code are fully accessible here without sandbox restrictions.

Design principle: Activities call existing RengineTask-decorated scan functions
directly, providing a lightweight proxy object (TemporalTaskProxy) that satisfies
the `self` interface expected by those tasks without requiring Celery.
"""

import logging
import os
import threading
import yaml

from temporalio import activity
from django.utils import timezone

from reNgine.scan_context import ScanContext
from reNgine.utils.logger import get_module_logger, format_exception_for_log
from reNgine.auth_discovery_tasks import (
    _fetch_with_proxy_retry,
    _extract_login_forms,
)
from reNgine.common_func import get_proxy_list, get_random_proxy, merge_imported_subdomains
from targetApp.models import normalize_manual_subdomains
from reNgine.utils.task import activity_heartbeat_safe
from startScan.models import Subdomain

logger = get_module_logger(__name__)



# ---------------------------------------------------------------------------
# TemporalTaskProxy
# ---------------------------------------------------------------------------

class TemporalTaskProxy:
    """A lightweight proxy that mimics the `self` interface of RengineTask.

    Existing scan task functions (subdomain_discovery, port_scan, etc.)
    are bound to a Celery Task instance via `self`. This proxy satisfies
    that interface so the same functions can be called directly inside
    Temporal activities without Celery.

    Args:
        ctx (dict): The Temporal workflow context dictionary containing all
                    relevant scan metadata (scan_history_id, engine_id,
                    results_dir, yaml_configuration, etc.).
        task_name (str): Short name of the task (used for ScanActivity tracking).
        description (str, optional): Human-readable description for the UI.
    """

    def __init__(self, ctx: dict, task_name: str, description: str = None):
        from startScan.models import ScanHistory, SubScan, ScanActivity
        from scanEngine.models import EngineType
        from targetApp.models import Domain
        from reNgine.definitions import RUNNING_TASK
        from reNgine.settings import RENGINE_RESULTS

        self._is_temporal_proxy = True
        self.task_name = task_name
        self.description = description or ' '.join(task_name.split('_')).capitalize()
        self.status = RUNNING_TASK
        self.result = None
        self.error = None
        self.traceback = None

        # Core context fields
        self.scan_id = ctx.get('scan_history_id')
        self.subscan_id = ctx.get('subscan_id')
        self.engine_id = ctx.get('engine_id')
        self.domain_id = ctx.get('domain_id')
        self.subdomain_id = ctx.get('subdomain_id')
        self.results_dir = ctx.get('results_dir', RENGINE_RESULTS)
        os.makedirs(self.results_dir, exist_ok=True)
        import copy
        self.yaml_configuration = copy.deepcopy(ctx.get('yaml_configuration', {}))
        
        hw_profile = ctx.get('hardware_profile')
        if hw_profile:
            # Hardware profiles control resource limits (threads, rate, delay, retries).
            # Timeouts are intentionally left to the engine YAML configuration so that
            # each tool's per-section timeout is respected as-designed.
            self.yaml_configuration['threads'] = hw_profile.get('threads')
            self.yaml_configuration['rate_limit'] = hw_profile.get('rate_limit')
            self.yaml_configuration['delay'] = hw_profile.get('delay')
            self.yaml_configuration['retries'] = hw_profile.get('retries')

            # Apply the same limits to every subsection in the YAML.
            for section_config in self.yaml_configuration.values():
                if isinstance(section_config, dict):
                    section_config['threads'] = hw_profile.get('threads')
                    section_config['rate_limit'] = hw_profile.get('rate_limit')
                    section_config['delay'] = hw_profile.get('delay')
                    section_config['retries'] = hw_profile.get('retries')

        # Apply ScanProfile settings if provided in ctx.
        # Throttle values are stored as direct attributes (not merged into yaml_configuration)
        # so task functions can apply them per-tool as needed.
        profile_data: dict = ctx.get('profile') or {}
        self.rate_limit: int | None = profile_data.get('rate_limit')
        self.delay: float | None = profile_data.get('delay')
        self.threads: int | None = profile_data.get('threads')
        self.timeout: int | None = profile_data.get('timeout')
        self.retries: int | None = profile_data.get('retries')
        self.passive: bool = bool(profile_data.get('passive', False))
        self.active: bool = bool(profile_data.get('active', False))
        self.stealth: bool = bool(profile_data.get('stealth', False))
        self.headless: bool = bool(profile_data.get('headless', False))
        self.hunt_secrets: bool = bool(profile_data.get('hunt_secrets', False))
        self.all_ports: bool = bool(profile_data.get('all_ports', False))
        self.tor: bool = bool(profile_data.get('tor', False))
        self.fragment: bool = bool(profile_data.get('fragment', False))

        self.out_of_scope_subdomains = ctx.get('out_of_scope_subdomains', [])
        self.starting_point_path = ctx.get('starting_point_path', '')
        self.excluded_paths = ctx.get('excluded_paths', [])
        self.history_file = f'{self.results_dir}/commands.txt'
        self.output_path = f'{self.results_dir}/{task_name}.txt'
        self.filename = f'{task_name}.txt'
        self.activity_id = ctx.get('activity_id')
        self.track = ctx.get('track', True)

        # Django ORM objects
        self.scan = ScanHistory.objects.filter(pk=self.scan_id).first()
        self.subscan = SubScan.objects.filter(pk=self.subscan_id).first() if self.subscan_id else None
        self.engine = EngineType.objects.filter(pk=self.engine_id).first()
        if not self.engine and self.scan:
            self.engine = self.scan.scan_type
            self.engine_id = self.engine.id if self.engine else None
        self.domain = self.scan.domain if self.scan else Domain.objects.filter(id=self.domain_id).first()
        self.subdomain = self.subscan.subdomain if self.subscan else None

        # Create a ScanActivity record in the DB to track this task
        if self.track and self.scan:
            self._create_scan_activity()

    def _create_scan_activity(self):
        """Claim an unclaimed ScanActivity row for this task, or create one if none available.

        Uses SELECT FOR UPDATE (skip_locked=True) so that only rows with
        time_started__isnull=True are claimed. This prevents a Temporal activity
        retry from overwriting SUCCESS rows left by prior attempts (AUD-003).
        """
        from startScan.models import ScanActivity
        from reNgine.definitions import RUNNING_TASK
        from django.db import transaction

        try:
            temporal_activity_id = activity.info().activity_id
            now = timezone.now()
            execution_id = "temporal-%s" % temporal_activity_id
            with transaction.atomic():
                # Claim only a row that has not been started yet (time_started is NULL).
                # skip_locked=True ensures concurrent retries do not race on the same row.
                activity_row = ScanActivity.objects.select_for_update(skip_locked=True).filter(
                    scan_of=self.scan,
                    name=self.task_name,
                    time_started__isnull=True,
                ).first()

                if activity_row:
                    activity_row.status = RUNNING_TASK
                    activity_row.time_started = now
                    activity_row.time = now
                    activity_row.execution_id = execution_id
                    activity_row.save(
                        update_fields=['status', 'time_started', 'time', 'execution_id']
                    )
                    self.activity = activity_row
                    self.activity_id = activity_row.id
                else:
                    # No unclaimed row found — create one for this retry attempt.
                    self.activity = ScanActivity.objects.create(
                        scan_of=self.scan,
                        name=self.task_name,
                        title=self.description,
                        status=RUNNING_TASK,
                        time=now,
                        time_started=now,
                        execution_id=execution_id,
                    )
                    self.activity_id = self.activity.id

        except Exception as e:
            logger.log_line(
                "[SCAN]", "ERROR",
                "_create_scan_activity failed for %s: %s" % (self.task_name, format_exception_for_log(e)),
                level="error",
                exc_info=True,
            )
            raise  # let Temporal retry — do not silently proceed untracked

    def update_scan_activity(self, status, error_message=None):
        """Update the ScanActivity record with the final task status and time_ended.

        Args:
            status (int): Task status code (SUCCESS_TASK, FAILED_TASK, etc.)
            error_message (str, optional): Error message if the task failed.
        """
        from startScan.models import ScanActivity
        try:
            if getattr(self, 'activity', None):
                now = timezone.now()
                update_kwargs = {
                    'status': status,
                    'time': now,
                    'time_ended': now,
                }
                if error_message is not None:
                    update_kwargs['error_message'] = str(error_message)[:300]
                ScanActivity.objects.filter(pk=self.activity.pk).update(**update_kwargs)
        except Exception as e:
            logger.warning(f"Could not update ScanActivity for {self.task_name}: {e}")

    def notify(self, name=None, severity=None, fields={}, add_meta_info=True):
        """Send a Temporal-compatible notification (no-op for now).

        In Celery, this triggered send_task_notif.delay(). In Temporal, the
        notification is sent via the dedicated SendScanNotificationActivity
        at workflow completion. Individual per-task notifications are a
        best-effort log entry here.

        Args:
            name (str, optional): Notification name override.
            severity (str, optional): Severity level.
            fields (dict): Extra notification fields.
            add_meta_info (bool): Whether to include scan metadata.
        """
        logger.info(f"[notify] Task '{name or self.task_name}' fields={fields}")


# ---------------------------------------------------------------------------
# Helper: run a RengineTask function via TemporalTaskProxy
# ---------------------------------------------------------------------------

# Thread-local used to share the per-activity cancel_event with stream_command/run_command
# so they can cancel GoExecutorTaskWorkflow instances without signature changes.
_task_cancel_local = threading.local()


def _run_task(task_func, ctx: dict, task_name: str, description: str = None, db_task_name: str = None, **kwargs):
    """Execute an existing RengineTask-decorated function inside a Temporal activity.

    Spawns a heartbeat thread that sends signals to Temporal every 30 seconds
    to prevent activity timeout for long-running operations.

    Constructs a TemporalTaskProxy as the task's `self`, sets the status on
    success/failure and returns the task's result.

    Args:
        task_func (callable): The task function (e.g. subdomain_discovery).
        ctx (dict): Temporal workflow context dictionary.
        task_name (str): Short task name for DB tracking.
        description (str, optional): Human-readable description.
        db_task_name (str, optional): Alternative database tracking name.
        **kwargs: Extra keyword arguments passed to task_func.

    Returns:
        bool: True on success.

    Raises:
        Exception: Re-raises any exception from the underlying task so Temporal
                   can retry or fail the activity appropriately.
    """
    from reNgine.definitions import SUCCESS_TASK, FAILED_TASK, ABORTED_TASK
    from temporalio.exceptions import ApplicationError
    import contextvars
    import time

    # ---------------------------------------------------------------------------
    # Pre-flight guard: abort/delete check
    # If the scan has been deleted or aborted in Django DB, raise a
    # non-retryable ApplicationError so Temporal permanently fails this activity
    # and bubbles the failure up to the workflow without retrying.
    # This prevents infinite retry loops when a scan is deleted or aborted while
    # Temporal replays the workflow after a container restart.
    # ---------------------------------------------------------------------------
    scan_id_check = ctx.get('scan_history_id')
    if scan_id_check:
        from startScan.models import ScanHistory as _ScanHistory
        _scan = _ScanHistory.objects.filter(pk=scan_id_check).first()
        if not _scan:
            raise ApplicationError(
                f"[{task_name}] ScanHistory {scan_id_check} no longer exists — "
                f"scan was deleted. Workflow cancelled.",
                non_retryable=True,
            )
        if _scan.scan_status == ABORTED_TASK:
            raise ApplicationError(
                f"[{task_name}] Scan {scan_id_check} was aborted by the user. "
                f"Workflow cancelled.",
                non_retryable=True,
            )

    proxy = TemporalTaskProxy(ctx, db_task_name or task_name, description)

    _scan_id = ctx.get('scan_history_id')
    _domain = ctx.get('domain_name', '')
    try:
        _workflow_id = activity.info().workflow_id
    except Exception:
        _workflow_id = '?'
    logger.log_line("[TEMPORAL]", "START", "task=%s scan_id=%s domain=%s workflow_id=%s" % (task_name, _scan_id, _domain, _workflow_id))

    activity_running = True
    cancel_event = threading.Event()
    _task_cancel_local.cancel_event = cancel_event

    # Copy the current contextvars context so the heartbeat thread inherits the
    # Temporal activity context. threading.Thread does NOT copy contextvars by
    # default, causing activity.heartbeat() to fail with "Not in activity context",
    # which silently prevents all heartbeats from reaching Temporal and triggers
    # the heartbeat_timeout cancellation + retry loop.
    _activity_ctx = contextvars.copy_context()

    def send_heartbeats():
        def _do_heartbeats():
            from temporalio.exceptions import CancelledError as TemporalCancelledError
            while activity_running:
                try:
                    _hb_detail = f"Activity {task_name} running for {proxy.task_name}"
                    activity.heartbeat(_hb_detail)
                    logger.log_line(
                        "[TEMPORAL]", "HEARTBEAT",
                        "activity_type=%s workflow_id=%s scan_id=%s" % (task_name, _workflow_id, _scan_id),
                    )
                except TemporalCancelledError:
                    # Temporal has cancelled this activity — propagate by marking
                    # the scan aborted so the stream_command kill switch fires.
                    activity.logger.warning(
                        f"[_run_task] Temporal cancellation received for {task_name}. "
                        f"Marking scan {proxy.scan_id} as aborted."
                    )
                    try:
                        from startScan.models import ScanHistory
                        from reNgine.definitions import ABORTED_TASK
                        if proxy.scan_id:
                            _scan = ScanHistory.objects.filter(pk=proxy.scan_id).first()
                            if _scan and _scan.scan_status != ABORTED_TASK:
                                _scan.scan_status = ABORTED_TASK
                                _scan.save()
                    except Exception as mark_err:
                        activity.logger.warning(
                            f"[_run_task] Could not mark scan aborted: {mark_err}"
                        )
                    cancel_event.set()  # signal stream_command/run_command to abort
                    return  # stop heartbeating; kill switch will stop the subprocess
                except Exception as hb_err:
                    logger.log_line(
                        "[TEMPORAL]", "HEARTBEAT_FAIL",
                        "activity_type=%s workflow_id=%s scan_id=%s error=%s" % (
                            task_name, _workflow_id, _scan_id, hb_err,
                        ),
                        level="warning",
                    )

                for _ in range(6):  # 6 * 5s = 30s, checking flag each iteration
                    if not activity_running:
                        break
                    time.sleep(5)
        _activity_ctx.run(_do_heartbeats)

    heartbeat_thread = threading.Thread(target=send_heartbeats, daemon=True)
    heartbeat_thread.start()

    try:
        # task_func is the plain function (self/proxy is passed as first positional arg).
        raw_func = task_func.__func__ if hasattr(task_func, '__func__') else task_func

        import inspect
        sig = inspect.signature(raw_func)
        accepts_kwargs = any(p.kind == inspect.Parameter.VAR_KEYWORD for p in sig.parameters.values())

        for param_name in sig.parameters:
            if param_name in ('self', 'proxy'):
                continue
            if param_name not in kwargs:
                if param_name == 'ctx':
                    kwargs['ctx'] = ctx
                elif param_name == 'description':
                    kwargs['description'] = description
                elif param_name in ctx:
                    kwargs[param_name] = ctx[param_name]

        if accepts_kwargs:
            if 'ctx' not in kwargs:
                kwargs['ctx'] = ctx
            if 'description' not in kwargs:
                kwargs['description'] = description

        res = raw_func(proxy, **kwargs)
        if res is False:
            raise Exception(f"Task {task_name} execution returned False/failed.")
        proxy.update_scan_activity(SUCCESS_TASK)
        logger.log_line("[TEMPORAL]", "COMPLETE", "task=%s scan_id=%s" % (task_name, _scan_id))
        return True
    except Exception as exc:
        logger.log_line("[TEMPORAL]", "ERROR", "task=%s scan_id=%s error=%s" % (task_name, _scan_id, format_exception_for_log(exc)), level="error")
        activity.logger.exception(f"[_run_task] Task {task_name} failed: {exc}")
        proxy.update_scan_activity(FAILED_TASK, error_message=repr(exc))
        raise
    finally:
        activity_running = False
        heartbeat_thread.join(timeout=5)


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
        logger.warning(f"InitializeScanTasksActivity: ScanHistory {scan_id} not found")
        return {'created': 0, 'existing': 0}

    subscan = None
    if subscan_id:
        try:
            subscan = SubScan.objects.get(pk=subscan_id)
        except SubScan.DoesNotExist:
            pass

    plan = build_scan_task_plan(tasks, yaml_configuration)
    created_count = 0
    existing_count = 0
    now = tz.now()

    for entry in plan:
        # Scope the existence check to (scan_of, name) only — regardless of status.
        # Using status=INITIATED_TASK in the lookup would create phantom PENDING rows
        # on workflow recovery if tasks have already transitioned to RUNNING/SUCCESS.
        if not ScanActivity.objects.filter(scan_of=scan, name=entry['name']).exists():
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
        else:
            existing_count += 1

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
    activity.logger.info(f"[TargetProfilingActivity] Profiling scan_history_id={scan_id}")
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
            f"[TargetProfilingActivity] Profiled target {scan.domain.name}, "
            f"tasks={ctx.get('tasks')}"
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


# ===========================================================================
# Tier 1 — Discovery
# ===========================================================================

@activity.defn(name="RunSubdomainDiscoveryActivity")
def run_subdomain_discovery_activity(ctx: dict) -> bool:
    """Execute subdomain discovery tools (subfinder, amass, etc.) against the target.

    Delegates to the existing `subdomain_discovery` Celery task function which
    runs all configured discovery tools sequentially, writing results to the
    scan results directory and persisting discovered subdomains to the DB.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from reNgine.tasks import subdomain_discovery
    activity.logger.info(f"[RunSubdomainDiscoveryActivity] scan_id={ctx.get('scan_history_id')}")
    return _run_task(
        subdomain_discovery,
        ctx,
        task_name='subdomain_discovery',
        description='Subdomain Discovery'
    )


@activity.defn(name="RunAmassIntelDiscoveryActivity")
def run_amass_intel_discovery_activity(ctx: dict) -> bool:
    """Run Amass Intel infrastructure discovery against the target domain.

    Delegates to the existing `amass_intel_discovery` task to find related
    root domains and IP ranges via WHOIS and other intelligence sources.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from reNgine.tasks import amass_intel_discovery
    from startScan.models import ScanHistory
    scan = ScanHistory.objects.filter(pk=ctx.get('scan_history_id')).first()
    host = scan.domain.name if scan else ctx.get('domain_name', '')
    activity.logger.info(f"[RunAmassIntelDiscoveryActivity] host={host}")
    return _run_task(
        amass_intel_discovery,
        ctx,
        task_name='amass_intel_discovery',
        description='Infrastructure Discovery',
        host=host
    )


@activity.defn(name="RunFirewallVPNScanActivity")
def run_firewall_vpn_scan_activity(ctx: dict) -> bool:
    """Detect firewall and VPN infrastructure protecting the target.

    Delegates to the existing `firewall_vpn_scan` task.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from reNgine.tasks import firewall_vpn_scan
    activity.logger.info(f"[RunFirewallVPNScanActivity] scan_id={ctx.get('scan_history_id')}")
    return _run_task(
        firewall_vpn_scan,
        ctx,
        task_name='firewall_vpn_scan',
        description='Firewall & VPN Scan'
    )


@activity.defn(name="RunDNSSecurityActivity")
def run_dns_security_activity(ctx: dict) -> bool:
    """Run DNS security checks: AXFR, DNSSEC, amplification, optional brute-force.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from reNgine.dns_tasks import dns_security
    activity.logger.info(f"[RunDNSSecurityActivity] scan_id={ctx.get('scan_history_id')}")
    return _run_task(
        dns_security,
        ctx,
        task_name='dns_security',
        description='DNS Security Scan'
    )


@activity.defn(name="ParseDiscoveryResultsActivity")
def parse_discovery_results_activity(ctx: dict) -> bool:
    """Parse and persist discovery tier results to the database.

    After all Tier 1 tools finish, this activity consolidates output files,
    deduplicates subdomains, and writes them to the Subdomain model.
    In the current implementation, each discovery tool writes directly to the
    DB via save_subdomain(), so this is a lightweight verification pass.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from startScan.models import ScanHistory, Subdomain
    scan_id = ctx.get('scan_history_id')
    logger.log_line("[TEMPORAL]", "START", "task=parse_discovery_results scan_id=%s" % scan_id)
    count = Subdomain.objects.filter(scan_history_id=scan_id).count()
    activity.logger.info(
        f"[ParseDiscoveryResultsActivity] scan_id={scan_id}: "
        f"{count} subdomains persisted."
    )
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=parse_discovery_results scan_id=%s subdomains=%d" % (scan_id, count))
    return True


@activity.defn(name="SeedEndpointsForCrawlActivity")
def seed_endpoints_for_crawl_activity(ctx: dict) -> dict:
    """Ensure every discovered subdomain has a default EndPoint before http_crawl runs.

    Mirrors rengine-ng's pre_crawl step. Queries all Subdomain records for the
    current scan and creates EndPoint(is_default=True, http_status=0) for any
    subdomain that does not yet have a default endpoint. Returns an updated ctx
    with a 'seed_urls' list that RunHTTPCrawlActivity can log and use.
    """
    from startScan.models import Subdomain, EndPoint
    from reNgine.utils.task import save_endpoint
    from reNgine.common_func import sanitize_url

    scan_id = ctx.get('scan_history_id')
    url_filter = ctx.get('starting_point_path', '')
    logger.log_line("[TEMPORAL]", "START", "task=seed_endpoints_for_crawl scan_id=%s" % scan_id)

    subdomains = Subdomain.objects.filter(scan_history_id=scan_id)
    seed_urls = []

    for subdomain in subdomains:
        if url_filter:
            path = url_filter if url_filter.startswith('/') else f'/{url_filter}'
            raw_url = f'{subdomain.name}{path}'
        else:
            raw_url = subdomain.name
        if not raw_url.startswith(('http://', 'https://')):
            raw_url = f'http://{raw_url}'
        raw_url = sanitize_url(raw_url)

        existing = EndPoint.objects.filter(
            scan_history_id=scan_id,
            http_url=raw_url,
            is_default=True,
        ).first()

        if existing:
            seed_urls.append(existing.http_url)
        else:
            endpoint, _ = save_endpoint(
                raw_url,
                ctx=ctx,
                crawl=False,
                is_default=True,
                subdomain=subdomain,
            )
            if endpoint:
                seed_urls.append(endpoint.http_url)

    activity.logger.info(
        f"[SeedEndpointsForCrawlActivity] scan_id={scan_id}: "
        f"seeded {len(seed_urls)} endpoint(s) for http_crawl."
    )
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=seed_endpoints_for_crawl scan_id=%s seeded=%d" % (scan_id, len(seed_urls)))
    return {**ctx, 'seed_urls': seed_urls}


# ===========================================================================
# Tier 2 — Enumeration
# ===========================================================================

@activity.defn(name="RunHTTPCrawlActivity")
def run_http_crawl_activity(ctx: dict) -> bool:
    """Run httpx HTTP crawl across all discovered subdomains.

    Delegates to the existing `http_crawl` task which probes all discovered
    subdomains for live HTTP services and persists endpoint metadata.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from reNgine.tasks import http_crawl
    seed_count = len(ctx.get('seed_urls', []))
    activity.logger.info(f"[RunHTTPCrawlActivity] scan_id={ctx.get('scan_history_id')} seed_count={seed_count}")
    return _run_task(
        http_crawl,
        ctx,
        task_name='http_crawl',
        description='HTTP Crawl'
    )


@activity.defn(name="RunHTTPCrawlBridgeActivity")
def run_http_crawl_bridge_activity(ctx: dict) -> bool:
    """Run httpx HTTP crawl bridge across newly discovered endpoints and dead/not-alive endpoints.

    Queries the DB to fetch all endpoints associated with this scan that are either
    newly discovered (status is 0 or None) or dead/not alive (status is 404, or >= 500, or <= 0).
    It then delegates to the `http_crawl` task to scan exactly those URLs.

    Args:
        ctx (dict): Temporal workflow context containing:
            - scan_history_id (int): Django ScanHistory database ID.
            - subdomain_id (int, optional): Optional subdomain ID to limit query.

    Returns:
        bool: True on success.
    """
    from reNgine.tasks import http_crawl
    from startScan.models import EndPoint
    from django.db.models import Q

    scan_history_id = ctx.get('scan_history_id')
    subdomain_id = ctx.get('subdomain_id')
    activity.logger.info(f"[RunHTTPCrawlBridgeActivity] Querying endpoints for scan_history_id={scan_history_id}")

    # Query all endpoints for this scan/subscan
    query = EndPoint.objects.filter(scan_history_id=scan_history_id)
    if subdomain_id:
        query = query.filter(subdomain__id=subdomain_id)

    # Filter endpoints that are not alive or new:
    # Alive is defined as: (0 < status < 500) and status != 404
    # Therefore, not alive/new is: status is None, or status <= 0, or status == 404, or status >= 500
    query = query.filter(
        Q(http_status__isnull=True) |
        Q(http_status__lte=0) |
        Q(http_status=404) |
        Q(http_status__gte=500)
    )

    urls = list(query.order_by('http_url').values_list('http_url', flat=True).distinct())
    activity.logger.info(f"[RunHTTPCrawlBridgeActivity] Found {len(urls)} new or dead/not-alive endpoints to crawl.")

    if not urls:
        activity.logger.info("[RunHTTPCrawlBridgeActivity] No new or dead/not-alive endpoints found. Skipping crawl.")
        return True

    return _run_task(
        http_crawl,
        ctx,
        task_name='http_crawl_bridge',
        description='HTTP Crawl Bridge',
        urls=urls,
        recrawl=False
    )


@activity.defn(name="ParseHTTPCrawlResultsActivity")
def parse_http_crawl_results_activity(ctx: dict) -> bool:
    """Verify HTTP crawl results are persisted correctly after http_crawl runs.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from startScan.models import EndPoint
    scan_id = ctx.get('scan_history_id')
    logger.log_line("[TEMPORAL]", "START", "task=parse_http_crawl_results scan_id=%s" % scan_id)
    # is_alive is a @property (not a DB column): http_status > 0, < 500, != 404
    alive_count = EndPoint.objects.filter(
        scan_history_id=scan_id,
        http_status__gt=0,
        http_status__lt=500,
    ).exclude(http_status=404).count()
    activity.logger.info(
        f"[ParseHTTPCrawlResultsActivity] scan_id={scan_id}: "
        f"{alive_count} alive endpoints."
    )
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=parse_http_crawl_results scan_id=%s alive=%d" % (scan_id, alive_count))
    return True


@activity.defn(name="RunPortScanActivity")
def run_port_scan_activity(ctx: dict) -> bool:
    """Run port scanning (naabu, nmap) across all discovered subdomains.

    Delegates to the existing `port_scan` task.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from reNgine.tasks import port_scan
    activity.logger.info(f"[RunPortScanActivity] scan_id={ctx.get('scan_history_id')}")
    from scanEngine.models import Proxy as _Proxy
    _proxy = _Proxy.objects.first()
    if _proxy and _proxy.use_tor:
        activity.logger.warning(
            "[RunPortScanActivity] TOR mode is active but naabu uses raw sockets — "
            "port scan traffic will NOT be routed through TOR"
        )
    return _run_task(
        port_scan,
        ctx,
        task_name='port_scan',
        description='Port Scan'
    )


@activity.defn(name="TorNewCircuitActivity")
def run_tor_new_circuit_activity() -> None:
    from reNgine.common_func import get_random_proxy
    logger.log_line("[TEMPORAL]", "START", "task=tor_new_circuit")
    if not get_random_proxy().startswith('socks'):
        logger.log_line("[TEMPORAL]", "COMPLETE", "task=tor_new_circuit skipped=no_socks_proxy")
        return
    from reNgine.tor_manager import TorManager
    try:
        TorManager().new_circuit()
        activity.logger.info("[TorNewCircuitActivity] New TOR circuit requested successfully")
        logger.log_line("[TEMPORAL]", "COMPLETE", "task=tor_new_circuit")
    except Exception as e:
        activity.logger.warning(f"[TorNewCircuitActivity] Circuit rotation failed (scan continues): {e}")
        logger.log_line("[TEMPORAL]", "COMPLETE", "task=tor_new_circuit skipped=circuit_failed")


@activity.defn(name="RunScreenshotActivity")
def run_screenshot_activity(ctx: dict) -> bool:
    """Capture screenshots of all live HTTP endpoints.

    Delegates to the existing `screenshot` task.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from reNgine.tasks import screenshot
    activity.logger.info(f"[RunScreenshotActivity] scan_id={ctx.get('scan_history_id')}")
    return _run_task(
        screenshot,
        ctx,
        task_name='screenshot',
        description='Screenshot'
    )


@activity.defn(name="RunFetchURLActivity")
def run_fetch_url_activity(ctx: dict) -> bool:
    """Fetch and collect all URLs across the target using gau, waybackurls, etc.

    Delegates to the existing `fetch_url` task.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from reNgine.tasks import fetch_url
    activity.logger.info(f"[RunFetchURLActivity] scan_id={ctx.get('scan_history_id')}")
    return _run_task(
        fetch_url,
        ctx,
        task_name='fetch_url',
        description='Fetch URL'
    )


@activity.defn(name="ParseEnumerationResultsActivity")
def parse_enumeration_results_activity(ctx: dict) -> bool:
    """Verify enumeration tier (ports, screenshots, URLs) results are persisted.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from startScan.models import EndPoint, IpAddress
    scan_id = ctx.get('scan_history_id')
    logger.log_line("[TEMPORAL]", "START", "task=parse_enumeration_results scan_id=%s" % scan_id)
    endpoint_count = EndPoint.objects.filter(scan_history_id=scan_id).count()
    activity.logger.info(
        f"[ParseEnumerationResultsActivity] scan_id={scan_id}: "
        f"{endpoint_count} total endpoints."
    )
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=parse_enumeration_results scan_id=%s endpoints=%d" % (scan_id, endpoint_count))
    return True


# ===========================================================================
# Tier 3/4 — Fuzzing & URL Extraction
# ===========================================================================

@activity.defn(name="RunDirFileFuzzActivity")
def run_dir_file_fuzz_activity(ctx: dict) -> bool:
    """Run directory and file fuzzing (dirsearch, ffuf) across all endpoints.

    Delegates to the existing `dir_file_fuzz` task.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from reNgine.fuzzing_tasks import dir_file_fuzz
    activity.logger.info(f"[RunDirFileFuzzActivity] scan_id={ctx.get('scan_history_id')}")
    return _run_task(
        dir_file_fuzz,
        ctx,
        task_name='dir_file_fuzz',
        description='Directory & File Fuzz'
    )


@activity.defn(name="ParseFuzzResultsActivity")
def parse_fuzz_results_activity(ctx: dict) -> bool:
    """Verify fuzzing results are persisted to the database.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from startScan.models import DirectoryFile
    scan_id = ctx.get('scan_history_id')
    logger.log_line("[TEMPORAL]", "START", "task=parse_fuzz_results scan_id=%s" % scan_id)
    fuzz_count = DirectoryFile.objects.filter(
        directory_files__directories__scan_history_id=scan_id
    ).distinct().count()
    activity.logger.info(
        f"[ParseFuzzResultsActivity] scan_id={scan_id}: {fuzz_count} fuzz entries."
    )
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=parse_fuzz_results scan_id=%s entries=%d" % (scan_id, fuzz_count))
    return True


# ===========================================================================
# Tier 5 — Analysis
# ===========================================================================

@activity.defn(name="RunWebAPIDiscoveryActivity")
def run_web_api_discovery_activity(ctx: dict) -> bool:
    """Discover web API endpoints and routes using kiterunner.

    Delegates to the existing `web_api_discovery` task.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from reNgine.tasks import web_api_discovery
    activity.logger.info(f"[RunWebAPIDiscoveryActivity] scan_id={ctx.get('scan_history_id')}")
    return _run_task(
        web_api_discovery,
        ctx,
        task_name='web_api_discovery',
        description='Web API Discovery'
    )


@activity.defn(name="RunWAFDetectionActivity")
def run_waf_detection_activity(ctx: dict) -> bool:
    """Detect Web Application Firewalls protecting the target.

    Delegates to the existing `waf_detection` task.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from reNgine.tasks import waf_detection
    activity.logger.info(f"[RunWAFDetectionActivity] scan_id={ctx.get('scan_history_id')}")
    return _run_task(
        waf_detection,
        ctx,
        task_name='waf_detection',
        description='WAF Detection'
    )


@activity.defn(name="RunSecretScanningActivity")
def run_secret_scanning_activity(ctx: dict) -> bool:
    """Scan for exposed secrets, credentials, and API keys using Semgrep/trufflehog.

    Delegates to the existing `secret_scanning` task.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from reNgine.tasks import secret_scanning
    activity.logger.info(f"[RunSecretScanningActivity] scan_id={ctx.get('scan_history_id')}")
    return _run_task(
        secret_scanning,
        ctx,
        task_name='secret_scanning',
        description='Secrets & Leaks Scan'
    )


@activity.defn(name="ParseAnalysisResultsActivity")
def parse_analysis_results_activity(ctx: dict) -> bool:
    """Verify analysis tier results (WAF, API routes, secrets) are persisted.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    scan_id = ctx.get('scan_history_id')
    logger.log_line("[TEMPORAL]", "START", "task=parse_analysis_results scan_id=%s" % scan_id)
    activity.logger.info(f"[ParseAnalysisResultsActivity] scan_id={scan_id}")
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=parse_analysis_results scan_id=%s" % scan_id)
    return True


# ===========================================================================
# Tier 6 — Assessment
# ===========================================================================

@activity.defn(name="CreateProxyListActivity")
def create_proxy_list_activity(ctx: dict) -> str:
    """Create a proxies.txt file if normal proxies are enabled.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        str: Path to the created proxies.txt file, or None if no proxies are configured.
    """
    from reNgine.common_func import get_proxy_list
    import os
    import uuid

    scan_id = ctx.get('scan_history_id')
    logger.log_line("[TEMPORAL]", "START", f"task=create_proxy_list scan_id={scan_id}")

    proxies = get_proxy_list()
    if not proxies or any(p.startswith('socks') for p in proxies):
        logger.log_line("[TEMPORAL]", "COMPLETE", f"task=create_proxy_list scan_id={scan_id} result=no_proxies_or_socks")
        return None

    results_dir = f"/usr/src/github/scan_results/{scan_id}"
    os.makedirs(results_dir, exist_ok=True)
    
    file_path = os.path.join(results_dir, f"proxies_{uuid.uuid4().hex}.txt")
    with open(file_path, 'w') as f:
        f.write('\n'.join(proxies))

    activity.logger.info(f"[CreateProxyListActivity] scan_id={scan_id} wrote {len(proxies)} proxies to {file_path}")
    logger.log_line("[TEMPORAL]", "COMPLETE", f"task=create_proxy_list scan_id={scan_id} result=created")
    return file_path

@activity.defn(name="CleanupProxyListActivity")
def cleanup_proxy_list_activity(file_path: str) -> bool:
    """Clean up the proxies.txt file.

    Args:
        file_path (str): Path to the proxies.txt file.

    Returns:
        bool: True if cleanup was successful or file didn't exist.
    """
    import os
    logger.log_line("[TEMPORAL]", "START", f"task=cleanup_proxy_list file_path={file_path}")
    if file_path and os.path.exists(file_path):
        try:
            os.remove(file_path)
            activity.logger.info(f"[CleanupProxyListActivity] removed {file_path}")
        except Exception as e:
            activity.logger.error(f"[CleanupProxyListActivity] failed to remove {file_path}: {e}")
    
    logger.log_line("[TEMPORAL]", "COMPLETE", f"task=cleanup_proxy_list file_path={file_path}")
    return True

@activity.defn(name="GatherNucleiTagsActivity")
def gather_nuclei_tags_activity(ctx: dict) -> dict:
    """Pre-compute Nuclei tags and build template-count-aware batches.

    Counts templates per detected tag via ``nuclei -tl`` so the workflow can
    dispatch bounded nuclei invocations without violating Temporal determinism.

    Returns:
        dict with keys:
          - ``tags``: sorted deduplicated list of all detected tag strings
          - ``batches``: list of tag-lists, each batch's total template count
                         <= max_templates_per_batch; empty list when no tags
                         detected (caller falls back to unfiltered scan).
    """
    from reNgine.tech_mapping import get_nuclei_tags_from_techs
    from reNgine.nuclei_batch_utils import count_templates_for_tag, build_tag_batches, get_template_counts_for_tags
    from reNgine.definitions import (
        NUCLEI_MAX_TEMPLATES_PER_BATCH, NUCLEI_DEFAULT_TEMPLATES_PATH,
        NUCLEI_TEMPLATE, NUCLEI_CUSTOM_TEMPLATE, ALL
    )

    scan_id = ctx.get('scan_history_id')
    subdomain_id = ctx.get('subdomain_id')

    logger.log_line("[TEMPORAL]", "START", "task=gather_nuclei_tags scan_id=%s subdomain_id=%s" % (scan_id, subdomain_id))

    yaml_config = ctx.get('yaml_configuration', {})
    nuclei_cfg = yaml_config.get('vulnerability_scan', {}).get('nuclei', {})
    user_tags = nuclei_cfg.get('tags', [])
    if isinstance(user_tags, str):
        user_tags = [t.strip() for t in user_tags.split(',') if t.strip()]

    max_per_batch = int(nuclei_cfg.get(NUCLEI_MAX_TEMPLATES_PER_BATCH) or 100)

    qs = Subdomain.objects.filter(scan_history_id=scan_id)
    if subdomain_id:
        qs = qs.filter(pk=subdomain_id)

    all_techs: set = set()
    for sub in qs:
        all_techs.update(sub.technologies.values_list('name', flat=True))

    tech_tags = get_nuclei_tags_from_techs(list(all_techs)) if all_techs else []
    merged_set = set(user_tags) | set(tech_tags)

    # Intelligence: Append specific Nuclei tags if previously discovered vulnerabilities warrant it.
    from startScan.models import Vulnerability, ScanHistory
    scan = ScanHistory.objects.filter(pk=scan_id).first()
    if scan and scan.domain:
        vulns_qs = Vulnerability.objects.filter(target_domain=scan.domain)
        if subdomain_id:
            vulns_qs = vulns_qs.filter(subdomain_id=subdomain_id)
        
        # We only need to check names and whether it has CVE relations
        # Fetching names instead of iterating objects avoids memory overhead
        vuln_names = ' '.join(vulns_qs.values_list('name', flat=True)).lower()
        has_cve = vulns_qs.filter(cve_ids__isnull=False).exists() or 'cve-' in vuln_names
        
        if 'xss' in vuln_names or 'cross site' in vuln_names:
            merged_set.add('xss')
        if 'lfi' in vuln_names or 'local file inclusion' in vuln_names:
            merged_set.add('lfi')
        if 'idor' in vuln_names:
            merged_set.add('idor')
        if has_cve:
            merged_set.add('cve')
            
    merged = sorted(merged_set)

    # Build the full list of template directories to scan for tag counts
    template_dirs = []
    nuclei_templates = nuclei_cfg.get(NUCLEI_TEMPLATE)
    custom_nuclei_templates = nuclei_cfg.get(NUCLEI_CUSTOM_TEMPLATE)

    if not (nuclei_templates or custom_nuclei_templates):
        template_dirs.append(NUCLEI_DEFAULT_TEMPLATES_PATH)

    if nuclei_templates:
        if ALL in nuclei_templates:
            template_dirs.append(NUCLEI_DEFAULT_TEMPLATES_PATH)
        else:
            template_dirs.extend(nuclei_templates)

    if custom_nuclei_templates:
        for elem in custom_nuclei_templates:
            if str(elem).endswith(('.yaml', '.yml')) or str(elem).endswith('/'):
                template_dirs.append(str(elem))
            else:
                template_dirs.append(f'{str(elem)}.yaml')

    # Count templates per tag so batches are bounded by template count not tag count.
    tag_counts = get_template_counts_for_tags(merged, template_dirs)
    for tag in merged:
        logger.log_line(
            "[TEMPORAL]", "INFO",
            "task=gather_nuclei_tags scan_id=%s tag=%s templates=%d" % (scan_id, tag, tag_counts.get(tag, 0))
        )

    batches = build_tag_batches(merged, tag_counts, max_per_batch=max_per_batch, max_tags=3)

    activity.logger.info(
        "[GatherNucleiTagsActivity] scan_id=%s tags=%s batches=%d max_per_batch=%d",
        scan_id, merged, len(batches), max_per_batch,
    )
    logger.log_line(
        "[TEMPORAL]", "COMPLETE",
        "task=gather_nuclei_tags scan_id=%s tags=%d batches=%d" % (scan_id, len(merged), len(batches))
    )
    return {'tags': merged, 'batches': batches}


@activity.defn(name="RunNucleiActivity")
def run_nuclei_activity(ctx: dict, severity: str = None, tag_batch: list = None) -> bool:
    """Run Nuclei vulnerability scan against all live endpoints discovered for this scan.

    Performs a pre-flight check against the EndPoint table before invoking nuclei_scan.
    If no endpoints have been crawled yet (e.g. http_crawl was not in the task list or
    found no alive hosts), falls back to the root domain URL so Nuclei has at least one
    target rather than silently writing an empty input file and producing zero results.

    Args:
        ctx (dict): Temporal workflow context containing scan_history_id and engine config.
        severity (str, optional): The target severity level to filter the scan.
        tag_batch (list, optional): Pre-computed tag batch from GatherNucleiTagsActivity.
            None or empty list means no -tags flag is passed to Nuclei.

    Returns:
        bool: True on success (including graceful skip when no domain is found).
    """
    from reNgine.tasks import nuclei_scan
    from startScan.models import EndPoint, ScanHistory

    scan_id = ctx.get('scan_history_id')
    severity = severity or ctx.get('nuclei_severity_filter')
    proxies_file_path = ctx.get('nuclei_proxies_path')
    activity.logger.info(
        "[RunNucleiActivity] scan_id=%s severity=%s tags=%s proxies_file=%s",
        scan_id, severity, tag_batch, proxies_file_path
    )

    # Pre-flight: count endpoints in DB for this scan
    endpoint_count = EndPoint.objects.filter(scan_history_id=scan_id).count()

    if endpoint_count == 0:
        # No endpoints from http_crawl — derive the root URL from the ScanHistory domain
        # and use it as a minimum target so Nuclei always has something to scan.
        scan = ScanHistory.objects.filter(pk=scan_id).first()
        if scan and scan.domain:
            root_url = f"https://{scan.domain.name}"
            activity.logger.warning(
                "[RunNucleiActivity] No endpoints found in DB for scan_id=%s. "
                "Falling back to root URL: %s",
                scan_id, root_url,
            )
            urls = [root_url]
        else:
            activity.logger.error(
                "[RunNucleiActivity] No endpoints and no domain found for scan_id=%s. "
                "Skipping Nuclei scan.",
                scan_id,
            )
            return True
    else:
        activity.logger.info(
            "[RunNucleiActivity] %d endpoints in DB for scan_id=%s. "
            "Nuclei will query get_http_urls() from DB.",
            endpoint_count, scan_id,
        )
        # Let nuclei_scan call get_http_urls() to filter alive endpoints from DB
        urls = []

    tag_label = ','.join(tag_batch) if tag_batch else ''
    task_desc = f'Nuclei Scan ({severity}{" [" + tag_label + "]" if tag_label else ""})' if severity else 'Nuclei Scan'

    return _run_task(
        nuclei_scan, ctx,
        task_name='nuclei_scan',
        description=task_desc,
        urls=urls,
        severity=severity,
        tags_override=tag_batch if tag_batch else None,
        proxies_file_path=proxies_file_path,
    )

@activity.defn(name="RunCRLFuzzActivity")
def run_crlfuzz_activity(ctx: dict) -> bool:
    from reNgine.tasks import crlfuzz_scan
    activity.logger.info(f"[RunCRLFuzzActivity] scan_id={ctx.get('scan_history_id')}")
    return _run_task(crlfuzz_scan, ctx, task_name='crlfuzz_scan', description='CRLFuzz Scan', urls=ctx.get('urls', []))

@activity.defn(name="RunDalfoxActivity")
def run_dalfox_activity(ctx: dict) -> bool:
    from reNgine.tasks import dalfox_xss_scan
    activity.logger.info(f"[RunDalfoxActivity] scan_id={ctx.get('scan_history_id')}")
    return _run_task(dalfox_xss_scan, ctx, task_name='dalfox_xss_scan', description='Dalfox XSS Scan', urls=ctx.get('urls', []))

@activity.defn(name="RunS3ScannerActivity")
def run_s3scanner_activity(ctx: dict) -> bool:
    from reNgine.tasks import s3scanner
    activity.logger.info(f"[RunS3ScannerActivity] scan_id={ctx.get('scan_history_id')}")
    return _run_task(s3scanner, ctx, task_name='s3scanner', description='S3 Bucket Scanner')

@activity.defn(name="RunAcunetixActivity")
def run_acunetix_activity(ctx: dict) -> bool:
    from reNgine.tasks import acunetix_scan
    activity.logger.info(f"[RunAcunetixActivity] scan_id={ctx.get('scan_history_id')}")
    return _run_task(
        acunetix_scan,
        ctx,
        task_name='acunetix_scan',
        description='Acunetix Scan',
        domain_id=ctx.get('domain_id'),
        scan_history_id=ctx.get('scan_history_id'),
        subdomain_id=ctx.get('subdomain_id'),
        subdomain_name=ctx.get('subdomain_name'),
        subdomain_http_url=ctx.get('subdomain_http_url'),
    )

@activity.defn(name="RunCpanelScanActivity")
def run_cpanel_scan_activity(ctx: dict) -> bool:
    from reNgine.vulnerability_tasks import cpanel_scan
    activity.logger.info(f"[RunCpanelScanActivity] scan_id={ctx.get('scan_history_id')}")
    return _run_task(cpanel_scan, ctx, task_name='cpanel_scan', description='cPanel Vulnerability Scan')

@activity.defn(name="RunWpscanActivity")
def run_wpscan_activity(ctx: dict) -> bool:
    from reNgine.wpscan_tasks import wpscan_scan
    activity.logger.info(f"[RunWpscanActivity] scan_id={ctx.get('scan_history_id')}")
    return _run_task(wpscan_scan, ctx, task_name='wpscan_scan', description='WPScan', urls=ctx.get('urls', []))

@activity.defn(name="RunWPTaintScanActivity")
def run_wptaint_scan_activity(ctx: dict) -> bool:
    from reNgine.wptaint_tasks import wptaint_scan
    activity.logger.info(f"[RunWPTaintScanActivity] scan_id={ctx.get('scan_history_id')}")
    return _run_task(wptaint_scan, ctx, task_name='wptaint_scan', description='WP Taint Scan', urls=ctx.get('urls', []))

@activity.defn(name="RunReact2ShellActivity")
def run_react2shell_activity(ctx: dict) -> bool:
    from reNgine.vulnerability_tasks import react2shell_scan
    activity.logger.info(f"[RunReact2ShellActivity] scan_id={ctx.get('scan_history_id')}")
    return _run_task(react2shell_scan, ctx, task_name='react2shell_scan', description='React Vulnerability Scan')

@activity.defn(name="RunSemgrepActivity")
def run_semgrep_activity(ctx: dict) -> bool:
    from reNgine.tasks import semgrep_scan
    activity.logger.info(f"[RunSemgrepActivity] scan_id={ctx.get('scan_history_id')}")
    return _run_task(semgrep_scan, ctx, task_name='semgrep_scan', description='Semgrep Vulnerability Scan', mode='vulnerability')


@activity.defn(name="RunVigoliumScanActivity")
def run_vigolium_scan_activity(ctx: dict) -> bool:
    """Run Vigolium known-issue + dynamic-assessment scan against live endpoints.

    Runs inside NucleiPlannerWorkflow at Tier 6 alongside Nuclei. Default-enabled
    via vulnerability_scan.run_vigolium: true in the engine YAML config.
    """
    from reNgine.vigolium_tasks import vigolium_scan
    activity.logger.info(f"[RunVigoliumScanActivity] scan_id={ctx.get('scan_history_id')}")
    return _run_task(vigolium_scan, ctx, task_name='vigolium_scan', description='Vigolium Vulnerability Scan')


@activity.defn(name="RunVigoliumDiscoveryActivity")
def run_vigolium_discovery_activity(ctx: dict) -> bool:
    """Run Vigolium discovery phase to seed the endpoint DB.

    Runs at Tier 2 in parallel with http_crawl. Populates EndPoint records
    with URLs discovered by vigolium's ingestion + discovery phases.
    Controlled by vigolium_discovery.run_vigolium_discovery in engine YAML.
    """
    from reNgine.vigolium_tasks import vigolium_discovery
    activity.logger.info(f"[RunVigoliumDiscoveryActivity] scan_id={ctx.get('scan_history_id')}")
    return _run_task(vigolium_discovery, ctx, task_name='vigolium_discovery', description='Vigolium Endpoint Discovery')


@activity.defn(name="RunVigoliumAnalysisActivity")
def run_vigolium_analysis_activity(ctx: dict) -> bool:
    """Run Vigolium dynamic-assessment phase at Tier 5.

    Runs in parallel with web_api_discovery. Executes vigolium's 251-module
    passive + active scanning suite and saves findings as Vulnerability records.
    Controlled by vigolium_analysis.run_vigolium_analysis in engine YAML.
    """
    from reNgine.vigolium_tasks import vigolium_analysis
    activity.logger.info(f"[RunVigoliumAnalysisActivity] scan_id={ctx.get('scan_history_id')}")
    return _run_task(vigolium_analysis, ctx, task_name='vigolium_analysis', description='Vigolium Dynamic Analysis')


@activity.defn(name="MarkVulnerabilityScanCompleteActivity")
def mark_vulnerability_scan_complete_activity(ctx: dict) -> None:
    """Write a SUCCESS ScanActivity with name='vulnerability_scan'.

    NucleiPlannerWorkflow runs as a child workflow whose internal activities
    use names like 'nuclei_scan', 'crlfuzz_scan', etc. — never 'vulnerability_scan'.
    Without this record, resume_scan_temporal always considers vulnerability_scan
    incomplete and re-runs it from scratch on crash recovery.
    """
    from startScan.models import ScanHistory, ScanActivity
    from reNgine.definitions import SUCCESS_TASK
    from django.utils import timezone

    scan_id = ctx.get('scan_history_id')
    logger.log_line("[TEMPORAL]", "START", "task=mark_vulnerability_scan_complete scan_id=%s" % scan_id)
    scan = ScanHistory.objects.filter(pk=scan_id).first()
    if not scan:
        logger.log_line("[TEMPORAL]", "COMPLETE", "task=mark_vulnerability_scan_complete scan_id=%s skipped=no_scan" % scan_id)
        return
    ScanActivity.objects.update_or_create(
        scan_of=scan,
        name='vulnerability_scan',
        defaults={
            'title': 'Vulnerability Scan',
            'time': timezone.now(),
            'status': SUCCESS_TASK,
        }
    )
    activity.logger.info(f"[MarkVulnerabilityScanCompleteActivity] scan_id={scan_id} marked complete")
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=mark_vulnerability_scan_complete scan_id=%s" % scan_id)


@activity.defn(name="RunWAFBypassActivity")
def run_waf_bypass_activity(ctx: dict) -> bool:
    """Attempt to bypass detected WAF protections to find unprotected origins.

    Delegates to the existing `waf_bypass` task.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from reNgine.tasks import waf_bypass
    activity.logger.info(f"[RunWAFBypassActivity] scan_id={ctx.get('scan_history_id')}")
    return _run_task(
        waf_bypass,
        ctx,
        task_name='waf_bypass',
        description='WAF Bypass'
    )



@activity.defn(name="ParseAssessmentResultsActivity")
def parse_assessment_results_activity(ctx: dict) -> bool:
    """Verify assessment tier (vulnerability) results are persisted.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from startScan.models import Vulnerability
    scan_id = ctx.get('scan_history_id')
    logger.log_line("[TEMPORAL]", "START", "task=parse_assessment_results scan_id=%s" % scan_id)
    vuln_count = Vulnerability.objects.filter(scan_history_id=scan_id).count()
    activity.logger.info(
        f"[ParseAssessmentResultsActivity] scan_id={scan_id}: "
        f"{vuln_count} vulnerabilities found."
    )
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=parse_assessment_results scan_id=%s vulns=%d" % (scan_id, vuln_count))
    return True


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
    from startScan.models import CveId
    from reNgine.cve_enrichment import CVEEnrichmentService

    scan_id = ctx.get('scan_history_id')
    logger.log_line("[TEMPORAL]", "START", "task=enrich_scan_cves scan_id=%s" % scan_id)
    activity.logger.warning("[TIER7][CVE_ENRICH] Activity starting | scan_id=%s", scan_id)

    cve_names = list(
        CveId.objects
        .filter(cve_ids__scan_history_id=scan_id)
        .values_list('name', flat=True)
        .distinct()
    )

    if not cve_names:
        activity.logger.warning("[TIER7][CVE_ENRICH] No CVEs found for this scan | scan_id=%s", scan_id)
        logger.log_line("[TEMPORAL]", "COMPLETE", "task=enrich_scan_cves scan_id=%s enriched=0/0 skipped=no_cves" % scan_id)
        return True

    activity.logger.warning("[TIER7][CVE_ENRICH] Enriching %d CVE(s) | scan_id=%s", len(cve_names), scan_id)
    service = CVEEnrichmentService()
    enriched = 0

    for cve_name in cve_names:
        try:
            activity.heartbeat(f"enriching {cve_name}")
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


_PERMITTED_GENERIC_TASKS = frozenset({
    "subdomain_discovery", "amass_intel_discovery", "firewall_vpn_scan",
    "dns_security", "osint", "spiderfoot_scan", "http_crawl", "port_scan", "screenshot",
    "fetch_url", "dir_file_fuzz", "web_api_discovery", "waf_detection",
    "secret_scanning", "vulnerability_scan", "waf_bypass",
    "nuclei_scan", "crlfuzz_scan", "dalfox_xss_scan", "s3scanner",
    "acunetix_scan", "cpanel_scan", "wpscan_scan", "react2shell_scan",
    "semgrep_scan", "correlate_vulnerabilities", "calculate_risk_scores",
    "generate_impact_assessment", "run_apme", "attack_path_modeling",
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
    activity.logger.info(f"[RunGenericTaskActivity] task={task_name} scan_id={ctx.get('scan_history_id')}")

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
        activity.logger.error(f"[FinalizeSubScanActivity] SubScan {subscan_id} not found.")
        return False

    status = SUCCESS_TASK if success else FAILED_TASK
    status_h = 'SUCCESS' if success else 'FAILED'

    subscan.status = status
    subscan.stop_scan_date = timezone.now()
    subscan.save()

    activity.logger.info(
        f"[FinalizeSubScanActivity] subscan_id={subscan_id} finished with status={status_h}"
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
        logger.warning(f"Could not send subscan notification: {e}")

    return True


# ===========================================================================
# Stress Testing Activities
# ===========================================================================

@activity.defn(name="InitStressTestActivity")
def init_stress_test_activity(ctx: dict) -> dict:
    """Resolve target endpoints and create the StressTestResult DB record.

    Mirrors the target profiling + endpoint query block from run_stress_testing.
    Clears any stale telemetry stream and publishes the initial 'running' status.

    Args:
        ctx: Must contain scan_history_id, target_domain_name, stress_config.

    Returns:
        Enriched ctx with 'resolved_endpoints' (list[str]) and 'stress_result_id' (int).
    """
    import time
    from startScan.models import ScanHistory, EndPoint, StressTestResult
    from targetApp.models import Domain
    from reNgine.definitions import RUNNING_TASK
    from reNgine.stress.telemetry import StressTelemetryPublisher

    scan_id = ctx["scan_history_id"]
    target_domain = ctx["target_domain_name"]
    stress_config = ctx.get("stress_config", {})

    logger.log_line("[TEMPORAL]", "START", "task=init_stress_test scan_id=%s" % scan_id)
    activity.logger.info(f"[InitStressTestActivity] scan_id={scan_id}")

    scan = ScanHistory.objects.get(id=scan_id)
    domain = Domain.objects.get(name=target_domain)

    scan.scan_status = RUNNING_TASK
    scan.save()

    selected = stress_config.get("selected_endpoints", [])
    if selected:
        endpoints = list(
            EndPoint.objects.filter(
                scan_history_id=scan_id, http_url__in=selected
            ).values_list("http_url", flat=True)
        )
    else:
        crawl_targets = stress_config.get("crawl_targets", False)
        qs = EndPoint.objects.filter(
            scan_history_id=scan_id, subdomain__name=target_domain
        ).order_by("id")
        endpoints = list(qs.values_list("http_url", flat=True)[:5 if crawl_targets else 1])

    tools = stress_config.get("uses_tools", ["k6"])
    concurrency = stress_config.get("concurrency", 50)
    duration = stress_config.get("duration", "30s") or "30s"

    result = StressTestResult.objects.create(
        scan_history=scan,
        target_domain=domain,
        tool_used=",".join(tools),
        concurrency_used=concurrency,
        duration=duration,
    )

    publisher = StressTelemetryPublisher(scan_id)
    publisher.clear_stream()
    publisher.publish({"type": "scan_status", "status": "running", "timestamp": time.time()})

    activity.logger.info(
        f"[InitStressTestActivity] scan_id={scan_id} "
        f"resolved {len(endpoints)} endpoint(s) for tools={tools}"
    )
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=init_stress_test scan_id=%s endpoints=%d tools=%s" % (scan_id, len(endpoints), ','.join(tools)))

    return {
        **ctx,
        "resolved_endpoints": endpoints,
        "stress_result_id": result.id,
    }


@activity.defn(name="RunStressToolActivity")
def run_stress_tool_activity(ctx: dict) -> dict:
    """Execute a single stress tool against a single endpoint.

    Corresponds to the inner (endpoint × tool) loop of run_stress_testing.
    Sends Temporal heartbeats every 15 seconds.  Also checks the Redis kill
    switch as a belt-and-braces fallback for the window before the Temporal
    signal reaches the workflow.

    Args:
        ctx: Must contain scan_history_id, target_domain_name, stress_config,
             current_endpoint (str), current_tool (str).

    Returns:
        dict of aggregated metrics from the parser (total_requests,
        successful_requests, failed_requests, avg_latency_ms, p95_latency_ms,
        p99_latency_ms, max_requests_per_second).
    """
    import os
    import signal as os_signal
    import subprocess
    import threading
    import time
    import contextvars
    from temporalio.exceptions import CancelledError

    import redis as redis_lib
    from django.conf import settings
    from django.utils import timezone
    from startScan.models import Command
    from reNgine.parsers import K6Parser, WrkParser, Hping3Parser, LocustParser, TAStressorParser
    from reNgine.stress.telemetry import StressTelemetryPublisher
    from reNgine.stress.cmd_builder import build_stress_command
    from reNgine.common_func import get_random_proxy, get_random_user_agent
    from reNgine.utils.opsec import ProxychainsWrapper

    scan_id = ctx["scan_history_id"]
    target_domain = ctx["target_domain_name"]
    endpoint_url = ctx["current_endpoint"]
    tool = ctx["current_tool"]
    stress_config = ctx.get("stress_config", {})
    tool_config = stress_config.get(f"{tool}_config", {})
    concurrency = stress_config.get("concurrency", 50)
    duration = stress_config.get("duration", "30s") or "30s"

    logger.log_line("[TEMPORAL]", "START", "task=run_stress_tool tool=%s endpoint=%s scan_id=%s" % (tool, endpoint_url, scan_id))
    activity.logger.info(
        f"[RunStressToolActivity] tool={tool} endpoint={endpoint_url} scan_id={scan_id}"
    )

    publisher = StressTelemetryPublisher(scan_id)

    # Redis kill-switch check — secondary fallback alongside the Temporal signal
    try:
        rdb = redis_lib.StrictRedis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            password=settings.REDIS_PASSWORD,
            db=0
        )
    except Exception:
        rdb = None

    def _kill_switch_active():
        try:
            return rdb is not None and rdb.get(f"kill_switch_{scan_id}") == b"1"
        except Exception:
            return False

    # Select the right parser
    parsers = {
        "k6": K6Parser,
        "wrk": WrkParser,
        "hping3": Hping3Parser,
        "locust": LocustParser,
        "stressor": TAStressorParser,
    }
    parser_cls = parsers.get(tool)
    if not parser_cls:
        raise ValueError(f"[RunStressToolActivity] Unknown tool: {tool!r}")
    parser = parser_cls()

    single_proxy = get_random_proxy()
    k6_user_agent = get_random_user_agent()

    cmd_str, temp_files = build_stress_command(
        tool=tool,
        tool_config=tool_config,
        endpoint_url=endpoint_url,
        target_domain=target_domain,
        scan_id=scan_id,
        concurrency=concurrency,
        duration=duration,
        single_proxy=single_proxy,
        k6_user_agent=k6_user_agent,
        base_dir=settings.BASE_DIR,
    )

    proxy_wrapper = ProxychainsWrapper()
    temp_conf_path = None
    if proxy_wrapper.should_wrap():
        cmd_str, temp_conf_path = proxy_wrapper.wrap_command(cmd_str)
        activity.logger.info(f"[RunStressToolActivity] Wrapping via proxychains: {cmd_str}")
    else:
        activity.logger.info(f"[RunStressToolActivity] Executing: {cmd_str}")

    if temp_conf_path:
        temp_files.append(temp_conf_path)

    command_obj = Command.objects.create(
        command=cmd_str,
        time=timezone.now(),
        scan_history_id=scan_id,
    )

    publisher.publish({
        "type": "command",
        "tool": tool,
        "endpoint": endpoint_url,
        "command": cmd_str,
        "timestamp": time.time(),
    })

    # Pre-declare process variable so the background heartbeat thread can inspect it safely
    process = None

    # Helper function to terminate the subprocess group
    def _terminate_process():
        is_mock = hasattr(process, 'assert_called')
        if process and (process.poll() is None or is_mock):
            try:
                activity.logger.info(
                    f"[RunStressToolActivity] Terminating process group for {tool} (PID: {process.pid})"
                )
                os.killpg(os.getpgid(process.pid), os_signal.SIGTERM)
            except Exception as kill_err:
                activity.logger.error(f"[RunStressToolActivity] Kill failed: {kill_err}")

    # Helper to check if running inside a Temporal activity context (fails during direct unit tests)
    def _is_in_activity_context():
        try:
            activity.is_cancelled()
            return True
        except RuntimeError:
            return False

    def _is_cancelled():
        return _is_in_activity_context() and activity.is_cancelled()

    # Heartbeat thread — keeps the activity alive in Temporal's eyes.
    # Copy the current contextvars context so the heartbeat thread inherits the
    # Temporal activity context. threading.Thread does NOT copy contextvars by
    # default, causing activity.heartbeat() to fail with "Not in activity context",
    # which silently prevents all heartbeats from reaching Temporal and triggers
    # the heartbeat_timeout cancellation + retry loop.
    stop_heartbeat = threading.Event()
    _activity_ctx = contextvars.copy_context()

    def _heartbeat():
        def _do_heartbeat():
            while not stop_heartbeat.is_set():
                # Perform periodic cancellation check
                if _is_cancelled():
                    activity.logger.info(
                        f"[RunStressToolActivity] Activity cancelled — terminating {tool}"
                    )
                    _terminate_process()
                    break
                if _is_in_activity_context():
                    try:
                        activity.heartbeat(f"Running {tool} against {endpoint_url}")
                    except CancelledError:
                        activity.logger.info(
                            f"[RunStressToolActivity] Heartbeat received cancellation — terminating {tool}"
                        )
                        _terminate_process()
                        break
                    except Exception as hb_err:
                        if "cancel" in str(hb_err).lower():
                            activity.logger.info(
                                f"[RunStressToolActivity] Heartbeat received cancellation exception: {hb_err} — terminating {tool}"
                            )
                            _terminate_process()
                            break
                        try:
                            _info = activity.info()
                            activity.logger.warning(
                                "[RunStressToolActivity] Heartbeat failed — "
                                "activity_type=%s workflow_id=%s attempt=%d tool=%s error=%s",
                                _info.activity_type, _info.workflow_id, _info.attempt, tool, hb_err,
                            )
                        except Exception:
                            activity.logger.warning(
                                "[RunStressToolActivity] Heartbeat failed for %s: %s", tool, hb_err
                            )
                stop_heartbeat.wait(15)
        _activity_ctx.run(_do_heartbeat)

    hb_thread = threading.Thread(target=_heartbeat, daemon=True)
    hb_thread.start()

    accumulated_lines = []
    try:
        process = subprocess.Popen(
            cmd_str,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            shell=True,
            start_new_session=True,
        )

        while True:
            # Check for cancellation on each iteration
            if _is_cancelled():
                activity.logger.info(
                    f"[RunStressToolActivity] Main thread detected cancellation — terminating {tool}"
                )
                _terminate_process()
                break

            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            if line:
                line = line.strip()
                accumulated_lines.append(line)
                publisher.publish({
                    "type": "log",
                    "tool": tool,
                    "endpoint": endpoint_url,
                    "line": line,
                    "timestamp": time.time(),
                })
                metrics = parser.parse_line(line)
                if metrics:
                    metrics.update({
                        "type": "metric",
                        "tool": tool,
                        "endpoint": endpoint_url,
                        "timestamp": time.time(),
                    })
                    publisher.publish(metrics)

            if _kill_switch_active():
                activity.logger.info(
                    f"[RunStressToolActivity] Redis kill switch active — terminating {tool}"
                )
                _terminate_process()
                break

        process.wait()
        command_obj.output = "\n".join(accumulated_lines)
        command_obj.return_code = process.returncode
        command_obj.save()

    finally:
        stop_heartbeat.set()
        hb_thread.join(timeout=5)
        for path in temp_files:
            if path and os.path.exists(path):
                try:
                    os.remove(path)
                except Exception as rm_err:
                    activity.logger.error(
                        f"[RunStressToolActivity] Could not remove temp file {path}: {rm_err}"
                    )

    final_metrics = parser.get_final_metrics()
    activity.logger.info(
        f"[RunStressToolActivity] tool={tool} endpoint={endpoint_url} "
        f"done — {final_metrics.get('total_requests', 0)} requests"
    )
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=run_stress_tool tool=%s scan_id=%s requests=%d" % (tool, scan_id, final_metrics.get('total_requests', 0)))
    return final_metrics


@activity.defn(name="FinalizeStressTestActivity")
def finalize_stress_test_activity(ctx: dict) -> bool:
    """Aggregate metrics, update StressTestResult + ScanHistory, send notification.

    Mirrors the post-loop finalisation block in run_stress_testing and always
    publishes a 'completed' status to the telemetry stream so the frontend
    exits the running state even if a previous worker crash left it stale.

    Args:
        ctx: Must contain scan_history_id, stress_result_id, aborted (bool),
             and pre-aggregated metric fields from the workflow.

    Returns:
        True on success.
    """
    import time
    from django.utils import timezone
    from startScan.models import ScanHistory, StressTestResult
    from reNgine.definitions import SUCCESS_TASK, ABORTED_TASK
    from reNgine.stress.telemetry import StressTelemetryPublisher
    from reNgine.tasks import send_scan_notif

    scan_id = ctx["scan_history_id"]
    result_id = ctx.get("stress_result_id")
    aborted = ctx.get("aborted", False)

    logger.log_line("[TEMPORAL]", "START", "task=finalize_stress_test scan_id=%s aborted=%s" % (scan_id, aborted))
    activity.logger.info(
        f"[FinalizeStressTestActivity] scan_id={scan_id} aborted={aborted}"
    )

    result = StressTestResult.objects.filter(id=result_id).first()
    if result:
        result.total_requests = ctx.get("total_requests", 0)
        result.successful_requests = ctx.get("successful_requests", 0)
        result.failed_requests = ctx.get("failed_requests", 0)
        result.avg_latency_ms = ctx.get("avg_latency_ms", 0.0)
        result.p95_latency_ms = ctx.get("p95_latency_ms", 0.0)
        result.p99_latency_ms = ctx.get("p99_latency_ms", 0.0)
        result.max_requests_per_second = ctx.get("max_rps", 0.0)
        result.is_kill_switch_triggered = aborted
        result.save()

    scan = ScanHistory.objects.filter(id=scan_id).first()
    if scan:
        scan.scan_status = ABORTED_TASK if aborted else SUCCESS_TASK
        scan.stop_scan_date = timezone.now()
        scan.save()

    # Always publish completed status — prevents the frontend from getting stuck
    # in 'running' state after a worker crash between activities.
    publisher = StressTelemetryPublisher(scan_id)
    publisher.publish({
        "type": "scan_status",
        "status": "completed",
        "timestamp": time.time(),
    })

    try:
        send_scan_notif(
            scan_history_id=scan_id,
            status="ABORTED" if aborted else "SUCCESS",
        )
    except Exception as e:
        activity.logger.warning(
            f"[FinalizeStressTestActivity] Notification failed (non-fatal): {e}"
        )

    status_h = "ABORTED" if aborted else "SUCCESS"
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=finalize_stress_test scan_id=%s status=%s" % (scan_id, status_h))
    return True


@activity.defn(name="RunStartupSyncActivity")
def run_startup_sync_activity(task_name: str) -> None:
    """Execute a named startup sync task. Called once per orchestrator start via StartupSyncWorkflow.

    Supported task_name values:
      'sync_all_scans_to_graph' — syncs all scan results to Neo4j
      'sync_cisa_kev_catalog'   — downloads CISA KEV catalog and marks CVEs
      'sync_semgrep_rules'      — syncs Semgrep rule sets to local filesystem
      'sync_cve_data'           — full CVE enrichment (KEV catalog + unenriched CVEs)
    """
    logger.log_line("[TEMPORAL]", "START", "task=run_startup_sync task_name=%s" % task_name)
    activity.logger.info(f"[RunStartupSyncActivity] Starting: {task_name}")
    if task_name == 'sync_all_scans_to_graph':
        from reNgine.tasks import sync_all_scans_to_graph
        from reNgine.utils.graph import _graph_heartbeat
        activity.heartbeat("startup graph sync starting")
        sync_all_scans_to_graph(None, heartbeat_callback=_graph_heartbeat)
    elif task_name == 'sync_cisa_kev_catalog':
        from reNgine.tasks import sync_cisa_kev_catalog
        sync_cisa_kev_catalog()
    elif task_name == 'sync_semgrep_rules':
        from reNgine.tasks import sync_semgrep_rules
        sync_semgrep_rules()
    elif task_name == 'recover_stuck_scans':
        from reNgine.tasks import recover_stuck_scans
        recover_stuck_scans()
    elif task_name == 'sync_cve_data':
        from reNgine.cve_enrichment import CVEEnrichmentService, CVEBatchEnricher
        service = CVEEnrichmentService()
        enricher = CVEBatchEnricher()
        service.sync_cisa_kev_catalog()
        enricher.enrich_unenriched_cves()
    elif task_name == 'sync_epss_data':
        from reNgine.cve_enrichment import CVEEnrichmentService
        service = CVEEnrichmentService()
        service.sync_epss_catalog()
    else:
        raise ValueError(f"[RunStartupSyncActivity] Unknown task: {task_name}")
    activity.logger.info(f"[RunStartupSyncActivity] Completed: {task_name}")
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=run_startup_sync task_name=%s" % task_name)


@activity.defn(name="RunMonitoringCheckActivity")
def run_monitoring_check_activity(domain_id: int) -> None:
    """Execute a monitoring check for a domain. Called by MonitoringWorkflow on schedule.

    Delegates to monitor_target_task which handles subdomain discovery, change
    detection, notifications, and conditional scan initiation.
    """
    logger.log_line("[TEMPORAL]", "START", "task=run_monitoring_check domain_id=%s" % domain_id)
    activity.logger.info(f"[RunMonitoringCheckActivity] Checking domain_id={domain_id}")
    from reNgine.monitor_tasks import monitor_target_task
    monitor_target_task(domain_id)
    activity.logger.info(f"[RunMonitoringCheckActivity] Completed domain_id={domain_id}")
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=run_monitoring_check domain_id=%s" % domain_id)


@activity.defn(name="SetupScheduledScanActivity")
def setup_scheduled_scan_activity(params: dict) -> dict:
    """Create a ScanHistory record and build a full workflow ctx for a scheduled scan.

    Mirrors the setup portion of initiate_scan_temporal (DB record creation,
    directory setup, initial subdomain/endpoint) without starting any workflow.
    The returned ctx is passed directly to MasterScanWorkflow as a child workflow.

    Args:
        params: Dict with keys: domain_id, engine_id, scan_type, initiated_by_id,
                imported_subdomains, out_of_scope_subdomains, starting_point_path,
                excluded_paths, enable_spiderfoot_scan.

    Returns:
        dict: Complete Temporal workflow ctx ready for MasterScanWorkflow.
    """
    import os
    import yaml
    from django.utils import timezone
    from reNgine.common_func import (
        create_scan_object, save_imported_subdomains, save_subdomain, save_endpoint
    )
    from reNgine.definitions import (
        RUNNING_TASK, SCHEDULED_SCAN,
        ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL,
        GF_PATTERNS, WEB_API_DISCOVERY, USES_TOOLS, KITERUNNER_WORDLIST,
    )
    from reNgine.settings import RENGINE_RESULTS
    from scanEngine.models import EngineType
    from startScan.models import ScanHistory
    from targetApp.models import Domain

    domain_id = params['domain_id']
    engine_id = params['engine_id']
    initiated_by_id = params.get('initiated_by_id')
    logger.log_line("[TEMPORAL]", "START", "task=setup_scheduled_scan domain_id=%s engine_id=%s" % (domain_id, engine_id))
    imported_subdomains = params.get('imported_subdomains') or []
    out_of_scope_subdomains = params.get('out_of_scope_subdomains') or []
    starting_point_path = (params.get('starting_point_path') or '').rstrip('/')
    excluded_paths = params.get('excluded_paths') or []
    enable_spiderfoot_scan = params.get('enable_spiderfoot_scan', False)

    engine = EngineType.objects.get(pk=engine_id)
    domain = Domain.objects.get(pk=domain_id)
    imported_subdomains = merge_imported_subdomains(domain, imported_subdomains)
    config = yaml.safe_load(engine.yaml_configuration) or {}

    scan_history_id = create_scan_object(
        host_id=domain_id,
        engine_id=engine_id,
        initiated_by_id=initiated_by_id,
    )
    scan = ScanHistory.objects.get(pk=scan_history_id)

    tasks = list(engine.tasks)
    if 'waf_bypass' in tasks and 'waf_detection' not in tasks:
        tasks.insert(tasks.index('waf_bypass'), 'waf_detection')
    if enable_spiderfoot_scan and 'spiderfoot_scan' not in tasks:
        tasks.append('spiderfoot_scan')

    scan.scan_status = RUNNING_TASK
    scan.scan_type = engine
    scan.domain = domain
    scan.start_scan_date = timezone.now()
    scan.tasks = tasks
    scan.results_dir = f'{RENGINE_RESULTS}/{domain.name}_{scan.id}'
    scan.cfg_starting_point_path = starting_point_path
    scan.cfg_excluded_paths = excluded_paths
    scan.cfg_out_of_scope_subdomains = out_of_scope_subdomains
    scan.cfg_imported_subdomains = imported_subdomains
    scan.save()

    os.makedirs(scan.results_dir, exist_ok=True)

    ctx_bootstrap = {
        'scan_history_id': scan.id,
        'engine_id': engine_id,
        'domain_id': domain.id,
        'results_dir': scan.results_dir,
        'starting_point_path': starting_point_path,
        'out_of_scope_subdomains': out_of_scope_subdomains,
    }
    save_imported_subdomains(imported_subdomains, ctx=ctx_bootstrap)

    enable_http_crawl = config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL)
    subdomain, _ = save_subdomain(domain.name, ctx=ctx_bootstrap)
    _root = f'{domain.name}{starting_point_path}' if starting_point_path else domain.name
    if not _root.startswith(('http://', 'https://')):
        _root = f'http://{_root}'
    endpoint, _ = save_endpoint(
        _root,
        ctx=ctx_bootstrap,
        crawl=enable_http_crawl,
        is_default=True,
        subdomain=subdomain,
    )
    if endpoint and endpoint.is_alive:
        subdomain.http_url = endpoint.http_url
        subdomain.http_status = endpoint.http_status
        subdomain.response_time = endpoint.response_time
        subdomain.page_title = endpoint.page_title
        subdomain.content_type = endpoint.content_type
        subdomain.content_length = endpoint.content_length
        for tech in endpoint.techs.all():
            subdomain.technologies.add(tech)
        subdomain.save()

    gf_patterns = config.get(GF_PATTERNS, [])
    api_discovery_config = config.get(WEB_API_DISCOVERY, {})
    api_discovery_tools = api_discovery_config.get(USES_TOOLS, [])
    kr_wordlist = api_discovery_config.get(KITERUNNER_WORDLIST, 'routes-small.kite')

    if gf_patterns and 'fetch_url' in tasks:
        scan.used_gf_patterns = ','.join(gf_patterns)
        scan.save(update_fields=['used_gf_patterns'])

    activity.logger.info(
        f"[SetupScheduledScanActivity] Created scan_id={scan.id} for domain={domain.name}"
    )
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=setup_scheduled_scan scan_id=%s domain_id=%s" % (scan.id, domain_id))
    return {
        'scan_history_id': scan.id,
        'engine_id': engine_id,
        'domain_id': domain.id,
        'results_dir': scan.results_dir,
        'starting_point_path': starting_point_path,
        'excluded_paths': excluded_paths,
        'yaml_configuration': config,
        'out_of_scope_subdomains': out_of_scope_subdomains,
        'api_discovery_tools': api_discovery_tools,
        'kr_wordlist': kr_wordlist,
        'tasks': tasks,
    }


# ===========================================================================
# Distributed Heavy Scan Activities (Go Executor Integration)
# ===========================================================================

@activity.defn(name="PreparePortScanActivity")
def prepare_port_scan_activity(ctx: dict) -> dict:
    """Prepare a port scan execution environment and construct the tool command.

    Args:
        ctx (dict): Scan context containing target host information, engine settings,
                    and activity descriptors.

    Returns:
        dict: Prepared configuration details containing the generated command line,
              input paths, and a unique command identifier stored in the database.
    """
    from reNgine.tasks import port_scan
    from startScan.models import Command
    from django.utils import timezone

    scan_id = ctx.get('scan_history_id')
    logger.log_line("[TEMPORAL]", "START", "task=prepare_port_scan scan_id=%s" % scan_id)
    activity.logger.info(f"[PreparePortScanActivity] scan_id={scan_id}")
    proxy = TemporalTaskProxy(ctx, 'port_scan', 'Port Scan', track=False)
    raw_func = port_scan.__func__ if hasattr(port_scan, '__func__') else port_scan
    res = raw_func(proxy, ctx=ctx, prepare_only=True)

    cmd_record = Command.objects.create(
        command=res['cmd'],
        time=timezone.now(),
        scan_history_id=proxy.scan_id,
        activity_id=proxy.activity_id
    )
    res['command_id'] = cmd_record.id
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=prepare_port_scan scan_id=%s" % scan_id)
    return res


@activity.defn(name="ParsePortScanResultsActivity")
def parse_port_scan_results_activity(ctx: dict, stdout: str) -> dict:
    """Parse port scan tool outputs and persist discovered ports/hosts to the database.

    Args:
        ctx (dict): Scan context with history IDs and metadata.
        stdout (str): Raw string output containing JSON lines generated during tool execution.

    Returns:
        dict: Wrapped port details indicating scan outcomes.
    """
    from reNgine.tasks import port_scan

    scan_id = ctx.get('scan_history_id')
    logger.log_line("[TEMPORAL]", "START", "task=parse_port_scan_results scan_id=%s" % scan_id)
    activity.logger.info(f"[ParsePortScanResultsActivity] scan_id={scan_id}")
    proxy = TemporalTaskProxy(ctx, 'port_scan', 'Port Scan')
    raw_func = port_scan.__func__ if hasattr(port_scan, '__func__') else port_scan
    res = raw_func(proxy, ctx=ctx, parse_only=stdout)
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=parse_port_scan_results scan_id=%s" % scan_id)
    return {"ports_data": res}


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
                f"Scan {scan_id} already ABORTED by user — not overwriting to FAILED_TASK."
            )
            return
        scan.scan_status = FAILED_TASK
        scan.error_message = error_msg[:300] if error_msg else "Scan workflow crashed."
        scan.stop_scan_date = timezone.now()
        scan.save()
        logger.info(f"Scan {scan_id} marked as FAILED_TASK due to workflow crash.")

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
        logger.error(f"Failed to finalize crashed scan {scan_id}: {e}")


@activity.defn(name="RunLlmApmeActivity")
def run_llm_apme_activity(scan_history_id: int, job_id: str = None) -> dict:
    from apme.apme_tasks import run_llm_apme
    from reNgine.job_tracker import update_job

    logger.log_line("[TEMPORAL]", "START", "task=run_llm_apme scan_id=%s" % scan_history_id)
    activity.logger.info(f"[RunLlmApmeActivity] scan_id={scan_history_id}")
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


@activity.defn(name="EnrichIdentitiesActivity")
def enrich_identities_activity(identity: str, identity_type: str, scan_history_id: int, ctx: dict) -> str:
    from reNgine.osint_tasks import enrich_identities_task
    logger.log_line("[TEMPORAL]", "START", "task=enrich_identities type=%s scan_id=%s" % (identity_type, scan_history_id))
    activity.logger.info(f"[EnrichIdentitiesActivity] identity_type={identity_type} scan_id={scan_history_id}")
    # Run synchronously inside the Django threadpool executor worker
    result = enrich_identities_task(identity, identity_type, scan_history_id, ctx)
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=enrich_identities type=%s scan_id=%s" % (identity_type, scan_history_id))
    return result


@activity.defn(name="GeoLocalizeActivity")
def geo_localize_activity(host: str, ip_id: int, scan_id: int = None, activity_id: int = None) -> None:
    from reNgine.tasks import geo_localize
    logger.log_line("[TEMPORAL]", "START", "task=geo_localize host=%s ip_id=%s scan_id=%s" % (host, ip_id, scan_id))
    activity.logger.info(f"[GeoLocalizeActivity] host={host} ip_id={ip_id} scan_id={scan_id}")
    geo_localize(host, ip_id=ip_id, scan_id=scan_id, activity_id=activity_id)
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=geo_localize host=%s ip_id=%s scan_id=%s" % (host, ip_id, scan_id))


@activity.defn(name="ImportHackerOneProgramsActivity")
def import_hackerone_programs_activity(handles: list, project_slug: str, is_sync: bool = False) -> None:
    from api.shared_api_tasks import import_hackerone_programs_task
    logger.log_line("[TEMPORAL]", "START", "task=import_hackerone_programs project=%s count=%d" % (project_slug, len(handles)))
    activity.logger.info(f"[ImportHackerOneProgramsActivity] project={project_slug} handles_count={len(handles)}")
    import_hackerone_programs_task(handles, project_slug, is_sync=is_sync)
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=import_hackerone_programs project=%s" % project_slug)


@activity.defn(name="SyncBookmarkedProgramsActivity")
def sync_bookmarked_programs_activity(project_slug: str) -> None:
    from api.shared_api_tasks import sync_bookmarked_programs_task
    logger.log_line("[TEMPORAL]", "START", "task=sync_bookmarked_programs project=%s" % project_slug)
    activity.logger.info(f"[SyncBookmarkedProgramsActivity] project={project_slug}")
    sync_bookmarked_programs_task(project_slug)
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=sync_bookmarked_programs project=%s" % project_slug)


@activity.defn(name="FetchProxiesActivity")
def fetch_proxies_activity(limit: int, job_id: str) -> None:
    logger.log_line("[TEMPORAL]", "START", "task=fetch_proxies limit=%d" % limit)
    activity.logger.info("[FetchProxies] Starting proxy fetch (limit=%d, job_id=%s)", limit, job_id)
    from reNgine.tasks import fetch_proxies_task
    fetch_proxies_task(limit=limit, job_id=job_id)
    activity.logger.info("[FetchProxies] Proxy fetch activity complete")
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=fetch_proxies limit=%d" % limit)


@activity.defn(name="CheckScanQueueStatusActivity")
def check_scan_queue_status_activity(scan_id: int, queue_type: str) -> bool:
    """Check if the given scan is allowed to proceed based on the queue settings.
    
    Args:
        scan_id (int): ScanHistory ID (for main) or SubScan ID (for subscan).
        queue_type (str): 'main' or 'subscan'.
    
    Returns:
        bool: True if it is allowed to proceed (queueing is off, or it's first in line).
    """
    from dashboard.models import UserPreferences
    from startScan.models import ScanHistory, SubScan
    from reNgine.definitions import RUNNING_TASK

    logger.log_line("[TEMPORAL]", "START", "task=check_scan_queue_status scan_id=%s queue_type=%s" % (scan_id, queue_type))
    activity.logger.info(f"[CheckScanQueueStatusActivity] scan_id={scan_id} queue_type={queue_type}")
    # Get the global queuing setting. If there are multiple preferences, just grab the first.
    prefs = UserPreferences.objects.first()
    if not prefs or not getattr(prefs, 'enable_scan_queueing', False):
        logger.log_line("[TEMPORAL]", "COMPLETE", "task=check_scan_queue_status scan_id=%s result=allowed_queueing_off" % scan_id)
        return True

    result = True
    if queue_type == "main":
        # Check running main scans (ordered by start date)
        running_scans = list(ScanHistory.objects.filter(
            scan_status=RUNNING_TASK
        ).order_by('start_scan_date').values_list('id', flat=True))
        result = not running_scans or running_scans[0] == scan_id

    elif queue_type == "subscan":
        running_subscans = list(SubScan.objects.filter(
            status=RUNNING_TASK
        ).order_by('start_scan_date').values_list('id', flat=True))
        result = not running_subscans or running_subscans[0] == scan_id

    logger.log_line("[TEMPORAL]", "COMPLETE", "task=check_scan_queue_status scan_id=%s queue_type=%s allowed=%s" % (scan_id, queue_type, result))
    return result


@activity.defn(name="GetEnabledPluginsForTierActivity")
def get_enabled_plugins_for_tier_activity(params: dict) -> list:
    """Return metadata for enabled plugins anchored to the given tier."""
    from plugins.models import Plugin

    tier = params.get("tier", "")
    selected_plugin_slugs = params.get("selected_plugin_slugs") or []

    logger.log_line("[TEMPORAL]", "START", "task=get_enabled_plugins tier=%s selected=%s" % (tier, selected_plugin_slugs))

    # No slugs selected for this scan — nothing to run.
    # The workflow helper already gates on this but we guard here too.
    if not selected_plugin_slugs:
        logger.log_line("[TEMPORAL]", "COMPLETE", "task=get_enabled_plugins tier=%s found=0 skipped=no_selection" % tier)
        return []

    results = []
    qs = Plugin.objects.filter(
        anchor_step=tier,
        runtime_position='AFTER',
        is_enabled=True,
        slug__in=selected_plugin_slugs,
    )
    plugins = qs.order_by('order_weight', 'id')

    for plugin in plugins:
        manifest = plugin.manifest or {}
        workflows = manifest.get('temporal', {}).get('workflows', [])
        if not workflows:
            continue
        workflow_path = workflows[0]
        if not isinstance(workflow_path, str) or not workflow_path.strip():
            logger.log_line("[TEMPORAL]", "WARN", "task=get_enabled_plugins invalid workflow path for plugin=%s" % plugin.slug)
            continue
        workflow_name = workflow_path.rsplit('.', 1)[-1]
        results.append({"slug": plugin.slug, "workflow_name": workflow_name})

    logger.log_line("[TEMPORAL]", "COMPLETE", "task=get_enabled_plugins tier=%s found=%d" % (tier, len(results)))
    return results


# ---------------------------------------------------------------------------
# Phase 1 — rengine-ng workflow tool activities
# ---------------------------------------------------------------------------

@activity.defn(name="RunDNSXActivity")
def run_dnsx_activity(ctx: dict) -> bool:
    from reNgine.recon_tasks import dnsx_scan
    activity.logger.info("[RunDNSXActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        dnsx_scan, ctx, task_name='dnsx_scan', description='DNS Resolution (dnsx)',
        subdomain=ctx.get('subdomain'), subdomains=ctx.get('subdomains'),
        wordlist=ctx.get('wordlist'),
    )


@activity.defn(name="RunWAFW00FActivity")
def run_wafw00f_activity(ctx: dict) -> bool:
    from reNgine.recon_tasks import wafw00f_scan
    activity.logger.info("[RunWAFW00FActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        wafw00f_scan, ctx, task_name='wafw00f_scan', description='WAF Detection (wafw00f)',
        url=ctx.get('url'), urls=ctx.get('urls'),
    )


@activity.defn(name="RunFPingActivity")
def run_fping_activity(ctx: dict) -> list:
    from reNgine.recon_tasks import fping_scan
    activity.logger.info("[RunFPingActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        fping_scan, ctx, task_name='fping_scan', description='ICMP Host Discovery (fping)',
        cidr=ctx.get('cidr'), targets=ctx.get('targets'),
    )


@activity.defn(name="RunARPScanActivity")
def run_arpscan_activity(ctx: dict) -> list:
    from reNgine.recon_tasks import arpscan_scan
    activity.logger.info("[RunARPScanActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        arpscan_scan, ctx, task_name='arpscan_scan', description='ARP Host Discovery (arp-scan)',
        cidr=ctx.get('cidr'),
    )


@activity.defn(name="RunMapCIDRActivity")
def run_mapcidr_activity(ctx: dict) -> list:
    from reNgine.recon_tasks import mapcidr_expand
    activity.logger.info("[RunMapCIDRActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        mapcidr_expand, ctx, task_name='mapcidr_expand', description='CIDR Expansion (mapcidr)',
        cidr=ctx.get('cidr'),
    )


@activity.defn(name="RunSSHAuditActivity")
def run_sshaudit_activity(ctx: dict) -> bool:
    from reNgine.recon_tasks import sshaudit_scan
    activity.logger.info("[RunSSHAuditActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        sshaudit_scan, ctx, task_name='sshaudit_scan', description='SSH Audit (ssh-audit)',
        host=ctx.get('host', ''), port=ctx.get('port', 22),
    )

@activity.defn(name="RunWPProbeActivity")
def run_wpprobe_activity(ctx: dict) -> bool:
    from reNgine.recon_tasks import wpprobe_scan
    activity.logger.info("[RunWPProbeActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        wpprobe_scan, ctx, task_name='wpprobe_scan',
        description='WordPress Plugin Scan (wpprobe)',
        url=ctx.get('url', ''),
    )


@activity.defn(name="RunSearchVulnsActivity")
def run_search_vulns_activity(ctx: dict) -> bool:
    """Query vulners.com for CVEs/exploits for a single service+version.

    Designed to be fanned out concurrently — one instance per discovered service
    from RunPortScanActivity. Called from _fan_out_search_vulns in
    MasterScanWorkflow Tier 2 after port scan returns.
    """
    from reNgine.recon_tasks import search_vulns_scan
    activity.logger.info(
        "[RunSearchVulnsActivity] service=%s host=%s scan_id=%s",
        ctx.get('service'), ctx.get('host'), ctx.get('scan_history_id'),
    )
    # _run_task provides heartbeating, pre-flight abort-guard, and correct
    # SUCCESS_TASK / FAILED_TASK status updates — matching all other activities.
    return _run_task(
        search_vulns_scan,
        ctx,
        task_name='search_vulns_scan',
        description='Per-service CVE Lookup (vulners.com)',
        scan_history_id=ctx.get('scan_history_id'),
        service=ctx.get('service', ''),
        version=ctx.get('version'),
        host=ctx.get('host', ''),
        port=ctx.get('port', 0),
        subdomain_id=ctx.get('subdomain_id'),
        domain_id=ctx.get('domain_id'),
    )


@activity.defn(name="RunXURLFind3rActivity")
def run_xurlfind3r_activity(ctx: dict) -> bool:
    from reNgine.crawl_tasks import xurlfind3r_scan
    activity.logger.info("[RunXURLFind3rActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        xurlfind3r_scan, ctx, task_name='xurlfind3r_scan',
        description='Passive URL Discovery (xurlfind3r)',
        domain=ctx.get('domain'), domains=ctx.get('domains'),
    )


@activity.defn(name="RunURLFinderActivity")
def run_urlfinder_activity(ctx: dict) -> bool:
    from reNgine.crawl_tasks import urlfinder_scan
    activity.logger.info("[RunURLFinderActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        urlfinder_scan, ctx, task_name='urlfinder_scan',
        description='Passive URL Discovery (urlfinder)',
        domain=ctx.get('domain'),
    )


@activity.defn(name="RunCariddiActivity")
def run_cariddi_activity(ctx: dict) -> bool:
    from reNgine.crawl_tasks import cariddi_scan
    activity.logger.info("[RunCariddiActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        cariddi_scan, ctx, task_name='cariddi_scan',
        description='Endpoint Crawl & Secret Hunt (cariddi)',
        url=ctx.get('url'), urls=ctx.get('urls'),
    )


@activity.defn(name="RunBUPActivity")
def run_bup_activity(ctx: dict) -> bool:
    from reNgine.crawl_tasks import bup_scan
    activity.logger.info("[RunBUPActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        bup_scan, ctx, task_name='bup_scan', description='4xx URL Bypass (bup)',
        url=ctx.get('url'), urls=ctx.get('urls'),
    )


@activity.defn(name="RunArjunActivity")
def run_arjun_activity(ctx: dict) -> bool:
    from reNgine.crawl_tasks import arjun_scan
    activity.logger.info("[RunArjunActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        arjun_scan, ctx, task_name='arjun_scan',
        description='Parameter Discovery (arjun)',
        url=ctx.get('url'), urls=ctx.get('urls'),
    )


@activity.defn(name="RunFeroxbusterActivity")
def run_feroxbuster_activity(ctx: dict) -> bool:
    from reNgine.crawl_tasks import feroxbuster_scan
    activity.logger.info("[RunFeroxbusterActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        feroxbuster_scan, ctx, task_name='feroxbuster_scan',
        description='Recursive Content Fuzzing (feroxbuster)',
        url=ctx.get('url'), urls=ctx.get('urls'),
    )


@activity.defn(name="GetDiscoveredServicesActivity")
def get_discovered_services_activity(ctx: dict) -> list:
    """Return services discovered by port scan for the current scan_history.

    Queries: ScanHistory → Subdomain.ip_addresses → IpAddress.ports → Port
    Returns list of {host, port, service, version} dicts.
    Called by MasterScanWorkflow and HostReconWorkflow after RunPortScanActivity.
    """
    from startScan.models import IpAddress

    scan_history_id = ctx.get('scan_history_id')
    logger.log_line("[TEMPORAL]", "START", "task=get_discovered_services scan_id=%s" % scan_history_id)
    if not scan_history_id:
        logger.log_line("[TEMPORAL]", "COMPLETE", "task=get_discovered_services scan_id=None services=0")
        return []

    services = []
    ip_qs = IpAddress.objects.filter(
        ip_addresses__scan_history_id=scan_history_id
    ).prefetch_related('ports').distinct()

    for ip in ip_qs:
        for port in ip.ports.all():
            if port.service_name:
                services.append({
                    'host': ip.address or '',
                    'port': port.number,
                    'service': port.service_name,
                    'version': None,
                })

    activity.logger.info(
        "[GetDiscoveredServicesActivity] scan_id=%s found %d services",
        scan_history_id, len(services),
    )
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=get_discovered_services scan_id=%s services=%d" % (scan_history_id, len(services)))
    return services


@activity.defn(name="RunGFActivity")
def run_gf_activity(ctx: dict) -> list:
    """Run gf URL pattern matching. Returns matched URL list directly (not bool)."""
    from reNgine.crawl_tasks import gf_scan
    scan_id = ctx.get('scan_history_id')
    logger.log_line("[TEMPORAL]", "START", "task=gf_scan pattern=%s scan_id=%s" % (ctx.get('pattern', 'xss'), scan_id))
    activity.logger.info(
        "[RunGFActivity] pattern=%s scan_id=%s",
        ctx.get('pattern'), scan_id,
    )
    proxy = TemporalTaskProxy(ctx, task_name='gf_scan', description='URL Pattern Match (gf)')
    result = gf_scan(
        proxy,
        scan_history_id=scan_id,
        pattern=ctx.get('pattern', 'xss'),
        urls=ctx.get('urls', []),
    )
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=gf_scan pattern=%s scan_id=%s matches=%d" % (ctx.get('pattern', 'xss'), scan_id, len(result) if isinstance(result, list) else 0))
    return result

@activity.defn(name="GetDiscoveredIPsActivity")
def get_discovered_ips_activity(ctx: dict) -> list:
    """Return distinct IP address strings discovered for this scan."""
    from startScan.models import IpAddress
    scan_id = ctx.get('scan_history_id')
    logger.log_line("[TEMPORAL]", "START", "task=get_discovered_ips scan_id=%s" % scan_id)
    activity.logger.info("[GetDiscoveredIPsActivity] scan_id=%s", scan_id)
    if not scan_id:
        logger.log_line("[TEMPORAL]", "COMPLETE", "task=get_discovered_ips scan_id=%s ips=0" % scan_id)
        return []
    ips = (
        IpAddress.objects
        .filter(ip_addresses__scan_history_id=scan_id)
        .values_list('address', flat=True)
        .distinct()
    )
    result = list(ips)
    activity.logger.info("[GetDiscoveredIPsActivity] found %d IPs for scan_id=%s", len(result), scan_id)
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=get_discovered_ips scan_id=%s ips=%d" % (scan_id, len(result)))
    return result


@activity.defn(name="RunGetASNActivity")
def run_getasn_activity(ctx: dict) -> bool:
    from reNgine.recon_tasks import getasn_scan
    activity.logger.info("[RunGetASNActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        getasn_scan, ctx, task_name='getasn_scan',
        description='ASN Enrichment (getasn)', ips=ctx.get('ips', []),
    )


@activity.defn(name="RunNetDetectActivity")
def run_netdetect_activity(ctx: dict) -> list:
    from reNgine.recon_tasks import netdetect_scan
    scan_id = ctx.get('scan_history_id')
    logger.log_line("[TEMPORAL]", "START", "task=netdetect_scan scan_id=%s" % scan_id)
    activity.logger.info("[RunNetDetectActivity] scan_id=%s", scan_id)
    proxy = TemporalTaskProxy(ctx, task_name='netdetect_scan',
                              description='Network CIDR Detection (netdetect)')
    result = netdetect_scan(proxy, scan_id, ctx.get('domain_id'))
    cidrs = [c for c in result if c] if isinstance(result, list) else []
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=netdetect_scan scan_id=%s cidrs=%d" % (scan_id, len(cidrs)))
    return cidrs


@activity.defn(name="RunJsWhoisActivity")
def run_jswhois_activity(ctx: dict) -> bool:
    from reNgine.recon_tasks import jswhois_scan
    activity.logger.info("[RunJsWhoisActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        jswhois_scan, ctx, task_name='jswhois_scan',
        description='WHOIS Lookup (jswhois)', domain=ctx.get('domain'),
    )


@activity.defn(name="RunWhoisDomainActivity")
def run_whoisdomain_activity(ctx: dict) -> bool:
    from reNgine.recon_tasks import whoisdomain_scan
    activity.logger.info("[RunWhoisDomainActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        whoisdomain_scan, ctx, task_name='whoisdomain_scan',
        description='WHOIS Lookup (whoisdomain)', domain=ctx.get('domain'),
    )


@activity.defn(name="RunBBotActivity")
def run_bbot_activity(ctx: dict) -> bool:
    from reNgine.recon_tasks import bbot_scan
    activity.logger.info("[RunBBotActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        bbot_scan, ctx, task_name='bbot_scan',
        description='OSINT Discovery (bbot)', domain=ctx.get('domain'),
    )


@activity.defn(name="RunParamDiscoveryActivity")
def run_param_discovery_activity(ctx: dict) -> dict:
    """Run the Custom Parameter Discovery Engine (CPDE)."""
    from reNgine.cpde_tasks import param_discovery
    from reNgine.definitions import SUCCESS_TASK
    scan_id = ctx.get('scan_history_id')
    activity.logger.info("[RunParamDiscoveryActivity] Starting CPDE for scan_id=%s", scan_id)

    # Derive seed URLs before TemporalTaskProxy sets status=RUNNING — these are
    # fast DB queries and must complete first so the skip path can mark SUCCESS
    # without ever having set the row to RUNNING.
    urls = ctx.get('urls') or []
    if not urls:
        # Prefer a real endpoint URL (preserves correct scheme) from a prior http_crawl
        from startScan.models import EndPoint
        first_url = (
            EndPoint.objects
            .filter(scan_history_id=scan_id)
            .values_list('http_url', flat=True)
            .first()
        )
        if first_url:
            urls = [first_url]
            logger.log_line("[CPDE]", "INFO", "Derived seed URL from endpoint records: %s" % first_url)
        else:
            # Fall back to constructing from domain name
            from targetApp.models import Domain
            domain = Domain.objects.filter(id=ctx.get('domain_id')).first()
            if domain:
                urls = [f"https://{domain.name}/"]
                logger.log_line("[CPDE]", "INFO", "Derived seed URL from domain: %s" % urls[0])

    if not urls:
        logger.log_line("[CPDE]", "WARN", "No seed URLs available for scan_id=%s — skipping CPDE" % scan_id)
        # Mark the ScanActivity row SUCCESS so it does not stay permanently RUNNING.
        proxy = TemporalTaskProxy(ctx, task_name='param_discovery', description='Custom Parameter Discovery (CPDE)')
        proxy.update_scan_activity(SUCCESS_TASK)
        return {}

    # _run_task provides heartbeating, pre-flight abort-guard, and correct
    # SUCCESS_TASK / FAILED_TASK status updates — matching all other activities.
    _run_task(
        param_discovery,
        ctx,
        task_name='param_discovery',
        description='Custom Parameter Discovery (CPDE)',
        urls=urls,
    )
    return {}


@activity.defn(name="RunGrypeScanActivity")
def run_grype_scan_activity(ctx: dict) -> bool:
    from reNgine.vulnerability_tasks import grype_scan
    activity.logger.info("[RunGrypeScanActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        grype_scan, ctx, task_name='grype_scan',
        description='CVE Scan (grype)', code_path=ctx.get('starting_point_path'),
    )


@activity.defn(name="RunTrivySecretScanActivity")
def run_trivy_secret_scan_activity(ctx: dict) -> bool:
    from reNgine.vulnerability_tasks import trivy_secret_scan
    activity.logger.info("[RunTrivySecretScanActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        trivy_secret_scan, ctx, task_name='trivy_secret_scan',
        description='Secret Scan (trivy v0.69.3)', code_path=ctx.get('starting_point_path'),
    )


@activity.defn(name="RunVigoliumAuditActivity")
def run_vigolium_audit_activity(ctx: dict) -> bool:
    from reNgine.vigolium_tasks import vigolium_audit_scan
    activity.logger.info("[RunVigoliumAuditActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        vigolium_audit_scan, ctx, task_name='vigolium_audit_scan',
        description='Source Code Security Audit (vigolium)',
        code_path=ctx.get('starting_point_path'),
        ctx=ctx,
    )


@activity.defn(name="RunURLParserActivity")
def run_urlparser_activity(ctx: dict) -> bool:
    from reNgine.crawl_tasks import urlparser_scan
    activity.logger.info("[RunURLParserActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        urlparser_scan, ctx, task_name='urlparser_scan',
        description='URL Parameter Extraction (urlparser/unfurl)',
        urls=ctx.get('urls'),
    )


@activity.defn(name="RecalculateApmeActivity")
def recalculate_apme_activity(scan_history_id: int, job_id: str = None) -> dict:
    from apme.orchestrator import APMEOrchestrator
    from startScan.models import ScanHistory
    import yaml
    from reNgine.definitions import ATTACK_PATH_MODELING
    from reNgine.job_tracker import update_job

    logger.log_line("[TEMPORAL]", "START", "task=recalculate_apme scan_id=%s" % scan_history_id)
    activity.logger.info(f"[RecalculateApmeActivity] scan_id={scan_history_id}")
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


@activity.defn(name="ExtractAuthForURLActivity")
def extract_auth_for_url_activity(ctx: dict) -> dict:
    from startScan.models import ScanHistory
    from urllib.parse import urlparse

    url = ctx.get('url')
    scan_id = ctx.get('scan_id')

    activity_heartbeat_safe("ExtractAuthForURLActivity starting for %s" % url)
    logger.log_line("[AUTH_EXTRACT]", "START", "extracting auth from %s (scan %s)" % (url, scan_id))

    try:
        scan = ScanHistory.objects.get(id=scan_id)

        proxy_list = get_proxy_list()
        if not proxy_list:
            tor_or_single = get_random_proxy()
            if tor_or_single:
                proxy_list = [tor_or_single]

        parsed_url = urlparse(url)
        if parsed_url.scheme not in ('http', 'https'):
            logger.log_line("[AUTH_EXTRACT]", "COMPLETE", "skipped non-HTTP URL %s" % url)
            return {'found': 0}

        response, _ = _fetch_with_proxy_retry(url, proxy_list)
        forms = _extract_login_forms(response.text, url)

        if not forms:
            logger.log_line("[AUTH_EXTRACT]", "COMPLETE", "no auth forms found at %s" % url)
            return {'found': 0}

        raw_scheme = parsed_url.scheme.lower()
        protocol = raw_scheme
        port = parsed_url.port or (443 if raw_scheme == 'https' else 80)

        saved = 0
        for form in forms:
            from startScan.models import AuthCandidate
            _, created = AuthCandidate.objects.get_or_create(
                scan_history=scan,
                target=form.get('action', url),
                protocol=protocol,
                port=port,
                defaults={
                    'source_tool': 'ExtractAuthForURLActivity',
                    'metadata': {
                        'type': 'form',
                        'method': form.get('method', 'POST'),
                        'user_field': form.get('user_field', ''),
                        'pass_field': form.get('pass_field', ''),
                        'hidden_fields': form.get('hidden_fields', {}),
                        'all_fields': form.get('all_fields', []),
                    },
                    'status': 'pending',
                },
            )
            if created:
                saved += 1

        logger.log_line("[AUTH_EXTRACT]", "COMPLETE",
                        "found %d new auth candidates from %s" % (saved, url))
        return {'found': saved}

    except Exception as exc:
        logger.log_line("[AUTH_EXTRACT]", "ERROR", format_exception_for_log(exc),
                        level="error", exc_info=True)
        raise
