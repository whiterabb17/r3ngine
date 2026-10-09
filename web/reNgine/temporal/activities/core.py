"""
Core glue shared by every module of the r3ngine Temporal activities package.

Holds the TemporalTaskProxy that satisfies the `self` interface of the
RengineTask-decorated scan functions, `_run_task` which executes such a
function inside an activity with heartbeats and ScanActivity bookkeeping, and
the thread-local cancel event shared with stream_command/run_command.

Sibling modules import from here; nothing here imports a sibling module.
"""

import os
import threading
from datetime import datetime, timedelta, timezone as dt_timezone
from typing import Optional

from temporalio import activity
from django.utils import timezone

from reNgine.utils.logger import get_module_logger, format_exception_for_log
from startScan.models import Subdomain

logger = get_module_logger(__name__)


def resolve_target_host(ctx: dict, subdomain=None, domain=None) -> str:
    """Resolve the host a task runs against, for display on its timeline entry.

    Fan-out activities (acunetix, per-service CVE lookup, wpscan, ...) run once per
    subdomain or per service, so without this the timeline shows a row of identical
    titles with no way to tell which host each one covered.

    Args:
        ctx: Temporal workflow context of the activity.
        subdomain: Subdomain instance already resolved by the caller, if any.
        domain: Domain instance the scan belongs to, used as the last resort.

    Returns:
        str: Host, `host:port` or URL, empty when the task has no single target.
    """
    from urllib.parse import urlparse

    host = (ctx.get('subdomain_name') or '').strip()
    if not host and subdomain is not None:
        host = (getattr(subdomain, 'name', '') or '').strip()
    if not host:
        host = str(ctx.get('host') or '').strip()
    if not host:
        url = str(ctx.get('url') or ctx.get('subdomain_http_url') or '').strip()
        if url:
            host = urlparse(url).hostname or url
    if not host and domain is not None:
        host = (getattr(domain, 'name', '') or '').strip()

    port = ctx.get('port')
    if host and port and ':' not in host:
        suffix = ':%s' % port
        host = '%s%s' % (host[:500 - len(suffix)], suffix)

    return host[:500]


_HARDWARE_PROFILE_KEYS = ('threads', 'rate_limit', 'delay', 'retries')


def apply_hardware_profile(yaml_configuration: dict, hw_profile: dict) -> None:
    """Apply a scan's hardware profile to its engine configuration, in place.

    Per resource limit: a value set in a tool's section wins, then the profile,
    then the engine's global value. The engine editor always writes the global
    limits, so letting them beat the profile would reduce the profile chosen for
    the scan to its delay. Timeouts stay with the engine.
    """
    for key in _HARDWARE_PROFILE_KEYS:
        if hw_profile.get(key) is not None:
            yaml_configuration[key] = hw_profile[key]
    for section in yaml_configuration.values():
        if not isinstance(section, dict):
            continue
        for key in _HARDWARE_PROFILE_KEYS:
            if section.get(key) is None and yaml_configuration.get(key) is not None:
                section[key] = yaml_configuration[key]


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
        self.singular_tool_run = bool(ctx.get('singular_tool_run'))
        from reNgine.task_plan import singular_activity_name
        self.scan_activity_name = (
            singular_activity_name(task_name) if self.singular_tool_run else task_name
        )

        # Django ORM objects
        self.scan = (
            ScanHistory.objects.select_related('hardware_profile').filter(pk=self.scan_id).first()
            if self.scan_id else None
        )

        # Resolved per activity, not taken from the workflow input, so a profile
        # switched (or edited) while the scan runs applies to the steps that start next.
        self.hardware_profile = self._resolve_hardware_profile(ctx)
        if self.hardware_profile:
            apply_hardware_profile(self.yaml_configuration, self.hardware_profile)

        self.subscan = SubScan.objects.filter(pk=self.subscan_id).first() if self.subscan_id else None
        self.engine = EngineType.objects.filter(pk=self.engine_id).first()
        if not self.engine and self.scan:
            self.engine = self.scan.scan_type
            self.engine_id = self.engine.id if self.engine else None
        self.domain = self.scan.domain if self.scan else Domain.objects.filter(id=self.domain_id).first()
        self.subdomain = self.subscan.subdomain if self.subscan else None
        if not self.subdomain and self.subdomain_id:
            self.subdomain = Subdomain.objects.filter(pk=self.subdomain_id).first()

        # Host shown next to this task in the scan timeline. Task functions may refine
        # it (see acunetix_scan) once they know the exact target they resolved.
        self.target_host = resolve_target_host(ctx, self.subdomain, self.domain)

        # Create a ScanActivity record in the DB to track this task
        if self.track and self.scan:
            self._create_scan_activity()

    def _create_scan_activity(self):
        """Claim an unclaimed ScanActivity row for this task, or create one if none available.

        Uses SELECT FOR UPDATE (skip_locked=True) so that only INITIATED rows
        are claimed (including retries that keep time_started so the timeline
        does not hide them as ghosts). This prevents a Temporal activity retry
        from overwriting SUCCESS rows left by prior attempts (AUD-003).
        """
        from startScan.models import ScanActivity
        from reNgine.definitions import FAILED_TASK, INITIATED_TASK, RUNNING_TASK
        from reNgine.task_plan import get_task_tier
        from django.db import transaction

        try:
            info = activity.info()
            temporal_activity_id = info.activity_id
            now = timezone.now()
            execution_id = "temporal-%s" % temporal_activity_id
            with transaction.atomic():
                # Prefer the pre-created singular/retry row when ctx carries activity_id.
                # Singular rows live under single_tool_<task> so they never collide with
                # pipeline INITIATED ghosts that share the bare task slug.
                claim_name = self.scan_activity_name
                activity_row = None
                preferred_id = self.activity_id
                if info.attempt > 1:
                    # An attempt whose worker died (container restart, OOM kill) never
                    # finalised its row, which would otherwise stay RUNNING beside this one.
                    interrupted = ScanActivity.objects.filter(
                        scan_of=self.scan,
                        name=claim_name,
                        execution_id=execution_id,
                        status=RUNNING_TASK,
                    )
                    if preferred_id:
                        # A pinned row is reclaimed below instead.
                        interrupted = interrupted.exclude(pk=preferred_id)
                    interrupted.update(
                        status=FAILED_TASK,
                        time_ended=now,
                        error_message=(
                            "Interrupted: the worker running this attempt stopped "
                            "(e.g. a container restart); Temporal started attempt %d." % info.attempt
                        ),
                    )
                if preferred_id:
                    # Pin to the pre-created row. Allow RUNNING so a Temporal
                    # activity retry can reclaim the same row instead of forking
                    # a duplicate while the pinned id stays stuck RUNNING.
                    activity_row = ScanActivity.objects.select_for_update(skip_locked=True).filter(
                        pk=preferred_id,
                        scan_of=self.scan,
                        name=claim_name,
                        status__in=[INITIATED_TASK, RUNNING_TASK],
                    ).first()
                if activity_row is None:
                    # Claim only an INITIATED row with this activity name namespace.
                    activity_row = ScanActivity.objects.select_for_update(skip_locked=True).filter(
                        scan_of=self.scan,
                        name=claim_name,
                        status=INITIATED_TASK,
                    ).first()

                if activity_row:
                    activity_row.status = RUNNING_TASK
                    activity_row.time_started = now
                    activity_row.time = now
                    activity_row.execution_id = execution_id
                    activity_row.target_host = self.target_host
                    update_fields = [
                        'status', 'time_started', 'time', 'execution_id', 'target_host',
                    ]
                    # Stamp subscan when claiming a parent-scan row so subscan
                    # detail tools can find the activity.
                    if self.subscan and activity_row.subscan_id is None:
                        activity_row.subscan = self.subscan
                        update_fields.append('subscan')
                    activity_row.save(update_fields=update_fields)
                    self.activity = activity_row
                    self.activity_id = activity_row.id
                else:
                    # No unclaimed row found — create one for this retry attempt.
                    # Carry the planned tier over so retries stay in their own tier
                    # instead of collapsing into Tier 7 in the timeline.
                    self.activity = ScanActivity.objects.create(
                        scan_of=self.scan,
                        name=claim_name,
                        title=self.description,
                        target_host=self.target_host,
                        tier=get_task_tier(self.task_name),
                        subscan=self.subscan,
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

    def update_scan_activity(self, status, error_message=None, traceback_text=None):
        """Update the ScanActivity record with the final task status and time_ended.

        Args:
            status (int): Task status code (SUCCESS_TASK, FAILED_TASK, etc.)
            error_message (str, optional): Error message if the task failed.
            traceback_text (str, optional): Full traceback, shown in the task detail
                overlay so a failure can be diagnosed without reading container logs.
        """
        from startScan.models import ScanActivity
        from reNgine.definitions import SUCCESS_TASK
        try:
            if getattr(self, 'activity', None):
                now = timezone.now()
                update_kwargs = {
                    'status': status,
                    'time': now,
                    'time_ended': now,
                }
                # Task functions may have narrowed the host while running. Keep the
                # write additive — never blank out what _create_scan_activity stored.
                final_host = str(getattr(self, 'target_host', '') or '')[:500]
                if final_host:
                    update_kwargs['target_host'] = final_host
                if error_message is not None:
                    update_kwargs['error_message'] = str(error_message)[:300]
                    # Only callers that captured a traceback overwrite the stored one —
                    # the other failure paths must not blank out what _run_task saved.
                    if traceback_text is not None:
                        update_kwargs['traceback'] = traceback_text
                elif status == SUCCESS_TASK:
                    # Clear stale error fields from any previous failed attempt on this record
                    update_kwargs['error_message'] = ''
                    update_kwargs['traceback'] = ''
                ScanActivity.objects.filter(pk=self.activity.pk).update(**update_kwargs)
        except Exception as e:
            logger.warning("Could not update ScanActivity for %s: %s", self.task_name, e)

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
        logger.info("[notify] Task '%s' fields=%s", name or self.task_name, fields)

    def _resolve_hardware_profile(self, ctx: dict) -> Optional[dict]:
        """Hardware profile the scan has now, else the one frozen in the workflow input.

        Reads the scan loaded by __init__ (profile joined in), so the only extra
        query is the default-profile lookup of a scan that has no profile of its own.
        """
        frozen = ctx.get('hardware_profile')
        if self.scan is None:
            if self.scan_id:
                logger.warning(
                    "Scan %s not found for task %s; using the hardware profile from the workflow input",
                    self.scan_id, self.task_name,
                )
            return frozen

        from reNgine.tasks.scan_init import hardware_profile_context

        current = hardware_profile_context(self.scan)
        if current is None and frozen:
            logger.warning(
                "No hardware profile resolvable for scan %s (task %s); keeping the one it started with",
                self.scan_id, self.task_name,
            )
            return frozen
        return current


def _start_scan_task_proxy(ctx: dict, task_name: str, description: str):
    """Claim a pre-populated ScanActivity row. No-op outside a Temporal activity."""
    if not activity.in_activity():
        return None
    return TemporalTaskProxy(ctx, task_name, description)


# ---------------------------------------------------------------------------
# Helper: run a RengineTask function via TemporalTaskProxy
# ---------------------------------------------------------------------------

# Thread-local used to share the per-activity cancel_event with stream_command/run_command
# so they can cancel GoExecutorTaskWorkflow instances without signature changes.
_task_cancel_local = threading.local()

#: Bounds of the time kept between stopping a tool and the attempt's timeout, so
#: what the tool found can still be parsed and saved.
_TIME_LIMIT_MARGIN_MIN = timedelta(minutes=1)
_TIME_LIMIT_MARGIN_MAX = timedelta(minutes=10)


def task_is_stopping() -> bool:
    """True once the running task was told to stop (scan abort or time limit).

    Loops over many targets check this so they neither start the next target nor
    mark the one that was cut short as done.
    """
    event = getattr(_task_cancel_local, 'cancel_event', None)
    return event is not None and event.is_set()


def _attempt_stop_time(info) -> Optional[datetime]:
    """When this attempt should stop its tool, or None when it has no time limit.

    Temporal times an attempt out on the server but cannot interrupt the thread
    running it, so a timed-out tool kept running beside the retry Temporal
    started (two fuzzers on one scan), and the retry began again from scratch.
    Stopping shortly before the limit ends the attempt with its partial results.
    """
    limits = []
    for start, length in (
        (getattr(info, 'started_time', None), getattr(info, 'start_to_close_timeout', None)),
        (getattr(info, 'scheduled_time', None), getattr(info, 'schedule_to_close_timeout', None)),
    ):
        if isinstance(start, datetime) and isinstance(length, timedelta) and length:
            limits.append((start + length, length))
    if not limits:
        return None
    end, length = min(limits, key=lambda limit: limit[0])
    margin = min(max(length / 20, _TIME_LIMIT_MARGIN_MIN), _TIME_LIMIT_MARGIN_MAX)
    return end - margin


def _time_limit_note(info) -> str:
    hours = (info.start_to_close_timeout or timedelta()).total_seconds() / 3600
    limit = f"its {hours:g} h time limit" if hours else "its time limit"
    return f"Stopped at {limit}; the results found until then were kept."


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
    time_limit_reached = threading.Event()
    try:
        _info = activity.info()
    except RuntimeError:  # called outside an activity (tests, management commands)
        _info = None
    stop_at = _attempt_stop_time(_info) if _info else None

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
                if stop_at is not None and not time_limit_reached.is_set() and datetime.now(dt_timezone.utc) >= stop_at:
                    logger.log_line(
                        "[TEMPORAL]", "TIME_LIMIT",
                        "task=%s scan_id=%s — stopping the tool before the attempt times out; results so far are kept" % (task_name, _scan_id),
                        level="warning",
                    )
                    time_limit_reached.set()
                    cancel_event.set()  # stream_command kills the tool and starts no new ones
                try:
                    _hb_detail = f"Activity {task_name} running for {proxy.task_name}"
                    activity.heartbeat(_hb_detail)
                    logger.log_line(
                        "[TEMPORAL]", "HEARTBEAT",
                        "activity_type=%s workflow_id=%s scan_id=%s" % (task_name, _workflow_id, _scan_id),
                    )
                except TemporalCancelledError:
                    details = activity.cancellation_details()
                    if details and details.paused:
                        # Temporal paused this activity (e.g. via UI or temporal CLI).
                        # Kill the subprocess to free resources; do NOT mark the scan
                        # aborted — Temporal will retry the activity when unpaused.
                        activity.logger.warning(
                            "[_run_task] Activity %s paused by Temporal for scan %s "
                            "— subprocess will be killed, activity retried when unpaused.",
                            task_name, proxy.scan_id,
                        )
                        cancel_event.set()
                        return
                    # Real cancellation (user abort or workflow cancel).
                    activity.logger.warning(
                        "[_run_task] Temporal cancellation received for %s "
                        "— marking scan %s as aborted.",
                        task_name, proxy.scan_id,
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
                            "[_run_task] Could not mark scan aborted: %s", mark_err,
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
        if time_limit_reached.is_set():
            # The tool was cut off, so a False/empty result says nothing about the
            # target. Finishing here stops Temporal re-running hours of work.
            note = _time_limit_note(_info)
            proxy.update_scan_activity(SUCCESS_TASK, error_message=note)
            logger.log_line("[TEMPORAL]", "COMPLETE", "task=%s scan_id=%s time_limit=1" % (task_name, _scan_id))
            return True
        if res is False:
            # Task functions report why they gave up via proxy.error; without it the
            # timeline can only show the generic "returned False" message.
            reason = getattr(proxy, 'error', None)
            raise Exception(
                f"Task {task_name} failed: {reason}" if reason
                else f"Task {task_name} execution returned False/failed."
            )
        proxy.update_scan_activity(SUCCESS_TASK)
        logger.log_line("[TEMPORAL]", "COMPLETE", "task=%s scan_id=%s" % (task_name, _scan_id))
        return True
    except Exception as exc:
        import traceback as _traceback
        logger.log_line("[TEMPORAL]", "ERROR", "task=%s scan_id=%s error=%s" % (task_name, _scan_id, format_exception_for_log(exc)), level="error")
        activity.logger.exception("[_run_task] Task %s failed: %s", task_name, exc)
        proxy.update_scan_activity(
            FAILED_TASK,
            error_message=(
                f"{_time_limit_note(_info)} Then: {exc!r}" if time_limit_reached.is_set() else repr(exc)
            ),
            traceback_text=_traceback.format_exc(),
        )
        if time_limit_reached.is_set():
            # A retry would start the same hours-long run from scratch.
            raise ApplicationError(
                f"Task {task_name} stopped at its time limit and then failed: {type(exc).__name__}",
                non_retryable=True,
            ) from exc
        raise
    finally:
        activity_running = False
        heartbeat_thread.join(timeout=5)
        # The worker reuses this thread for other activities; a stale set event
        # would make every later stream_command on it refuse to start.
        _task_cancel_local.cancel_event = None
