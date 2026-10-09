"""Activities that run a per-host tool over batches of hosts.

The workflow side (`_run_chunked` in temporal/workflows/_common.py) plans the
batches with PlanChunkedTaskActivity, runs RunChunkedTaskBatchActivity for each
of them a few at a time, closes the step with FinalizeChunkedTaskActivity and
then runs the tool's once-per-step follow-up (RunChunkedTaskFollowUpActivity).

All batches write to the step's one planned timeline row: they run untracked
with that row's activity_id, so their commands and the per-batch progress lines
appear in its detail overlay, and Retry/recovery keep working by task name.
The host lists and the activity context live in files next to the scan results
and never enter the workflow history.

If the workflow dies between planning and finalizing, the claimed row stays
RUNNING until the scan's completion step or recovery reconciles it, as a row
claimed by any other activity would.
"""
import json
import os
from dataclasses import dataclass
from typing import Callable

from django.utils import timezone
from temporalio import activity

from reNgine.chunking import batching_config, plan_batches, target_host
from reNgine.temporal.activities.core import TemporalTaskProxy, _run_task
from reNgine.temporal.heartbeat import keep_alive
from reNgine.utils.logger import get_module_logger

logger = get_module_logger(__name__)

#: Error text stored on the step's row; ScanActivity.error_message holds 300 characters.
_MESSAGE_LIMIT = 300
#: Bumped when the plan file layout changes; an older plan is replaced.
PLAN_VERSION = 1


@dataclass(frozen=True)
class ChunkedTask:
    """What the batching machinery needs to know about one tool."""

    title: str
    config_key: str
    select_targets: Callable  # (proxy, ctx) -> list[str]
    run_batch: Callable  # (ctx, targets) -> None
    is_done: Callable  # (results_dir, target) -> bool
    follow_up: Callable | None = None  # (ctx, targets) -> None, run once after every batch


def _fuzz_targets(proxy, ctx: dict) -> list:
    from reNgine.tasks.fuzzing import dir_file_fuzz
    prepared = dir_file_fuzz(proxy, ctx=ctx, prepare_only=True) or {}
    return list(prepared.get('urls') or []) if isinstance(prepared, dict) else []


def _fuzz_batch(ctx: dict, targets: list) -> None:
    from reNgine.tasks.fuzzing import dir_file_fuzz
    _run_task(
        dir_file_fuzz,
        {**ctx, 'urls_override': targets, 'skip_post_crawl': True},
        task_name='dir_file_fuzz',
        description='Directory & File Fuzz',
    )


def _fuzz_done(results_dir: str, target: str) -> bool:
    from reNgine.tasks.fuzzing import _fuzz_target_marker
    return os.path.exists(_fuzz_target_marker(results_dir, target))


def _fuzz_follow_up(ctx: dict, targets: list) -> None:
    """The batches skip the fuzzer's trailing crawl of its targets; run it once here."""
    from reNgine.definitions import DIR_FILE_FUZZ, ENABLE_HTTP_CRAWL
    from reNgine.settings import DEFAULT_ENABLE_HTTP_CRAWL
    from reNgine.tasks import http_crawl

    config = (ctx.get('yaml_configuration') or {}).get(DIR_FILE_FUZZ) or {}
    if targets and config.get(ENABLE_HTTP_CRAWL, DEFAULT_ENABLE_HTTP_CRAWL):
        _run_task(http_crawl, ctx, task_name='dir_file_fuzz', description='Directory & File Fuzz', urls=targets)


CHUNKED_TASKS = {
    'dir_file_fuzz': ChunkedTask(
        title='Directory & File Fuzz',
        config_key='dir_file_fuzz',
        select_targets=_fuzz_targets,
        run_batch=_fuzz_batch,
        is_done=_fuzz_done,
        follow_up=_fuzz_follow_up,
    ),
}


def _chunked_task(task: str) -> ChunkedTask:
    try:
        return CHUNKED_TASKS[task]
    except KeyError:
        raise ValueError(f"{task} cannot run in batches") from None


def _step_dir(results_dir: str, task: str) -> str:
    # `task` is a CHUNKED_TASKS key (checked by _chunked_task), never user input.
    return os.path.join(results_dir, 'batches', task)


def _plan_scope(ctx: dict) -> dict:
    """What a plan covers: a retry of one host must not leave its one-host plan for the whole scan."""
    return {
        'subdomain_id': ctx.get('subdomain_id') or None,
        'subscan_id': ctx.get('subscan_id') or None,
        'singular_tool_run': bool(ctx.get('singular_tool_run')),
    }


def _read_json(path: str):
    try:
        with open(path, encoding='utf-8') as handle:
            return json.load(handle)
    except (OSError, ValueError):
        return None


def _write_json(path: str, data) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    tmp = f'{path}.tmp'
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o640)
    with os.fdopen(fd, 'w', encoding='utf-8') as handle:
        json.dump(data, handle)
    os.replace(tmp, path)


def _load_plan(results_dir: str, task: str, scope: dict | None = None) -> dict | None:
    """The saved plan, or None when it is missing, malformed, outdated or for another scope."""
    plan = _read_json(os.path.join(_step_dir(results_dir, task), 'plan.json'))
    if not isinstance(plan, dict) or plan.get('version') != PLAN_VERSION:
        return None
    batches = plan.get('batches')
    if not isinstance(batches, list) or not all(
        isinstance(batch, list) and all(isinstance(target, str) for target in batch) for batch in batches
    ):
        return None
    if scope is not None and plan.get('scope') != scope:
        return None
    return plan


def _record(scan_id, activity_id, command: str, output: str, return_code: int = 0) -> None:
    """One progress line in the step's detail overlay."""
    from startScan.models import Command
    try:
        Command.objects.create(
            command=command, output=output, return_code=return_code, time=timezone.now(),
            scan_history_id=scan_id, activity_id=activity_id,
        )
    except Exception as exc:
        logger.warning("Could not record batch progress for activity %s: %s", activity_id, exc)


def _hosts(targets: list) -> list:
    return sorted({target_host(target) for target in targets})


@activity.defn(name="PlanChunkedTaskActivity")
@keep_alive
def plan_chunked_task_activity(ctx: dict, task: str) -> dict:
    """Claim the step's timeline row and split its targets into batches.

    A plan saved for the same scope is reused, so a retry or a resumed scan gets
    the same batches; finished targets are skipped by the tool's own done
    markers. The activity context is saved fresh every time for the batches.

    Returns:
        dict: activity_id, batches, targets, hosts and the batching settings the
        workflow schedules with (it may not read the engine YAML itself).
    """
    spec = _chunked_task(task)
    scan_id = ctx.get('scan_history_id')
    logger.log_line("[TEMPORAL]", "START", "task=plan_chunked step=%s scan_id=%s" % (task, scan_id))

    proxy = TemporalTaskProxy(ctx, task, spec.title)
    config = batching_config(proxy.yaml_configuration.get(spec.config_key))
    results_dir = proxy.results_dir
    step_dir = _step_dir(results_dir, task)
    scope = _plan_scope(ctx)

    plan = _load_plan(results_dir, task, scope)
    reused = plan is not None
    if not reused:
        from reNgine.host_dedup import drop_duplicate_targets
        targets, dropped = drop_duplicate_targets(scan_id, spec.select_targets(proxy, ctx), ctx)
        plan = {
            'version': PLAN_VERSION,
            'scope': scope,
            'batches': plan_batches(targets, config.batch_size, config.max_batches),
            'duplicates_skipped': len(dropped),
        }
        _write_json(os.path.join(step_dir, 'plan.json'), plan)
    # seed_urls holds one URL per subdomain and is not needed past the crawl.
    _write_json(
        os.path.join(step_dir, 'ctx.json'),
        {key: value for key, value in ctx.items() if key != 'seed_urls'},
    )

    batches = plan['batches']
    targets = [target for batch in batches for target in batch]
    hosts = _hosts(targets)
    _record(
        scan_id, proxy.activity_id, f"{task} plan",
        "%s %d targets on %d hosts in %d batches, %d at a time%s%s" % (
            "Reusing the plan:" if reused else "Planned",
            len(targets), len(hosts), len(batches), config.max_parallel,
            "; %d targets on duplicate hosts skipped (see Target Deduplication)" % plan.get('duplicates_skipped', 0)
            if plan.get('duplicates_skipped') else "",
            "" if batches else " — nothing to do",
        ),
    )
    logger.log_line(
        "[TEMPORAL]", "COMPLETE",
        "task=plan_chunked step=%s scan_id=%s batches=%d targets=%d" % (task, scan_id, len(batches), len(targets)),
    )
    return {
        'activity_id': proxy.activity_id,
        'results_dir': results_dir,
        'batches': len(batches),
        'targets': len(targets),
        'hosts': len(hosts),
        **config.as_dict(),
    }


def _saved_step(results_dir: str, task: str) -> tuple[dict, dict]:
    plan = _load_plan(results_dir, task)
    ctx = _read_json(os.path.join(_step_dir(results_dir, task), 'ctx.json'))
    if plan is None or not isinstance(ctx, dict):
        raise ValueError(f"No saved {task} plan under the scan results")
    return plan, ctx


@activity.defn(name="RunChunkedTaskBatchActivity")
@keep_alive
def run_chunked_task_batch_activity(results_dir: str, task: str, index: int, activity_id: int) -> dict:
    """Run the tool over one batch; finished targets are skipped by the tool itself.

    The stop before the attempt's time limit comes from _run_task. A failure
    raises so Temporal retries the batch, which resumes where it stopped.

    Returns:
        dict: index, status ("done", or "partial" when the run was stopped before
        every target finished), targets and finished counts.
    """
    spec = _chunked_task(task)
    plan, ctx = _saved_step(results_dir, task)
    scan_id = ctx.get('scan_history_id')
    if not 0 <= index < len(plan['batches']):
        raise ValueError(f"No batch {index} in the {task} plan of scan {scan_id}")
    targets = plan['batches'][index]
    label = f"{task} batch {index + 1}/{len(plan['batches'])}"
    logger.log_line("[TEMPORAL]", "START", "task=%s scan_id=%s targets=%d" % (label, scan_id, len(targets)))

    pending = [target for target in targets if not spec.is_done(results_dir, target)]
    if pending:
        _record(scan_id, activity_id, label, "START — %d of %d targets left on %s" % (
            len(pending), len(targets), ', '.join(_hosts(pending))[:2000]))
        try:
            spec.run_batch({**ctx, 'track': False, 'activity_id': activity_id}, pending)
        except Exception as exc:
            _record(scan_id, activity_id, label, "FAILED — %s" % type(exc).__name__, return_code=1)
            raise

    finished = sum(1 for target in targets if spec.is_done(results_dir, target))
    status = 'done' if finished == len(targets) else 'partial'
    if pending:
        _record(scan_id, activity_id, label, (
            "DONE" if status == 'done'
            else "STOPPED at the batch time limit — %d of %d targets finished" % (finished, len(targets))
        ))
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=%s scan_id=%s status=%s" % (label, scan_id, status))
    return {'index': index, 'status': status, 'targets': len(targets), 'finished': finished}


def summarize_batches(results: list, total: int) -> tuple[bool, str | None]:
    """(succeeded, note) for the step's row from every batch's outcome.

    A batch that failed, or that still had unfinished targets after its extra
    passes, fails the step so Retry and auto-recovery pick it up. Batches never
    started because the overall budget ran out do not: like a single run stopped
    at its time limit, the step keeps what it found and says so.
    """
    failed = sorted(r['index'] + 1 for r in results if r.get('status') in ('failed', 'partial'))
    skipped = sorted(r['index'] + 1 for r in results if r.get('status') == 'skipped')

    def _list(numbers: list) -> str:
        shown = ', '.join(map(str, numbers[:20]))
        return shown + (', …' if len(numbers) > 20 else '')

    if failed:
        note = "%d/%d batches did not finish (%s); Retry re-runs only the targets not done yet" % (
            len(failed), total, _list(failed))
        return False, note[:_MESSAGE_LIMIT]
    if skipped:
        note = "Stopped at the time budget with %d/%d batches not started (%s); Retry continues with them" % (
            len(skipped), total, _list(skipped))
        return True, note[:_MESSAGE_LIMIT]
    return True, None


@activity.defn(name="FinalizeChunkedTaskActivity")
def finalize_chunked_task_activity(results_dir: str, task: str, activity_id: int, results: list) -> bool:
    """Close the step's row from the batch outcomes; an aborted row is left alone."""
    from reNgine.definitions import FAILED_TASK, INITIATED_TASK, RUNNING_TASK, SUCCESS_TASK
    from startScan.models import ScanActivity

    _chunked_task(task)
    plan = _load_plan(results_dir, task) or {'batches': []}
    succeeded, note = summarize_batches(results, len(plan['batches']))
    now = timezone.now()
    ScanActivity.objects.filter(pk=activity_id, status__in=[INITIATED_TASK, RUNNING_TASK]).update(
        status=SUCCESS_TASK if succeeded else FAILED_TASK,
        time=now, time_ended=now, error_message=note,
    )
    logger.log_line(
        "[TEMPORAL]", "COMPLETE",
        "task=finalize_chunked step=%s activity_id=%s succeeded=%s" % (task, activity_id, succeeded),
    )
    return succeeded


@activity.defn(name="RunChunkedTaskFollowUpActivity")
@keep_alive
def run_chunked_task_follow_up_activity(results_dir: str, task: str, activity_id: int) -> bool:
    """The tool's once-per-step work after every batch (for the fuzzer, crawling its targets)."""
    spec = _chunked_task(task)
    if spec.follow_up is None:
        return True
    plan, ctx = _saved_step(results_dir, task)
    targets = [target for batch in plan['batches'] for target in batch]
    logger.log_line("[TEMPORAL]", "START", "task=%s follow-up targets=%d" % (task, len(targets)))
    spec.follow_up({**ctx, 'track': False, 'activity_id': activity_id}, targets)
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=%s follow-up" % task)
    return True
