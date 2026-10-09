---
description: Temporal workflow and activity conventions for r3ngine — scan orchestration, determinism rules, debugging, and the Go executor.
---

# r3ngine – Temporal conventions

## Scope

Use this rule when working on features that interact with Temporal:

- Scan workflows and activities
- Orchestration of scans from the web UI
- Adding new scanning tiers or tool integrations
- Debugging workflow failures or cancellations

## Key files

| File | Role |
|------|------|
| `web/reNgine/temporal/workflows/*.py` | Workflow definitions (deterministic orchestrators only): `_common.py` (retry presets, shared helpers), `master_scan.py`, `subscan.py`, `stress.py`, `jobs.py`, `recon.py`, `assessment_workflow.py`; `__init__.py` only re-exports |
| `web/reNgine/temporal/activities/*.py` | Activity definitions (all side-effecting work): `core.py` (`_run_task`, `TemporalTaskProxy`, cancellation), then one module per domain; `__init__.py` only re-exports |
| `web/reNgine/temporal_workflows.py` | Backward-compatible shim → re-exports from `temporal/workflows/` |
| `web/reNgine/temporal_activities.py` | Backward-compatible shim → re-exports from `temporal/activities/` |
| `web/reNgine/temporal_client.py` | Client for starting and cancelling workflows from Django |
| `web/executor/main.go` | Go executor — handles subprocess-based tool execution |
| `web/scanEngine/management/commands/run_temporal_orchestrator.py` | Worker startup command |

## Workflow vs Activity — the golden rule

**Workflows are deterministic orchestrators. Activities do the actual work.**

| Do in workflows | Do in activities |
|-----------------|-----------------|
| Sequence activities | Call Django ORM |
| Branch on activity results | Run security tools (subprocess) |
| Signal handling (pause/resume) | Write to PostgreSQL / Neo4j |
| Retry policy definitions | Make HTTP calls |
| Fan-out via `asyncio.gather` | Read environment variables |

## Determinism violations — never do these in a workflow

```python
# ❌ All forbidden in any temporal/workflows/*.py module
import datetime
datetime.datetime.now()          # use workflow.now() instead
random.choice(items)             # non-deterministic
subprocess.run(...)              # I/O belongs in an activity
ScanHistory.objects.get(id=x)   # DB call — belongs in an activity

# ✅ Correct — delegate to activity
result = await workflow.execute_activity(
    my_activity,
    args=[scan_id],
    start_to_close_timeout=timedelta(minutes=30),
)
```

## Retry policies — every activity call needs one

**Never call `workflow.execute_activity` without an explicit `retry_policy`.** Temporal's
default is *unlimited* attempts with a 100s maximum interval. Scan tasks report failure by
returning `False`, which `_run_task` turns into an exception, so one unreachable backend
produced 200+ failed timeline rows over 13 hours before anyone noticed.

Use the presets in `temporal/workflows/_common.py` — do not inline a new
`RetryPolicy` when one of these fits:

| Preset | Attempts | Use for |
|--------|----------|---------|
| `_RETRY_SCANNER` | 3 | Tier 6 scanners (nuclei DAST, acunetix, wpscan, semgrep, …) |
| `_RETRY_LONG_SCAN` | 2 | Hours-long tools where a retry re-runs everything |
| `_RETRY_NETWORK_SCAN` | 3 | Short network probes |
| `_RETRY_INTERNAL` | 5 | DB bookkeeping and finalisation activities |
| `_RETRY_LLM` | 3 | LLM calls |

Three things to check before picking one:

- **Idempotency.** A retry that inserts a row (rather than updating one keyed on the scan)
  leaves orphaned records — give such an activity `maximum_attempts=1` or key the write.
  The same applies to notifications: they are re-sent on every attempt.
- **Total wall-time.** `start_to_close_timeout` is *per attempt*. For a long-running tool add
  `schedule_to_close_timeout`, the only bound across all retries, and keep the product under
  the parent workflow's `run_timeout`.
- **Retries are visible.** Attempt 1 claims the pre-planned `ScanActivity` row; every later
  attempt inserts a new one, so N attempts mean N rows in the scan timeline.

**`heartbeat_timeout` needs heartbeats.** An activity scheduled with a `heartbeat_timeout`
shorter than its `start_to_close_timeout` is killed after that interval unless it calls
`activity.heartbeat()`, then retried — a healthy long run fails on a timer. Task functions
behind `_run_task` and `stream_command` already heartbeat; any other activity that blocks
(a whole-task call, a wait on another workflow) goes under `@keep_alive` from
`reNgine.temporal.heartbeat`, placed below `@activity.defn`. `tests/test_activity_heartbeats.py`
fails for an activity that has neither.

`execute_child_workflow` is the opposite case: its default is a single attempt, so omitting
the policy there is safe.

The policy is captured by the server when the activity is **scheduled**. Redeploying a worker
does not change the policy of an execution that is already retrying — those have to be
cancelled (or the scan aborted, which trips the non-retryable guard in `_run_task`).

## Making a task's timeline entry useful

`TemporalTaskProxy` fills `ScanActivity.target_host` from the activity context
(`subdomain_name` → `host[:port]` → `url` → the scan's domain) so fan-out tasks are
distinguishable in the UI. Two things a task function should do:

- Set `self.target_host` when it resolves a more precise target than the context carried
  (see `acunetix_scan`).
- Set `self.error` before returning `False`. Without it the timeline can only show
  "Task <name> execution returned False/failed."; with it, `_run_task` uses the reason as the
  exception message and stores the traceback on the row.

## Django imports in workflows

Workflows must not import Django directly. Use the workaround:

```python
with workflow.unsafe.imports_passed_through():
    from reNgine.definitions import SCAN_STATUS_RUNNING
```

## Inspecting running workflows

Temporal UI is available at `http://localhost:8080` — full workflow history, signals, event replay, and cancellation.

```bash
# Python orchestrator logs
docker compose --env-file .env -f docker/docker-compose.yml logs temporal-python-orchestrator

# Go executor logs
docker compose --env-file .env -f docker/docker-compose.yml logs temporal-go-executor

# Or tail everything through the Makefile
make logs
```

## Starting a scan workflow (from Django)

Entry point in `web/reNgine/tasks/scan_init.py` → `initiate_scan_temporal()` → starts `MasterScanWorkflow`.
Import via the shim: `from reNgine.tasks import initiate_scan_temporal`.

```python
# Pattern for starting a workflow from a Django view
from reNgine.temporal_client import TemporalClientProvider

async def start_scan(scan_id: int) -> str:
    handle = await TemporalClientProvider.start_workflow(
        "MasterScanWorkflow",
        args=[scan_id],
        id=f"scan-{scan_id}",
        task_queue="python-orchestrator-queue",
    )
    return handle.id
```

## Cancelling a workflow

```python
from reNgine.temporal_client import TemporalClientProvider

await TemporalClientProvider.cancel_workflow(workflow_id)
```

Cancel is tracked via `TemporalWorkflowExecution` FK on `ScanHistory`.

## Adding a new scanning activity

1. Add the activity function to the matching domain module in `web/reNgine/temporal/activities/` (decorate with `@activity.defn`) and re-export it from `activities/__init__.py`.
2. Register it in the worker in `run_temporal_orchestrator.py` (add to `activities=[]`).
3. Call it from the appropriate tier in `MasterScanWorkflow` (`temporal/workflows/master_scan.py`) or `SubScanWorkflow` (`temporal/workflows/subscan.py`), **with an explicit `retry_policy`** (see "Retry policies" above).
4. Add the task name to `_TASK_TIER` in `web/reNgine/task_plan.py`, otherwise its retry rows land in Tier 7 in the timeline.
5. If the activity shells out to a tool, consider using the Go executor (`go-executor-queue`) for subprocess management.

**Note**: Existing imports via `from reNgine.temporal_activities import X` continue to work through the compatibility shim. New code should import directly: `from reNgine.temporal.activities import X`.

## Go executor activities

The Go executor (`web/executor/main.go`) handles tool subprocesses on `go-executor-queue` — on a remote worker, on `go-executor-queue-<WORKER_NAME>` (`queue.go`). Use it for tools with complex subprocess lifecycle (nmap, ffuf, nuclei, etc.).

The queue name is host-specific, so never hard-code it: the activity/task side gets it from `reNgine.utils.task_queues.go_executor_queue()` (reads `WORKER_NAME`; `python_orchestrator_queue()` is its Python counterpart) and passes it into the workflow's input, and the workflow forwards that value — a workflow must not read the environment. `GoExecutorTaskWorkflow` (`input_data["executor_task_queue"]`) is the reference.

To add a new Go activity:
1. Add a handler in `main.go`.
2. Register on the Go worker.
3. Call from a Python workflow via:
```python
result = await workflow.execute_activity(
    "GoToolActivity",
    args=[tool_config],
    task_queue=tool_config["executor_task_queue"],  # set by the caller from go_executor_queue()
    start_to_close_timeout=timedelta(hours=2),
    retry_policy=_RETRY_LONG_SCAN,
)
```

## Debugging workflows

1. **Temporal UI**: `http://localhost:8080` — event history, replay, cancellation.
2. **Python orchestrator logs**: `docker compose --env-file .env -f docker/docker-compose.yml logs temporal-python-orchestrator`
3. **Go executor logs**: `docker compose --env-file .env -f docker/docker-compose.yml logs temporal-go-executor`
4. **DB audit**: Query `startScan_scanactivity` and `startScan_temporalworkflowexecution` tables.
5. **Redis inspect**: `redis-cli` to inspect channel layer state.

## Logging in activities

Activities use `get_module_logger` (Pattern 2 from `r3ngine-python-backend.md`):

```python
from reNgine.utils.logger import get_module_logger, format_exception_for_log

logger = get_module_logger(__name__)

# ✅ Use log_line with a section prefix for every major step
logger.log_line("[SCAN]", "START", "activity started for scan %s" % scan_id)
logger.log_line("[SCAN]", "COMPLETE", "activity finished, found %d results" % count)
logger.log_line("[SCAN]", "ERROR", format_exception_for_log(exc), level="error", exc_info=True)
```

Every activity **must** emit a START log and a COMPLETE (or ERROR) log. This is critical for debugging stuck workflows — missing start/complete logs are the primary signal that an activity is hung.

Activity log output goes to both `temporal.log` (file, via `temporal_file` handler) and the console (via propagation to the `reNgine` catch-all).

Scan task helpers called from activities (`tasks/` package, `common_func/` package, `*_tasks.py`) use plain `logging.getLogger(__name__)` — their output goes to the `task` handler (stdout, `module.funcName | LEVEL | message` format). Do not mix the two patterns within a single file.

## Integration guidelines

- Orchestrate scans from `temporal_client.py`; avoid mixing workflow start logic directly into views.
- Validate all user input before passing it into workflow arguments (target URLs, scan config).
- Do not duplicate activity logic — reuse shared helpers in the `tasks/` and `common_func/` packages.
- All activities must be idempotent by design (Temporal may retry them).
- All activities must log START and COMPLETE/ERROR — see logging section above.