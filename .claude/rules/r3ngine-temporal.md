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
| `web/reNgine/temporal/workflows/__init__.py` | Workflow definitions (deterministic orchestrators only) |
| `web/reNgine/temporal/activities/__init__.py` | Activity definitions (all side-effecting work) |
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
# ❌ All forbidden in temporal/workflows/__init__.py
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
docker compose logs temporal-python-orchestrator

# Go executor logs
docker compose logs temporal-go-executor
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

1. Add the activity function to `web/reNgine/temporal/activities/__init__.py` (decorate with `@activity.defn`).
2. Register it in the worker in `run_temporal_orchestrator.py` (add to `activities=[]`).
3. Call it from the appropriate tier in `MasterScanWorkflow` or `SubScanWorkflow` in `temporal/workflows/__init__.py`.
4. If the activity shells out to a tool, consider using the Go executor (`go-executor-queue`) for subprocess management.

**Note**: Existing imports via `from reNgine.temporal_activities import X` continue to work through the compatibility shim. New code should import directly: `from reNgine.temporal.activities import X`.

## Go executor activities

The Go executor (`web/executor/main.go`) handles tool subprocesses on `go-executor-queue`. Use it for tools with complex subprocess lifecycle (nmap, ffuf, nuclei, etc.).

To add a new Go activity:
1. Add a handler in `main.go`.
2. Register on the Go worker.
3. Call from a Python workflow via:
```python
result = await workflow.execute_activity(
    "GoToolActivity",
    args=[tool_config],
    task_queue="go-executor-queue",
    start_to_close_timeout=timedelta(hours=2),
)
```

## Debugging workflows

1. **Temporal UI**: `http://localhost:8080` — event history, replay, cancellation.
2. **Python orchestrator logs**: `docker compose logs temporal-python-orchestrator`
3. **Go executor logs**: `docker compose logs temporal-go-executor`
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

Scan task helpers called from activities (`tasks.py`, `common_func.py`, `*_tasks.py`) use plain `logging.getLogger(__name__)` — their output goes to the `task` handler (stdout, `module.funcName | LEVEL | message` format). Do not mix the two patterns within a single file.

## Integration guidelines

- Orchestrate scans from `temporal_client.py`; avoid mixing workflow start logic directly into views.
- Validate all user input before passing it into workflow arguments (target URLs, scan config).
- Do not duplicate activity logic — reuse shared helpers in the `tasks/` package and `common_func.py`.
- All activities must be idempotent by design (Temporal may retry them).
- All activities must log START and COMPLETE/ERROR — see logging section above.