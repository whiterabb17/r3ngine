# r3ngine — Task Recovery

## Overview

Temporal's durable execution model provides automatic scan recovery. If the `temporal-orchestrator` container crashes or restarts mid-scan, the workflow resumes exactly from where it left off — no data is lost and no work is duplicated.

---

## How Temporal Durability Works

Every step in a Temporal workflow is recorded as an **event** in the workflow's event history, stored in the Temporal Server's persistence layer (PostgreSQL in r3ngine's case).

When the worker restarts, Temporal **replays** the workflow's event history to reconstruct the exact in-memory state. Activities that have already completed are **not re-executed** — their results are loaded from the event history.

```
Worker crashes at Tier 3 mid-execution
    │
    ▼
Worker restarts and reconnects to Temporal
    │
    ▼
Temporal replays workflow history:
  ✓ Tier 1 activities — replayed from history (no re-execution)
  ✓ Tier 2 activities — replayed from history (no re-execution)
  → Tier 3 RunFetchURLActivity — re-dispatched and executed fresh
```

---

## `CheckScanQueueStatusActivity`

Both `MasterScanWorkflow` and `SubScanWorkflow` start with a **queue status check** loop:

```python
while True:
    can_proceed = await workflow.execute_activity(
        "CheckScanQueueStatusActivity",
        args=[scan_history_id, "main"],
        start_to_close_timeout=timedelta(minutes=1),
        retry_policy=_RETRY_INTERNAL,
        task_queue="python-orchestrator-queue"
    )
    if can_proceed:
        break
    await workflow.sleep(timedelta(seconds=30))
```

This implements **concurrency control**: if too many scans are already running, the workflow waits 30 seconds and checks again. This prevents the system from being overwhelmed when multiple scans start simultaneously.

---

## `MarkVulnerabilityScanCompleteActivity`

After `NucleiPlannerWorkflow` finishes all vulnerability scanners, it calls:

```python
await workflow.execute_activity(
    "MarkVulnerabilityScanCompleteActivity",
    ctx,
    start_to_close_timeout=timedelta(seconds=30),
    ...
)
```

This writes a `ScanActivity(name='vulnerability_scan', status=SUCCESS)` record to the DB.

**Why?** The `vulnerability_scan` task is a composite (Nuclei + CRLFuzz + Dalfox + WPScan + etc.). If the scan crashes mid-vulnerability-scan and resumes, the recovery logic can detect `vulnerability_scan` is marked `SUCCESS` in the `ScanActivity` table and skip re-running it — preventing expensive tool re-execution.

---

## `LoadCheckpointActivity`

A backward-compatibility stub that exists solely to preserve the event history position for workflows started before the checkpoint stubs were removed. It is a no-op (returns immediately) but must remain to avoid Temporal non-determinism errors on old workflow histories.

---

## Scan Recovery via `resume_scan_temporal`

When a scan is recovered after a crash (workflow missing or terminated), `resume_scan_temporal`:

1. Queries `ScanActivity` records to find which **pipeline** tasks have already completed.
2. Drops YAML resource keys (`threads`, `timeout`, `rate_limit`, ...) that sometimes leak into `ScanHistory.tasks`.
3. Starts a new `MasterScanWorkflow` with only the remaining pipeline tasks.

If the master workflow **already completed** but the scan is FAILED (a late task such as AI Impact Assessment failed), startup recovery must **not** start another `MasterScanWorkflow`. `recover_stuck_scans` retries only unsuccessful `ScanActivity` rows via `SingleTaskRetryWorkflow`.

> **Note:** In normal operation, Temporal handles in-flight recovery by replaying the workflow's event history. `recover_stuck_scans` is the fallback when that history is gone or the scan finished failed.

On every orchestrator start, `recover_stuck_scans` first runs `cleanup_orphan_workflows_for_completed_scans`: it lists Running Temporal workflows, maps scan-scoped ids (`go-exec-*`, `master-scan-*`, `scan-*`, `subscan-*`, …) back to `ScanHistory`, and cancels any whose scan is already `SUCCESS` or `ABORTED` (also arming Redis `scan_stop_{id}` so Go executor subprocesses die). This stops tool workflows that outlived a finalized scan after heartbeat retries or missed parent cancellation.

---

## `FinalizeFailedScanActivity`

If `MasterScanWorkflow.run()` raises an exception, the `except` block calls:

```python
await workflow.execute_activity(
    "FinalizeFailedScanActivity",
    args=[ctx, str(e)],
    ...
)
```

This:
- Sets `ScanHistory.scan_status = FAILED_TASK`.
- Records the error message.
- Ensures the scan doesn't remain stuck in "RUNNING" state if the workflow terminates abnormally.

---

## Temporal Retry Policies

Activities are not retried indefinitely. Each retry policy has a `maximum_attempts` cap:

| Policy | Max Attempts | Use Case |
|---|---|---|
| `_RETRY_LONG_SCAN` | 2 | Long-running network scans |
| `_RETRY_NETWORK_SCAN` | 3 | Network connectivity-dependent |
| `_RETRY_INTERNAL` | 5 | Internal DB/state operations |
| `_RETRY_LLM` | 3 | LLM API calls (rate limits) |
| Stress tests | 1 | Never retry (not idempotent) |

When retries are exhausted, the activity raises a `ActivityError`, which propagates to the workflow and triggers `FinalizeFailedScanActivity`.

---

## Monitoring Recovery via Temporal UI

The Temporal Web UI (`http://localhost:8080`) shows:
- **Running workflows**: All currently executing scans.
- **Failed workflows**: Scans that exhausted their retry budget.
- **Terminated workflows**: Scans that were cancelled.
- **Event history**: Full chronological log of every activity in the workflow.

To manually re-trigger a failed workflow, use the Temporal CLI:
```bash
temporal workflow start --workflow-type MasterScanWorkflow --task-queue python-orchestrator-queue --input '{"scan_history_id": 42, ...}'
```
