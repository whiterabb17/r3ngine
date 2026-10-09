"""
StressTestWorkflow — load/stress test orchestration triggered from the
StressTestControlAPI (not via SubScanWorkflow). Deterministic orchestrator.
"""

import asyncio
from datetime import timedelta
from typing import Any, Dict, List
from temporalio import workflow
from temporalio.common import RetryPolicy

from reNgine.temporal.workflows._common import _RETRY_INTERNAL


# ===========================================================================
# Stress Test Workflow
# ===========================================================================

@workflow.defn(name="StressTestWorkflow")
class StressTestWorkflow:
    """Durable stress test orchestrator replacing the run_stress_testing Celery task.

    Executes configured stress tools (k6, wrk, hping3, locust, stressor) against
    resolved target endpoints sequentially.  Supports instant cancellation via the
    'kill_switch' signal — the workflow stops at the next endpoint/tool boundary
    without needing a Redis poll.

    Input ctx keys (passed as the first workflow argument):
        scan_history_id  (int)   — ScanHistory PK
        target_domain_name (str) — bare hostname for the target
        stress_config    (dict)  — full stress_test config from the API payload
    """

    def __init__(self) -> None:
        self._kill_requested: bool = False
        self._kill_event = asyncio.Event()

    @workflow.run
    async def run(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        scan_id = ctx.get("scan_history_id")
        workflow.logger.info("[StressTestWorkflow] Starting for scan_id=%s", scan_id)

        # Step 1 — Resolve endpoints, create DB record, publish 'running' to telemetry
        ctx = await workflow.execute_activity(
            "InitStressTestActivity",
            ctx,
            start_to_close_timeout=timedelta(minutes=2),
            heartbeat_timeout=timedelta(minutes=5),
            # Not idempotent: it creates a StressTestResult row unconditionally, so a
            # retry would leave an orphaned all-zero result behind.
            retry_policy=RetryPolicy(maximum_attempts=1),
            task_queue="python-orchestrator-queue",
        )

        endpoints: List[str] = ctx.get("resolved_endpoints", [])
        tools: List[str] = ctx.get("stress_config", {}).get("uses_tools", ["k6"])

        if not endpoints:
            workflow.logger.warning(
                "[StressTestWorkflow] No endpoints resolved for scan_id=%s. Finalising immediately.", scan_id
            )

        # Step 2 — Run each (endpoint x tool) pair sequentially.
        # Matches current Celery behaviour; promote to asyncio.gather() per endpoint
        # in a future iteration if parallelism is required.
        aggregate: Dict[str, Any] = {
            "total_requests": 0,
            "successful_requests": 0,
            "failed_requests": 0,
            "avg_latencies": [],
            "p95_latencies": [],
            "p99_latencies": [],
            "max_rps_values": [],
        }

        outer_break = False
        for endpoint_url in endpoints:
            if outer_break:
                break
            for tool in tools:
                if self._kill_requested:
                    workflow.logger.info(
                        "[StressTestWorkflow] Kill signal — aborting before tool=%s endpoint=%s", tool, endpoint_url
                    )
                    outer_break = True
                    break

                tool_ctx = {**ctx, "current_endpoint": endpoint_url, "current_tool": tool}
                try:
                    activity_task = asyncio.create_task(
                        workflow.execute_activity(
                            "RunStressToolActivity",
                            tool_ctx,
                            # Allow up to 15 minutes per slot:
                            # longest supported duration is 10 min + 5 min overhead.
                            start_to_close_timeout=timedelta(minutes=15),
                            heartbeat_timeout=timedelta(seconds=30),
                            # Stress tests are not idempotent — never auto-retry.
                            retry_policy=RetryPolicy(maximum_attempts=1),
                            task_queue="python-orchestrator-queue",
                        )
                    )
                    kill_task = asyncio.create_task(self._kill_event.wait())
                    
                    done, pending = await asyncio.wait(
                        [activity_task, kill_task],
                        return_when=asyncio.FIRST_COMPLETED
                    )
                    
                    if kill_task in done:
                        activity_task.cancel()
                        workflow.logger.info("[StressTestWorkflow] Kill signal received. Cancelling activity.")
                        outer_break = True
                        break
                    
                    metrics = activity_task.result()
                    aggregate["total_requests"] += metrics.get("total_requests", 0)
                    aggregate["successful_requests"] += metrics.get("successful_requests", 0)
                    aggregate["failed_requests"] += metrics.get("failed_requests", 0)
                    if metrics.get("avg_latency_ms", 0) > 0:
                        aggregate["avg_latencies"].append(metrics["avg_latency_ms"])
                    if metrics.get("p95_latency_ms", 0) > 0:
                        aggregate["p95_latencies"].append(metrics["p95_latency_ms"])
                    if metrics.get("p99_latency_ms", 0) > 0:
                        aggregate["p99_latencies"].append(metrics["p99_latency_ms"])
                    if metrics.get("max_requests_per_second", 0) > 0:
                        aggregate["max_rps_values"].append(metrics["max_requests_per_second"])
                except Exception as exc:
                    workflow.logger.error(
                        "[StressTestWorkflow] tool=%s endpoint=%s failed: %s", tool, endpoint_url, exc
                    )
                    # Continue to next tool/endpoint rather than aborting the whole
                    # workflow — mirrors the Celery task's try/except per subprocess.

        # Step 3 — Aggregate + finalise DB records + send notification
        avgs = aggregate["avg_latencies"]
        p95s = aggregate["p95_latencies"]
        p99s = aggregate["p99_latencies"]
        maxrps = aggregate["max_rps_values"]

        final_ctx = {
            **ctx,
            "aborted": self._kill_requested,
            "total_requests": aggregate["total_requests"],
            "successful_requests": aggregate["successful_requests"],
            "failed_requests": aggregate["failed_requests"],
            "avg_latency_ms": sum(avgs) / len(avgs) if avgs else 0.0,
            "p95_latency_ms": sum(p95s) / len(p95s) if p95s else 0.0,
            "p99_latency_ms": sum(p99s) / len(p99s) if p99s else 0.0,
            "max_rps": max(maxrps) if maxrps else 0.0,
        }

        await workflow.execute_activity(
            "FinalizeStressTestActivity",
            final_ctx,
            start_to_close_timeout=timedelta(minutes=5),
            heartbeat_timeout=timedelta(minutes=5),
            retry_policy=_RETRY_INTERNAL,
            task_queue="python-orchestrator-queue",
        )

        status = "ABORTED" if self._kill_requested else "SUCCESS"
        workflow.logger.info(
            "[StressTestWorkflow] Complete — scan_id=%s status=%s", scan_id, status
        )
        return {"status": status, "scan_id": scan_id}

    @workflow.signal(name="kill_switch")
    def kill_switch(self) -> None:
        """Signal the workflow to abort at the next endpoint/tool boundary."""
        workflow.logger.info("[StressTestWorkflow] KILL SWITCH signal received.")
        self._kill_requested = True
        self._kill_event.set()

    @workflow.query(name="is_running")
    def is_running(self) -> bool:
        """Return True if the workflow has not yet received a kill signal."""
        return not self._kill_requested
