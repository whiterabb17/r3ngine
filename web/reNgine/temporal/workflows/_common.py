"""
Shared building blocks for the r3ngine Temporal workflow modules.

Retry policy presets and the helper coroutines used by more than one workflow
live here so every workflow module imports a single definition. This module
must stay deterministic like the workflows that import it (see
.claude/rules/r3ngine-temporal.md).
"""

import asyncio
from datetime import timedelta
from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ActivityError

with workflow.unsafe.imports_passed_through():
    from reNgine.host_dedup import target_dedup_config


# Retry policy presets — applied explicitly to every execute_activity call.
# Default Temporal policy (unlimited, backoff to 100s) is intentionally overridden.

_RETRY_LONG_SCAN = RetryPolicy(
    maximum_attempts=2,
    initial_interval=timedelta(minutes=1),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(minutes=10),
)


_RETRY_NETWORK_SCAN = RetryPolicy(
    maximum_attempts=3,
    initial_interval=timedelta(seconds=30),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(minutes=5),
)


# Tier 6 scanners signal failure by returning False, which _run_task converts into
# an exception. Without an explicit policy Temporal retries such an activity forever,
# so a scanner whose backend is unreachable floods the timeline for hours.
_RETRY_SCANNER = RetryPolicy(
    maximum_attempts=3,
    initial_interval=timedelta(minutes=2),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(minutes=10),
)


_RETRY_INTERNAL = RetryPolicy(
    maximum_attempts=5,
    initial_interval=timedelta(seconds=5),
    backoff_coefficient=1.5,
    maximum_interval=timedelta(seconds=30),
)


_RETRY_LLM = RetryPolicy(
    maximum_attempts=3,
    initial_interval=timedelta(seconds=30),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(minutes=5),
)


async def _isolated_tool(name: str, call):
    """Await a scanning tool's activity; if it fails, log it and let the scan go on.

    One tool that exhausts its retries (a fuzzer past its time limit, a crawler
    whose backend is down) used to fail the whole MasterScanWorkflow, so every
    later tier was marked FAILED without having run. Its own timeline row already
    records the failure, the scan still ends FAILED, and Retry re-runs just that
    tool. Cancellation (a user abort) is not an ActivityError and still propagates.
    """
    try:
        return await call
    except ActivityError as exc:
        workflow.logger.error(
            "%s failed in workflow %s — continuing with the rest of the scan: %s",
            name, workflow.info().workflow_id, exc,
        )
        return None


#: Runs of one batch, the first included, while its tool keeps stopping at the
#: batch time limit with targets left; the fuzzer resumes where it stopped.
_BATCH_PASSES = 3


def _batching_enabled(yaml_config: dict, section: str) -> bool:
    """Whether the engine runs `section` in batches (on unless `batching.enabled: false`)."""
    batching = (yaml_config.get(section) or {}).get('batching')
    return not isinstance(batching, dict) or batching.get('enabled', True) is not False


def _target_dedup_enabled(yaml_config: dict) -> bool:
    """Whether the engine marks same-site hosts after HTTP crawl (on by default)."""
    return target_dedup_config(yaml_config)[0]


async def _run_chunked(ctx: dict, task: str) -> list:
    """Run a per-host tool as batches of hosts, a few at a time, under one timeline row.

    The plan activity splits the targets and returns the settings; the host lists
    and ctx stay in files, so each batch only carries its index. A batch stopped
    at its time limit runs again while the overall budget lasts; batches not
    started before the budget runs out are left for a Retry. The budget is checked
    before each run, so the step can end up to one batch time limit later.

    Returns:
        One outcome dict per batch, in batch order.
    """
    queue = "python-orchestrator-queue"
    plan = await workflow.execute_activity(
        "PlanChunkedTaskActivity",
        args=[ctx, task],
        start_to_close_timeout=timedelta(hours=1),
        heartbeat_timeout=timedelta(minutes=5),
        retry_policy=_RETRY_INTERNAL,
        task_queue=queue,
    )
    results_dir, activity_id = plan["results_dir"], plan["activity_id"]
    batch_timeout = timedelta(minutes=plan["batch_timeout_minutes"])
    deadline = workflow.now() + timedelta(hours=plan["max_total_hours"])
    slots = asyncio.Semaphore(plan["max_parallel"])

    async def _batch(index: int) -> dict:
        result = {"index": index, "status": "skipped"}
        async with slots:
            for _ in range(_BATCH_PASSES):
                if workflow.now() >= deadline:
                    break
                try:
                    result = await workflow.execute_activity(
                        "RunChunkedTaskBatchActivity",
                        args=[results_dir, task, index, activity_id],
                        start_to_close_timeout=batch_timeout,
                        heartbeat_timeout=timedelta(minutes=15),
                        retry_policy=_RETRY_LONG_SCAN,
                        task_queue=queue,
                    )
                except ActivityError as exc:
                    workflow.logger.error("%s batch %d failed: %s", task, index + 1, exc)
                    return {"index": index, "status": "failed"}
                if result.get("status") != "partial":
                    return result
        # Cut short by the overall budget rather than by its own failure.
        if result.get("status") == "partial" and workflow.now() >= deadline:
            result = {**result, "status": "skipped"}
        return result

    results = list(await asyncio.gather(*(_batch(index) for index in range(plan["batches"]))))

    await workflow.execute_activity(
        "FinalizeChunkedTaskActivity",
        args=[results_dir, task, activity_id, results],
        start_to_close_timeout=timedelta(minutes=5),
        retry_policy=_RETRY_INTERNAL,
        task_queue=queue,
    )
    await _isolated_tool("RunChunkedTaskFollowUpActivity", workflow.execute_activity(
        "RunChunkedTaskFollowUpActivity",
        args=[results_dir, task, activity_id],
        start_to_close_timeout=timedelta(hours=3),
        heartbeat_timeout=timedelta(minutes=10),
        retry_policy=_RETRY_LONG_SCAN,
        task_queue=queue,
    ))
    return results


async def _dispatch_tier_plugins(ctx: dict, tier: str, wf_id_prefix: str) -> None:
    """Dispatch selected plugins anchored to `tier` as child workflows.

    Called after every scan tier completes. Valid tier values:
      tier_1 (subdomain discovery), tier_2 (port scan / HTTP crawl),
      tier_3 (URL fetch / screenshot), tier_4 (dir/file fuzz),
      tier_5 (API discovery / secrets / WAF), tier_6 (vulnerability scan),
      tier_7 (correlation / risk / APME), standalone (not injected).

    Only runs if the scan explicitly selected at least one plugin slug.
    An empty or absent `selected_plugin_slugs` in ctx means no plugins were
    chosen for this scan — the activity is skipped entirely in that case.

    Args:
        ctx: Scan context dict passed through to each plugin workflow.
        tier: Anchor tier string, e.g. "tier_2", "tier_7".
        wf_id_prefix: Unique prefix for child workflow IDs (scan or subscan ID).
    """
    selected_slugs = ctx.get("selected_plugin_slugs") or []
    if not selected_slugs:
        return

    plugin_list = await workflow.execute_activity(
        "GetEnabledPluginsForTierActivity",
        {"tier": tier, "selected_plugin_slugs": selected_slugs},
        start_to_close_timeout=timedelta(seconds=15),
        heartbeat_timeout=timedelta(seconds=15),
        retry_policy=_RETRY_INTERNAL,
        task_queue="python-orchestrator-queue",
    )
    for plugin_meta in plugin_list:
        wf_name = plugin_meta.get("workflow_name")
        slug = plugin_meta.get("slug")
        plugin_name = plugin_meta.get("name", slug)
        if not wf_name:
            continue
            
        log_res = await workflow.execute_activity(
            "LogPluginStartActivity",
            {
                "scan_id": ctx.get("scan_history_id"),
                "name": wf_name,
                "title": f"Plugin: {plugin_name}",
                "tier": tier,
            },
            start_to_close_timeout=timedelta(seconds=15),
            retry_policy=_RETRY_INTERNAL,
            task_queue="python-orchestrator-queue",
        )
        act_id = log_res.get("activity_id")

        try:
            await workflow.execute_child_workflow(
                wf_name,
                ctx,
                id=f"{wf_id_prefix}-plugin-{slug}",
                task_queue="python-orchestrator-queue",
                execution_timeout=timedelta(days=7),
            )
            await workflow.execute_activity(
                "LogPluginEndActivity",
                {"activity_id": act_id, "status": 2}, # SUCCESS_TASK
                start_to_close_timeout=timedelta(seconds=15),
                retry_policy=_RETRY_INTERNAL,
                task_queue="python-orchestrator-queue",
            )
        except Exception as e:
            await workflow.execute_activity(
                "LogPluginEndActivity",
                {"activity_id": act_id, "status": 0, "error": str(e)}, # FAILED_TASK
                start_to_close_timeout=timedelta(seconds=15),
                retry_policy=_RETRY_INTERNAL,
                task_queue="python-orchestrator-queue",
            )
            # We don't re-raise here so other plugins/tiers can still run


async def _fan_out_search_vulns(ctx: dict, services: list) -> None:
    """Fan out concurrent per-service CVE + exploit lookups.

    Reads a list of {host, port, service, version} dicts and launches one
    RunSearchVulnsActivity per service,
    all gathered concurrently with return_exceptions=True so a single
    lookup failure never aborts the scan.

    Called from MasterScanWorkflow after GetDiscoveredServicesActivity and
    from HostReconWorkflow after RunPortScanActivity.
    """
    if not services:
        return

    lookup_tasks = []
    for svc in services:
        service_name = (svc.get('service') or '').strip()
        if not service_name:
            continue
        svc_ctx = {
            **ctx,
            'host': svc.get('host', ''),
            'port': svc.get('port', 0),
            'service': service_name,
            'version': svc.get('version'),
        }
        lookup_tasks.append(
            workflow.execute_activity(
                "RunSearchVulnsActivity",
                svc_ctx,
                start_to_close_timeout=timedelta(minutes=5),
                retry_policy=_RETRY_INTERNAL,
                task_queue="python-orchestrator-queue",
            )
        )

    if lookup_tasks:
        await asyncio.gather(*lookup_tasks, return_exceptions=True)
