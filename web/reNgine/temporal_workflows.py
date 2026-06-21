"""
Temporal Workflow definitions for the r3ngine scan pipeline.

Workflows define the durable orchestration logic — the "what runs when" in the
scan pipeline. All workflows are pure Python and must be deterministic (no I/O,
no random, no datetime.now()). Side-effecting work is delegated to activities.

The Python Orchestrator Worker hosts these workflow classes and listens on the
'python-orchestrator-queue' task queue.

Design principles:
  - Workflows are thin orchestrators: they gather, sequence, and fork activities.
  - All actual scan logic lives in activities (temporal_activities.py).
  - Activities on the 'go-executor-queue' are dispatched to the Go binary
    (web/executor/main.go) for heavy subprocess-based tool execution.
  - Activities on the 'python-orchestrator-queue' are dispatched back to this
    Python worker for Django DB reads/writes and Neo4j sync.
"""

import asyncio
from datetime import timedelta
from typing import Any, Dict, List, Union
from temporalio import workflow
from temporalio.common import RetryPolicy

# All imports that touch Django or any non-deterministic module must be wrapped
# in workflow.unsafe.imports_passed_through() to prevent sandbox errors.
with workflow.unsafe.imports_passed_through():
    from reNgine.temporal_activities import _PERMITTED_GENERIC_TASKS
    from reNgine.scan_context import ScanContext
    from reNgine.definitions import NUCLEI_DEFAULT_SEVERITIES


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
        if not wf_name:
            continue
        await workflow.execute_child_workflow(
            wf_name,
            ctx,
            id=f"{wf_id_prefix}-plugin-{slug}",
            task_queue="python-orchestrator-queue",
            execution_timeout=timedelta(hours=2),
        )


@workflow.defn(name="MasterScanWorkflow")
class MasterScanWorkflow:
    """Master workflow orchestrating the full 7-tier scan pipeline.

    Handles:
      - Target profiling and context enrichment (Step 0)
      - Tier 1: Subdomain discovery, Amass Intel, Firewall detection
      - Tier 2: HTTP crawl, Port scan, Screenshot, URL fetch
      - Tier 3/4: Directory/file fuzzing
      - Tier 5: Web API discovery, WAF detection, Secret scanning
      - Tier 6: Vulnerability scan (via NucleiPlannerWorkflow), WAF bypass
      - Tier 7: Vulnerability correlation, risk scoring, AI impact, Neo4j APME sync
      - Scan completion notification

    The workflow supports pause/resume via Temporal signals and exposes the
    current checkpoint state via a query handler for the frontend to read.
    """

    def __init__(self) -> None:
        self._paused = False

    @workflow.run
    async def run(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the full scan pipeline.

        Args:
            ctx (dict): Scan context dict. Must include at minimum:
                - scan_history_id (int)
                - engine_id (int)
                - domain_id (int)
                - results_dir (str)
                - tasks (list[str]): Task names enabled by the engine.
                - yaml_configuration (dict): Parsed engine YAML config.

        Returns:
            dict: {'status': 'SUCCESS', 'scan_history_id': int}
        """
        workflow.logger.info(
            f"Starting MasterScanWorkflow for scan_id={ctx.get('scan_history_id')}"
        )

        while True:
            can_proceed = await workflow.execute_activity(
                "CheckScanQueueStatusActivity",
                args=[ctx.get('scan_history_id'), "main"],
                start_to_close_timeout=timedelta(minutes=1),
                retry_policy=_RETRY_INTERNAL,
                task_queue="python-orchestrator-queue"
            )
            if can_proceed:
                break
            await workflow.sleep(timedelta(seconds=30))

        # ------------------------------------------------------------------
        # STEP -1: Pre-populate task timeline (idempotent)
        # ------------------------------------------------------------------
        try:
            await workflow.execute_activity(
                "InitializeScanTasksActivity",
                ctx,
                start_to_close_timeout=timedelta(minutes=2),
                retry_policy=_RETRY_INTERNAL,
                task_queue="python-orchestrator-queue"
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            # Non-fatal: scan runs normally even if timeline pre-population fails
            pass

        # TOR circuit rotation — only dispatched when TOR mode is active
        if ctx.get('use_tor', False):
            try:
                await workflow.execute_activity(
                    "TorNewCircuitActivity",
                    start_to_close_timeout=timedelta(seconds=30),
                    retry_policy=RetryPolicy(maximum_attempts=1),
                    task_queue="python-orchestrator-queue"
                )
            except Exception:
                pass

        # State flags for finally-block dispatch (mirrors SubScanWorkflow pattern).
        is_cancelled = False
        success = False
        _failure_reason: str | None = None

        # ------------------------------------------------------------------
        # STEP 0: Target Profiling — validate scan, enrich context, set up dirs
        # ------------------------------------------------------------------
        try:
            ctx = await workflow.execute_activity(
                "TargetProfilingActivity",
                ctx,
                start_to_close_timeout=timedelta(minutes=5),
                heartbeat_timeout=timedelta(minutes=5),
                retry_policy=_RETRY_INTERNAL,
                task_queue="python-orchestrator-queue"
            )

            # Backward-compat: preserve event-history position for workflows started
            # before the checkpoint stubs were removed. No-op; returns immediately.
            await workflow.execute_activity(
                "LoadCheckpointActivity",
                ctx,
                start_to_close_timeout=timedelta(seconds=15),
                retry_policy=_RETRY_INTERNAL,
                task_queue="python-orchestrator-queue"
            )

            tasks = ctx.get("tasks", [])
            yaml_config = ctx.get("yaml_configuration", {})

            # ------------------------------------------------------------------
            # TIER 1: Discovery (parallel — all discovery tools run concurrently)
            # All must complete before Tier 2 begins (subdomains must be in DB).
            # osint runs in this group (mirrors Celery t1_background parallel group).
            # spiderfoot_scan runs here only when its YAML config block is present.
            # ------------------------------------------------------------------
            discovery_futures = []
            if "subdomain_discovery" in tasks:
                discovery_futures.append(
                    workflow.execute_activity(
                        "RunSubdomainDiscoveryActivity",
                        ctx,
                        start_to_close_timeout=timedelta(hours=4),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_LONG_SCAN,
                        task_queue="python-orchestrator-queue"
                    )
                )
            if "amass_intel_discovery" in tasks:
                discovery_futures.append(
                    workflow.execute_activity(
                        "RunAmassIntelDiscoveryActivity",
                        ctx,
                        start_to_close_timeout=timedelta(hours=2),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_LONG_SCAN,
                        task_queue="python-orchestrator-queue"
                    )
                )
            if "firewall_vpn_scan" in tasks:
                discovery_futures.append(
                    workflow.execute_activity(
                        "RunFirewallVPNScanActivity",
                        ctx,
                        start_to_close_timeout=timedelta(minutes=30),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_NETWORK_SCAN,
                        task_queue="python-orchestrator-queue"
                    )
                )
            if "dns_security" in tasks:
                discovery_futures.append(
                    workflow.execute_activity(
                        "RunDNSSecurityActivity",
                        ctx,
                        start_to_close_timeout=timedelta(hours=1),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_NETWORK_SCAN,
                        task_queue="python-orchestrator-queue"
                    )
                )
            if "osint" in tasks:
                discovery_futures.append(
                    workflow.execute_activity(
                        "RunGenericTaskActivity",
                        args=[ctx, "osint", "OSINT Scan"],
                        start_to_close_timeout=timedelta(hours=4),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_LONG_SCAN,
                        task_queue="python-orchestrator-queue"
                    )
                )
            if "spiderfoot_scan" in tasks and yaml_config.get("spiderfoot_scan"):
                discovery_futures.append(
                    workflow.execute_activity(
                        "RunGenericTaskActivity",
                        args=[ctx, "spiderfoot_scan", "SpiderFoot Attack Surface Intelligence"],
                        start_to_close_timeout=timedelta(hours=24),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_LONG_SCAN,
                        task_queue="python-orchestrator-queue"
                    )
                )
            if "baddns" in tasks:
                ctx_baddns = {
                    **ctx,
                    "yaml_configuration": {
                        **ctx.get("yaml_configuration", {}),
                        "subdomain_discovery": {
                            **ctx.get("yaml_configuration", {}).get("subdomain_discovery", {}),
                            "uses_tools": ["baddns"],
                        },
                    },
                }
                discovery_futures.append(
                    workflow.execute_activity(
                        "RunGenericTaskActivity",
                        args=[ctx_baddns, "subdomain_discovery", "Baddns Scan", {}, "baddns"],
                        start_to_close_timeout=timedelta(hours=4),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_LONG_SCAN,
                        task_queue="python-orchestrator-queue"
                    )
                )

            if discovery_futures:
                await asyncio.gather(*discovery_futures)
                # Verify / log discovery results persisted to DB
                await workflow.execute_activity(
                    "ParseDiscoveryResultsActivity",
                    ctx,
                    start_to_close_timeout=timedelta(minutes=15),
                    heartbeat_timeout=timedelta(minutes=5),
                    retry_policy=_RETRY_INTERNAL,
                    task_queue="python-orchestrator-queue"
                )

            await self._check_paused()

            # Post-Tier-1: dispatch any enabled "run after tier_1" plugins
            await _dispatch_tier_plugins(ctx, "tier_1", str(ctx.get('scan_history_id', 'scan')))

            await self._check_paused()
            # ------------------------------------------------------------------
            # TIER 2: HTTP Crawl + Port Scan + Screenshot (all parallel)
            #
            # http_crawl is a global config — it runs here and populates the
            # endpoint DB, which Tier 3 and Tier 4 depend on.
            # ------------------------------------------------------------------
            async def _http_crawl_branch():
                if "http_crawl" in tasks:
                    nonlocal ctx
                    ctx = await workflow.execute_activity(
                        "SeedEndpointsForCrawlActivity",
                        ctx,
                        start_to_close_timeout=timedelta(minutes=5),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_INTERNAL,
                        task_queue="python-orchestrator-queue"
                    )
                    await workflow.execute_activity(
                        "RunHTTPCrawlActivity",
                        ctx,
                        start_to_close_timeout=timedelta(hours=3),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_LONG_SCAN,
                        task_queue="python-orchestrator-queue"
                    )
                    await workflow.execute_activity(
                        "ParseHTTPCrawlResultsActivity",
                        ctx,
                        start_to_close_timeout=timedelta(minutes=15),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_INTERNAL,
                        task_queue="python-orchestrator-queue"
                    )

            tier2_futures = [_http_crawl_branch()]

            if "port_scan" in tasks:
                tier2_futures.append(
                    workflow.execute_activity(
                        "RunPortScanActivity",
                        ctx,
                        start_to_close_timeout=timedelta(hours=3),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_LONG_SCAN,
                        task_queue="python-orchestrator-queue"
                    )
                )

            vigolium_discovery_config = yaml_config.get('vigolium_discovery', {})
            if vigolium_discovery_config.get('run_vigolium_discovery', True):
                tier2_futures.append(
                    workflow.execute_activity(
                        "RunVigoliumDiscoveryActivity",
                        ctx,
                        start_to_close_timeout=timedelta(hours=4),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_LONG_SCAN,
                        task_queue="python-orchestrator-queue"
                    )
                )

            await asyncio.gather(*tier2_futures)

            # Per-service CVE + exploit lookup — fanned out concurrently after port scan data
            # is committed to DB. Uses GetDiscoveredServicesActivity to avoid DB calls in workflow.
            if "port_scan" in tasks:
                services = await workflow.execute_activity(
                    "GetDiscoveredServicesActivity",
                    ctx,
                    start_to_close_timeout=timedelta(minutes=5),
                    retry_policy=_RETRY_INTERNAL,
                    task_queue="python-orchestrator-queue",
                )
                await _fan_out_search_vulns(ctx, services or [])

            await self._check_paused()
            # Post-Tier-2: dispatch any enabled "run after tier_2" plugins
            await _dispatch_tier_plugins(ctx, "tier_2", str(ctx.get('scan_history_id', 'scan')))

            await self._check_paused()
            # ------------------------------------------------------------------
            # TIER 3: URL Fetching + Screenshot (parallel — both depend only on
            # Tier 2 http_crawl; screenshot does NOT depend on fetch_url output)
            # ------------------------------------------------------------------
            tier3_futures = []
            if "fetch_url" in tasks:
                tier3_futures.append(
                    workflow.execute_activity(
                        "RunFetchURLActivity",
                        ctx,
                        start_to_close_timeout=timedelta(hours=8),
                        heartbeat_timeout=timedelta(minutes=15),
                        retry_policy=_RETRY_LONG_SCAN,
                        task_queue="python-orchestrator-queue"
                    )
                )
            if "screenshot" in tasks:
                tier3_futures.append(
                    workflow.execute_activity(
                        "RunScreenshotActivity",
                        ctx,
                        start_to_close_timeout=timedelta(hours=1),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_NETWORK_SCAN,
                        task_queue="python-orchestrator-queue"
                    )
                )
            if tier3_futures:
                await asyncio.gather(*tier3_futures)

            await self._check_paused()

            # ------------------------------------------------------------------
            # TIER 3a: HTTP Crawl Bridge
            # Runs only if fetch_url is in tasks. Probes newly discovered endpoints
            # and dead/not-alive ones for HTTP/HTTPS responses and technologies.
            #
            # workflow.patched() guards this block so that workflows started
            # BEFORE this activity was introduced replay their recorded history
            # (RunDirFileFuzzActivity directly after fetch_url) without hitting a
            # nondeterminism error.  New workflows always execute the bridge.
            # ------------------------------------------------------------------
            if "fetch_url" in tasks and workflow.patched("add-http-crawl-bridge"):
                await workflow.execute_activity(
                    "RunHTTPCrawlBridgeActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=3),
                    heartbeat_timeout=timedelta(minutes=5),
                    retry_policy=_RETRY_LONG_SCAN,
                    task_queue="python-orchestrator-queue"
                )

            # ------------------------------------------------------------------
            # TIER 3b: Web API Discovery
            # Moved here from Tier 5 so kiterunner output (kr_*.json) is ready
            # before CPDE reads it. Guarded with workflow.patched() so that
            # in-flight workflows replaying recorded history (where this activity
            # ran at Tier 5) skip this block and still execute at Tier 5 below.
            # ------------------------------------------------------------------
            if "web_api_discovery" in tasks and workflow.patched("web-api-to-tier-3b"):
                await workflow.execute_activity(
                    "RunWebAPIDiscoveryActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=4),
                    heartbeat_timeout=timedelta(minutes=10),
                    retry_policy=_RETRY_NETWORK_SCAN,
                    task_queue="python-orchestrator-queue"
                )

            # ------------------------------------------------------------------
            # TIER 3c: Custom Parameter Discovery Engine (CPDE)
            # Reads kiterunner (kr_*.json), arjun, paramspider, linkfinder, and
            # JS bundles discovered by Tier 3. Runs after web_api_discovery so
            # all tool output files are present.
            # ------------------------------------------------------------------
            if "param_discovery" in tasks:
                await workflow.execute_activity(
                    "RunParamDiscoveryActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=2),
                    heartbeat_timeout=timedelta(minutes=10),
                    retry_policy=_RETRY_LONG_SCAN,
                    task_queue="python-orchestrator-queue"
                )

            await self._check_paused()

            # Post-Tier-3: dispatch any enabled "run after tier_3" plugins
            await _dispatch_tier_plugins(ctx, "tier_3", str(ctx.get('scan_history_id', 'scan')))

            await self._check_paused()
            # ------------------------------------------------------------------
            # TIER 4: Directory & File Fuzzing (sequential — needs Tier 3 URLs)
            # ------------------------------------------------------------------
            if "dir_file_fuzz" in tasks:
                await workflow.execute_activity(
                    "RunDirFileFuzzActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=8),
                    heartbeat_timeout=timedelta(minutes=15),
                    retry_policy=_RETRY_LONG_SCAN,
                    task_queue="python-orchestrator-queue"
                )
                await workflow.execute_activity(
                    "ParseFuzzResultsActivity",
                    ctx,
                    start_to_close_timeout=timedelta(minutes=15),
                    heartbeat_timeout=timedelta(minutes=5),
                    retry_policy=_RETRY_INTERNAL,
                    task_queue="python-orchestrator-queue"
                )

            # Consolidation: log total endpoint count after Tiers 2-4 complete
            await workflow.execute_activity(
                "ParseEnumerationResultsActivity",
                ctx,
                start_to_close_timeout=timedelta(minutes=5),
                heartbeat_timeout=timedelta(minutes=5),
                retry_policy=_RETRY_INTERNAL,
                task_queue="python-orchestrator-queue"
            )

            await self._check_paused()

            # Post-Tier-4: dispatch any enabled "run after tier_4" plugins
            await _dispatch_tier_plugins(ctx, "tier_4", str(ctx.get('scan_history_id', 'scan')))

            await self._check_paused()
            # ------------------------------------------------------------------
            # TIER 5: Analysis (parallel — WAF detection, secrets, vigolium)
            # web_api_discovery is only included here for old in-flight workflows
            # replaying history recorded before the "web-api-to-tier-3b" patch.
            # New workflows execute web_api_discovery at Tier 3b instead.
            # ------------------------------------------------------------------
            analysis_futures = []
            if "web_api_discovery" in tasks and not workflow.patched("web-api-to-tier-3b"):
                analysis_futures.append(
                    workflow.execute_activity(
                        "RunWebAPIDiscoveryActivity",
                        ctx,
                        start_to_close_timeout=timedelta(hours=4),
                        heartbeat_timeout=timedelta(minutes=10),
                        retry_policy=_RETRY_NETWORK_SCAN,
                        task_queue="python-orchestrator-queue"
                    )
                )
            if "waf_detection" in tasks:
                analysis_futures.append(
                    workflow.execute_activity(
                        "RunWAFDetectionActivity",
                        ctx,
                        start_to_close_timeout=timedelta(minutes=30),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_NETWORK_SCAN,
                        task_queue="python-orchestrator-queue"
                    )
                )
            if "secret_scanning" in tasks:
                analysis_futures.append(
                    workflow.execute_activity(
                        "RunSecretScanningActivity",
                        ctx,
                        start_to_close_timeout=timedelta(hours=2),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_LONG_SCAN,
                        task_queue="python-orchestrator-queue"
                    )
                )

            vigolium_analysis_config = yaml_config.get('vigolium_analysis', {})
            if vigolium_analysis_config.get('run_vigolium_analysis', True):
                analysis_futures.append(
                    workflow.execute_activity(
                        "RunVigoliumAnalysisActivity",
                        ctx,
                        start_to_close_timeout=timedelta(hours=8),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_LONG_SCAN,
                        task_queue="python-orchestrator-queue"
                    )
                )

            if analysis_futures:
                await asyncio.gather(*analysis_futures)
                await workflow.execute_activity(
                    "ParseAnalysisResultsActivity",
                    ctx,
                    start_to_close_timeout=timedelta(minutes=5),
                    heartbeat_timeout=timedelta(minutes=5),
                    retry_policy=_RETRY_INTERNAL,
                    task_queue="python-orchestrator-queue"
                )

            await self._check_paused()

            # Post-Tier-5: dispatch any enabled "run after tier_5" plugins
            await _dispatch_tier_plugins(ctx, "tier_5", str(ctx.get('scan_history_id', 'scan')))

            await self._check_paused()
            # ------------------------------------------------------------------
            # TIER 6: Security Assessment
            # NucleiPlannerWorkflow runs sequentially FIRST to prevent orphaned
            # child workflows when a concurrent T6 activity fails. asyncio.gather
            # cannot cancel a Temporal child workflow — the sequential pattern
            # eliminates the detachment risk entirely (see FIXES.md Fix 2).
            # waf_bypass runs concurrently after nuclei; it is an
            # activity (not child workflow) so gather is safe for it.
            # ------------------------------------------------------------------
            ran_t6 = False
            nuclei_failed = False

            if "vulnerability_scan" in tasks:
                # Spawn as a child workflow so Nuclei execution has its own
                # independent Temporal history and can be tracked separately.
                ran_t6 = True
                try:
                    await workflow.execute_child_workflow(
                        "NucleiPlannerWorkflow",
                        ctx,
                        id=f"{workflow.info().workflow_id}-{workflow.info().run_id[:8]}-nuclei",
                        task_queue="python-orchestrator-queue",
                        execution_timeout=timedelta(hours=24),
                        run_timeout=timedelta(hours=24),
                        retry_policy=RetryPolicy(maximum_attempts=1),
                    )
                except Exception as nuclei_err:
                    # Nuclei failure is non-fatal: completed batches are already in DB.
                    # Tier 7 (correlation, risk scoring, Neo4j) will still run on partial
                    # results. Failure is logged and the scan continues.
                    workflow.logger.error(
                        "NucleiPlannerWorkflow failed for scan_id=%s — continuing to Tier 7. error=%s",
                        ctx.get('scan_history_id'), str(nuclei_err),
                    )
                    nuclei_failed = True

            other_t6_futures = []
            if "waf_bypass" in tasks:
                ran_t6 = True
                other_t6_futures.append(
                    workflow.execute_activity(
                        "RunWAFBypassActivity",
                        ctx,
                        start_to_close_timeout=timedelta(hours=1),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_NETWORK_SCAN,
                        task_queue="python-orchestrator-queue"
                    )
                )
            if other_t6_futures:
                await asyncio.gather(*other_t6_futures)

            if ran_t6:
                await workflow.execute_activity(
                    "ParseAssessmentResultsActivity",
                    ctx,
                    start_to_close_timeout=timedelta(minutes=5),
                    heartbeat_timeout=timedelta(minutes=5),
                    retry_policy=_RETRY_INTERNAL,
                    task_queue="python-orchestrator-queue"
                )

            await self._check_paused()

            # Post-Tier-6: dispatch any enabled "run after tier_6" plugins
            await _dispatch_tier_plugins(ctx, "tier_6", str(ctx.get('scan_history_id', 'scan')))

            await self._check_paused()
            
            # Tier 7, notification, and finalization have moved to the finally
            # block below — guarded by `if success:` to match SubScanWorkflow.
            success = True
            return {"status": "SUCCESS", "scan_history_id": ctx.get("scan_history_id")}

        except asyncio.CancelledError:
            workflow.logger.info(
                f"MasterScanWorkflow cancelled for scan_id={ctx.get('scan_history_id')} "
                "— skipping FinalizeFailedScanActivity (ABORTED_TASK already set by API)."
            )
            is_cancelled = True
            raise

        except Exception as e:
            workflow.logger.error(
                f"MasterScanWorkflow FAILED for scan_id={ctx.get('scan_history_id')}: {e}"
            )
            _failure_reason = str(e)
            raise e

        finally:
            if not is_cancelled:
                if success:
                    # ------------------------------------------------------------------
                    # TIER 7: Post-Processing & Intelligence (sequential — ordering matters)
                    # Runs only when all scan tiers completed cleanly (success=True),
                    # matching the SubScanWorkflow pattern. Errors here are non-fatal:
                    # findings are still queryable even without correlation/risk data.
                    # ------------------------------------------------------------------
                    try:
                        if "vulnerability_scan" in tasks:
                            await workflow.execute_activity(
                                "CorrelateVulnerabilitiesActivity",
                                ctx,
                                start_to_close_timeout=timedelta(minutes=90),
                                heartbeat_timeout=timedelta(minutes=5),
                                retry_policy=_RETRY_INTERNAL,
                                task_queue="python-orchestrator-queue"
                            )
                            await workflow.execute_activity(
                                "CorrelateExposuresActivity",
                                ctx,
                                start_to_close_timeout=timedelta(minutes=30),
                                heartbeat_timeout=timedelta(minutes=5),
                                retry_policy=_RETRY_INTERNAL,
                                task_queue="python-orchestrator-queue"
                            )
                            # Enrich CVEs found during this scan with NVD/EPSS/KEV data
                            # before risk scoring so CVSS and EPSS values are available.
                            await workflow.execute_activity(
                                "EnrichScanCVEsActivity",
                                ctx,
                                start_to_close_timeout=timedelta(minutes=45),
                                heartbeat_timeout=timedelta(minutes=5),
                                retry_policy=_RETRY_INTERNAL,
                                task_queue="python-orchestrator-queue"
                            )
                            await workflow.execute_activity(
                                "CalculateRiskScoresActivity",
                                ctx,
                                start_to_close_timeout=timedelta(minutes=30),
                                heartbeat_timeout=timedelta(minutes=5),
                                retry_policy=_RETRY_INTERNAL,
                                task_queue="python-orchestrator-queue"
                            )
                            # AI Impact Assessment — capped at 100 vulns per run;
                            # timeout sized for 100 × 30s worst-case OpenAI latency.
                            await workflow.execute_activity(
                                "GenerateImpactAssessmentActivity",
                                ctx,
                                start_to_close_timeout=timedelta(hours=1),
                                heartbeat_timeout=timedelta(minutes=5),
                                retry_policy=_RETRY_LLM,
                                task_queue="python-orchestrator-queue"
                            )

                        _graph_tasks = {
                            "subdomain_discovery", "amass_intel_discovery", "firewall_vpn_scan",
                            "osint", "spiderfoot_scan", "baddns", "http_crawl", "port_scan",
                            "fetch_url", "dir_file_fuzz", "web_api_discovery", "vulnerability_scan",
                            "param_discovery"
                        }
                        if any(t in _graph_tasks for t in tasks):
                            # Neo4j graph sync (must precede APME so graph nodes exist)
                            await workflow.execute_activity(
                                "SyncGraphActivity",
                                ctx,
                                start_to_close_timeout=timedelta(minutes=30),
                                heartbeat_timeout=timedelta(minutes=5),
                                retry_policy=_RETRY_NETWORK_SCAN,
                                task_queue="python-orchestrator-queue"
                            )
                            # Attack Path Modeling Engine — must be the final analysis step
                            await workflow.execute_activity(
                                "RunGenericTaskActivity",
                                args=[ctx, "run_apme", "Attack Path Modeling Engine",
                                      {"scan_history_id": ctx.get("scan_history_id")}],
                                start_to_close_timeout=timedelta(minutes=30),
                                heartbeat_timeout=timedelta(minutes=5),
                                retry_policy=_RETRY_INTERNAL,
                                task_queue="python-orchestrator-queue"
                            )
                        # Post-Tier-7: dispatch any enabled "run after tier_7" plugins
                        # (e.g. compliance_assessment). Runs after APME so full graph data is available.
                        await _dispatch_tier_plugins(
                            ctx, "tier_7", str(ctx.get('scan_history_id', 'scan'))
                        )
                    except asyncio.CancelledError:
                        raise
                    except Exception as post_e:
                        workflow.logger.error(
                            f"MasterScanWorkflow post-scan tasks failed for "
                            f"scan_id={ctx.get('scan_history_id')}: {post_e}"
                        )

                    # ------------------------------------------------------------------
                    # FINAL: Mark scan complete and send notification.
                    # Outside the Tier 7 try/except so it always runs even when
                    # post-processing (correlation, graph sync, APME) raises — without
                    # this guarantee a swallowed Tier 7 exception leaves scan_status as
                    # RUNNING_TASK indefinitely and recover_stuck_scans incorrectly
                    # marks the scan FAILED on the next orchestrator restart.
                    # ------------------------------------------------------------------
                    await workflow.execute_activity(
                        "SendScanNotificationActivity",
                        ctx,
                        start_to_close_timeout=timedelta(minutes=5),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_INTERNAL,
                        task_queue="python-orchestrator-queue"
                    )
                    workflow.logger.info(
                        f"MasterScanWorkflow COMPLETE for scan_id={ctx.get('scan_history_id')}"
                    )
                else:
                    # Scan tiers failed — finalize the scan record in Django DB.
                    try:
                        await workflow.execute_activity(
                            "FinalizeFailedScanActivity",
                            args=[ctx, _failure_reason or "Workflow failed during execution"],
                            start_to_close_timeout=timedelta(minutes=5),
                            heartbeat_timeout=timedelta(minutes=5),
                            retry_policy=_RETRY_INTERNAL,
                            task_queue="python-orchestrator-queue"
                        )
                    except Exception as fin_e:
                        workflow.logger.error(
                            f"FinalizeFailedScanActivity itself failed for "
                            f"scan_id={ctx.get('scan_history_id')}: {fin_e}"
                        )

    # ------------------------------------------------------------------
    # Signal Handlers
    # ------------------------------------------------------------------

    @workflow.signal(name="pause")
    def pause_workflow(self) -> None:
        """Signal handler: pause the scan pipeline at the next tier boundary.

        The pipeline will save a checkpoint and wait until a 'resume' signal
        is received before proceeding to the next tier.
        """
        workflow.logger.info("MasterScanWorkflow received PAUSE signal.")
        self._paused = True

    @workflow.signal(name="resume")
    def resume_workflow(self) -> None:
        """Signal handler: resume a paused scan pipeline.

        Clears the paused flag so the workflow continues from the last
        completed tier.
        """
        workflow.logger.info("MasterScanWorkflow received RESUME signal.")
        self._paused = False

    # ------------------------------------------------------------------
    # Query Handlers
    # ------------------------------------------------------------------

    @workflow.query(name="get_current_state")
    def get_current_state(self) -> Dict[str, Any]:
        """Query handler: return the current workflow state for the frontend."""
        return {"paused": self._paused}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _check_paused(self) -> None:
        """Block at a tier boundary if a pause signal was received.

        Temporal's event history handles durability — no explicit checkpoint
        is needed. The workflow simply waits for the resume signal.
        """
        if self._paused:
            workflow.logger.info("MasterScanWorkflow PAUSED — waiting for resume signal.")
            await workflow.wait_condition(lambda: not self._paused)
            workflow.logger.info("MasterScanWorkflow RESUMED.")


@workflow.defn(name="NucleiPlannerWorkflow")
class NucleiPlannerWorkflow:
    """Child workflow managing vulnerability scan orchestration via Nuclei.

    Spawned as a child of MasterScanWorkflow when 'vulnerability_scan' is in
    the engine's task list. Running this as a child workflow gives the
    vulnerability scan its own independent Temporal history, making it easier
    to trace failures, retries, and individual template results separately.

    Args (via ctx):
        scan_history_id (int): Parent scan history ID.
        yaml_configuration (dict): Full engine config including nuclei settings.
    """

    @workflow.run
    async def run(self, ctx: Dict[str, Any]) -> Dict[str, Any]:
        """Execute the full vulnerability scan pipeline.

        Args:
            ctx (dict): Temporal workflow context (passed from MasterScanWorkflow).

        Returns:
            dict: {'status': 'SUCCESS'} on completion.
        """
        workflow.logger.info(
            f"Starting NucleiPlannerWorkflow for scan_id={ctx.get('scan_history_id')}"
        )

        # -----------------------------------------------------------------------
        # Lifecycle guard — child workflow abort/delete check
        # When Temporal replays this child workflow after a container restart, it
        # skips MasterScanWorkflow's TargetProfilingActivity guard entirely.
        # CheckScanAliveActivity mirrors that guard here at the earliest possible
        # point, raising non_retryable ApplicationError if the scan was deleted or
        # aborted so the child workflow terminates cleanly without retry loops.
        # -----------------------------------------------------------------------
        await workflow.execute_activity(
            "CheckScanAliveActivity",
            args=[ctx.get('scan_history_id')],
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=_RETRY_INTERNAL,
            task_queue="python-orchestrator-queue",
        )

        yaml_config = ctx.get('yaml_configuration', {})
        vuln_config = yaml_config.get('vulnerability_scan', {})

        # --- Stage 1: Primary scanners ---

        if vuln_config.get('run_nuclei', True):
            nuclei_specific_config = vuln_config.get('nuclei', {})
            severities = nuclei_specific_config.get('severity') or NUCLEI_DEFAULT_SEVERITIES

            if workflow.patched("nuclei-proxy-rotation"):
                proxies_file_path = None
                try:
                    proxies_file_path = await workflow.execute_activity(
                        "CreateProxyListActivity",
                        args=[ctx],
                        start_to_close_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_INTERNAL,
                        task_queue="python-orchestrator-queue",
                    )

                    # Gather tags and pre-built batches via activity.
                    # Activity counts templates per tag so each batch is bounded by
                    # template count rather than tag count — prevents 2-hour timeouts
                    # on WordPress-heavy scans with 2000+ templates.
                    nuclei_tag_result = await workflow.execute_activity(
                        "GatherNucleiTagsActivity",
                        args=[ctx],
                        start_to_close_timeout=timedelta(minutes=10),
                        retry_policy=_RETRY_INTERNAL,
                        task_queue="python-orchestrator-queue",
                    )
                    tag_batches = nuclei_tag_result.get('batches') or [None]

                    for severity in severities:
                        for batch in tag_batches:
                            severity_ctx = {
                                **ctx,
                                "nuclei_severity_filter": severity,
                                "nuclei_proxies_path": proxies_file_path
                            }
                            await workflow.execute_activity(
                                "RunNucleiActivity",
                                args=[severity_ctx, severity, batch],
                                start_to_close_timeout=timedelta(hours=6),
                                heartbeat_timeout=timedelta(minutes=5),
                                retry_policy=_RETRY_LONG_SCAN,
                                task_queue="python-orchestrator-queue",
                            )
                finally:
                    if proxies_file_path:
                        # Clean up the proxies list to avoid leaving sensitive network details around
                        await workflow.execute_activity(
                            "CleanupProxyListActivity",
                            args=[proxies_file_path],
                            start_to_close_timeout=timedelta(minutes=5),
                            retry_policy=_RETRY_INTERNAL,
                            task_queue="python-orchestrator-queue",
                        )
            else:
                # Gather tags and pre-built batches via activity.
                # Activity counts templates per tag so each batch is bounded by
                # template count rather than tag count — prevents 2-hour timeouts
                # on WordPress-heavy scans with 2000+ templates.
                nuclei_tag_result = await workflow.execute_activity(
                    "GatherNucleiTagsActivity",
                    args=[ctx],
                    start_to_close_timeout=timedelta(minutes=10),
                    retry_policy=_RETRY_INTERNAL,
                    task_queue="python-orchestrator-queue",
                )
                tag_batches = nuclei_tag_result.get('batches') or [None]

                for severity in severities:
                    for batch in tag_batches:
                        severity_ctx = {
                            **ctx,
                            "nuclei_severity_filter": severity
                        }
                        await workflow.execute_activity(
                            "RunNucleiActivity",
                            args=[severity_ctx, severity, batch],
                            start_to_close_timeout=timedelta(hours=6),
                            heartbeat_timeout=timedelta(minutes=5),
                            retry_policy=_RETRY_LONG_SCAN,
                            task_queue="python-orchestrator-queue",
                        )

        if vuln_config.get('run_crlfuzz', False):
            await workflow.execute_activity(
                "RunCRLFuzzActivity", 
                ctx, 
                start_to_close_timeout=timedelta(hours=4), 
                heartbeat_timeout=timedelta(minutes=5),
                task_queue="python-orchestrator-queue"
            )
            
        if vuln_config.get('run_dalfox', False):
            await workflow.execute_activity(
                "RunDalfoxActivity", 
                ctx, 
                start_to_close_timeout=timedelta(hours=4), 
                heartbeat_timeout=timedelta(minutes=5),
                task_queue="python-orchestrator-queue"
            )
            
        if vuln_config.get('run_s3scanner', True):
            await workflow.execute_activity(
                "RunS3ScannerActivity", 
                ctx, 
                start_to_close_timeout=timedelta(hours=2), 
                heartbeat_timeout=timedelta(minutes=5),
                task_queue="python-orchestrator-queue"
            )
            
        # --- Stage 2: Additional scanners ---
        if vuln_config.get('run_acunetix', False):
            await workflow.execute_activity(
                "RunAcunetixActivity", 
                ctx, 
                start_to_close_timeout=timedelta(hours=4), 
                heartbeat_timeout=timedelta(minutes=5),
                task_queue="python-orchestrator-queue"
            )
            
        cpanel_cfg = vuln_config.get('cpanel_scanner', {})
        if cpanel_cfg.get('run_cpanel2shell', True):
            await workflow.execute_activity(
                "RunCpanelScanActivity", 
                ctx, 
                start_to_close_timeout=timedelta(hours=2), 
                heartbeat_timeout=timedelta(minutes=5),
                task_queue="python-orchestrator-queue"
            )
            
        if vuln_config.get('run_wpscan', True):
            await workflow.execute_activity(
                "RunWpscanActivity", 
                ctx, 
                start_to_close_timeout=timedelta(hours=2), 
                heartbeat_timeout=timedelta(minutes=5),
                task_queue="python-orchestrator-queue"
            )
            
        react_cfg = vuln_config.get('react_scanner', {})
        if react_cfg.get('run_react2shell', True):
            await workflow.execute_activity(
                "RunReact2ShellActivity", 
                ctx, 
                start_to_close_timeout=timedelta(hours=2), 
                heartbeat_timeout=timedelta(minutes=5),
                task_queue="python-orchestrator-queue"
            )
            
        leaks_config = yaml_config.get('leaks_and_secrets', {})
        if leaks_config.get('run_semgrep', True):
            await workflow.execute_activity(
                "RunSemgrepActivity", 
                ctx, 
                start_to_close_timeout=timedelta(hours=2), 
                heartbeat_timeout=timedelta(minutes=5),
                task_queue="python-orchestrator-queue"
            )

        if vuln_config.get('run_vigolium', True):
            await workflow.execute_activity(
                "RunVigoliumScanActivity",
                ctx,
                start_to_close_timeout=timedelta(hours=6),
                heartbeat_timeout=timedelta(minutes=5),
                retry_policy=_RETRY_LONG_SCAN,
                task_queue="python-orchestrator-queue"
            )

        if vuln_config.get('run_wptaint_scan', True):
            await workflow.execute_activity(
                "RunWPTaintScanActivity", 
                ctx, 
                start_to_close_timeout=timedelta(hours=2), 
                heartbeat_timeout=timedelta(minutes=5),
                task_queue="python-orchestrator-queue"
            )

        # Write a ScanActivity(name='vulnerability_scan', status=SUCCESS) so that
        # resume_scan_temporal can recognise this compound task as complete and
        # skip it on crash recovery, instead of restarting the whole vuln scan.
        await workflow.execute_activity(
            "MarkVulnerabilityScanCompleteActivity",
            ctx,
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=_RETRY_INTERNAL,
            task_queue="python-orchestrator-queue"
        )

        workflow.logger.info(
            f"NucleiPlannerWorkflow COMPLETE for scan_id={ctx.get('scan_history_id')}"
        )
        return {"status": "SUCCESS"}


# Registry for SubScanWorkflow dispatch.
# value=None means the scan type has special handling and is coded inline.
# value=dict means standard dispatch: call `activity` with args from `args_builder`.
_SUBSCAN_DISPATCH = {
    "osint": {
        "activity": "RunGenericTaskActivity",
        "timeout": timedelta(hours=2),
        "args_builder": lambda ctx: [
            ctx, "osint", "OSINT Scan", {"host": ctx.get("subdomain_name", "")}
        ],
    },
    "subdomain_discovery": {
        "activity": "RunGenericTaskActivity",
        "timeout": timedelta(hours=4),
        "args_builder": lambda ctx: [
            ctx, "subdomain_discovery", "Subdomain Discovery",
            {"host": ctx.get("subdomain_name", "")},
        ],
    },
    "port_scan": {
        "activity": "RunGenericTaskActivity",
        "timeout": timedelta(hours=2),
        "args_builder": lambda ctx: [
            ctx, "port_scan", "Port Scan",
            {"hosts": [ctx.get("subdomain_name", "")]},
        ],
    },
    "fetch_url": {
        "activity": "RunGenericTaskActivity",
        "timeout": timedelta(hours=8),
        "args_builder": lambda ctx: [
            ctx, "fetch_url", "Fetch URL",
            {"urls": [ctx.get("subdomain_http_url") or f"http://{ctx.get('subdomain_name', '')}/"]},
        ],
    },
    "dir_file_fuzz": {
        "activity": "RunGenericTaskActivity",
        "timeout": timedelta(hours=8),
        "args_builder": lambda ctx: [ctx, "dir_file_fuzz", "Dir File Fuzz", {}],
    },
    "screenshot": {
        "activity": "RunGenericTaskActivity",
        "timeout": timedelta(hours=1),
        "args_builder": lambda ctx: [ctx, "screenshot", "Screenshot", {}],
    },
    "waf_detection": {
        "activity": "RunGenericTaskActivity",
        "timeout": timedelta(minutes=30),
        "args_builder": lambda ctx: [ctx, "waf_detection", "WAF Detection", {}],
    },
    "http_crawl": {
        "activity": "RunGenericTaskActivity",
        "timeout": timedelta(hours=2),
        "args_builder": lambda ctx: [
            ctx, "http_crawl", "HTTP Crawl",
            {"urls": [ctx.get("subdomain_http_url") or f"http://{ctx.get('subdomain_name', '')}/"]},
        ],
    },
    "http_crawl_bridge": {
        "activity": "RunHTTPCrawlBridgeActivity",
        "timeout": timedelta(hours=3),
        "args_builder": lambda ctx: [ctx],
    },
    "web_api_discovery": {
        "activity": "RunGenericTaskActivity",
        "timeout": timedelta(hours=2),
        "args_builder": lambda ctx: [
            ctx, "web_api_discovery", "Web API Discovery",
            {"urls": [ctx.get("subdomain_http_url") or f"http://{ctx.get('subdomain_name', '')}/"]},
        ],
    },
    "param_discovery": {
        "activity": "RunParamDiscoveryActivity",
        "timeout": timedelta(hours=2),
        "args_builder": lambda ctx: [ctx],
    },
    "waf_bypass": {
        "activity": "RunGenericTaskActivity",
        "timeout": timedelta(hours=1),
        "args_builder": lambda ctx: [ctx, "waf_bypass", "WAF Bypass", {}],
    },
    "firewall_vpn_scan": {
        "activity": "RunGenericTaskActivity",
        "timeout": timedelta(hours=1),
        "args_builder": lambda ctx: [ctx, "firewall_vpn_scan", "Firewall/VPN Scan", {}],
    },
    "spiderfoot_scan": {
        "activity": "RunGenericTaskActivity",
        "timeout": timedelta(hours=8),
        "args_builder": lambda ctx: [ctx, "spiderfoot_scan", "SpiderFoot Scan", {}],
    },
    "secret_scanning": {
        "activity": "RunGenericTaskActivity",
        "timeout": timedelta(hours=2),
        "args_builder": lambda ctx: [ctx, "secret_scanning", "Secret Scanning", {}],
    },
    "attack_path_modeling": {
        "activity": "RunGenericTaskActivity",
        "timeout": timedelta(minutes=30),
        "args_builder": lambda ctx: [ctx, "run_apme", "Attack Path Modeling Engine", {"scan_history_id": ctx.get("scan_history_id")}],
    },
    "vigolium_discovery": {
        "activity": "RunVigoliumDiscoveryActivity",
        "timeout": timedelta(hours=2),
        "args_builder": lambda ctx: [ctx],
    },
    "vigolium_analysis": {
        "activity": "RunVigoliumAnalysisActivity",
        "timeout": timedelta(hours=3),
        "args_builder": lambda ctx: [ctx],
    },
    "vigolium_scan": {
        "activity": "RunVigoliumScanActivity",
        "timeout": timedelta(hours=4),
        "args_builder": lambda ctx: [ctx],
    },
    "run_acunetix": {
        "activity": "RunAcunetixActivity",
        "timeout": timedelta(hours=4),
        "args_builder": lambda ctx: [ctx],
    },
    # Special cases — handled with inline logic in SubScanWorkflow.run():
    "vulnerability_scan": None,  # Has Tier 7 post-steps (correlation, risk, APME)
    "baddns": None,              # Modifies ctx before dispatch
}


@workflow.defn(name="SubScanWorkflow")
class SubScanWorkflow:
    """Workflow orchestrating target subdomain subscans.

    Subscans are scoped to a single subdomain and execute one or more scan tasks
    (e.g., 'port_scan', 'fetch_url', 'vulnerability_scan') inside a Temporal
    workflow, strictly enforcing sequence-enforced execution tiers.
    """

    def __init__(self) -> None:
        self._paused = False

    # ------------------------------------------------------------------
    # Signal Handlers
    # ------------------------------------------------------------------

    @workflow.signal(name="pause")
    def pause_workflow(self) -> None:
        """Signal handler: pause the subscan pipeline at the next tier boundary."""
        workflow.logger.info("SubScanWorkflow received PAUSE signal.")
        self._paused = True

    @workflow.signal(name="resume")
    def resume_workflow(self) -> None:
        """Signal handler: resume a paused subscan pipeline."""
        workflow.logger.info("SubScanWorkflow received RESUME signal.")
        self._paused = False

    # ------------------------------------------------------------------
    # Query Handlers
    # ------------------------------------------------------------------

    @workflow.query(name="get_current_state")
    def get_current_state(self) -> Dict[str, Any]:
        """Query handler: return the current workflow state for the frontend."""
        return {"paused": self._paused}

    # ------------------------------------------------------------------
    # Internal helpers
    # ------------------------------------------------------------------

    async def _check_paused(self) -> None:
        """Block at a tier boundary if a pause signal was received."""
        if self._paused:
            workflow.logger.info("SubScanWorkflow PAUSED — waiting for resume signal.")
            await workflow.wait_condition(lambda: not self._paused)
            workflow.logger.info("SubScanWorkflow RESUMED.")

    @workflow.run
    async def run(self, ctx: Dict[str, Any], scan_type: Union[str, List[str]]) -> Dict[str, Any]:
        """Execute the subscan workflow.

        Groups all requested tasks into their respective execution tiers, runs them
        sequentially tier-by-tier, and executes tasks within each tier concurrently.
        Maintains backward compatibility with string scan_type arguments.

        Args:
            ctx (dict): Subscan context containing target domains, engine settings, and subscans metadata.
            scan_type (str or list): One or more scan/task type names to run.

        Returns:
            dict: {'status': 'SUCCESS'} on completion.
        """
        # Normalize scan_type to a unique, ordered list of tasks
        if isinstance(scan_type, str):
            tasks = [scan_type]
        else:
            tasks = []
            for t in scan_type:
                if t not in tasks:
                    tasks.append(t)

        # Automatically inject http_crawl_bridge if fetch_url is in tasks
        if "fetch_url" in tasks and "http_crawl_bridge" not in tasks:
            tasks.append("http_crawl_bridge")

        workflow.logger.info(
            f"Starting SubScanWorkflow for subdomain_id={ctx.get('subdomain_id')} tasks={tasks}"
        )

        while True:
            can_proceed = await workflow.execute_activity(
                "CheckScanQueueStatusActivity",
                args=[ctx.get('subscan_id'), "subscan"],
                start_to_close_timeout=timedelta(minutes=1),
                retry_policy=_RETRY_INTERNAL,
                task_queue="python-orchestrator-queue"
            )
            if can_proceed:
                break
            await workflow.sleep(timedelta(seconds=30))

        # Pre-populate subscan task timeline (idempotent)
        try:
            subscan_init_ctx = {**ctx, 'tasks': tasks}
            await workflow.execute_activity(
                "InitializeScanTasksActivity",
                subscan_init_ctx,
                start_to_close_timeout=timedelta(minutes=2),
                retry_policy=_RETRY_INTERNAL,
                task_queue="python-orchestrator-queue"
            )
        except asyncio.CancelledError:
            raise
        except Exception:
            pass

        # TOR circuit rotation — only dispatched when TOR mode is active
        if ctx.get('use_tor', False):
            try:
                await workflow.execute_activity(
                    "TorNewCircuitActivity",
                    start_to_close_timeout=timedelta(seconds=30),
                    retry_policy=RetryPolicy(maximum_attempts=1),
                    task_queue="python-orchestrator-queue"
                )
            except Exception:
                pass

        # Validate tasks against the permitted task list before any dispatch
        known_explicit = set(_SUBSCAN_DISPATCH.keys())
        for t in tasks:
            if t not in known_explicit and t not in _PERMITTED_GENERIC_TASKS:
                raise ValueError(
                    f"[SubScanWorkflow] '{t}' is not a recognized subscan type. "
                    f"Add it to _PERMITTED_GENERIC_TASKS in temporal_activities.py to enable dispatch."
                )

        # -----------------------------------------------------------------------
        # Lifecycle guard — child workflow abort/delete check
        # SubScanWorkflow is spawned after MasterScanWorkflow has run
        # TargetProfilingActivity. When Temporal replays this child workflow after
        # a container restart it skips the parent's guard entirely. This call
        # mirrors that guard at the earliest point before any task dispatch,
        # raising a non_retryable ApplicationError if the scan was deleted or
        # aborted so the child workflow terminates cleanly without retry loops.
        # -----------------------------------------------------------------------
        await workflow.execute_activity(
            "CheckScanAliveActivity",
            args=[ctx.get('scan_history_id'), ctx.get('subscan_id')],
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=_RETRY_INTERNAL,
            task_queue="python-orchestrator-queue",
        )

        is_cancelled = False

        success = False
        task_success = {}

        try:
            subdomain_name = ctx.get('subdomain_name', '')
            # Determine target url
            subdomain_http_url = ctx.get('subdomain_http_url')
            target_url = subdomain_http_url or f"http://{subdomain_name}/"
            yaml_config = ctx.get('yaml_configuration', {})

            # Parse task-specific subscan IDs to track individual task status
            subscans_info = ctx.get('subscans_info', [])
            subscan_id_map = {item['type']: item['id'] for item in subscans_info}

            async def execute_single_task(t: str, custom_ctx: Dict[str, Any] = None) -> None:
                """Helper to execute a single task with its matching subscan context.

                Args:
                    t (str): Short name of the task to execute.
                    custom_ctx (dict, optional): Custom context dictionary to use instead of workflow's ctx.
                """
                base_ctx = custom_ctx if custom_ctx is not None else ctx
                # Resolve task-specific subscan_id to set in activity context
                subscan_id = subscan_id_map.get(t) or base_ctx.get('subscan_id')
                ctx_task = {**base_ctx, "subscan_id": subscan_id} if subscan_id else base_ctx

                dispatch = _SUBSCAN_DISPATCH.get(t)
                if t == "baddns":
                    ctx_baddns = {
                        **ctx_task,
                        "yaml_configuration": {
                            **ctx_task.get("yaml_configuration", {}),
                            "subdomain_discovery": {
                                **ctx_task.get("yaml_configuration", {}).get("subdomain_discovery", {}),
                                "uses_tools": ["baddns"],
                            },
                        },
                    }
                    await workflow.execute_activity(
                        "RunGenericTaskActivity",
                        args=[ctx_baddns, "subdomain_discovery", "Baddns Scan", {"host": subdomain_name}, "baddns"],
                        start_to_close_timeout=timedelta(hours=2),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_NETWORK_SCAN,
                        task_queue="python-orchestrator-queue",
                    )
                elif t == "vulnerability_scan":
                    await workflow.execute_child_workflow(
                        "NucleiPlannerWorkflow",
                        ctx_task,
                        id=f"{workflow.info().workflow_id}-{workflow.info().run_id[:8]}-nuclei",
                        task_queue="python-orchestrator-queue",
                        execution_timeout=timedelta(hours=12),
                        run_timeout=timedelta(hours=12),
                        retry_policy=RetryPolicy(maximum_attempts=1),
                    )
                elif dispatch is not None:
                    args = dispatch["args_builder"](ctx_task)
                    await workflow.execute_activity(
                        dispatch["activity"],
                        args=args,
                        start_to_close_timeout=dispatch["timeout"],
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_NETWORK_SCAN,
                        task_queue="python-orchestrator-queue",
                    )
                else:
                    await workflow.execute_activity(
                        "RunGenericTaskActivity",
                        args=[ctx_task, t, t.replace("_", " ").title()],
                        start_to_close_timeout=timedelta(hours=2),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_NETWORK_SCAN,
                        task_queue="python-orchestrator-queue",
                    )

            async def run_and_track_task(t: str, custom_ctx: Dict[str, Any] = None) -> None:
                """Wrap task execution to track its outcome in the task_success registry.

                Args:
                    t (str): Task type string.
                    custom_ctx (dict, optional): Custom context dictionary to pass to the task.
                """
                try:
                    await execute_single_task(t, custom_ctx)
                    task_success[t] = True
                except Exception as task_err:
                    task_success[t] = False
                    raise task_err

            # Group active tasks by sequence-enforced execution tiers
            active_tasks = [t for t in tasks if t not in {
                "correlate_vulnerabilities", "calculate_risk_scores",
                "generate_impact_assessment", "sync_graph", "run_apme", "attack_path_modeling"
            }]

            tiers = [
                # TIER 1: Discovery — all discovery tools run concurrently.
                # All must complete before Tier 2 (subdomains must be in DB).
                [t for t in active_tasks if t in {
                    "subdomain_discovery", "amass_intel_discovery", "firewall_vpn_scan",
                    "dns_security", "osint", "spiderfoot_scan", "baddns"
                }],
                # TIER 2: HTTP Crawl & Port Scan — populates endpoint DB for Tiers 3+.
                # vigolium_discovery runs alongside http_crawl to seed endpoints concurrently.
                [t for t in active_tasks if t in {"http_crawl", "port_scan", "vigolium_discovery"}],
                # TIER 3: URL Fetching + Screenshot — both depend only on Tier 2 http_crawl;
                # screenshot does NOT depend on fetch_url output so they run concurrently.
                [t for t in active_tasks if t in {"fetch_url", "screenshot"}],
                # TIER 3a: HTTP Crawl Bridge — crawls new/dead endpoints from fetch_url
                [t for t in active_tasks if t == "http_crawl_bridge"],
                # TIER 3b: Web API Discovery — runs before CPDE so kiterunner output is available.
                [t for t in active_tasks if t == "web_api_discovery"],
                # TIER 3c: Custom Parameter Discovery Engine (CPDE) — reads kiterunner/arjun/JS output.
                [t for t in active_tasks if t == "param_discovery"],
                # TIER 4: Directory & File Fuzzing — needs Tier 3 URLs.
                [t for t in active_tasks if t == "dir_file_fuzz"],
                # TIER 5: Analysis — WAF detection, secret scanning, vigolium.
                [t for t in active_tasks if t in {"waf_detection", "secret_scanning", "vigolium_analysis"}],
                # TIER 6: Security Assessment — explicit inclusion, mirrors MasterScanWorkflow Tier 6.
                # vigolium_scan runs alongside vulnerability_scan at Tier 6.
                [t for t in active_tasks if t in {
                    "vulnerability_scan", "waf_bypass", "vigolium_scan", "run_acunetix"
                }],
                # TIER 6b: Fallback for any task not classified in Tiers 1-6.
                # Handles future tasks added to _SUBSCAN_DISPATCH without breaking existing tiers.
                [t for t in active_tasks if t not in {
                    "subdomain_discovery", "amass_intel_discovery", "firewall_vpn_scan",
                    "dns_security", "osint", "spiderfoot_scan", "baddns", "http_crawl", "port_scan",
                    "fetch_url", "screenshot", "dir_file_fuzz", "web_api_discovery", "waf_detection",
                    "secret_scanning", "vulnerability_scan", "waf_bypass",
                    "vigolium_discovery", "vigolium_analysis", "vigolium_scan", "param_discovery",
                    "http_crawl_bridge", "run_acunetix"
                }],
            ]

            # Execute tiers sequentially, running tasks within each tier concurrently
            for tier_index, tier_tasks in enumerate(tiers, start=1):
                # Build futures list before the guard so vigolium appends can add work
                # even when no standard tasks exist in this tier.
                tier_futures = []
                # For Tier 6 only: vulnerability_scan (NucleiPlannerWorkflow child) is
                # separated from the concurrent gather to prevent orphaned child workflows
                # when another Tier 6 activity fails (see FIXES.md Fix 2).
                nuclei_future = None

                for t in tier_tasks:
                    if t == "http_crawl":
                        # Build the per-task context with the correct subscan_id for http_crawl.
                        # Bug fix: previously passed outer `ctx` (which lacks the http_crawl-specific
                        # subscan_id) to ParseHTTPCrawlResultsActivity, breaking per-task DB tracking.
                        _http_subscan_id = subscan_id_map.get("http_crawl") or ctx.get("subscan_id")
                        _http_ctx = {**ctx, "subscan_id": _http_subscan_id} if _http_subscan_id else ctx

                        async def _http_crawl_branch_tracked(_ctx=_http_ctx):
                            """Run http_crawl then parse results; flips task_success on parse failure."""
                            try:
                                _ctx_seeded = await workflow.execute_activity(
                                    "SeedEndpointsForCrawlActivity",
                                    _ctx,
                                    start_to_close_timeout=timedelta(minutes=5),
                                    heartbeat_timeout=timedelta(minutes=5),
                                    retry_policy=_RETRY_INTERNAL,
                                    task_queue="python-orchestrator-queue"
                                )
                                await run_and_track_task("http_crawl", _ctx_seeded)
                                await workflow.execute_activity(
                                    "ParseHTTPCrawlResultsActivity",
                                    _ctx_seeded,
                                    start_to_close_timeout=timedelta(minutes=5),
                                    heartbeat_timeout=timedelta(minutes=5),
                                    retry_policy=_RETRY_INTERNAL,
                                    task_queue="python-orchestrator-queue"
                                )
                            except Exception:
                                # Ensure parse failure is reflected in task_success so
                                # FinalizeSubScanActivity correctly marks http_crawl as FAILED.
                                task_success["http_crawl"] = False
                                raise

                        tier_futures.append(_http_crawl_branch_tracked())
                    elif tier_index == 6 and t == "vulnerability_scan":
                        # Run nuclei sequentially (not in gather) so that if another
                        # Tier 6 activity fails, the child workflow is never orphaned.
                        nuclei_future = run_and_track_task(t)
                    else:
                        tier_futures.append(run_and_track_task(t))

                if not tier_futures and nuclei_future is None:
                    continue

                workflow.logger.info(
                    f"[SubScanWorkflow] Executing Tier {tier_index} tasks: {tier_tasks}"
                )

                # Nuclei runs first (sequential) so that if the concurrent gather below
                # raises, the child workflow has already completed cleanly — never orphaned.
                if nuclei_future is not None:
                    await nuclei_future

                if tier_futures:
                    await asyncio.gather(*tier_futures)

                # Execute matching Parse verification activity if any tasks in this tier ran.
                # Tier indices align with the tiers list above:
                #   1=Discovery, 2=HTTP/Port, 3=URL, 4=Fuzz, 5=Analysis, 6=Assessment, 7=Fallback
                if tier_index == 1:
                    await workflow.execute_activity(
                        "ParseDiscoveryResultsActivity",
                        ctx,
                        start_to_close_timeout=timedelta(minutes=5),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_INTERNAL,
                        task_queue="python-orchestrator-queue"
                    )
                    await self._check_paused()
                    await _dispatch_tier_plugins(
                        ctx, "tier_1",
                        str(ctx.get('subscan_id') or ctx.get('scan_history_id', 'scan')),
                    )
                    await self._check_paused()
                elif tier_index == 2:
                    await self._check_paused()
                    # Post-Tier-2 plugin dispatch
                    await _dispatch_tier_plugins(
                        ctx, "tier_2",
                        str(ctx.get('subscan_id') or ctx.get('scan_history_id', 'scan')),
                    )
                    await self._check_paused()
                elif tier_index == 3:
                    await self._check_paused()
                    await _dispatch_tier_plugins(
                        ctx, "tier_3",
                        str(ctx.get('subscan_id') or ctx.get('scan_history_id', 'scan')),
                    )
                    await self._check_paused()
                elif tier_index == 4:
                    # ParseFuzzResultsActivity after dir_file_fuzz completes.
                    # ParseEnumerationResultsActivity is run unconditionally AFTER the tier loop
                    # (mirrors MasterScanWorkflow behaviour — always consolidates endpoint count).
                    await workflow.execute_activity(
                        "ParseFuzzResultsActivity",
                        ctx,
                        start_to_close_timeout=timedelta(minutes=5),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_INTERNAL,
                        task_queue="python-orchestrator-queue"
                    )
                    await self._check_paused()
                    await _dispatch_tier_plugins(
                        ctx, "tier_4",
                        str(ctx.get('subscan_id') or ctx.get('scan_history_id', 'scan')),
                    )
                    await self._check_paused()
                elif tier_index == 5:
                    await workflow.execute_activity(
                        "ParseAnalysisResultsActivity",
                        ctx,
                        start_to_close_timeout=timedelta(minutes=5),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_INTERNAL,
                        task_queue="python-orchestrator-queue"
                    )
                    await self._check_paused()
                    await _dispatch_tier_plugins(
                        ctx, "tier_5",
                        str(ctx.get('subscan_id') or ctx.get('scan_history_id', 'scan')),
                    )
                    await self._check_paused()
                elif tier_index == 6:
                    await workflow.execute_activity(
                        "ParseAssessmentResultsActivity",
                        ctx,
                        start_to_close_timeout=timedelta(minutes=5),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_INTERNAL,
                        task_queue="python-orchestrator-queue"
                    )
                    await self._check_paused()
                    await _dispatch_tier_plugins(
                        ctx, "tier_6",
                        str(ctx.get('subscan_id') or ctx.get('scan_history_id', 'scan')),
                    )

            # Unconditional endpoint count consolidation after all enumeration tiers complete.
            # Bug fix: previously this only ran when dir_file_fuzz was selected (inside Tier 4
            # block), skipping it entirely for subscans without fuzzing. Mirrors MasterScanWorkflow
            # which always calls ParseEnumerationResultsActivity after Tiers 2-4.
            await workflow.execute_activity(
                "ParseEnumerationResultsActivity",
                ctx,
                start_to_close_timeout=timedelta(minutes=5),
                heartbeat_timeout=timedelta(minutes=5),
                retry_policy=_RETRY_INTERNAL,
                task_queue="python-orchestrator-queue"
            )

            success = True
        except asyncio.CancelledError:
            workflow.logger.info("SubScanWorkflow was cancelled. Skipping post-scan tasks.")
            is_cancelled = True
            raise
        except Exception as e:
            workflow.logger.error(f"SubScanWorkflow failed during execution: {e}")
            success = False
            raise

        finally:
            if not is_cancelled:
                # TIER 7: Post-processing & Intelligence.
                # Bug fix: previously ran even when success=False, producing incorrect risk scores
                # and APME attack paths built on incomplete/partial scan data. Now guarded by
                # `success` so post-processing only runs when the full pipeline completed cleanly.
                if success:
                    try:
                        # 1. Run vulnerability correlation/scoring if vulnerability_scan was selected.
                        if "vulnerability_scan" in tasks:
                            await workflow.execute_activity(
                                "CorrelateVulnerabilitiesActivity",
                                ctx,
                                start_to_close_timeout=timedelta(minutes=30),
                                heartbeat_timeout=timedelta(minutes=5),
                                retry_policy=_RETRY_INTERNAL,
                                task_queue="python-orchestrator-queue",
                            )
                            await workflow.execute_activity(
                                "CorrelateExposuresActivity",
                                ctx,
                                start_to_close_timeout=timedelta(minutes=30),
                                heartbeat_timeout=timedelta(minutes=5),
                                retry_policy=_RETRY_INTERNAL,
                                task_queue="python-orchestrator-queue"
                            )
                            await workflow.execute_activity(
                                "CalculateRiskScoresActivity",
                                ctx,
                                start_to_close_timeout=timedelta(minutes=15),
                                heartbeat_timeout=timedelta(minutes=5),
                                retry_policy=_RETRY_INTERNAL,
                                task_queue="python-orchestrator-queue",
                            )
                            await workflow.execute_activity(
                                "GenerateImpactAssessmentActivity",
                                ctx,
                                start_to_close_timeout=timedelta(minutes=30),
                                heartbeat_timeout=timedelta(minutes=5),
                                retry_policy=_RETRY_LLM,
                                task_queue="python-orchestrator-queue"
                            )

                        # 2. Run graph sync and APME if any graph-modifying tasks were selected.
                        graph_modifying_tasks = {
                            "subdomain_discovery", "amass_intel_discovery", "firewall_vpn_scan",
                            "osint", "spiderfoot_scan", "baddns", "http_crawl", "port_scan",
                            "fetch_url", "dir_file_fuzz", "web_api_discovery", "vulnerability_scan"
                        }
                        if any(t in graph_modifying_tasks for t in tasks):
                            await workflow.execute_activity(
                                "SyncGraphActivity",
                                ctx,
                                start_to_close_timeout=timedelta(minutes=30),
                                heartbeat_timeout=timedelta(minutes=5),
                                retry_policy=_RETRY_NETWORK_SCAN,
                                task_queue="python-orchestrator-queue",
                            )
                            await workflow.execute_activity(
                                "RunGenericTaskActivity",
                                args=[ctx, "run_apme", "Attack Path Modeling Engine", {"scan_history_id": ctx.get("scan_history_id")}],
                                start_to_close_timeout=timedelta(minutes=30),
                                heartbeat_timeout=timedelta(minutes=5),
                                retry_policy=_RETRY_INTERNAL,
                                task_queue="python-orchestrator-queue",
                            )
                        await _dispatch_tier_plugins(
                            ctx, "tier_7",
                            str(ctx.get('subscan_id') or ctx.get('scan_history_id', 'scan')),
                        )
                    except asyncio.CancelledError:
                        raise
                    except Exception as post_e:
                        workflow.logger.error(f"SubScanWorkflow post-scan tasks failed: {post_e}")

                # 3. Always finalize all subscan records, regardless of success/failure.
                # This ensures the UI reflects the correct terminal state even when tasks fail.
                if subscans_info:
                    for item in subscans_info:
                        t = item['type']
                        sid = item['id']
                        task_ok = task_success.get(t, False)
                        await workflow.execute_activity(
                            "FinalizeSubScanActivity",
                            args=[ctx, task_ok, sid],
                            start_to_close_timeout=timedelta(seconds=60),
                            heartbeat_timeout=timedelta(minutes=5),
                            task_queue="python-orchestrator-queue"
                        )
                else:
                    # Fallback for single legacy subscan (no subscans_info mapping).
                    await workflow.execute_activity(
                        "FinalizeSubScanActivity",
                        args=[ctx, success],
                        start_to_close_timeout=timedelta(seconds=60),
                        heartbeat_timeout=timedelta(minutes=5),
                        task_queue="python-orchestrator-queue"
                    )

        return {"status": "SUCCESS"}


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
        workflow.logger.info(f"[StressTestWorkflow] Starting for scan_id={scan_id}")

        # Step 1 — Resolve endpoints, create DB record, publish 'running' to telemetry
        ctx = await workflow.execute_activity(
            "InitStressTestActivity",
            ctx,
            start_to_close_timeout=timedelta(minutes=2),
            heartbeat_timeout=timedelta(minutes=5),
            task_queue="python-orchestrator-queue",
        )

        endpoints: List[str] = ctx.get("resolved_endpoints", [])
        tools: List[str] = ctx.get("stress_config", {}).get("uses_tools", ["k6"])

        if not endpoints:
            workflow.logger.warning(
                f"[StressTestWorkflow] No endpoints resolved for scan_id={scan_id}. "
                "Finalising immediately."
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
                        f"[StressTestWorkflow] Kill signal — aborting before "
                        f"tool={tool} endpoint={endpoint_url}"
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
                        workflow.logger.info(f"[StressTestWorkflow] Kill signal received. Cancelling activity.")
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
                        f"[StressTestWorkflow] tool={tool} endpoint={endpoint_url} "
                        f"failed: {exc}"
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
            task_queue="python-orchestrator-queue",
        )

        status = "ABORTED" if self._kill_requested else "SUCCESS"
        workflow.logger.info(
            f"[StressTestWorkflow] Complete — scan_id={scan_id} status={status}"
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


@workflow.defn(name="MonitoringWorkflow")
class MonitoringWorkflow:
    """Periodic workflow launched by a Temporal Schedule for domain monitoring.

    Runs RunMonitoringCheckActivity for a single domain on the configured
    frequency (hourly/daily/weekly/monthly). The schedule is created/deleted
    by manage_monitoring_task() in targetApp/views.py.
    """

    @workflow.run
    async def run(self, domain_id: int) -> None:
        await workflow.execute_activity(
            "RunMonitoringCheckActivity",
            args=[domain_id],
            start_to_close_timeout=timedelta(hours=6),
            heartbeat_timeout=timedelta(minutes=5),
            # Don't retry — if a monitoring check fails, wait for next scheduled run
            retry_policy=RetryPolicy(maximum_attempts=1),
            task_queue="python-orchestrator-queue",
        )


@workflow.defn(name="ScheduledScanWorkflow")
class ScheduledScanWorkflow:
    """Durable workflow launched by a Temporal Schedule for periodic/clocked scans.

    Step 1: SetupScheduledScanActivity creates ScanHistory + initial subdomain/endpoint
            and returns a complete workflow ctx.
    Step 2: MasterScanWorkflow runs the full scan pipeline as a child workflow.
    """

    @workflow.run
    async def run(self, params: dict) -> dict:
        ctx = await workflow.execute_activity(
            "SetupScheduledScanActivity",
            args=[params],
            start_to_close_timeout=timedelta(minutes=10),
            heartbeat_timeout=timedelta(minutes=5),
            retry_policy=RetryPolicy(maximum_attempts=3),
            task_queue="python-orchestrator-queue",
        )
        scan_id = ctx.get("scan_history_id", "unknown")
        result = await workflow.execute_child_workflow(
            "MasterScanWorkflow",
            args=[ctx],
            id=f"scheduled-master-{scan_id}",
            task_queue="python-orchestrator-queue",
            execution_timeout=timedelta(days=30),
        )
        return result


@workflow.defn(name="StartupSyncWorkflow")
class StartupSyncWorkflow:
    """One-shot workflow that runs a single named startup sync task as an activity.

    Launched by a one-shot Temporal Schedule created on each orchestrator startup.
    The schedule fires once (limited_actions=1) then exhausts itself.
    """

    @workflow.run
    async def run(self, task_name: str) -> None:
        if task_name == "sync_all_scans_to_graph":
            start_to_close_timeout = timedelta(hours=3)
            heartbeat_timeout = timedelta(minutes=2)
        elif task_name == "sync_cve_data":
            start_to_close_timeout = timedelta(hours=2)
            heartbeat_timeout = timedelta(minutes=5)
        else:
            start_to_close_timeout = timedelta(minutes=30)
            heartbeat_timeout = timedelta(minutes=5)

        await workflow.execute_activity(
            "RunStartupSyncActivity",
            args=[task_name],
            start_to_close_timeout=start_to_close_timeout,
            heartbeat_timeout=heartbeat_timeout,
            retry_policy=RetryPolicy(maximum_attempts=3),
            task_queue="python-orchestrator-queue",
        )


@workflow.defn(name="GoExecutorTaskWorkflow")
class GoExecutorTaskWorkflow:
    """Temporal workflow that routes heavy task command executions to the Go worker queue.
    
    This workflow acts as a gateway to run security tools on the dedicated 
    temporal-go-executor container where dependencies and environment setups are optimized.
    """

    @workflow.run
    async def run(self, input_data: dict) -> dict:
        """Run the remote subprocess activity on the go-executor-queue.

        Args:
            input_data (dict): Dictionary containing command details:
                - command (list): The command split into parts (binary + arguments)
                - scan_id (int): Associated Scan History ID
                - command_id (int): Database record Command ID to log stdout/stderr to
                
        Returns:
            dict: The output result of the subprocess execution, including stdout, stderr,
                  and exit code.
        """
        # Execute the activity on the dedicated go-executor-queue task queue
        return await workflow.execute_activity(
            "RunToolSubprocessActivity",
            input_data,
            start_to_close_timeout=timedelta(hours=2),
            heartbeat_timeout=timedelta(minutes=5),
            task_queue="go-executor-queue"
        )


@workflow.defn(name="ApmeTaskWorkflow")
class ApmeTaskWorkflow:
    """Workflow to execute LLM Attack Path modeling on scan findings."""

    @workflow.run
    async def run(self, scan_history_id: int, job_id: str = None) -> dict:
        return await workflow.execute_activity(
            "RunLlmApmeActivity",
            args=[scan_history_id, job_id],
            start_to_close_timeout=timedelta(hours=1),
            heartbeat_timeout=timedelta(minutes=5),
            retry_policy=_RETRY_LLM,
            task_queue="python-orchestrator-queue",
        )


@workflow.defn(name="IdentityEnrichmentWorkflow")
class IdentityEnrichmentWorkflow:
    """Workflow to run identity (names and emails) enrichment OSINT tools."""

    @workflow.run
    async def run(self, identity: str, identity_type: str, scan_history_id: int, ctx: dict = None) -> str:
        return await workflow.execute_activity(
            "EnrichIdentitiesActivity",
            args=[identity, identity_type, scan_history_id, ctx or {}],
            start_to_close_timeout=timedelta(hours=2),
            heartbeat_timeout=timedelta(minutes=5),
            retry_policy=_RETRY_INTERNAL,
            task_queue="python-orchestrator-queue",
        )


@workflow.defn(name="GeoLocalizeWorkflow")
class GeoLocalizeWorkflow:
    """Workflow to run geolocation lookup for discovered IP addresses."""

    @workflow.run
    async def run(self, host: str, ip_id: int, scan_id: int = None, activity_id: int = None) -> None:
        await workflow.execute_activity(
            "GeoLocalizeActivity",
            args=[host, ip_id, scan_id, activity_id],
            start_to_close_timeout=timedelta(minutes=5),
            heartbeat_timeout=timedelta(minutes=5),
            retry_policy=_RETRY_INTERNAL,
            task_queue="python-orchestrator-queue",
        )


@workflow.defn(name="HackerOneImportWorkflow")
class HackerOneImportWorkflow:
    """Workflow to import program scopes from HackerOne."""

    @workflow.run
    async def run(self, handles: list, project_slug: str, is_sync: bool = False) -> None:
        await workflow.execute_activity(
            "ImportHackerOneProgramsActivity",
            args=[handles, project_slug, is_sync],
            start_to_close_timeout=timedelta(hours=4),
            heartbeat_timeout=timedelta(minutes=5),
            retry_policy=_RETRY_INTERNAL,
            task_queue="python-orchestrator-queue",
        )


@workflow.defn(name="HackerOneSyncBookmarkedWorkflow")
class HackerOneSyncBookmarkedWorkflow:
    """Workflow to sync bookmarked programs from HackerOne."""

    @workflow.run
    async def run(self, project_slug: str) -> None:
        await workflow.execute_activity(
            "SyncBookmarkedProgramsActivity",
            args=[project_slug],
            start_to_close_timeout=timedelta(hours=4),
            heartbeat_timeout=timedelta(minutes=5),
            retry_policy=_RETRY_INTERNAL,
            task_queue="python-orchestrator-queue",
        )


@workflow.defn(name="ProxyFetchWorkflow")
class ProxyFetchWorkflow:
    """Workflow to fetch and validate proxy lists."""

    @workflow.run
    async def run(self, limit: int, job_id: str) -> None:
        await workflow.execute_activity(
            "FetchProxiesActivity",
            args=[limit, job_id],
            start_to_close_timeout=timedelta(hours=1),
            heartbeat_timeout=timedelta(minutes=5),
            retry_policy=_RETRY_NETWORK_SCAN,
            task_queue="python-orchestrator-queue",
        )


# ---------------------------------------------------------------------------
# Phase 2 — rengine-ng standalone workflow helpers + 13 new workflows
# ---------------------------------------------------------------------------

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


@workflow.defn(name="UserHuntWorkflow")
class UserHuntWorkflow:
    """Standalone user/email OSINT workflow.

    Runs maigret for username targets and h8mail for email targets.
    Triggered directly from the API for email or username input.
    rengine-ng equivalent: user_hunt workflow.
    """

    @workflow.run
    async def run(self, ctx: dict) -> bool:
        target_type = ctx.get('target_type', 'username')

        if target_type == 'email':
            await workflow.execute_activity(
                "RunGenericTaskActivity",
                {**ctx, 'task_name': 'h8mail'},
                start_to_close_timeout=timedelta(minutes=30),
                retry_policy=_RETRY_NETWORK_SCAN,
                task_queue="python-orchestrator-queue",
            )
        else:
            await workflow.execute_activity(
                "RunGenericTaskActivity",
                {**ctx, 'task_name': 'maigret'},
                start_to_close_timeout=timedelta(minutes=30),
                retry_policy=_RETRY_NETWORK_SCAN,
                task_queue="python-orchestrator-queue",
            )
        return True


@workflow.defn(name="URLBypassWorkflow")
class URLBypassWorkflow:
    """Attempt 4xx URL bypass on a list of URLs using bup.

    rengine-ng equivalent: url_bypass workflow.
    """

    @workflow.run
    async def run(self, ctx: dict) -> bool:
        await workflow.execute_activity(
            "RunBUPActivity",
            ctx,
            start_to_close_timeout=timedelta(minutes=30),
            retry_policy=_RETRY_NETWORK_SCAN,
            task_queue="python-orchestrator-queue",
        )
        return True


@workflow.defn(name="WordPressWorkflow")
class WordPressWorkflow:
    """Standalone WordPress security assessment.

    Runs HTTP probe, wpscan, wpprobe, and nuclei (wordpress tag).
    rengine-ng equivalent: wordpress workflow.
    """

    @workflow.run
    async def run(self, ctx: dict) -> bool:
        await workflow.execute_activity(
            "RunHTTPCrawlActivity",
            ctx,
            start_to_close_timeout=timedelta(minutes=15),
            retry_policy=_RETRY_NETWORK_SCAN,
            task_queue="python-orchestrator-queue",
        )

        await asyncio.gather(
            workflow.execute_activity(
                "RunWpscanActivity",
                ctx,
                start_to_close_timeout=timedelta(hours=1),
                retry_policy=_RETRY_LONG_SCAN,
                task_queue="python-orchestrator-queue",
            ),
            workflow.execute_activity(
                "RunWPProbeActivity",
                ctx,
                start_to_close_timeout=timedelta(minutes=30),
                retry_policy=_RETRY_NETWORK_SCAN,
                task_queue="python-orchestrator-queue",
            ),
            workflow.execute_activity(
                "RunNucleiActivity",
                {**ctx, 'tags_override': ['wordpress'], 'severity': 'critical,high,medium,low'},
                start_to_close_timeout=timedelta(hours=2),
                retry_policy=_RETRY_LONG_SCAN,
                task_queue="python-orchestrator-queue",
            ),
        )

        await workflow.execute_activity(
            "RunWPTaintScanActivity", 
            ctx, 
            start_to_close_timeout=timedelta(hours=2), 
            heartbeat_timeout=timedelta(minutes=5),
            task_queue="python-orchestrator-queue"
        )

        return True


@workflow.defn(name="HostReconWorkflow")
class HostReconWorkflow:
    """Standalone host/IP reconnaissance workflow.

    Port scan (naabu + nmap) → SSH audit → HTTP probe → optional nuclei.
    Fans out search_vulns per discovered service.
    rengine-ng equivalent: host_recon workflow.
    """

    @workflow.run
    async def run(self, ctx: dict) -> bool:
        yaml_config = ctx.get('yaml_configuration') or {}
        host_config = yaml_config.get('host_recon', {})
        run_nuclei = host_config.get('run_nuclei', False)

        await workflow.execute_activity(
            "RunPortScanActivity",
            {**ctx, 'port_scan_tool': 'naabu'},
            start_to_close_timeout=timedelta(minutes=30),
            retry_policy=_RETRY_NETWORK_SCAN,
            task_queue="python-orchestrator-queue",
        )

        await workflow.execute_activity(
            "RunPortScanActivity",
            {**ctx, 'port_scan_tool': 'nmap', 'version_detection': True},
            start_to_close_timeout=timedelta(minutes=30),
            retry_policy=_RETRY_NETWORK_SCAN,
            task_queue="python-orchestrator-queue",
        )

        # Fan out per-service CVE + exploit lookups
        services = await workflow.execute_activity(
            "GetDiscoveredServicesActivity",
            ctx,
            start_to_close_timeout=timedelta(minutes=5),
            retry_policy=_RETRY_INTERNAL,
            task_queue="python-orchestrator-queue",
        )
        await _fan_out_search_vulns(ctx, services or [])

        await asyncio.gather(
            workflow.execute_activity(
                "RunHTTPCrawlActivity",
                ctx,
                start_to_close_timeout=timedelta(minutes=15),
                retry_policy=_RETRY_NETWORK_SCAN,
                task_queue="python-orchestrator-queue",
            ),
            workflow.execute_activity(
                "RunSSHAuditActivity",
                {**ctx, 'port': 22},
                start_to_close_timeout=timedelta(minutes=10),
                retry_policy=_RETRY_NETWORK_SCAN,
                task_queue="python-orchestrator-queue",
            ),
        )

        # Enrich discovered IPs with ASN data (uses DB-backed IPs, not hostname string)
        host_ips = await workflow.execute_activity(
            "GetDiscoveredIPsActivity",
            ctx,
            start_to_close_timeout=timedelta(minutes=2),
            retry_policy=_RETRY_INTERNAL,
            task_queue="python-orchestrator-queue",
        )
        if host_ips:
            await workflow.execute_activity(
                "RunGetASNActivity",
                {**ctx, 'ips': host_ips},
                start_to_close_timeout=timedelta(minutes=5),
                retry_policy=_RETRY_NETWORK_SCAN,
                task_queue="python-orchestrator-queue",
            )

        if run_nuclei:
            await workflow.execute_activity(
                "RunNucleiActivity",
                {**ctx, 'tags_override': ['network', 'ssl'], 'severity': 'critical,high,medium'},
                start_to_close_timeout=timedelta(hours=2),
                retry_policy=_RETRY_LONG_SCAN,
                task_queue="python-orchestrator-queue",
            )
        return True


@workflow.defn(name="CIDRReconWorkflow")
class CIDRReconWorkflow:
    """Network CIDR reconnaissance workflow.

    Discovers alive hosts (ARP or ICMP), expands CIDR, port scans, HTTP probes.
    rengine-ng equivalent: cidr_recon workflow.
    """

    @workflow.run
    async def run(self, ctx: dict) -> bool:
        cidr = ctx.get('cidr', '')
        yaml_config = ctx.get('yaml_configuration') or {}
        cidr_config = yaml_config.get('cidr_recon', {})
        use_arp = cidr_config.get('use_arp', False)

        # Auto-detect CIDR from local network interfaces when no target is given
        if not cidr:
            detected = await workflow.execute_activity(
                "RunNetDetectActivity",
                ctx,
                start_to_close_timeout=timedelta(minutes=2),
                retry_policy=_RETRY_INTERNAL,
                task_queue="python-orchestrator-queue",
            )
            detected = [c for c in (detected or []) if c]
            if not detected:
                return True
            cidr = detected[0]
            ctx = {**ctx, 'cidr': cidr}

        if use_arp:
            await workflow.execute_activity(
                "RunARPScanActivity",
                {**ctx, 'cidr': cidr},
                start_to_close_timeout=timedelta(minutes=15),
                retry_policy=_RETRY_NETWORK_SCAN,
                task_queue="python-orchestrator-queue",
            )
        else:
            await workflow.execute_activity(
                "RunMapCIDRActivity",
                {**ctx, 'cidr': cidr},
                start_to_close_timeout=timedelta(minutes=5),
                retry_policy=_RETRY_INTERNAL,
                task_queue="python-orchestrator-queue",
            )
            await workflow.execute_activity(
                "RunFPingActivity",
                {**ctx, 'cidr': cidr},
                start_to_close_timeout=timedelta(minutes=15),
                retry_policy=_RETRY_NETWORK_SCAN,
                task_queue="python-orchestrator-queue",
            )

        await workflow.execute_activity(
            "RunPortScanActivity",
            {**ctx, 'port_scan_tool': 'nmap', 'version_detection': True},
            start_to_close_timeout=timedelta(hours=1),
            retry_policy=_RETRY_LONG_SCAN,
            task_queue="python-orchestrator-queue",
        )

        await workflow.execute_activity(
            "RunHTTPCrawlActivity",
            ctx,
            start_to_close_timeout=timedelta(minutes=30),
            retry_policy=_RETRY_NETWORK_SCAN,
            task_queue="python-orchestrator-queue",
        )
        return True


@workflow.defn(name="CodeScanWorkflow")
class CodeScanWorkflow:
    """Source code vulnerability and secrets scanning.

    Runs gitleaks, trufflehog (via secret_scanning), and semgrep in parallel.
    rengine-ng equivalent: code_scan workflow.
    """

    @workflow.run
    async def run(self, ctx: dict) -> bool:
        yaml_config = ctx.get('yaml_configuration') or {}
        audit_config = yaml_config.get('vigolium_audit', {})

        activities = [
            workflow.execute_activity(
                "RunGenericTaskActivity",
                {**ctx, 'task_name': 'gitleaks_scan'},
                start_to_close_timeout=timedelta(hours=1),
                retry_policy=_RETRY_LONG_SCAN,
                task_queue="python-orchestrator-queue",
            ),
            workflow.execute_activity(
                "RunSecretScanningActivity",
                ctx,
                start_to_close_timeout=timedelta(hours=1),
                retry_policy=_RETRY_LONG_SCAN,
                task_queue="python-orchestrator-queue",
            ),
            workflow.execute_activity(
                "RunSemgrepActivity",
                {**ctx, 'mode': 'vulnerability'},
                start_to_close_timeout=timedelta(hours=1),
                retry_policy=_RETRY_LONG_SCAN,
                task_queue="python-orchestrator-queue",
            ),
            workflow.execute_activity(
                "RunGrypeScanActivity",
                ctx,
                start_to_close_timeout=timedelta(hours=2),
                retry_policy=_RETRY_LONG_SCAN,
                task_queue="python-orchestrator-queue",
            ),
            workflow.execute_activity(
                "RunTrivySecretScanActivity",
                ctx,
                start_to_close_timeout=timedelta(hours=2),
                retry_policy=_RETRY_LONG_SCAN,
                task_queue="python-orchestrator-queue",
            ),
        ]

        if audit_config.get('run_vigolium_audit', True):
            # Timeout from config (seconds), default 1 hour; cap at 4 hours.
            try:
                audit_timeout_s = min(int(audit_config.get('timeout', 3600)), 14400)
            except (ValueError, TypeError):
                audit_timeout_s = 3600
            activities.append(
                workflow.execute_activity(
                    "RunVigoliumAuditActivity",
                    ctx,
                    start_to_close_timeout=timedelta(seconds=audit_timeout_s + 300),
                    retry_policy=_RETRY_LONG_SCAN,
                    task_queue="python-orchestrator-queue",
                )
            )

        await asyncio.gather(*activities)
        return True


@workflow.defn(name="DomainReconWorkflow")
class DomainReconWorkflow:
    """Lightweight standalone domain intelligence workflow.

    WHOIS + DNS resolution + passive URL collection (parallel), then
    HTTP probe + WAF detection + testssl (parallel if not passive).
    rengine-ng equivalent: domain_recon workflow.
    """

    @workflow.run
    async def run(self, ctx: dict) -> bool:
        yaml_config = ctx.get('yaml_configuration') or {}
        passive_only = yaml_config.get('domain_recon', {}).get('passive', False)

        await asyncio.gather(
            workflow.execute_activity(
                "RunGenericTaskActivity",
                {**ctx, 'task_name': 'whois'},
                start_to_close_timeout=timedelta(minutes=5),
                retry_policy=_RETRY_INTERNAL,
                task_queue="python-orchestrator-queue",
            ),
            workflow.execute_activity(
                "RunJsWhoisActivity",
                {**ctx, 'domain': ctx.get('domain')},
                start_to_close_timeout=timedelta(minutes=5),
                retry_policy=_RETRY_INTERNAL,
                task_queue="python-orchestrator-queue",
            ),
            workflow.execute_activity(
                "RunWhoisDomainActivity",
                {**ctx, 'domain': ctx.get('domain')},
                start_to_close_timeout=timedelta(minutes=5),
                retry_policy=_RETRY_INTERNAL,
                task_queue="python-orchestrator-queue",
            ),
            workflow.execute_activity(
                "RunDNSXActivity",
                {**ctx, 'subdomain': ctx.get('domain')},
                start_to_close_timeout=timedelta(minutes=10),
                retry_policy=_RETRY_NETWORK_SCAN,
                task_queue="python-orchestrator-queue",
            ),
            workflow.execute_activity(
                "RunXURLFind3rActivity",
                {**ctx, 'domain': ctx.get('domain')},
                start_to_close_timeout=timedelta(minutes=15),
                retry_policy=_RETRY_NETWORK_SCAN,
                task_queue="python-orchestrator-queue",
            ),
        )

        if not passive_only:
            await asyncio.gather(
                workflow.execute_activity(
                    "RunHTTPCrawlActivity",
                    ctx,
                    start_to_close_timeout=timedelta(minutes=15),
                    retry_policy=_RETRY_NETWORK_SCAN,
                    task_queue="python-orchestrator-queue",
                ),
                workflow.execute_activity(
                    "RunWAFDetectionActivity",
                    ctx,
                    start_to_close_timeout=timedelta(minutes=10),
                    retry_policy=_RETRY_NETWORK_SCAN,
                    task_queue="python-orchestrator-queue",
                ),
                workflow.execute_activity(
                    "RunWAFW00FActivity",
                    {**ctx, 'url': 'https://' + (ctx.get('domain') or '')},
                    start_to_close_timeout=timedelta(minutes=10),
                    retry_policy=_RETRY_NETWORK_SCAN,
                    task_queue="python-orchestrator-queue",
                ),
            )

        # Enrich discovered IPs with ASN data after initial discovery
        discovered_ips = await workflow.execute_activity(
            "GetDiscoveredIPsActivity",
            ctx,
            start_to_close_timeout=timedelta(minutes=2),
            retry_policy=_RETRY_INTERNAL,
            task_queue="python-orchestrator-queue",
        )
        if discovered_ips:
            await workflow.execute_activity(
                "RunGetASNActivity",
                {**ctx, 'ips': discovered_ips},
                start_to_close_timeout=timedelta(minutes=10),
                retry_policy=_RETRY_NETWORK_SCAN,
                task_queue="python-orchestrator-queue",
            )
        return True


@workflow.defn(name="SubdomainReconWorkflow")
class SubdomainReconWorkflow:
    """Standalone subdomain discovery and verification workflow.

    Passive (subfinder, gau) + optional brute (dnsx) + HTTP probe + takeover check.
    rengine-ng equivalent: subdomain_recon workflow.
    """

    @workflow.run
    async def run(self, ctx: dict) -> bool:
        yaml_config = ctx.get('yaml_configuration') or {}
        subdomain_config = yaml_config.get('subdomain_recon', {})
        passive_only = subdomain_config.get('passive', False)
        brute_dns = subdomain_config.get('brute_dns', False)
        run_bbot = subdomain_config.get('bbot', False)

        discovery_tasks = [
            workflow.execute_activity(
                "RunSubdomainDiscoveryActivity",
                ctx,
                start_to_close_timeout=timedelta(hours=1),
                retry_policy=_RETRY_LONG_SCAN,
                task_queue="python-orchestrator-queue",
            ),
            workflow.execute_activity(
                "RunFetchURLActivity",
                ctx,
                start_to_close_timeout=timedelta(minutes=30),
                retry_policy=_RETRY_NETWORK_SCAN,
                task_queue="python-orchestrator-queue",
            ),
        ]
        if brute_dns and not passive_only:
            discovery_tasks.append(
                workflow.execute_activity(
                    "RunDNSXActivity",
                    {**ctx, 'wordlist': 'combined_subdomains'},
                    start_to_close_timeout=timedelta(hours=2),
                    retry_policy=_RETRY_LONG_SCAN,
                    task_queue="python-orchestrator-queue",
                )
            )
        if run_bbot:
            discovery_tasks.append(
                workflow.execute_activity(
                    "RunBBotActivity",
                    {**ctx, 'domain': ctx.get('domain')},
                    start_to_close_timeout=timedelta(hours=2),
                    retry_policy=_RETRY_LONG_SCAN,
                    task_queue="python-orchestrator-queue",
                )
            )
        await asyncio.gather(*discovery_tasks)

        if not passive_only:
            await asyncio.gather(
                workflow.execute_activity(
                    "RunHTTPCrawlActivity",
                    ctx,
                    start_to_close_timeout=timedelta(minutes=30),
                    retry_policy=_RETRY_NETWORK_SCAN,
                    task_queue="python-orchestrator-queue",
                ),
                workflow.execute_activity(
                    "RunNucleiActivity",
                    {**ctx, 'tags_override': ['takeover'], 'severity': 'critical,high,medium'},
                    start_to_close_timeout=timedelta(hours=1),
                    retry_policy=_RETRY_LONG_SCAN,
                    task_queue="python-orchestrator-queue",
                ),
            )
        return True


@workflow.defn(name="URLCrawlWorkflow")
class URLCrawlWorkflow:
    """Standalone URL crawl and passive discovery workflow.

    Passive (xurlfind3r, urlfinder, gau) + active (katana, cariddi).
    Optional secret hunt (trufflehog) and OSINT on found emails (maigret).
    rengine-ng equivalent: url_crawl workflow.
    """

    @workflow.run
    async def run(self, ctx: dict) -> bool:
        yaml_config = ctx.get('yaml_configuration') or {}
        crawl_config = yaml_config.get('url_crawl', {})
        passive_only = crawl_config.get('passive', False)
        active_only = crawl_config.get('active', False)
        hunt_secrets = crawl_config.get('hunt_secrets', False)

        if not active_only:
            await asyncio.gather(
                workflow.execute_activity(
                    "RunXURLFind3rActivity",
                    ctx,
                    start_to_close_timeout=timedelta(minutes=30),
                    retry_policy=_RETRY_NETWORK_SCAN,
                    task_queue="python-orchestrator-queue",
                ),
                workflow.execute_activity(
                    "RunURLFinderActivity",
                    ctx,
                    start_to_close_timeout=timedelta(minutes=30),
                    retry_policy=_RETRY_NETWORK_SCAN,
                    task_queue="python-orchestrator-queue",
                ),
                workflow.execute_activity(
                    "RunFetchURLActivity",
                    ctx,
                    start_to_close_timeout=timedelta(minutes=30),
                    retry_policy=_RETRY_NETWORK_SCAN,
                    task_queue="python-orchestrator-queue",
                ),
            )

        if not passive_only:
            await asyncio.gather(
                workflow.execute_activity(
                    "RunDirFileFuzzActivity",
                    {**ctx, 'tool': 'katana'},
                    start_to_close_timeout=timedelta(hours=1),
                    retry_policy=_RETRY_LONG_SCAN,
                    task_queue="python-orchestrator-queue",
                ),
                workflow.execute_activity(
                    "RunCariddiActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=1),
                    retry_policy=_RETRY_LONG_SCAN,
                    task_queue="python-orchestrator-queue",
                ),
            )

            await workflow.execute_activity(
                "RunHTTPCrawlActivity",
                ctx,
                start_to_close_timeout=timedelta(minutes=30),
                retry_policy=_RETRY_NETWORK_SCAN,
                task_queue="python-orchestrator-queue",
            )

            if hunt_secrets:
                await asyncio.gather(
                    workflow.execute_activity(
                        "RunSecretScanningActivity",
                        ctx,
                        start_to_close_timeout=timedelta(hours=1),
                        retry_policy=_RETRY_LONG_SCAN,
                        task_queue="python-orchestrator-queue",
                    ),
                    workflow.execute_activity(
                        "RunGenericTaskActivity",
                        {**ctx, 'task_name': 'maigret'},
                        start_to_close_timeout=timedelta(minutes=30),
                        retry_policy=_RETRY_NETWORK_SCAN,
                        task_queue="python-orchestrator-queue",
                    ),
                )

            # Extract URL parameters from all crawled endpoints
            await workflow.execute_activity(
                "RunURLParserActivity",
                ctx,
                start_to_close_timeout=timedelta(minutes=10),
                retry_policy=_RETRY_INTERNAL,
                task_queue="python-orchestrator-queue",
            )
        return True


@workflow.defn(name="URLDirSearchWorkflow")
class URLDirSearchWorkflow:
    """Hidden directory and file discovery on web servers.

    HTTP probe → ffuf dir mode → optional katana + secret scan.
    rengine-ng equivalent: url_dirsearch workflow.
    """

    @workflow.run
    async def run(self, ctx: dict) -> bool:
        yaml_config = ctx.get('yaml_configuration') or {}
        dirsearch_config = yaml_config.get('url_dirsearch', {})
        hunt_secrets = dirsearch_config.get('hunt_secrets', False)

        await workflow.execute_activity(
            "RunHTTPCrawlActivity",
            ctx,
            start_to_close_timeout=timedelta(minutes=15),
            retry_policy=_RETRY_NETWORK_SCAN,
            task_queue="python-orchestrator-queue",
        )

        await workflow.execute_activity(
            "RunDirFileFuzzActivity",
            {**ctx, 'mode': 'directory'},
            start_to_close_timeout=timedelta(hours=2),
            retry_policy=_RETRY_LONG_SCAN,
            task_queue="python-orchestrator-queue",
        )

        if hunt_secrets:
            await workflow.execute_activity(
                "RunSecretScanningActivity",
                ctx,
                start_to_close_timeout=timedelta(hours=1),
                retry_policy=_RETRY_LONG_SCAN,
                task_queue="python-orchestrator-queue",
            )
        return True


@workflow.defn(name="URLFuzzWorkflow")
class URLFuzzWorkflow:
    """Comprehensive URL fuzzing with feroxbuster and/or ffuf.

    rengine-ng equivalent: url_fuzz workflow.
    """

    @workflow.run
    async def run(self, ctx: dict) -> bool:
        yaml_config = ctx.get('yaml_configuration') or {}
        fuzz_config = yaml_config.get('url_fuzz', {})
        hunt_secrets = fuzz_config.get('hunt_secrets', False)
        fuzzers = fuzz_config.get('fuzzers', ['ffuf'])

        fuzz_tasks = []
        if 'feroxbuster' in fuzzers:
            fuzz_tasks.append(
                workflow.execute_activity(
                    "RunFeroxbusterActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=2),
                    retry_policy=_RETRY_LONG_SCAN,
                    task_queue="python-orchestrator-queue",
                )
            )
        if 'ffuf' in fuzzers:
            fuzz_tasks.append(
                workflow.execute_activity(
                    "RunDirFileFuzzActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=2),
                    retry_policy=_RETRY_LONG_SCAN,
                    task_queue="python-orchestrator-queue",
                )
            )
        if fuzz_tasks:
            await asyncio.gather(*fuzz_tasks)

        await workflow.execute_activity(
            "RunHTTPCrawlActivity",
            ctx,
            start_to_close_timeout=timedelta(minutes=15),
            retry_policy=_RETRY_NETWORK_SCAN,
            task_queue="python-orchestrator-queue",
        )

        if hunt_secrets:
            await workflow.execute_activity(
                "RunSecretScanningActivity",
                ctx,
                start_to_close_timeout=timedelta(hours=1),
                retry_policy=_RETRY_LONG_SCAN,
                task_queue="python-orchestrator-queue",
            )
        return True


@workflow.defn(name="URLParamsFuzzWorkflow")
class URLParamsFuzzWorkflow:
    """URL parameter discovery and fuzzing.

    HTTP probe → arjun parameter discovery → optional ffuf value fuzzing.
    rengine-ng equivalent: url_params_fuzz workflow.
    """

    @workflow.run
    async def run(self, ctx: dict) -> bool:
        yaml_config = ctx.get('yaml_configuration') or {}
        params_config = yaml_config.get('url_params_fuzz', {})
        fuzz_values = params_config.get('fuzz_values', False)
        hunt_secrets = params_config.get('hunt_secrets', False)

        await workflow.execute_activity(
            "RunHTTPCrawlActivity",
            ctx,
            start_to_close_timeout=timedelta(minutes=15),
            retry_policy=_RETRY_NETWORK_SCAN,
            task_queue="python-orchestrator-queue",
        )

        # Passive parameter harvest from already-crawled URLs
        await workflow.execute_activity(
            "RunURLParserActivity",
            ctx,
            start_to_close_timeout=timedelta(minutes=10),
            retry_policy=_RETRY_INTERNAL,
            task_queue="python-orchestrator-queue",
        )

        await workflow.execute_activity(
            "RunArjunActivity",
            ctx,
            start_to_close_timeout=timedelta(hours=1),
            retry_policy=_RETRY_LONG_SCAN,
            task_queue="python-orchestrator-queue",
        )

        if fuzz_values:
            await workflow.execute_activity(
                "RunDirFileFuzzActivity",
                {**ctx, 'mode': 'params'},
                start_to_close_timeout=timedelta(hours=2),
                retry_policy=_RETRY_LONG_SCAN,
                task_queue="python-orchestrator-queue",
            )

        if hunt_secrets:
            await workflow.execute_activity(
                "RunSecretScanningActivity",
                ctx,
                start_to_close_timeout=timedelta(hours=1),
                retry_policy=_RETRY_LONG_SCAN,
                task_queue="python-orchestrator-queue",
            )
        return True


@workflow.defn(name="URLVulnWorkflow")
class URLVulnWorkflow:
    """URL vulnerability scanning with gf pattern matching + dalfox + nuclei.

    Fans gf patterns (xss/lfi/ssrf/rce/idor/debug_logic) across provided URLs,
    attacks XSS candidates with dalfox, and optionally runs nuclei HTTP scan.
    rengine-ng equivalent: url_vuln workflow.
    """

    @workflow.run
    async def run(self, ctx: dict) -> bool:
        yaml_config = ctx.get('yaml_configuration') or {}
        vuln_config = yaml_config.get('url_vuln', {})
        run_nuclei = vuln_config.get('nuclei', False)

        urls = ctx.get('urls', [])
        if not urls:
            return True

        gf_patterns = ['xss', 'lfi', 'ssrf', 'rce', 'idor', 'debug_logic', 'interestingparams']
        gf_results = await asyncio.gather(*[
            workflow.execute_activity(
                "RunGFActivity",
                {**ctx, 'pattern': pattern, 'urls': urls},
                start_to_close_timeout=timedelta(minutes=5),
                retry_policy=_RETRY_INTERNAL,
                task_queue="python-orchestrator-queue",
            )
            for pattern in gf_patterns
        ])

        # First result is xss pattern matches
        xss_urls = gf_results[0] if gf_results and isinstance(gf_results[0], list) else []

        if xss_urls:
            await workflow.execute_activity(
                "RunDalfoxActivity",
                {**ctx, 'urls': xss_urls},
                start_to_close_timeout=timedelta(hours=1),
                retry_policy=_RETRY_LONG_SCAN,
                task_queue="python-orchestrator-queue",
            )

        if run_nuclei:
            await workflow.execute_activity(
                "RunNucleiActivity",
                {**ctx, 'exclude_tags': ['network', 'ssl', 'file', 'dns', 'osint'],
                 'severity': 'critical,high,medium'},
                start_to_close_timeout=timedelta(hours=2),
                retry_policy=_RETRY_LONG_SCAN,
                task_queue="python-orchestrator-queue",
            )
        return True


@workflow.defn(name="URLAuthExtractWorkflow")
class URLAuthExtractWorkflow:
    """Extract authentication form candidates from a single URL.

    Expects ctx: {'url': str, 'scan_id': int}.
    Delegates to ExtractAuthForURLActivity with a 10-minute timeout.
    """

    @workflow.run
    async def run(self, ctx: dict) -> dict:
        return await workflow.execute_activity(
            "ExtractAuthForURLActivity",
            ctx,
            start_to_close_timeout=timedelta(minutes=10),
            retry_policy=_RETRY_INTERNAL,
            task_queue="python-orchestrator-queue",
        )


@workflow.defn(name="RecalculateApmeWorkflow")
class RecalculateApmeWorkflow:
    """Workflow to execute algorithmic Attack Path modeling (non-LLM) recalculation."""

    @workflow.run
    async def run(self, scan_history_id: int, job_id: str = None) -> dict:
        return await workflow.execute_activity(
            "RecalculateApmeActivity",
            args=[scan_history_id, job_id],
            start_to_close_timeout=timedelta(minutes=30),
            heartbeat_timeout=timedelta(minutes=5),
            retry_policy=RetryPolicy(maximum_attempts=3),
            task_queue="python-orchestrator-queue",
        )

