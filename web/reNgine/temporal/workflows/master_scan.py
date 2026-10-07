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

This module holds the full-scan orchestrators: MasterScanWorkflow (7-tier
pipeline) and NucleiPlannerWorkflow (Tier 6 vulnerability scan child).
"""

import asyncio
from datetime import timedelta
from typing import Any, Dict
from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ApplicationError, ChildWorkflowError

from reNgine.temporal.workflows._common import (
    _RETRY_INTERNAL,
    _RETRY_LLM,
    _RETRY_LONG_SCAN,
    _RETRY_NETWORK_SCAN,
    _RETRY_SCANNER,
    _dispatch_tier_plugins,
    _fan_out_search_vulns,
    _batching_enabled,
    _isolated_tool,
    _run_chunked,
    _target_dedup_enabled,
)

# All imports that touch Django or any non-deterministic module must be wrapped
# in workflow.unsafe.imports_passed_through() to prevent sandbox errors.
with workflow.unsafe.imports_passed_through():
    from reNgine.definitions import (
        NUCLEI_DEFAULT_SEVERITIES,
        NUCLEI_STAGE_BUDGET_HOURS,
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
            "Starting MasterScanWorkflow for scan_id=%s", ctx.get('scan_history_id')
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
            await workflow.sleep(30)

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
        except Exception as exc:
            # Non-fatal: scan runs normally even if timeline pre-population fails
            workflow.logger.warning("Scan timeline pre-population failed: %s", exc)

        # TOR circuit rotation — only dispatched when TOR mode is active
        if ctx.get('use_tor', False):
            try:
                await workflow.execute_activity(
                    "TorNewCircuitActivity",
                    start_to_close_timeout=timedelta(seconds=30),
                    retry_policy=RetryPolicy(maximum_attempts=1),
                    task_queue="python-orchestrator-queue"
                )
            except Exception as exc:
                # The scan still goes through TOR, only on the previous circuit.
                workflow.logger.warning("TOR circuit rotation failed: %s", exc)

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
                    _isolated_tool("RunSubdomainDiscoveryActivity", workflow.execute_activity(
                        "RunSubdomainDiscoveryActivity",
                        ctx,
                        start_to_close_timeout=timedelta(hours=4),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_LONG_SCAN,
                        task_queue="python-orchestrator-queue"
                    ))
                )
            if "amass_intel_discovery" in tasks:
                discovery_futures.append(
                    _isolated_tool("RunAmassIntelDiscoveryActivity", workflow.execute_activity(
                        "RunAmassIntelDiscoveryActivity",
                        ctx,
                        start_to_close_timeout=timedelta(hours=2),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_LONG_SCAN,
                        task_queue="python-orchestrator-queue"
                    ))
                )
            if "firewall_vpn_scan" in tasks:
                discovery_futures.append(
                    _isolated_tool("RunFirewallVPNScanActivity", workflow.execute_activity(
                        "RunFirewallVPNScanActivity",
                        ctx,
                        start_to_close_timeout=timedelta(minutes=30),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_NETWORK_SCAN,
                        task_queue="python-orchestrator-queue"
                    ))
                )
            if "dns_security" in tasks:
                discovery_futures.append(
                    _isolated_tool("RunDNSSecurityActivity", workflow.execute_activity(
                        "RunDNSSecurityActivity",
                        ctx,
                        start_to_close_timeout=timedelta(hours=1),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_NETWORK_SCAN,
                        task_queue="python-orchestrator-queue"
                    ))
                )
            if "osint" in tasks:
                discovery_futures.append(
                    _isolated_tool("RunGenericTaskActivity", workflow.execute_activity(
                        "RunGenericTaskActivity",
                        args=[ctx, "osint", "OSINT Scan"],
                        start_to_close_timeout=timedelta(hours=4),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_LONG_SCAN,
                        task_queue="python-orchestrator-queue"
                    ))
                )
            if "spiderfoot_scan" in tasks and yaml_config.get("spiderfoot_scan"):
                discovery_futures.append(
                    _isolated_tool("RunGenericTaskActivity", workflow.execute_activity(
                        "RunGenericTaskActivity",
                        args=[ctx, "spiderfoot_scan", "SpiderFoot Attack Surface Intelligence"],
                        start_to_close_timeout=timedelta(hours=24),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_LONG_SCAN,
                        task_queue="python-orchestrator-queue"
                    ))
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
                    _isolated_tool("RunGenericTaskActivity", workflow.execute_activity(
                        "RunGenericTaskActivity",
                        args=[ctx_baddns, "subdomain_discovery", "Baddns Scan", {}, "baddns"],
                        start_to_close_timeout=timedelta(hours=4),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_LONG_SCAN,
                        task_queue="python-orchestrator-queue"
                    ))
                )

            # Vigolium harvest (passive ingestion) runs at Tier 1 alongside subdomain
            # enumeration — it seeds the DB with passively gathered endpoints early.
            # Vigolium discovery moves to Tier 2 so it can target all enumerated subdomains.
            vigolium_harvest_config = yaml_config.get('vigolium_harvest', {})
            if vigolium_harvest_config.get('run_vigolium_harvest', True) and (
                not ctx.get('resume_from_remaining')
                or 'vigolium_harvest' in tasks
                or 'vulnerability_scan' in tasks
            ):
                discovery_futures.append(
                    _isolated_tool("RunVigoliumHarvestActivity", workflow.execute_activity(
                        "RunVigoliumHarvestActivity",
                        ctx,
                        start_to_close_timeout=timedelta(hours=6),
                        heartbeat_timeout=timedelta(minutes=10),
                        retry_policy=_RETRY_LONG_SCAN,
                        task_queue="python-orchestrator-queue"
                    ))
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
                    await _isolated_tool("RunHTTPCrawlActivity", workflow.execute_activity(
                        "RunHTTPCrawlActivity",
                        ctx,
                        start_to_close_timeout=timedelta(hours=3),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_LONG_SCAN,
                        task_queue="python-orchestrator-queue"
                    ))
                    await workflow.execute_activity(
                        "ParseHTTPCrawlResultsActivity",
                        ctx,
                        start_to_close_timeout=timedelta(minutes=15),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_INTERNAL,
                        task_queue="python-orchestrator-queue"
                    )

            tier2_futures = [_http_crawl_branch()]

            vigolium_discovery_config = yaml_config.get('vigolium_discovery', {})
            if vigolium_discovery_config.get('run_vigolium_discovery', True) and (
                not ctx.get('resume_from_remaining')
                or 'vigolium_discovery' in tasks
                or 'vulnerability_scan' in tasks
            ):
                tier2_futures.append(
                    _isolated_tool("RunVigoliumDiscoveryActivity", workflow.execute_activity(
                        "RunVigoliumDiscoveryActivity",
                        ctx,
                        start_to_close_timeout=timedelta(hours=8),
                        heartbeat_timeout=timedelta(minutes=10),
                        retry_policy=_RETRY_LONG_SCAN,
                        task_queue="python-orchestrator-queue"
                    ))
                )

            if "port_scan" in tasks:
                tier2_futures.append(
                    _isolated_tool("RunPortScanActivity", workflow.execute_activity(
                        "RunPortScanActivity",
                        ctx,
                        start_to_close_timeout=timedelta(hours=6),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_LONG_SCAN,
                        task_queue="python-orchestrator-queue"
                    ))
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

            # Mark hosts that serve the same site as another (www twins, redirects to
            # another host's root) so the heavy tools below run once per site.
            if "http_crawl" in tasks and workflow.patched("target-dedup") and _target_dedup_enabled(yaml_config):
                await _isolated_tool("RunTargetDedupActivity", workflow.execute_activity(
                    "RunTargetDedupActivity",
                    ctx,
                    start_to_close_timeout=timedelta(minutes=30),
                    heartbeat_timeout=timedelta(minutes=5),
                    retry_policy=_RETRY_INTERNAL,
                    task_queue="python-orchestrator-queue",
                ))

            # Push every live subdomain to Acunetix as soon as liveness is known,
            # rather than waiting for Tier 6. Hosts already submitted inside the
            # configured window are skipped by the activity itself.
            acunetix_cfg = (yaml_config.get('vulnerability_scan') or {}).get('acunetix') or {}
            if acunetix_cfg.get('submit_live_subdomains', False) and "http_crawl" in tasks:
                await _isolated_tool("SubmitLiveSubdomainsToAcunetixActivity", workflow.execute_activity(
                    "SubmitLiveSubdomainsToAcunetixActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=1),
                    heartbeat_timeout=timedelta(minutes=5),
                    retry_policy=_RETRY_NETWORK_SCAN,
                    task_queue="python-orchestrator-queue",
                ))

            await self._check_paused()
            # Post-Tier-2: dispatch any enabled "run after tier_2" plugins
            await _dispatch_tier_plugins(ctx, "tier_2", str(ctx.get('scan_history_id', 'scan')))

            # Email security checks — run after Tier 2 (requires port scan results)
            if "port_scan" in tasks:
                await _isolated_tool("RunEmailSecurityActivity", workflow.execute_activity(
                    "RunEmailSecurityActivity",
                    ctx,
                    # Probes every SMTP host found by the port scan: relay, STARTTLS,
                    # certificate and VRFY enumeration, each with its own timeout. On a
                    # target with many mail hosts 30 minutes was not enough, and the
                    # activity was killed and restarted forever. Upstream settled on 90
                    # minutes; the longer bound is kept because it is the one that stopped
                    # the restart loop.
                    start_to_close_timeout=timedelta(hours=2),
                    heartbeat_timeout=timedelta(minutes=10),
                    retry_policy=_RETRY_NETWORK_SCAN,
                    task_queue="python-orchestrator-queue",
                ))

            await self._check_paused()
            # ------------------------------------------------------------------
            # TIER 3: URL Fetching + Screenshot (parallel — both depend only on
            # Tier 2 http_crawl; screenshot does NOT depend on fetch_url output)
            # ------------------------------------------------------------------
            tier3_futures = []
            if "fetch_url" in tasks:
                tier3_futures.append(
                    _isolated_tool("RunFetchURLActivity", workflow.execute_activity(
                        "RunFetchURLActivity",
                        ctx,
                        start_to_close_timeout=timedelta(hours=8),
                        heartbeat_timeout=timedelta(minutes=15),
                        retry_policy=_RETRY_LONG_SCAN,
                        task_queue="python-orchestrator-queue"
                    ))
                )
            if "screenshot" in tasks:
                tier3_futures.append(
                    _isolated_tool("RunScreenshotActivity", workflow.execute_activity(
                        "RunScreenshotActivity",
                        ctx,
                        start_to_close_timeout=timedelta(hours=1),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_NETWORK_SCAN,
                        task_queue="python-orchestrator-queue"
                    ))
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
                await _isolated_tool("RunHTTPCrawlBridgeActivity", workflow.execute_activity(
                    "RunHTTPCrawlBridgeActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=3),
                    heartbeat_timeout=timedelta(minutes=5),
                    retry_policy=_RETRY_LONG_SCAN,
                    task_queue="python-orchestrator-queue"
                ))

            # ------------------------------------------------------------------
            # TIER 3b: Web API Discovery
            # Moved here from Tier 5 so kiterunner output (kr_*.json) is ready
            # before CPDE reads it. Guarded with workflow.patched() so that
            # in-flight workflows replaying recorded history (where this activity
            # ran at Tier 5) skip this block and still execute at Tier 5 below.
            # ------------------------------------------------------------------
            if "web_api_discovery" in tasks and workflow.patched("web-api-to-tier-3b"):
                await _isolated_tool("RunWebAPIDiscoveryActivity", workflow.execute_activity(
                    "RunWebAPIDiscoveryActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=4),
                    heartbeat_timeout=timedelta(minutes=10),
                    retry_policy=_RETRY_NETWORK_SCAN,
                    task_queue="python-orchestrator-queue"
                ))

            # ------------------------------------------------------------------
            # TIER 3c: Custom Parameter Discovery Engine (CPDE)
            # Reads kiterunner (kr_*.json), arjun, paramspider, linkfinder, and
            # JS bundles discovered by Tier 3. Runs after web_api_discovery so
            # all tool output files are present.
            # ------------------------------------------------------------------
            if "param_discovery" in tasks:
                await _isolated_tool("RunParamDiscoveryActivity", workflow.execute_activity(
                    "RunParamDiscoveryActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=2),
                    heartbeat_timeout=timedelta(minutes=10),
                    retry_policy=_RETRY_LONG_SCAN,
                    task_queue="python-orchestrator-queue"
                ))

            await self._check_paused()

            # Post-Tier-3: dispatch any enabled "run after tier_3" plugins
            await _dispatch_tier_plugins(ctx, "tier_3", str(ctx.get('scan_history_id', 'scan')))

            await self._check_paused()
            # ------------------------------------------------------------------
            # TIER 4: Directory & File Fuzzing (sequential — needs Tier 3 URLs)
            # ------------------------------------------------------------------
            if "dir_file_fuzz" in tasks:
                # Batches of hosts, each with its own time limit, instead of one
                # activity over every host. Workflows that reached Tier 4 before this
                # patch replay the single activity.
                if workflow.patched("chunked-dir-file-fuzz") and _batching_enabled(yaml_config, "dir_file_fuzz"):
                    await _isolated_tool("dir_file_fuzz batches", _run_chunked(ctx, "dir_file_fuzz"))
                else:
                    await _isolated_tool("RunDirFileFuzzActivity", workflow.execute_activity(
                        "RunDirFileFuzzActivity",
                        ctx,
                        start_to_close_timeout=timedelta(hours=8),
                        heartbeat_timeout=timedelta(minutes=15),
                        retry_policy=_RETRY_LONG_SCAN,
                        task_queue="python-orchestrator-queue"
                    ))
                await workflow.execute_activity(
                    "ParseFuzzResultsActivity",
                    ctx,
                    start_to_close_timeout=timedelta(minutes=15),
                    heartbeat_timeout=timedelta(minutes=5),
                    retry_policy=_RETRY_INTERNAL,
                    task_queue="python-orchestrator-queue"
                )

            # Run gf patterns against every endpoint accumulated up to this point
            # (covers fetch_url + http_crawl + dir_file_fuzz results).
            await workflow.execute_activity(
                "RunGFOnAllEndpointsActivity",
                ctx,
                start_to_close_timeout=timedelta(minutes=30),
                heartbeat_timeout=timedelta(minutes=10),
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

            # Tier 4a: Post-crawl OSINT (exifray + SwaggerSpy path probe)
            if "post_crawl_osint" in tasks:
                await _isolated_tool("RunGenericTaskActivity", workflow.execute_activity(
                    "RunGenericTaskActivity",
                    args=[ctx, "post_crawl_osint", "Post-Crawl OSINT"],
                    start_to_close_timeout=timedelta(hours=2),
                    heartbeat_timeout=timedelta(minutes=10),
                    retry_policy=_RETRY_LONG_SCAN,
                    task_queue="python-orchestrator-queue"
                ))

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
                    _isolated_tool("RunWebAPIDiscoveryActivity", workflow.execute_activity(
                        "RunWebAPIDiscoveryActivity",
                        ctx,
                        start_to_close_timeout=timedelta(hours=4),
                        heartbeat_timeout=timedelta(minutes=10),
                        retry_policy=_RETRY_NETWORK_SCAN,
                        task_queue="python-orchestrator-queue"
                    ))
                )
            if "waf_detection" in tasks:
                analysis_futures.append(
                    _isolated_tool("RunWAFDetectionActivity", workflow.execute_activity(
                        "RunWAFDetectionActivity",
                        ctx,
                        start_to_close_timeout=timedelta(minutes=30),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_NETWORK_SCAN,
                        task_queue="python-orchestrator-queue"
                    ))
                )
            if "secret_scanning" in tasks:
                analysis_futures.append(
                    _isolated_tool("RunSecretScanningActivity", workflow.execute_activity(
                        "RunSecretScanningActivity",
                        ctx,
                        start_to_close_timeout=timedelta(hours=2),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_LONG_SCAN,
                        task_queue="python-orchestrator-queue"
                    ))
                )

            vigolium_analysis_config = yaml_config.get('vigolium_analysis', {})
            if vigolium_analysis_config.get('run_vigolium_analysis', True) and (
                not ctx.get('resume_from_remaining')
                or 'vigolium_analysis' in tasks
                or 'vulnerability_scan' in tasks
            ):
                analysis_futures.append(
                    _isolated_tool("RunVigoliumAnalysisActivity", workflow.execute_activity(
                        "RunVigoliumAnalysisActivity",
                        ctx,
                        start_to_close_timeout=timedelta(hours=12),
                        heartbeat_timeout=timedelta(minutes=10),
                        retry_policy=_RETRY_LONG_SCAN,
                        task_queue="python-orchestrator-queue"
                    ))
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

            if "vulnerability_scan" in tasks:
                ran_t6 = True
                try:
                    await workflow.execute_child_workflow(
                        "NucleiPlannerWorkflow",
                        ctx,
                        id=f"{workflow.info().workflow_id}-{workflow.info().run_id[:8]}-nuclei",
                        task_queue="python-orchestrator-queue",
                        execution_timeout=timedelta(days=7),
                        run_timeout=timedelta(days=7),
                        retry_policy=RetryPolicy(maximum_attempts=1),
                    )
                except (ChildWorkflowError, ApplicationError) as nuclei_err:
                    # Non-fatal: log and continue so Tier 7 (correlation, risk, Neo4j) still runs.
                    workflow.logger.warning(
                        "NucleiPlannerWorkflow failed for scan_id=%s (non-fatal, Tier 7 will still run): %s", ctx.get('scan_history_id'), nuclei_err
                    )

            other_t6_futures = []
            if "waf_bypass" in tasks:
                ran_t6 = True
                other_t6_futures.append(
                    _isolated_tool("RunWAFBypassActivity", workflow.execute_activity(
                        "RunWAFBypassActivity",
                        ctx,
                        start_to_close_timeout=timedelta(hours=1),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_NETWORK_SCAN,
                        task_queue="python-orchestrator-queue"
                    ))
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
                "MasterScanWorkflow cancelled for scan_id=%s — skipping FinalizeFailedScanActivity (ABORTED_TASK already set by API).", ctx.get('scan_history_id')
            )
            is_cancelled = True
            raise

        except Exception as e:
            workflow.logger.error(
                "MasterScanWorkflow FAILED for scan_id=%s: %s", ctx.get('scan_history_id'), e
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
                                # Budget sized for large CVE sets + slow NVD; heartbeat must
                                # outlast a single external API stall (NVD read timeout=10s
                                # plus vulnx/sploitscan).
                                start_to_close_timeout=timedelta(hours=2),
                                heartbeat_timeout=timedelta(minutes=15),
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
                            # Certificate intelligence — must run before APME ingestion
                            await workflow.execute_activity(
                                "run_certificate_intel_activity",
                                args=[ctx.get("scan_history_id")],
                                start_to_close_timeout=timedelta(minutes=15),
                                heartbeat_timeout=timedelta(minutes=5),
                                retry_policy=RetryPolicy(maximum_attempts=2),
                                task_queue="python-orchestrator-queue",
                            )
                            # Identity infrastructure detection — must run before APME
                            await workflow.execute_activity(
                                "run_identity_infra_activity",
                                args=[ctx.get("scan_history_id")],
                                start_to_close_timeout=timedelta(minutes=10),
                                retry_policy=RetryPolicy(maximum_attempts=2),
                                task_queue="python-orchestrator-queue",
                            )
                            # API intelligence — cluster endpoints before APME
                            await workflow.execute_activity(
                                "run_api_intel_activity",
                                args=[ctx.get("scan_history_id")],
                                start_to_close_timeout=timedelta(minutes=10),
                                retry_policy=RetryPolicy(maximum_attempts=2),
                                task_queue="python-orchestrator-queue",
                            )
                            # Attack Path Modeling Engine — must be the final analysis step.
                            # On unless the engine sets attack_path_modeling.enabled: false.
                            if (yaml_config.get('attack_path_modeling') or {}).get('enabled', True):
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
                            "MasterScanWorkflow post-scan tasks failed for scan_id=%s: %s", ctx.get('scan_history_id'), post_e
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
                        "MasterScanWorkflow COMPLETE for scan_id=%s", ctx.get('scan_history_id')
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
                            "FinalizeFailedScanActivity itself failed for scan_id=%s: %s", ctx.get('scan_history_id'), fin_e
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
            "Starting NucleiPlannerWorkflow for scan_id=%s", ctx.get('scan_history_id')
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

        if not vuln_config.get('run_nuclei', True):
            workflow.logger.warning(
                "[NUCLEI] SKIPPED | scan_id=%s — run_nuclei is false in the scan engine config",
                ctx.get('scan_history_id'),
            )

        if vuln_config.get('run_nuclei', True):
            nuclei_specific_config = vuln_config.get('nuclei', {})
            severities = (
                nuclei_specific_config.get('severities')
                or nuclei_specific_config.get('severity')
                or NUCLEI_DEFAULT_SEVERITIES
            )
            workflow.logger.info(
                "[NUCLEI] PLAN | scan_id=%s severities=%s — all severities go in a "
                "single -severity flag, so expect one run per tag batch",
                ctx.get('scan_history_id'), ','.join(severities),
            )

            if workflow.patched("nuclei-proxy-rotation"):
                proxies_file_path = None
                try:
                    # Going through the proxy pool costs most of nuclei's speed,
                    # because the concurrency and rate caps that stop it
                    # deadlocking on flaky proxies also throttle it. When the
                    # operator has asked for it, probe the target first and pay
                    # that price only if the target actually blocks us.
                    _proxy_policy = await workflow.execute_activity(
                        "GetProxyPolicyActivity",
                        args=[ctx],
                        start_to_close_timeout=timedelta(minutes=2),
                        retry_policy=_RETRY_INTERNAL,
                        task_queue="python-orchestrator-queue",
                    )
                    _need_proxy = True
                    if _proxy_policy.get('use_proxy') and _proxy_policy.get('only_after_ban'):
                        _need_proxy = await workflow.execute_activity(
                            "CheckTargetBlockingActivity",
                            args=[ctx],
                            start_to_close_timeout=timedelta(minutes=5),
                            retry_policy=_RETRY_INTERNAL,
                            task_queue="python-orchestrator-queue",
                        )
                        workflow.logger.warning(
                            "[NUCLEI] PROXY DECISION | scan_id=%s blocked=%s — %s",
                            ctx.get('scan_history_id'), _need_proxy,
                            "using the proxy pool" if _need_proxy
                            else "scanning direct at full speed",
                        )

                    if _need_proxy:
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

                    # One run per tag batch, with every severity in a single
                    # -severity flag. Looping over severities re-scanned the same
                    # target list once per level — six passes for identical
                    # coverage, since nuclei accepts the whole list at once. On a
                    # host with a rich technology fingerprint that multiplied the
                    # batch count by six and pushed Tier 6 past this child
                    # workflow's 24-hour execution_timeout, so everything queued
                    # behind nuclei (Acunetix, WPScan, cPanel, S3, Dalfox and the
                    # whole of Tier 7) never got to run at all.
                    severity_filter = (
                        ','.join(severities)
                        if isinstance(severities, (list, tuple))
                        else str(severities)
                    )
                    _nuclei_deadline = workflow.now() + timedelta(
                        hours=NUCLEI_STAGE_BUDGET_HOURS
                    )
                    for _idx, batch in enumerate(tag_batches, start=1):
                        if workflow.now() >= _nuclei_deadline:
                            workflow.logger.warning(
                                "[NUCLEI] BUDGET SPENT | scan_id=%s — %dh budget used "
                                "after %d of %d tag batches. Skipping the rest so the "
                                "remaining Tier 6 tools and Tier 7 still run.",
                                ctx.get('scan_history_id'),
                                NUCLEI_STAGE_BUDGET_HOURS, _idx - 1, len(tag_batches),
                            )
                            break
                        severity_ctx = {
                            **ctx,
                            "nuclei_severity_filter": severity_filter,
                            "nuclei_proxies_path": proxies_file_path
                        }
                        await workflow.execute_activity(
                            "RunNucleiActivity",
                            args=[severity_ctx, severity_filter, batch],
                            start_to_close_timeout=timedelta(hours=6),
                            heartbeat_timeout=timedelta(minutes=5),
                            retry_policy=_RETRY_LONG_SCAN,
                            task_queue="python-orchestrator-queue",
                        )
                except Exception as _nuclei_err:
                    # Nuclei failure is isolated — remaining tier 6 tools (cpanel, wpscan,
                    # s3scanner, vigolium, etc.) must still run. The parent workflow
                    # (MasterScanWorkflow) will only block tier 7 if this entire child
                    # workflow raises, not because nuclei specifically failed.
                    workflow.logger.error(
                        "[NUCLEI] ABANDONED | scan_id=%s — nuclei gave up after retries, "
                        "continuing with remaining tier 6 tools. The scan will still be "
                        "reported as finished, so this line is the only trace. error=%s",
                        ctx.get('scan_history_id'), str(_nuclei_err),
                    )
                finally:
                    if proxies_file_path:
                        try:
                            # Clean up the proxies list to avoid leaving sensitive network details around
                            await workflow.execute_activity(
                                "CleanupProxyListActivity",
                                args=[proxies_file_path],
                                start_to_close_timeout=timedelta(minutes=5),
                                retry_policy=_RETRY_INTERNAL,
                                task_queue="python-orchestrator-queue",
                            )
                        except Exception as _cleanup_exc:
                            workflow.logger.warning(
                                "CleanupProxyListActivity failed for scan_id=%s (non-fatal): %s",
                                ctx.get('scan_history_id'), str(_cleanup_exc),
                            )
            else:
                # Gather tags and pre-built batches via activity.
                # Activity counts templates per tag so each batch is bounded by
                # template count rather than tag count — prevents 2-hour timeouts
                # on WordPress-heavy scans with 2000+ templates.
                try:
                    nuclei_tag_result = await workflow.execute_activity(
                        "GatherNucleiTagsActivity",
                        args=[ctx],
                        start_to_close_timeout=timedelta(minutes=10),
                        retry_policy=_RETRY_INTERNAL,
                        task_queue="python-orchestrator-queue",
                    )
                    tag_batches = nuclei_tag_result.get('batches') or [None]

                    # Same collapse as the patched branch above: every severity in
                    # one -severity flag, one run per tag batch, bounded budget.
                    severity_filter = (
                        ','.join(severities)
                        if isinstance(severities, (list, tuple))
                        else str(severities)
                    )
                    _nuclei_deadline = workflow.now() + timedelta(
                        hours=NUCLEI_STAGE_BUDGET_HOURS
                    )
                    for _idx, batch in enumerate(tag_batches, start=1):
                        if workflow.now() >= _nuclei_deadline:
                            workflow.logger.warning(
                                "[NUCLEI] BUDGET SPENT | scan_id=%s — %dh budget used "
                                "after %d of %d tag batches. Skipping the rest so the "
                                "remaining Tier 6 tools and Tier 7 still run.",
                                ctx.get('scan_history_id'),
                                NUCLEI_STAGE_BUDGET_HOURS, _idx - 1, len(tag_batches),
                            )
                            break
                        severity_ctx = {
                            **ctx,
                            "nuclei_severity_filter": severity_filter
                        }
                        await workflow.execute_activity(
                            "RunNucleiActivity",
                            args=[severity_ctx, severity_filter, batch],
                            start_to_close_timeout=timedelta(hours=6),
                            heartbeat_timeout=timedelta(minutes=5),
                            retry_policy=_RETRY_LONG_SCAN,
                            task_queue="python-orchestrator-queue",
                        )
                except Exception as _nuclei_err:
                    workflow.logger.error(
                        "[NUCLEI] ABANDONED | scan_id=%s — nuclei gave up after retries, "
                        "continuing with remaining tier 6 tools. The scan will still be "
                        "reported as finished, so this line is the only trace. error=%s",
                        ctx.get('scan_history_id'), str(_nuclei_err),
                    )

        try:
            if vuln_config.get('run_crlfuzz', False):
                await workflow.execute_activity(
                    "RunCRLFuzzActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=4),
                    heartbeat_timeout=timedelta(minutes=5),
                    retry_policy=_RETRY_SCANNER,
                    task_queue="python-orchestrator-queue"
                )

            if vuln_config.get('run_dalfox', False):
                await workflow.execute_activity(
                    "RunDalfoxActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=4),
                    heartbeat_timeout=timedelta(minutes=5),
                    retry_policy=_RETRY_SCANNER,
                    task_queue="python-orchestrator-queue"
                )

            if vuln_config.get('run_s3scanner', True):
                await workflow.execute_activity(
                    "RunS3ScannerActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=2),
                    heartbeat_timeout=timedelta(minutes=5),
                    retry_policy=_RETRY_SCANNER,
                    task_queue="python-orchestrator-queue"
                )

            if vuln_config.get('run_smugglex', False):
                await workflow.execute_activity(
                    "RunSmugglexActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=2),
                    heartbeat_timeout=timedelta(minutes=5),
                    retry_policy=_RETRY_SCANNER,
                    task_queue="python-orchestrator-queue"
                )

            if vuln_config.get('run_second_order', False):
                await workflow.execute_activity(
                    "RunSecondOrderActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=2),
                    heartbeat_timeout=timedelta(minutes=5),
                    retry_policy=_RETRY_SCANNER,
                    task_queue="python-orchestrator-queue"
                )

            if vuln_config.get('run_nuclei_dast', False):
                await workflow.execute_activity(
                    "RunNucleiDASTActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=4),
                    heartbeat_timeout=timedelta(minutes=5),
                    retry_policy=_RETRY_SCANNER,
                    task_queue="python-orchestrator-queue"
                )

            # --- Stage 2: Additional scanners ---
            if vuln_config.get('run_acunetix', False):
                await workflow.execute_activity(
                    "RunAcunetixActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=4),
                    heartbeat_timeout=timedelta(minutes=5),
                    retry_policy=_RETRY_SCANNER,
                    task_queue="python-orchestrator-queue"
                )

            cpanel_cfg = vuln_config.get('cpanel_scanner', {})
            if cpanel_cfg.get('run_cpanel2shell', True):
                await workflow.execute_activity(
                    "RunCpanelScanActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=2),
                    heartbeat_timeout=timedelta(minutes=5),
                    retry_policy=_RETRY_SCANNER,
                    task_queue="python-orchestrator-queue"
                )

            if vuln_config.get('run_wpscan', True):
                await workflow.execute_activity(
                    "RunWpscanActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=2),
                    heartbeat_timeout=timedelta(minutes=5),
                    retry_policy=_RETRY_SCANNER,
                    task_queue="python-orchestrator-queue"
                )

            react_cfg = vuln_config.get('react_scanner', {})
            if react_cfg.get('run_react2shell', True):
                await workflow.execute_activity(
                    "RunReact2ShellActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=2),
                    heartbeat_timeout=timedelta(minutes=5),
                    retry_policy=_RETRY_SCANNER,
                    task_queue="python-orchestrator-queue"
                )

            # vulnerability_scan.run_semgrep is what the engine editor writes; the
            # top-level leaks_and_secrets.run_semgrep is the older spelling.
            leaks_config = yaml_config.get('leaks_and_secrets') or {}
            if vuln_config.get('run_semgrep', leaks_config.get('run_semgrep', True)):
                await workflow.execute_activity(
                    "RunSemgrepActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=2),
                    heartbeat_timeout=timedelta(minutes=5),
                    retry_policy=_RETRY_SCANNER,
                    task_queue="python-orchestrator-queue"
                )

            if vuln_config.get('run_vigolium', True):
                await workflow.execute_activity(
                    "RunVigoliumScanActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=12),
                    heartbeat_timeout=timedelta(minutes=10),
                    retry_policy=_RETRY_LONG_SCAN,
                    task_queue="python-orchestrator-queue"
                )

            if vuln_config.get('run_wptaint_scan', True):
                await workflow.execute_activity(
                    "RunWPTaintScanActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=2),
                    heartbeat_timeout=timedelta(minutes=5),
                    retry_policy=_RETRY_SCANNER,
                    task_queue="python-orchestrator-queue"
                )

            # --- Post-scan processing: dedup + OpenAPI extraction + GraphQL dispatch ---
            # Runs after all Tier 6 tools so it can act on Vigolium/Nuclei findings.
            # Controlled by vulnerability_scan.run_post_scan_processing (default True).
            if vuln_config.get('run_post_scan_processing', True):
                await workflow.execute_activity(
                    "PostScanProcessingActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=2),
                    heartbeat_timeout=timedelta(minutes=5),
                    retry_policy=_RETRY_INTERNAL,
                    task_queue="python-orchestrator-queue",
                )

        except Exception as _stage2_exc:
            # A Stage 2 tool failed. The individual activity already wrote FAILED_TASK
            # to its ScanActivity row via _run_task. Log and fall through so
            # MarkVulnerabilityScanCompleteActivity always runs below — this prevents
            # vulnerability_scan from being permanently stuck as INITIATED_TASK.
            workflow.logger.error(
                "NucleiPlannerWorkflow Stage 2 tool failed for scan_id=%s (non-fatal): %s",
                ctx.get('scan_history_id'), str(_stage2_exc),
            )

        # Write a ScanActivity(name='vulnerability_scan', status=SUCCESS) so that
        # resume_scan_temporal can recognise this compound task as complete and
        # skip it on crash recovery, instead of restarting the whole vuln scan.
        # Runs regardless of partial Stage 2 failures — individual tool rows are
        # already marked FAILED by _run_task before the exception propagated.
        await workflow.execute_activity(
            "MarkVulnerabilityScanCompleteActivity",
            ctx,
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=_RETRY_INTERNAL,
            task_queue="python-orchestrator-queue"
        )

        workflow.logger.info(
            "NucleiPlannerWorkflow COMPLETE for scan_id=%s", ctx.get('scan_history_id')
        )
        return {"status": "SUCCESS"}
