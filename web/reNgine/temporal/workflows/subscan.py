"""
SubScanWorkflow — per-subdomain subscan orchestration.

Holds the dispatch registry (_SUBSCAN_DISPATCH), the set of standalone
child-workflow subscan types (_STANDALONE_SUBSCAN_WORKFLOWS) and the
SubScanWorkflow class itself. Deterministic: no I/O, no ORM, no datetime.now().
"""

import asyncio
from datetime import timedelta
from typing import Any, Dict, List, Union
from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ApplicationError

from reNgine.temporal.workflows._common import (
    _RETRY_INTERNAL,
    _RETRY_LLM,
    _RETRY_NETWORK_SCAN,
    _dispatch_tier_plugins,
)

# All imports that touch Django or any non-deterministic module must be wrapped
# in workflow.unsafe.imports_passed_through() to prevent sandbox errors.
with workflow.unsafe.imports_passed_through():
    from reNgine.temporal_activities import _PERMITTED_GENERIC_TASKS


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
    "post_crawl_osint": {
        "activity": "RunGenericTaskActivity",
        "timeout": timedelta(hours=2),
        "args_builder": lambda ctx: [ctx, "post_crawl_osint", "Post-Crawl OSINT"],
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
    "vigolium_harvest": {
        "activity": "RunVigoliumHarvestActivity",
        "timeout": timedelta(hours=3),
        "args_builder": lambda ctx: [ctx],
    },
    "vigolium_discovery": {
        "activity": "RunVigoliumDiscoveryActivity",
        "timeout": timedelta(hours=4),
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
    "dns_security": {
        "activity": "RunDNSSecurityActivity",
        "timeout": timedelta(hours=1),
        "args_builder": lambda ctx: [ctx],
    },
    # Special cases — handled with inline logic in SubScanWorkflow.run():
    "vulnerability_scan": None,  # Has Tier 7 post-steps (correlation, risk, APME)
    "baddns": None,              # Modifies ctx before dispatch
    "url_vuln": None,            # Dispatched as URLVulnWorkflow child workflow
    "url_crawl": None,           # Dispatched as URLCrawlWorkflow child workflow
    "url_fuzz": None,            # Dispatched as URLFuzzWorkflow child workflow
    "url_dirsearch": None,       # Dispatched as URLDirSearchWorkflow child workflow
    "url_params_fuzz": None,     # Dispatched as URLParamsFuzzWorkflow child workflow
    "subdomain_recon": None,     # Dispatched as SubdomainReconWorkflow child workflow
    "domain_recon": None,        # Dispatched as DomainReconWorkflow child workflow
    "host_recon": None,          # Dispatched as HostReconWorkflow child workflow
    "cidr_recon": None,          # Dispatched as CIDRReconWorkflow child workflow
    "code_scan": None,           # Dispatched as CodeScanWorkflow child workflow
    "vigolium_audit": None,      # Dispatched as CodeScanWorkflow child workflow (vigolium_audit config section)
    # stress_test is triggered independently via StressTestControlAPI — not via SubScanWorkflow
}


# Standalone child-workflow subscan types.
# These are NOT placed into any execution tier in SubScanWorkflow because each
# standalone workflow manages its own internal pipeline sequencing (HTTP probe,
# port scan, crawl, etc.).  They are recognised by the validator (present in
# _SUBSCAN_DISPATCH) but stripped from `active_tasks` before tier construction
# and executed as a single concurrent gather AFTER the main tier pipeline.
# They can be triggered individually from the scan-start modal or the subscans
# tab without any dependency on the main scan's tier ordering.
_STANDALONE_SUBSCAN_WORKFLOWS: frozenset = frozenset({
    "url_crawl",
    "url_fuzz",
    "url_dirsearch",
    "url_params_fuzz",
    "url_vuln",
    "subdomain_recon",
    "domain_recon",
    "host_recon",
    "cidr_recon",
    "code_scan",
    "vigolium_audit",
})


def is_subscan_task(name: str) -> bool:
    """True when SubScanWorkflow can run `name` (engine YAML also holds settings-only keys)."""
    return name in _SUBSCAN_DISPATCH or name in _PERMITTED_GENERIC_TASKS


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
            "Starting SubScanWorkflow for subdomain_id=%s tasks=%s", ctx.get('subdomain_id'), tasks
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
            await workflow.sleep(30)

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
        except Exception as exc:
            workflow.logger.warning("Subscan timeline pre-population failed: %s", exc)

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

        # Validate tasks against the permitted task list before any dispatch
        # A plain exception here fails the workflow task, which Temporal retries
        # forever and leaves the subscan RUNNING; a non-retryable error ends it.
        for t in tasks:
            if not is_subscan_task(t):
                raise ApplicationError(
                    f"[SubScanWorkflow] '{t}' is not a recognized subscan type. "
                    f"Add it to _PERMITTED_GENERIC_TASKS in temporal_activities.py to enable dispatch.",
                    non_retryable=True,
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
                        execution_timeout=timedelta(days=7),
                        run_timeout=timedelta(days=7),
                        retry_policy=RetryPolicy(maximum_attempts=1),
                    )
                elif t == "url_vuln":
                    await workflow.execute_child_workflow(
                        "URLVulnWorkflow",
                        ctx_task,
                        id=f"{workflow.info().workflow_id}-{workflow.info().run_id[:8]}-urlvuln",
                        task_queue="python-orchestrator-queue",
                        execution_timeout=timedelta(days=7),
                        run_timeout=timedelta(days=7),
                        retry_policy=RetryPolicy(maximum_attempts=1),
                    )
                elif t == "url_crawl":
                    await workflow.execute_child_workflow(
                        "URLCrawlWorkflow",
                        ctx_task,
                        id=f"{workflow.info().workflow_id}-{workflow.info().run_id[:8]}-urlcrawl",
                        task_queue="python-orchestrator-queue",
                        execution_timeout=timedelta(days=7),
                        run_timeout=timedelta(days=7),
                        retry_policy=RetryPolicy(maximum_attempts=1),
                    )
                elif t == "url_fuzz":
                    await workflow.execute_child_workflow(
                        "URLFuzzWorkflow",
                        ctx_task,
                        id=f"{workflow.info().workflow_id}-{workflow.info().run_id[:8]}-urlfuzz",
                        task_queue="python-orchestrator-queue",
                        execution_timeout=timedelta(days=7),
                        run_timeout=timedelta(days=7),
                        retry_policy=RetryPolicy(maximum_attempts=1),
                    )
                elif t == "url_dirsearch":
                    await workflow.execute_child_workflow(
                        "URLDirSearchWorkflow",
                        ctx_task,
                        id=f"{workflow.info().workflow_id}-{workflow.info().run_id[:8]}-urldirsearch",
                        task_queue="python-orchestrator-queue",
                        execution_timeout=timedelta(days=7),
                        run_timeout=timedelta(days=7),
                        retry_policy=RetryPolicy(maximum_attempts=1),
                    )
                elif t == "url_params_fuzz":
                    await workflow.execute_child_workflow(
                        "URLParamsFuzzWorkflow",
                        ctx_task,
                        id=f"{workflow.info().workflow_id}-{workflow.info().run_id[:8]}-urlparamsfuzz",
                        task_queue="python-orchestrator-queue",
                        execution_timeout=timedelta(days=7),
                        run_timeout=timedelta(days=7),
                        retry_policy=RetryPolicy(maximum_attempts=1),
                    )
                elif t == "subdomain_recon":
                    await workflow.execute_child_workflow(
                        "SubdomainReconWorkflow",
                        ctx_task,
                        id=f"{workflow.info().workflow_id}-{workflow.info().run_id[:8]}-subdomainrecon",
                        task_queue="python-orchestrator-queue",
                        execution_timeout=timedelta(days=7),
                        run_timeout=timedelta(days=7),
                        retry_policy=RetryPolicy(maximum_attempts=1),
                    )
                elif t == "domain_recon":
                    await workflow.execute_child_workflow(
                        "DomainReconWorkflow",
                        ctx_task,
                        id=f"{workflow.info().workflow_id}-{workflow.info().run_id[:8]}-domainrecon",
                        task_queue="python-orchestrator-queue",
                        execution_timeout=timedelta(days=7),
                        run_timeout=timedelta(days=7),
                        retry_policy=RetryPolicy(maximum_attempts=1),
                    )
                elif t == "host_recon":
                    await workflow.execute_child_workflow(
                        "HostReconWorkflow",
                        ctx_task,
                        id=f"{workflow.info().workflow_id}-{workflow.info().run_id[:8]}-hostrecon",
                        task_queue="python-orchestrator-queue",
                        execution_timeout=timedelta(days=7),
                        run_timeout=timedelta(days=7),
                        retry_policy=RetryPolicy(maximum_attempts=1),
                    )
                elif t == "cidr_recon":
                    await workflow.execute_child_workflow(
                        "CIDRReconWorkflow",
                        ctx_task,
                        id=f"{workflow.info().workflow_id}-{workflow.info().run_id[:8]}-cidrrecon",
                        task_queue="python-orchestrator-queue",
                        execution_timeout=timedelta(days=7),
                        run_timeout=timedelta(days=7),
                        retry_policy=RetryPolicy(maximum_attempts=1),
                    )
                elif t in ("code_scan", "vigolium_audit"):
                    await workflow.execute_child_workflow(
                        "CodeScanWorkflow",
                        ctx_task,
                        id=f"{workflow.info().workflow_id}-{workflow.info().run_id[:8]}-codescan",
                        task_queue="python-orchestrator-queue",
                        execution_timeout=timedelta(days=7),
                        run_timeout=timedelta(days=7),
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

            # Group active tasks by sequence-enforced execution tiers.
            # Standalone child-workflow tasks are stripped out here — they run
            # independently after the tier pipeline (see standalone block below).
            active_tasks = [t for t in tasks if t not in {
                "correlate_vulnerabilities", "calculate_risk_scores",
                "generate_impact_assessment", "sync_graph", "run_apme", "attack_path_modeling"
            } and t not in _STANDALONE_SUBSCAN_WORKFLOWS]

            # Standalone tasks: extracted before tier calculation.
            # Each standalone workflow is self-sequencing, so no ordering is needed.
            standalone_tasks = [t for t in tasks if t in _STANDALONE_SUBSCAN_WORKFLOWS]

            tiers = [
                # TIER 1: Discovery — all discovery tools run concurrently.
                # vigolium_harvest seeds passive endpoints early alongside subdomain enumeration.
                # vigolium_discovery is in Tier 2 so it targets all enumerated subdomains.
                [t for t in active_tasks if t in {
                    "subdomain_discovery", "amass_intel_discovery", "firewall_vpn_scan",
                    "dns_security", "osint", "spiderfoot_scan", "baddns",
                    "vigolium_harvest",
                }],
                # TIER 2: HTTP Crawl & Port Scan + vigolium discovery — populates endpoint DB for Tiers 3+.
                # vigolium_discovery runs here (not Tier 1) so it targets all enumerated subdomains.
                [t for t in active_tasks if t in {"http_crawl", "port_scan", "vigolium_discovery"}],
                # TIER 3: URL Fetching + Screenshot — both depend only on Tier 2 http_crawl;
                # screenshot does NOT depend on fetch_url output so they run concurrently.
                # vigolium spidering runs as part of fetch_url (uses_tools: [vigolium]).
                [t for t in active_tasks if t in {"fetch_url", "screenshot"}],
                # TIER 3a: HTTP Crawl Bridge — crawls new/dead endpoints from fetch_url
                [t for t in active_tasks if t == "http_crawl_bridge"],
                # TIER 3b: Web API Discovery — runs before CPDE so kiterunner output is available.
                [t for t in active_tasks if t == "web_api_discovery"],
                # TIER 3c: Custom Parameter Discovery Engine (CPDE) — reads kiterunner/arjun/JS output.
                [t for t in active_tasks if t == "param_discovery"],
                # TIER 4: Directory & File Fuzzing — needs Tier 3 URLs.
                [t for t in active_tasks if t == "dir_file_fuzz"],
                # TIER 4a: Post-crawl OSINT — exifray + SwaggerSpy path probe (needs Tier 4 fuzz output).
                [t for t in active_tasks if t == "post_crawl_osint"],
                # TIER 5: Analysis — WAF detection, secret scanning, vigolium.
                [t for t in active_tasks if t in {"waf_detection", "secret_scanning", "vigolium_analysis"}],
                # TIER 6: Security Assessment — explicit inclusion, mirrors MasterScanWorkflow Tier 6.
                # vigolium_scan runs alongside vulnerability_scan at Tier 6.
                [t for t in active_tasks if t in {
                    "vulnerability_scan", "waf_bypass", "vigolium_scan", "run_acunetix",
                }],
                # TIER 6b: Fallback for any pipeline task not classified in Tiers 1-6.
                # Handles future tasks added to _SUBSCAN_DISPATCH without explicit tier placement.
                # Standalone workflow types are excluded here — they are handled separately.
                [t for t in active_tasks if t not in {
                    "subdomain_discovery", "amass_intel_discovery", "firewall_vpn_scan",
                    "dns_security", "osint", "spiderfoot_scan", "baddns",
                    "vigolium_harvest",
                    "http_crawl", "port_scan", "vigolium_discovery",
                    "fetch_url", "screenshot", "dir_file_fuzz", "post_crawl_osint",
                    "web_api_discovery", "waf_detection",
                    "secret_scanning", "vulnerability_scan", "waf_bypass",
                    "vigolium_analysis", "vigolium_scan", "param_discovery",
                    "http_crawl_bridge", "run_acunetix",
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
                    "[SubScanWorkflow] Executing Tier %s tasks: %s", tier_index, tier_tasks
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
                    # Run gf patterns against every endpoint accumulated up to this point.
                    await workflow.execute_activity(
                        "RunGFOnAllEndpointsActivity",
                        ctx,
                        start_to_close_timeout=timedelta(minutes=30),
                        heartbeat_timeout=timedelta(minutes=10),
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

            # -------------------------------------------------------------------
            # STANDALONE CHILD WORKFLOWS
            # Triggered individually (from scan-start modal or subscans tab).
            # Each manages its own internal pipeline sequencing, so no tier
            # ordering is required.  They run concurrently as a flat gather
            # AFTER the main tier pipeline so that base scan context (endpoints,
            # subdomains) is available, but before Tier 7 post-processing.
            # -------------------------------------------------------------------
            if standalone_tasks:
                workflow.logger.info(
                    "[SubScanWorkflow] Executing standalone workflows: %s", standalone_tasks
                )
                await asyncio.gather(*[
                    run_and_track_task(t) for t in standalone_tasks
                ])

            success = True
        except asyncio.CancelledError:
            workflow.logger.info("SubScanWorkflow was cancelled. Skipping post-scan tasks.")
            is_cancelled = True
            raise
        except Exception as e:
            workflow.logger.error("SubScanWorkflow failed during execution: %s", e)
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
                        workflow.logger.error("SubScanWorkflow post-scan tasks failed: %s", post_e)
                        # Tier-7 failed — mark any still-untracked tasks as failed so
                        # finalization reflects the correct status.
                        for _t in tasks:
                            if _t not in task_success:
                                task_success[_t] = False
                    else:
                        # Tier-7 succeeded — backfill task_success for tasks that were
                        # excluded from active_tasks (e.g. "attack_path_modeling",
                        # "run_apme") and therefore never went through run_and_track_task.
                        # Without this, any subscan whose type matches a tier-7 name
                        # defaults to False in task_success and is finalized as FAILED
                        # even though the activity completed successfully.
                        for _t in tasks:
                            if _t not in task_success:
                                task_success[_t] = True

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
                            retry_policy=_RETRY_INTERNAL,
                            task_queue="python-orchestrator-queue"
                        )
                else:
                    # Fallback for single legacy subscan (no subscans_info mapping).
                    await workflow.execute_activity(
                        "FinalizeSubScanActivity",
                        args=[ctx, success],
                        start_to_close_timeout=timedelta(seconds=60),
                        heartbeat_timeout=timedelta(minutes=5),
                        retry_policy=_RETRY_INTERNAL,
                        task_queue="python-orchestrator-queue"
                    )

        return {"status": "SUCCESS"}
