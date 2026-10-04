"""
Maintenance, scheduling and single-activity job workflows.

Monitoring / scheduled-scan / startup-sync bookkeeping, the Go executor task
wrapper, the small one-activity workflows (APME, identity enrichment, geo,
HackerOne, proxies, certificates), SingleTaskRetryWorkflow and
FollowupPlanWorkflow. Deterministic orchestrators only.
"""

from datetime import timedelta
from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ActivityError, ApplicationError, ChildWorkflowError

from reNgine.temporal.workflows._common import (
    _RETRY_INTERNAL,
    _RETRY_LLM,
    _RETRY_LONG_SCAN,
    _RETRY_NETWORK_SCAN,
)


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
        """Run the remote subprocess activity on the caller's Go executor queue.

        Args:
            input_data (dict): Dictionary containing command details:
                - command (list): The command split into parts (binary + arguments)
                - scan_id (int): Associated Scan History ID
                - command_id (int): Database record Command ID to log stdout/stderr to
                - timeout_seconds (int, optional): Custom execution timeout in seconds
                - executor_task_queue (str, optional): Go executor queue of the host
                  that started this workflow (``reNgine.utils.task_queues.go_executor_queue``).
                  Defaults to the master's queue for inputs recorded before the
                  key existed, so replays of those runs stay deterministic.

        Returns:
            dict: The output result of the subprocess execution, including stdout, stderr,
                  and exit code.
        """
        timeout_sec = input_data.get("timeout_seconds") or 43200
        # The queue comes from the caller, never from this process's environment:
        # a workflow must not read env vars, and the executor that runs the tool
        # has to be the one co-located with the Python host that parses its output.
        executor_queue = input_data.get("executor_task_queue") or "go-executor-queue"
        return await workflow.execute_activity(
            "RunToolSubprocessActivity",
            input_data,
            start_to_close_timeout=timedelta(seconds=timeout_sec),
            # Bound the total wall-time across retries: a tool can run for hours, and
            # the usual retryable failure here is a heartbeat timeout after the executor
            # container restarted, which re-runs the whole tool from scratch.
            schedule_to_close_timeout=timedelta(seconds=int(timeout_sec * 2.2)),
            heartbeat_timeout=timedelta(minutes=10),
            retry_policy=_RETRY_LONG_SCAN,
            task_queue=executor_queue,
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


@workflow.defn(name="ToolProbeWorkflow")
class ToolProbeWorkflow:
    """Run one tool inventory probe on the Python orchestrator and return its answer.

    Started by ``reNgine.tool_workers.dispatch_probe`` from processes that do
    not host the scan tools (the web container). The caller waits for the
    result, so a failed probe surfaces at once rather than being retried while
    a request or management command blocks on it.
    """

    @workflow.run
    async def run(self, op: str, payload: dict) -> dict:
        return await workflow.execute_activity(
            "ToolProbeActivity",
            args=[op, payload],
            start_to_close_timeout=timedelta(minutes=15),
            heartbeat_timeout=timedelta(minutes=2),
            retry_policy=RetryPolicy(maximum_attempts=1),
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


@workflow.defn(name="CertificateResyncWorkflow")
class CertificateResyncWorkflow:
    """Workflow to re-probe a single certificate's host via tlsx on demand."""

    @workflow.run
    async def run(self, cert_id: int, job_id: str = None) -> dict:
        return await workflow.execute_activity(
            "resync_certificate_activity",
            args=[cert_id, job_id],
            start_to_close_timeout=timedelta(minutes=5),
            heartbeat_timeout=timedelta(minutes=2),
            retry_policy=RetryPolicy(maximum_attempts=2),
            task_queue="python-orchestrator-queue",
        )


@workflow.defn(name="SingleTaskRetryWorkflow")
class SingleTaskRetryWorkflow:
    """Workflow to retry a single task from a completed scan.
    """

    @workflow.run
    async def run(self, ctx: dict, task_name: str) -> dict:
        with workflow.unsafe.imports_passed_through():
            from reNgine.definitions import SUCCESS_TASK, FAILED_TASK

        scan_id: int = ctx.get("scan_history_id")
        workflow.logger.info(
            "SingleTaskRetryWorkflow: scan_id=%s task=%s", scan_id, task_name
        )

        task_succeeded = False
        try:
            if task_name == "subdomain_discovery":
                await workflow.execute_activity("RunSubdomainDiscoveryActivity", ctx, start_to_close_timeout=timedelta(hours=4), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_LONG_SCAN, task_queue="python-orchestrator-queue")
                await workflow.execute_activity("ParseDiscoveryResultsActivity", ctx, start_to_close_timeout=timedelta(minutes=15), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_INTERNAL, task_queue="python-orchestrator-queue")
            elif task_name == "amass_intel_discovery":
                await workflow.execute_activity("RunAmassIntelDiscoveryActivity", ctx, start_to_close_timeout=timedelta(hours=2), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_LONG_SCAN, task_queue="python-orchestrator-queue")
                await workflow.execute_activity("ParseDiscoveryResultsActivity", ctx, start_to_close_timeout=timedelta(minutes=15), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_INTERNAL, task_queue="python-orchestrator-queue")
            elif task_name == "firewall_vpn_scan":
                await workflow.execute_activity("RunFirewallVPNScanActivity", ctx, start_to_close_timeout=timedelta(minutes=30), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_NETWORK_SCAN, task_queue="python-orchestrator-queue")
                await workflow.execute_activity("ParseDiscoveryResultsActivity", ctx, start_to_close_timeout=timedelta(minutes=15), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_INTERNAL, task_queue="python-orchestrator-queue")
            elif task_name == "dns_security":
                await workflow.execute_activity("RunDNSSecurityActivity", ctx, start_to_close_timeout=timedelta(hours=1), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_NETWORK_SCAN, task_queue="python-orchestrator-queue")
                await workflow.execute_activity("ParseDiscoveryResultsActivity", ctx, start_to_close_timeout=timedelta(minutes=15), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_INTERNAL, task_queue="python-orchestrator-queue")
            elif task_name == "osint":
                await workflow.execute_activity("RunGenericTaskActivity", args=[ctx, "osint", "OSINT Scan"], start_to_close_timeout=timedelta(hours=4), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_LONG_SCAN, task_queue="python-orchestrator-queue")
                await workflow.execute_activity("ParseDiscoveryResultsActivity", ctx, start_to_close_timeout=timedelta(minutes=15), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_INTERNAL, task_queue="python-orchestrator-queue")
            elif task_name == "spiderfoot_scan":
                await workflow.execute_activity("RunGenericTaskActivity", args=[ctx, "spiderfoot_scan", "SpiderFoot Attack Surface Intelligence"], start_to_close_timeout=timedelta(hours=24), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_LONG_SCAN, task_queue="python-orchestrator-queue")
                await workflow.execute_activity("ParseDiscoveryResultsActivity", ctx, start_to_close_timeout=timedelta(minutes=15), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_INTERNAL, task_queue="python-orchestrator-queue")
            elif task_name == "http_crawl":
                ctx = await workflow.execute_activity("SeedEndpointsForCrawlActivity", ctx, start_to_close_timeout=timedelta(minutes=5), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_INTERNAL, task_queue="python-orchestrator-queue")
                await workflow.execute_activity("RunHTTPCrawlActivity", ctx, start_to_close_timeout=timedelta(hours=3), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_LONG_SCAN, task_queue="python-orchestrator-queue")
                await workflow.execute_activity("ParseHTTPCrawlResultsActivity", ctx, start_to_close_timeout=timedelta(minutes=15), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_INTERNAL, task_queue="python-orchestrator-queue")
            elif task_name == "port_scan":
                await workflow.execute_activity("RunPortScanActivity", ctx, start_to_close_timeout=timedelta(hours=6), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_LONG_SCAN, task_queue="python-orchestrator-queue")
                await workflow.execute_activity("ParseEnumerationResultsActivity", ctx, start_to_close_timeout=timedelta(minutes=5), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_INTERNAL, task_queue="python-orchestrator-queue")
            elif task_name == "vigolium_harvest":
                await workflow.execute_activity("RunVigoliumHarvestActivity", ctx, start_to_close_timeout=timedelta(hours=6), heartbeat_timeout=timedelta(minutes=10), retry_policy=_RETRY_LONG_SCAN, task_queue="python-orchestrator-queue")
            elif task_name == "vigolium_discovery":
                await workflow.execute_activity("RunVigoliumDiscoveryActivity", ctx, start_to_close_timeout=timedelta(hours=8), heartbeat_timeout=timedelta(minutes=10), retry_policy=_RETRY_LONG_SCAN, task_queue="python-orchestrator-queue")
            elif task_name == "vigolium_scan":
                await workflow.execute_activity("RunVigoliumScanActivity", ctx, start_to_close_timeout=timedelta(hours=12), heartbeat_timeout=timedelta(minutes=10), retry_policy=_RETRY_LONG_SCAN, task_queue="python-orchestrator-queue")
            elif task_name == "fetch_url":
                await workflow.execute_activity("RunFetchURLActivity", ctx, start_to_close_timeout=timedelta(hours=8), heartbeat_timeout=timedelta(minutes=15), retry_policy=_RETRY_LONG_SCAN, task_queue="python-orchestrator-queue")
                await workflow.execute_activity("RunHTTPCrawlBridgeActivity", ctx, start_to_close_timeout=timedelta(hours=3), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_LONG_SCAN, task_queue="python-orchestrator-queue")
            elif task_name == "screenshot":
                await workflow.execute_activity("RunScreenshotActivity", ctx, start_to_close_timeout=timedelta(hours=1), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_NETWORK_SCAN, task_queue="python-orchestrator-queue")
            elif task_name == "web_api_discovery":
                await workflow.execute_activity("RunWebAPIDiscoveryActivity", ctx, start_to_close_timeout=timedelta(hours=4), heartbeat_timeout=timedelta(minutes=10), retry_policy=_RETRY_NETWORK_SCAN, task_queue="python-orchestrator-queue")
            elif task_name == "param_discovery":
                await workflow.execute_activity("RunParamDiscoveryActivity", ctx, start_to_close_timeout=timedelta(hours=2), heartbeat_timeout=timedelta(minutes=10), retry_policy=_RETRY_LONG_SCAN, task_queue="python-orchestrator-queue")
            elif task_name == "dir_file_fuzz":
                await workflow.execute_activity("RunDirFileFuzzActivity", ctx, start_to_close_timeout=timedelta(hours=8), heartbeat_timeout=timedelta(minutes=15), retry_policy=_RETRY_LONG_SCAN, task_queue="python-orchestrator-queue")
                await workflow.execute_activity("ParseFuzzResultsActivity", ctx, start_to_close_timeout=timedelta(minutes=15), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_INTERNAL, task_queue="python-orchestrator-queue")
                await workflow.execute_activity("RunGFOnAllEndpointsActivity", ctx, start_to_close_timeout=timedelta(minutes=30), heartbeat_timeout=timedelta(minutes=10), retry_policy=_RETRY_INTERNAL, task_queue="python-orchestrator-queue")
            elif task_name == "waf_detection":
                await workflow.execute_activity("RunWAFDetectionActivity", ctx, start_to_close_timeout=timedelta(minutes=30), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_NETWORK_SCAN, task_queue="python-orchestrator-queue")
                await workflow.execute_activity("ParseAnalysisResultsActivity", ctx, start_to_close_timeout=timedelta(minutes=5), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_INTERNAL, task_queue="python-orchestrator-queue")
            elif task_name == "secret_scanning":
                await workflow.execute_activity("RunSecretScanningActivity", ctx, start_to_close_timeout=timedelta(hours=2), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_LONG_SCAN, task_queue="python-orchestrator-queue")
                await workflow.execute_activity("ParseAnalysisResultsActivity", ctx, start_to_close_timeout=timedelta(minutes=5), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_INTERNAL, task_queue="python-orchestrator-queue")
            elif task_name == "vigolium_analysis":
                await workflow.execute_activity("RunVigoliumAnalysisActivity", ctx, start_to_close_timeout=timedelta(hours=12), heartbeat_timeout=timedelta(minutes=10), retry_policy=_RETRY_LONG_SCAN, task_queue="python-orchestrator-queue")
                await workflow.execute_activity("ParseAnalysisResultsActivity", ctx, start_to_close_timeout=timedelta(minutes=5), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_INTERNAL, task_queue="python-orchestrator-queue")
            elif task_name == "vulnerability_scan":
                await workflow.execute_child_workflow("NucleiPlannerWorkflow", ctx, id=f"{workflow.info().workflow_id}-nuclei", task_queue="python-orchestrator-queue", execution_timeout=timedelta(days=7), run_timeout=timedelta(days=7), retry_policy=RetryPolicy(maximum_attempts=1))
                await workflow.execute_activity("ParseAssessmentResultsActivity", ctx, start_to_close_timeout=timedelta(minutes=5), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_INTERNAL, task_queue="python-orchestrator-queue")
                await workflow.execute_activity("CorrelateVulnerabilitiesActivity", ctx, start_to_close_timeout=timedelta(minutes=90), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_INTERNAL, task_queue="python-orchestrator-queue")
                await workflow.execute_activity("CorrelateExposuresActivity", ctx, start_to_close_timeout=timedelta(minutes=30), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_INTERNAL, task_queue="python-orchestrator-queue")
                await workflow.execute_activity("EnrichScanCVEsActivity", ctx, start_to_close_timeout=timedelta(hours=2), heartbeat_timeout=timedelta(minutes=15), retry_policy=_RETRY_INTERNAL, task_queue="python-orchestrator-queue")
                await workflow.execute_activity("CalculateRiskScoresActivity", ctx, start_to_close_timeout=timedelta(minutes=30), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_INTERNAL, task_queue="python-orchestrator-queue")
                await workflow.execute_activity("GenerateImpactAssessmentActivity", ctx, start_to_close_timeout=timedelta(hours=1), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_LLM, task_queue="python-orchestrator-queue")
            elif task_name == "nuclei_scan":
                # Narrow retry: re-run Nuclei + parse only — not correlate/enrich/risk/impact.
                await workflow.execute_child_workflow("NucleiPlannerWorkflow", ctx, id=f"{workflow.info().workflow_id}-nuclei", task_queue="python-orchestrator-queue", execution_timeout=timedelta(days=7), run_timeout=timedelta(days=7), retry_policy=RetryPolicy(maximum_attempts=1))
                await workflow.execute_activity("ParseAssessmentResultsActivity", ctx, start_to_close_timeout=timedelta(minutes=5), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_INTERNAL, task_queue="python-orchestrator-queue")
            elif task_name == "dalfox_xss_scan":
                await workflow.execute_activity("RunDalfoxActivity", ctx, start_to_close_timeout=timedelta(hours=2), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_LONG_SCAN, task_queue="python-orchestrator-queue")
            elif task_name == "waf_bypass":
                await workflow.execute_activity("RunWAFBypassActivity", ctx, start_to_close_timeout=timedelta(hours=1), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_NETWORK_SCAN, task_queue="python-orchestrator-queue")
            elif task_name == "post_crawl_osint":
                await workflow.execute_activity("RunGenericTaskActivity", args=[ctx, "post_crawl_osint", "Post-Crawl OSINT"], start_to_close_timeout=timedelta(hours=2), heartbeat_timeout=timedelta(minutes=10), retry_policy=_RETRY_LONG_SCAN, task_queue="python-orchestrator-queue")
            elif task_name == "http_crawl_bridge":
                await workflow.execute_activity("RunHTTPCrawlBridgeActivity", ctx, start_to_close_timeout=timedelta(hours=3), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_LONG_SCAN, task_queue="python-orchestrator-queue")
            elif task_name in ("check_if_email_exists", "email_security", "mailbox_verification"):
                await workflow.execute_activity(
                    "RunEmailSecurityActivity",
                    ctx,
                    # Match MasterScanWorkflow: 2h stopped the restart loop on
                    # targets with many mail hosts (upstream's 90m was too short).
                    start_to_close_timeout=timedelta(hours=2),
                    heartbeat_timeout=timedelta(minutes=10),
                    retry_policy=_RETRY_NETWORK_SCAN,
                    task_queue="python-orchestrator-queue",
                )
            elif task_name == "generate_impact_assessment":
                await workflow.execute_activity("GenerateImpactAssessmentActivity", ctx, start_to_close_timeout=timedelta(hours=1), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_LLM, task_queue="python-orchestrator-queue")
            elif task_name == "correlate_vulnerabilities":
                await workflow.execute_activity("CorrelateVulnerabilitiesActivity", ctx, start_to_close_timeout=timedelta(minutes=90), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_INTERNAL, task_queue="python-orchestrator-queue")
            elif task_name == "calculate_risk_scores":
                await workflow.execute_activity("CalculateRiskScoresActivity", ctx, start_to_close_timeout=timedelta(minutes=30), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_INTERNAL, task_queue="python-orchestrator-queue")
            elif task_name == "sync_graph":
                await workflow.execute_activity("SyncGraphActivity", ctx, start_to_close_timeout=timedelta(minutes=30), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_NETWORK_SCAN, task_queue="python-orchestrator-queue")
            elif task_name in ("run_apme", "attack_path_modeling"):
                await workflow.execute_activity("RunGenericTaskActivity", args=[ctx, "run_apme", "Attack Path Modeling"], start_to_close_timeout=timedelta(hours=1), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_INTERNAL, task_queue="python-orchestrator-queue")
            elif task_name == "run_acunetix":
                await workflow.execute_activity("RunAcunetixActivity", ctx, start_to_close_timeout=timedelta(hours=4), heartbeat_timeout=timedelta(minutes=5), retry_policy=_RETRY_LONG_SCAN, task_queue="python-orchestrator-queue")
            elif task_name == "acunetix_submit":
                await workflow.execute_activity(
                    "SubmitLiveSubdomainsToAcunetixActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=1),
                    heartbeat_timeout=timedelta(minutes=5),
                    retry_policy=_RETRY_NETWORK_SCAN,
                    task_queue="python-orchestrator-queue",
                )
            else:
                raise ApplicationError(
                    f"Unrecognised task_name for retry: {task_name}",
                    non_retryable=True,
                )

            task_succeeded = True

        except (ActivityError, ChildWorkflowError, ApplicationError) as exc:
            workflow.logger.error(
                "SingleTaskRetryWorkflow: task=%s failed — %s", task_name, exc
            )

        original_scan_status = ctx.get("original_scan_status")

        # Always run final-status so an unclaimed INITIATED retry row is
        # restored to FAILED. Post-completion retries still force the scan
        # back to SUCCESS so a failed re-run cannot reopen a completed scan.
        final_status = await workflow.execute_activity(
            "GetScanFinalStatusActivity",
            args=[
                scan_id,
                task_succeeded,
                ctx.get("retry_batch_names") or [],
                task_name,
                ctx.get("activity_id"),
            ],
            start_to_close_timeout=timedelta(minutes=2),
            retry_policy=_RETRY_INTERNAL,
            task_queue="python-orchestrator-queue",
        )
        if original_scan_status == SUCCESS_TASK:
            final_status = SUCCESS_TASK

        await workflow.execute_activity(
            "UpdateScanStatusActivity",
            args=[scan_id, final_status],
            start_to_close_timeout=timedelta(minutes=2),
            retry_policy=_RETRY_INTERNAL,
            task_queue="python-orchestrator-queue",
        )

        return {"status": "SUCCESS" if task_succeeded else "FAILED", "task_name": task_name}


@workflow.defn(name="FollowupPlanWorkflow")
class FollowupPlanWorkflow:
    """Execute follow-up plan steps sequentially; stop on first failure unless continue_on_error."""

    @workflow.run
    async def run(self, payload: dict) -> dict:
        plan_id = payload.get('plan_id')
        only_step_ids = payload.get('step_ids')  # optional filter for retry
        plan = await workflow.execute_activity(
            "FollowupLoadPlanActivity",
            args=[plan_id],
            start_to_close_timeout=timedelta(minutes=2),
            retry_policy=_RETRY_INTERNAL,
            task_queue="python-orchestrator-queue",
        )
        steps = plan.get('steps') or []
        if only_step_ids:
            id_set = set(only_step_ids)
            steps = [s for s in steps if s.get('id') in id_set]

        overall_ok = True
        for step in steps:
            if step.get('status') == 'succeeded':
                continue
            aborted = await workflow.execute_activity(
                "FollowupCheckAbortActivity",
                args=[plan_id],
                start_to_close_timeout=timedelta(seconds=30),
                retry_policy=_RETRY_INTERNAL,
                task_queue="python-orchestrator-queue",
            )
            if aborted:
                overall_ok = False
                break

            await workflow.execute_activity(
                "FollowupUpdateStepActivity",
                args=[plan_id, step['id'], 'running', None, None, None],
                start_to_close_timeout=timedelta(minutes=2),
                retry_policy=_RETRY_INTERNAL,
                task_queue="python-orchestrator-queue",
            )

            result = await workflow.execute_activity(
                "FollowupDispatchStepActivity",
                args=[plan_id, step],
                start_to_close_timeout=timedelta(minutes=10),
                retry_policy=_RETRY_INTERNAL,
                task_queue="python-orchestrator-queue",
            )
            if not result.get('ok'):
                overall_ok = False
                await workflow.execute_activity(
                    "FollowupUpdateStepActivity",
                    args=[plan_id, step['id'], 'failed', result.get('error') or 'dispatch failed', None, None],
                    start_to_close_timeout=timedelta(minutes=2),
                    retry_policy=_RETRY_INTERNAL,
                    task_queue="python-orchestrator-queue",
                )
                if not step.get('continue_on_error'):
                    break
                continue

            wf_id = result.get('workflow_id')
            act_id = result.get('activity_id')
            await workflow.execute_activity(
                "FollowupUpdateStepActivity",
                args=[plan_id, step['id'], 'running', None, wf_id, act_id],
                start_to_close_timeout=timedelta(minutes=2),
                retry_policy=_RETRY_INTERNAL,
                task_queue="python-orchestrator-queue",
            )

            if result.get('wait') and wf_id:
                wait_res = await workflow.execute_activity(
                    "FollowupWaitWorkflowActivity",
                    args=[wf_id],
                    start_to_close_timeout=timedelta(hours=48),
                    heartbeat_timeout=timedelta(minutes=5),
                    retry_policy=_RETRY_INTERNAL,
                    task_queue="python-orchestrator-queue",
                )
                # Also wait extra workflow ids from subscan fan-out
                for extra in result.get('workflow_ids') or []:
                    if extra and extra != wf_id:
                        await workflow.execute_activity(
                            "FollowupWaitWorkflowActivity",
                            args=[extra],
                            start_to_close_timeout=timedelta(hours=48),
                            heartbeat_timeout=timedelta(minutes=5),
                            retry_policy=_RETRY_INTERNAL,
                            task_queue="python-orchestrator-queue",
                        )
                if not wait_res.get('ok'):
                    overall_ok = False
                    await workflow.execute_activity(
                        "FollowupUpdateStepActivity",
                        args=[plan_id, step['id'], 'failed', wait_res.get('error') or 'step failed', wf_id, act_id],
                        start_to_close_timeout=timedelta(minutes=2),
                        retry_policy=_RETRY_INTERNAL,
                        task_queue="python-orchestrator-queue",
                    )
                    if not step.get('continue_on_error'):
                        break
                    continue

            await workflow.execute_activity(
                "FollowupUpdateStepActivity",
                args=[plan_id, step['id'], 'succeeded', None, wf_id, act_id],
                start_to_close_timeout=timedelta(minutes=2),
                retry_policy=_RETRY_INTERNAL,
                task_queue="python-orchestrator-queue",
            )

        final = await workflow.execute_activity(
            "FollowupFinalizePlanActivity",
            args=[plan_id, overall_ok],
            start_to_close_timeout=timedelta(minutes=2),
            retry_policy=_RETRY_INTERNAL,
            task_queue="python-orchestrator-queue",
        )
        return {'plan_id': plan_id, **final}
