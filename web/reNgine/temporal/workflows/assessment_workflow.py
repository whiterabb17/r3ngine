"""Assessment Temporal workflows.

Hierarchy:
  AssessmentWorkflow (orchestrator)
    ├── DiscoveryWorkflow    — Tier 1: subdomain discovery, passive OSINT
    ├── EnumerationWorkflow  — Tier 2/3/4: crawl, ports, fetch, fuzz
    ├── AnalysisWorkflow     — Tier 5/6: WAF, secrets, nuclei vulnerability scan
    ├── ValidationWorkflow   — Wait state: blocks until analyst sends approval signal
    └── ReportingWorkflow    — Tier 7: correlate, risk, AI reports, graph sync

Each child workflow calls PrepareAssessmentContextActivity to obtain a
ScanContext dict, then fans out the same existing Temporal activities used by
MasterScanWorkflow. All workflows run on "python-orchestrator-queue".
"""
from datetime import timedelta
import asyncio
from dataclasses import dataclass, field
from typing import List, Dict, Any, Optional

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ApplicationError

with workflow.unsafe.imports_passed_through():
    from reNgine.temporal.activities.assessment_activities import (
        StateTransitionInput,
        PrepareAssessmentContextInput,
        update_assessment_state_activity,
        scan_orchestrator_activity,
        prepare_assessment_context_activity,
    )
    from reNgine.temporal.activities.asset_correlation_activities import (
        run_asset_correlation_activity,
    )
    from reNgine.temporal.activities.graph_activities import (
        sync_assessment_graph_activity,
    )

# ---------------------------------------------------------------------------
# Shared dataclasses
# ---------------------------------------------------------------------------

@dataclass
class AssessmentInput:
    """Input contract for AssessmentWorkflow and all its child workflows."""
    assessment_id: str
    engagement_id: str
    assessment_type: str
    scope_ids: List[str] = field(default_factory=list)


@dataclass
class AssessmentResult:
    """Result returned by AssessmentWorkflow on completion."""
    assessment_id: str
    status: str
    findings_count: int
    evidence_count: int


# ---------------------------------------------------------------------------
# Retry policies
# ---------------------------------------------------------------------------

# Standard: used for most scan activities (retried up to 5 times)
_standard_retry = RetryPolicy(
    initial_interval=timedelta(seconds=5),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(minutes=5),
    maximum_attempts=5,
)

# Long-running: used for scan activities that may take hours (nuclei, crawl, etc.)
_long_retry = RetryPolicy(
    initial_interval=timedelta(seconds=10),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(minutes=10),
    maximum_attempts=3,
)

# Short: used for state-update activities that should fail fast
_short_retry = RetryPolicy(
    initial_interval=timedelta(seconds=2),
    backoff_coefficient=1.5,
    maximum_interval=timedelta(seconds=30),
    maximum_attempts=3,
)

# Task queue all assessment workflows and activities run on
_TASK_QUEUE = "python-orchestrator-queue"


# ---------------------------------------------------------------------------
# Helper: call PrepareAssessmentContextActivity from a child workflow
# ---------------------------------------------------------------------------

async def _prepare_ctx(input: AssessmentInput) -> Dict[str, Any]:
    """Execute PrepareAssessmentContextActivity and return ScanContext dict.

    Args:
        input (AssessmentInput): The assessment input from the parent workflow.

    Returns:
        dict: Fully populated ScanContext ready for scan activities.
    """
    return await workflow.execute_activity(
        "PrepareAssessmentContextActivity",
        PrepareAssessmentContextInput(
            assessment_id=input.assessment_id,
            assessment_type=input.assessment_type,
            scope_ids=input.scope_ids,
        ),
        start_to_close_timeout=timedelta(minutes=5),
        retry_policy=_short_retry,
        task_queue=_TASK_QUEUE,
    )


# ---------------------------------------------------------------------------
# DiscoveryWorkflow — Tier 1
# ---------------------------------------------------------------------------

@workflow.defn
class DiscoveryWorkflow:
    """Tier 1 discovery phase: subdomain enumeration, passive OSINT, DNS.

    Runs subdomain discovery, amass intel, DNS security checks, and vigolium
    passive harvest in parallel, then parses and seeds the results.
    """

    @workflow.run
    async def run(self, input: AssessmentInput) -> bool:
        """Execute the discovery phase.

        Args:
            input (AssessmentInput): Assessment identifiers and scope.

        Returns:
            bool: True on success, raises on failure.
        """
        workflow.logger.info(f"[DiscoveryWorkflow] Starting for assessment {input.assessment_id}")

        # Build ScanContext — creates Domain + ScanHistory linked to Assessment
        ctx = await _prepare_ctx(input)
        tasks = ctx.get("tasks", [])

        # ------------------------------------------------------------------ #
        # Tier 1: Run discovery activities in parallel
        # ------------------------------------------------------------------ #
        discovery_futures = []

        if "subdomain_discovery" in tasks:
            discovery_futures.append(
                workflow.execute_activity(
                    "RunSubdomainDiscoveryActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=4),
                    retry_policy=_long_retry,
                    task_queue=_TASK_QUEUE,
                )
            )

        if "amass_intel_discovery" in tasks:
            discovery_futures.append(
                workflow.execute_activity(
                    "RunAmassIntelDiscoveryActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=2),
                    retry_policy=_long_retry,
                    task_queue=_TASK_QUEUE,
                )
            )

        if "dns_security" in tasks:
            discovery_futures.append(
                workflow.execute_activity(
                    "RunDNSSecurityActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=1),
                    retry_policy=_standard_retry,
                    task_queue=_TASK_QUEUE,
                )
            )

        if "firewall_vpn" in tasks:
            discovery_futures.append(
                workflow.execute_activity(
                    "RunFirewallVPNScanActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=1),
                    retry_policy=_standard_retry,
                    task_queue=_TASK_QUEUE,
                )
            )

        # Vigolium passive harvest always runs as it is non-intrusive
        discovery_futures.append(
            workflow.execute_activity(
                "RunVigoliumHarvestActivity",
                ctx,
                start_to_close_timeout=timedelta(hours=6),
                retry_policy=_long_retry,
                task_queue=_TASK_QUEUE,
            )
        )

        if discovery_futures:
            try:
                await asyncio.gather(*discovery_futures, return_exceptions=True)
            except Exception as e:
                workflow.logger.warning(f"[DiscoveryWorkflow] Some discovery activities failed (non-fatal): {e}")

        # Parse and persist discovery results
        await workflow.execute_activity(
            "ParseDiscoveryResultsActivity",
            ctx,
            start_to_close_timeout=timedelta(hours=1),
            retry_policy=_standard_retry,
            task_queue=_TASK_QUEUE,
        )

        workflow.logger.info(f"[DiscoveryWorkflow] Completed for assessment {input.assessment_id}")
        return True


# ---------------------------------------------------------------------------
# EnumerationWorkflow — Tier 2 / 3 / 4
# ---------------------------------------------------------------------------

@workflow.defn
class EnumerationWorkflow:
    """Tier 2/3/4 enumeration phase: HTTP crawl, port scan, fetch URLs, fuzzing.

    Runs HTTP crawl and port scan in parallel (Tier 2), then URL fetching
    (Tier 3), then directory/file fuzzing (Tier 4) if configured.
    """

    @workflow.run
    async def run(self, input: AssessmentInput) -> bool:
        """Execute the enumeration phase.

        Args:
            input (AssessmentInput): Assessment identifiers and scope.

        Returns:
            bool: True on success, raises on failure.
        """
        workflow.logger.info(f"[EnumerationWorkflow] Starting for assessment {input.assessment_id}")

        ctx = await _prepare_ctx(input)
        tasks = ctx.get("tasks", [])

        # ------------------------------------------------------------------ #
        # Tier 2: HTTP crawl + port scan in parallel
        # ------------------------------------------------------------------ #
        tier2_futures = []

        if "http_crawl" in tasks:
            async def _crawl_pipeline():
                # Seed known endpoints for crawl
                await workflow.execute_activity(
                    "SeedEndpointsForCrawlActivity",
                    ctx,
                    start_to_close_timeout=timedelta(minutes=30),
                    retry_policy=_standard_retry,
                    task_queue=_TASK_QUEUE,
                )
                # HTTP crawl
                await workflow.execute_activity(
                    "RunHTTPCrawlActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=4),
                    retry_policy=_long_retry,
                    task_queue=_TASK_QUEUE,
                )
                # Parse crawl results
                await workflow.execute_activity(
                    "ParseHTTPCrawlResultsActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=1),
                    retry_policy=_standard_retry,
                    task_queue=_TASK_QUEUE,
                )

            tier2_futures.append(_crawl_pipeline())

        if "port_scan" in tasks:
            tier2_futures.append(
                workflow.execute_activity(
                    "RunPortScanActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=4),
                    retry_policy=_long_retry,
                    task_queue=_TASK_QUEUE,
                )
            )

        if "screenshot" in tasks:
            tier2_futures.append(
                workflow.execute_activity(
                    "RunScreenshotActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=2),
                    retry_policy=_standard_retry,
                    task_queue=_TASK_QUEUE,
                )
            )

        if tier2_futures:
            try:
                await asyncio.gather(*tier2_futures, return_exceptions=True)
            except Exception as e:
                workflow.logger.warning(f"[EnumerationWorkflow] Tier 2 partial failure (non-fatal): {e}")

        # ------------------------------------------------------------------ #
        # Tier 3: Fetch URLs (passive)
        # ------------------------------------------------------------------ #
        if "fetch_url" in tasks:
            await workflow.execute_activity(
                "RunFetchURLActivity",
                ctx,
                start_to_close_timeout=timedelta(hours=3),
                retry_policy=_long_retry,
                task_queue=_TASK_QUEUE,
            )

        # ------------------------------------------------------------------ #
        # Tier 4: Directory / file fuzzing
        # ------------------------------------------------------------------ #
        if "dir_file_fuzz" in tasks:
            await workflow.execute_activity(
                "RunDirFileFuzzActivity",
                ctx,
                start_to_close_timeout=timedelta(hours=6),
                retry_policy=_long_retry,
                task_queue=_TASK_QUEUE,
            )
            await workflow.execute_activity(
                "ParseFuzzResultsActivity",
                ctx,
                start_to_close_timeout=timedelta(hours=1),
                retry_policy=_standard_retry,
                task_queue=_TASK_QUEUE,
            )

        if "param_discovery" in tasks:
            await workflow.execute_activity(
                "RunParamDiscoveryActivity",
                ctx,
                start_to_close_timeout=timedelta(hours=3),
                retry_policy=_long_retry,
                task_queue=_TASK_QUEUE,
            )

        # Parse and aggregate enumeration results
        await workflow.execute_activity(
            "ParseEnumerationResultsActivity",
            ctx,
            start_to_close_timeout=timedelta(hours=1),
            retry_policy=_standard_retry,
            task_queue=_TASK_QUEUE,
        )

        workflow.logger.info(f"[EnumerationWorkflow] Completed for assessment {input.assessment_id}")
        return True


# ---------------------------------------------------------------------------
# AnalysisWorkflow — Tier 5 / 6
# ---------------------------------------------------------------------------

@workflow.defn
class AnalysisWorkflow:
    """Tier 5/6 analysis phase: WAF detection, secret scanning, API discovery, nuclei.

    Runs Tier 5 (WAF, secrets, API discovery) in parallel, then Tier 6
    (nuclei vulnerability scanning via NucleiPlannerWorkflow child).
    """

    @workflow.run
    async def run(self, input: AssessmentInput) -> bool:
        """Execute the analysis phase.

        Args:
            input (AssessmentInput): Assessment identifiers and scope.

        Returns:
            bool: True on success, raises on failure.
        """
        workflow.logger.info(f"[AnalysisWorkflow] Starting for assessment {input.assessment_id}")

        ctx = await _prepare_ctx(input)
        tasks = ctx.get("tasks", [])

        # ------------------------------------------------------------------ #
        # Tier 5: Analysis activities in parallel
        # ------------------------------------------------------------------ #
        tier5_futures = []

        if "waf_detection" in tasks:
            tier5_futures.append(
                workflow.execute_activity(
                    "RunWAFDetectionActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=1),
                    retry_policy=_standard_retry,
                    task_queue=_TASK_QUEUE,
                )
            )

        if "secret_scanning" in tasks:
            tier5_futures.append(
                workflow.execute_activity(
                    "RunSecretScanningActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=2),
                    retry_policy=_long_retry,
                    task_queue=_TASK_QUEUE,
                )
            )

        if "web_api_discovery" in tasks:
            tier5_futures.append(
                workflow.execute_activity(
                    "RunWebAPIDiscoveryActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=2),
                    retry_policy=_long_retry,
                    task_queue=_TASK_QUEUE,
                )
            )

        if tier5_futures:
            try:
                await asyncio.gather(*tier5_futures, return_exceptions=True)
            except Exception as e:
                workflow.logger.warning(f"[AnalysisWorkflow] Tier 5 partial failure (non-fatal): {e}")

            await workflow.execute_activity(
                "ParseAnalysisResultsActivity",
                ctx,
                start_to_close_timeout=timedelta(hours=1),
                retry_policy=_standard_retry,
                task_queue=_TASK_QUEUE,
            )

        # ------------------------------------------------------------------ #
        # Tier 6: Nuclei vulnerability scanning (via NucleiPlannerWorkflow child)
        # ------------------------------------------------------------------ #
        if "vulnerability_scan" in tasks:
            workflow.logger.info(f"[AnalysisWorkflow] Launching NucleiPlannerWorkflow child")
            try:
                await workflow.execute_child_workflow(
                    "NucleiPlannerWorkflow",
                    ctx,
                    id=f"{workflow.info().workflow_id}-nuclei",
                    task_queue=_TASK_QUEUE,
                    execution_timeout=timedelta(days=7),
                    retry_policy=_long_retry,
                )
            except Exception as nuclei_err:
                # Nuclei failure is non-fatal — log and continue
                workflow.logger.error(f"[AnalysisWorkflow] NucleiPlannerWorkflow error: {nuclei_err}")

            await workflow.execute_activity(
                "ParseAssessmentResultsActivity",
                ctx,
                start_to_close_timeout=timedelta(hours=1),
                retry_policy=_standard_retry,
                task_queue=_TASK_QUEUE,
            )

        workflow.logger.info(f"[AnalysisWorkflow] Completed for assessment {input.assessment_id}")
        return True


# ---------------------------------------------------------------------------
# ValidationWorkflow — analyst wait state
# ---------------------------------------------------------------------------

@workflow.defn
class ValidationWorkflow:
    """Analyst validation gate.

    Blocks workflow execution until an analyst sends the 'validation_approved'
    signal via POST /api/engagements/assessments/{id}/approve-validation/.
    Times out after 30 days if no signal is received.
    """

    def __init__(self):
        self._approved = False

    @workflow.signal
    def validation_approved(self) -> None:
        """Signal from analyst approving findings and allowing Reporting to proceed."""
        workflow.logger.info("[ValidationWorkflow] validation_approved signal received")
        self._approved = True

    @workflow.run
    async def run(self, input: AssessmentInput) -> bool:
        """Wait for analyst approval signal.

        Args:
            input (AssessmentInput): Assessment identifiers (used for logging).

        Returns:
            bool: True when approved, False if timed out.
        """
        workflow.logger.info(
            f"[ValidationWorkflow] Waiting for analyst approval for assessment {input.assessment_id}"
        )

        # Run auto-validation activity first
        await workflow.execute_activity(
            "auto_validate_findings_activity",
            input.assessment_id,
            start_to_close_timeout=timedelta(minutes=10),
            retry_policy=_standard_retry,
            task_queue=_TASK_QUEUE,
        )

        # Block until validation_approved signal received, or 30-day timeout
        try:
            await workflow.wait_condition(
                lambda: self._approved,
                timeout=timedelta(days=30),
            )
            workflow.logger.info(f"[ValidationWorkflow] Approved for assessment {input.assessment_id}")
            return True
        except asyncio.TimeoutError:
            workflow.logger.warning(
                f"[ValidationWorkflow] Timed out waiting for approval for assessment {input.assessment_id}"
            )
            return False


# ---------------------------------------------------------------------------
# ReportingWorkflow — Tier 7
# ---------------------------------------------------------------------------

@workflow.defn
class ReportingWorkflow:
    """Tier 7 reporting phase: vulnerability correlation, risk scoring, AI reports, graph sync.

    Runs correlation, enrichment, and risk scoring activities, then generates
    AI-powered impact assessments, syncs the Neo4j graph, and sends notifications.
    """

    @workflow.run
    async def run(self, input: AssessmentInput) -> bool:
        """Execute the reporting phase.

        Args:
            input (AssessmentInput): Assessment identifiers and scope.

        Returns:
            bool: True on success, raises on failure.
        """
        workflow.logger.info(f"[ReportingWorkflow] Starting for assessment {input.assessment_id}")

        ctx = await _prepare_ctx(input)
        tasks = ctx.get("tasks", [])

        # ------------------------------------------------------------------ #
        # Tier 7: Post-processing (sequential — order matters for data deps)
        # ------------------------------------------------------------------ #
        if "vulnerability_scan" in tasks:
            # Correlate vulnerabilities across subdomains
            await workflow.execute_activity(
                "CorrelateVulnerabilitiesActivity",
                ctx,
                start_to_close_timeout=timedelta(hours=1),
                retry_policy=_standard_retry,
                task_queue=_TASK_QUEUE,
            )

            # Correlate exposure paths
            await workflow.execute_activity(
                "CorrelateExposuresActivity",
                ctx,
                start_to_close_timeout=timedelta(hours=1),
                retry_policy=_standard_retry,
                task_queue=_TASK_QUEUE,
            )

            # CVE enrichment (NVD + EPSS scores)
            await workflow.execute_activity(
                "EnrichScanCVEsActivity",
                ctx,
                start_to_close_timeout=timedelta(hours=2),
                retry_policy=_standard_retry,
                task_queue=_TASK_QUEUE,
            )

            # Risk score calculation
            await workflow.execute_activity(
                "CalculateRiskScoresActivity",
                ctx,
                start_to_close_timeout=timedelta(hours=1),
                retry_policy=_standard_retry,
                task_queue=_TASK_QUEUE,
            )

            # AI-powered impact assessment report
            await workflow.execute_activity(
                "GenerateImpactAssessmentActivity",
                ctx,
                start_to_close_timeout=timedelta(hours=2),
                retry_policy=_standard_retry,
                task_queue=_TASK_QUEUE,
            )

        # Sync to Neo4j attack surface graph
        await workflow.execute_activity(
            "SyncGraphActivity",
            ctx,
            start_to_close_timeout=timedelta(hours=2),
            retry_policy=_standard_retry,
            task_queue=_TASK_QUEUE,
        )

        # Send completion notification (Slack, Discord, Telegram, etc.)
        await workflow.execute_activity(
            "SendScanNotificationActivity",
            ctx,
            start_to_close_timeout=timedelta(minutes=10),
            retry_policy=_short_retry,
            task_queue=_TASK_QUEUE,
        )

        workflow.logger.info(f"[ReportingWorkflow] Completed for assessment {input.assessment_id}")
        return True


# ---------------------------------------------------------------------------
# AssessmentWorkflow — root orchestrator
# ---------------------------------------------------------------------------

@workflow.defn
class AssessmentWorkflow:
    """Root orchestrator for an end-to-end assessment.

    Launches and sequences child workflows:
        Discovery → Enumeration → Analysis → Validation (wait) → Reporting

    Supports pause/resume/cancel signals and exposes query handlers for
    the frontend to display real-time status and progress.
    """

    def __init__(self):
        self._status = "Draft"
        self._progress = 0
        self._current_stage = "Draft"
        self._assets_processed = 0
        self._findings_count = 0
        self._is_paused = False
        self._is_cancelled = False
        self._assessment_id = ""

    # ------------------------------------------------------------------ #
    # Signal handlers
    # ------------------------------------------------------------------ #

    @workflow.signal
    def pause_assessment(self) -> None:
        """Pause the assessment between phase transitions."""
        workflow.logger.info(f"[AssessmentWorkflow] Pause signal received")
        self._is_paused = True

    @workflow.signal
    def resume_assessment(self) -> None:
        """Resume a paused assessment."""
        workflow.logger.info(f"[AssessmentWorkflow] Resume signal received")
        self._is_paused = False

    @workflow.signal
    def cancel_assessment(self) -> None:
        """Cancel the assessment at the next phase transition checkpoint."""
        workflow.logger.info(f"[AssessmentWorkflow] Cancel signal received")
        self._is_cancelled = True

    @workflow.signal
    def update_scope(self, scope_data: Dict[str, Any]) -> None:
        """Update assessment scope (logged; scope changes take effect on next phase)."""
        workflow.logger.info(f"[AssessmentWorkflow] Scope updated: {scope_data}")

    # ------------------------------------------------------------------ #
    # Query handlers
    # ------------------------------------------------------------------ #

    @workflow.query
    def get_status(self) -> str:
        """Return current status, reflecting paused state if applicable."""
        return "Paused" if self._is_paused else self._status

    @workflow.query
    def get_progress(self) -> int:
        """Return progress percentage (0–100)."""
        return self._progress

    @workflow.query
    def get_current_stage(self) -> str:
        """Return the name of the currently executing phase."""
        return self._current_stage

    @workflow.query
    def get_assets_processed(self) -> int:
        """Return count of asset/scope items processed."""
        return self._assets_processed

    @workflow.query
    def get_findings_count(self) -> int:
        """Return total findings discovered so far."""
        return self._findings_count

    # ------------------------------------------------------------------ #
    # Internal helpers
    # ------------------------------------------------------------------ #

    async def _update_state(self, new_status: str, progress: int = None):
        """Transition the Assessment DB record to a new status and update internal state.

        Args:
            new_status (str): Target status (must be a valid AssessmentStateMachine state).
            progress (int, optional): Progress percentage to record.
        """
        self._status = new_status
        self._current_stage = new_status
        if progress is not None:
            self._progress = progress

        await workflow.execute_activity(
            update_assessment_state_activity,
            StateTransitionInput(
                assessment_id=self._assessment_id,
                new_status=new_status,
                event_data={"progress_percent": self._progress},
            ),
            start_to_close_timeout=timedelta(seconds=30),
            retry_policy=_short_retry,
        )

    async def _wait_if_paused(self):
        """Block execution at a phase checkpoint while paused.

        Breaks immediately if a cancel signal has been received.
        """
        while self._is_paused and not self._is_cancelled:
            await asyncio.sleep(5)

    # ------------------------------------------------------------------ #
    # Main run
    # ------------------------------------------------------------------ #

    @workflow.run
    async def run(self, input: AssessmentInput) -> AssessmentResult:
        """Orchestrate the full assessment lifecycle.

        Args:
            input (AssessmentInput): Assessment UUID, engagement UUID, type, and scope IDs.

        Returns:
            AssessmentResult: Final status summary.

        Raises:
            ApplicationError: If the assessment is cancelled or a phase raises.
        """
        self._assessment_id = input.assessment_id
        workflow.logger.info(f"[AssessmentWorkflow] Starting for assessment {self._assessment_id}")

        child_opts = {
            "task_queue": _TASK_QUEUE,
        }

        try:
            # ---------------------------------------------------------------- #
            # Phase 1: Discovery
            # ---------------------------------------------------------------- #
            await self._update_state("Discovery", 10)
            await self._wait_if_paused()
            if self._is_cancelled:
                raise ApplicationError("Assessment cancelled by user.", non_retryable=True)

            await workflow.execute_child_workflow(
                DiscoveryWorkflow.run,
                input,
                id=f"{workflow.info().workflow_id}-discovery",
                execution_timeout=timedelta(days=2),
                **child_opts,
            )

            # ---------------------------------------------------------------- #
            # Phase 2: Enumeration
            # ---------------------------------------------------------------- #
            await self._update_state("Enumeration", 30)
            await self._wait_if_paused()
            if self._is_cancelled:
                raise ApplicationError("Assessment cancelled by user.", non_retryable=True)

            await workflow.execute_child_workflow(
                EnumerationWorkflow.run,
                input,
                id=f"{workflow.info().workflow_id}-enumeration",
                execution_timeout=timedelta(days=3),
                **child_opts,
            )

            # ---------------------------------------------------------------- #
            # Phase 3: Analysis
            # ---------------------------------------------------------------- #
            await self._update_state("Analysis", 60)
            await self._wait_if_paused()
            if self._is_cancelled:
                raise ApplicationError("Assessment cancelled by user.", non_retryable=True)

            await workflow.execute_child_workflow(
                AnalysisWorkflow.run,
                input,
                id=f"{workflow.info().workflow_id}-analysis",
                execution_timeout=timedelta(days=3),
                **child_opts,
            )

            # ---------------------------------------------------------------- #
            # Phase 3b: Correlation (Phase 6)
            # ---------------------------------------------------------------- #
            await self._update_state("Correlation", 70)
            await self._wait_if_paused()
            if self._is_cancelled:
                raise ApplicationError("Assessment cancelled by user.", non_retryable=True)

            await workflow.execute_activity(
                run_asset_correlation_activity,
                self._assessment_id,
                start_to_close_timeout=timedelta(hours=1),
                retry_policy=_standard_retry,
                task_queue=_TASK_QUEUE,
            )

            # ---------------------------------------------------------------- #
            # Phase 4: Validation (analyst wait state)
            # ---------------------------------------------------------------- #
            await self._update_state("Validation", 80)
            # Note: do NOT check is_cancelled here — the analyst still needs
            # to review findings even if a cancel request was received during
            # an earlier phase. Cancel is honoured after validation completes.

            approved = await workflow.execute_child_workflow(
                ValidationWorkflow.run,
                input,
                id=f"{workflow.info().workflow_id}-validation",
                execution_timeout=timedelta(days=31),  # Slightly beyond 30-day inner timeout
                **child_opts,
            )

            if self._is_cancelled:
                raise ApplicationError("Assessment cancelled by user.", non_retryable=True)

            if not approved:
                # Validation timed out — transition to Review for manual intervention
                await self._update_state("Review", 80)
                return AssessmentResult(
                    assessment_id=self._assessment_id,
                    status="Review",
                    findings_count=self._findings_count,
                    evidence_count=0,
                )

            # ---------------------------------------------------------------- #
            # Phase 4b: GraphSync (Phase 5)
            # ---------------------------------------------------------------- #
            await self._update_state("GraphSync", 85)
            await self._wait_if_paused()

            await workflow.execute_activity(
                sync_assessment_graph_activity,
                self._assessment_id,
                start_to_close_timeout=timedelta(hours=1),
                retry_policy=_standard_retry,
                task_queue=_TASK_QUEUE,
            )

            # ---------------------------------------------------------------- #
            # Phase 5: Reporting
            # ---------------------------------------------------------------- #
            await self._update_state("Reporting", 90)
            await self._wait_if_paused()

            await workflow.execute_child_workflow(
                ReportingWorkflow.run,
                input,
                id=f"{workflow.info().workflow_id}-reporting",
                execution_timeout=timedelta(days=1),
                **child_opts,
            )

            # ---------------------------------------------------------------- #
            # Complete
            # ---------------------------------------------------------------- #
            await self._update_state("Complete", 100)

            return AssessmentResult(
                assessment_id=self._assessment_id,
                status="Complete",
                findings_count=self._findings_count,
                evidence_count=0,
            )

        except ApplicationError:
            await self._update_state("Cancelled")
            raise
        except Exception as e:
            await self._update_state("Failed")
            workflow.logger.error(f"[AssessmentWorkflow] Fatal error: {e}")
            raise
