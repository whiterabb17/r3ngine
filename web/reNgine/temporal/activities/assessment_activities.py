import os
import yaml
import uuid as _uuid
from temporalio import activity
from asgiref.sync import sync_to_async
from dataclasses import dataclass, field
from typing import Dict, Any, List, Optional
from reNgine.utils.logger import get_module_logger

logger = get_module_logger(__name__)

# ---------------------------------------------------------------------------
# Assessment-type → engine name mapping.
# These names correspond to the EngineType fixtures in
# web/fixtures/scan_engines/15_assessment_engines.yaml
# ---------------------------------------------------------------------------
ASSESSMENT_TYPE_ENGINE_MAP: Dict[str, str] = {
    "External": "Assessment: External",
    "Web":      "Assessment: Web",
    "API":      "Assessment: API",
    "Internal": "Assessment: Internal",
    "Hybrid":   "Assessment: Hybrid",
    # Fallback: types without a dedicated engine use the Web engine
    "Mobile":   "Assessment: Web",
    "Cloud":    "Assessment: Web",
    "AD":       "Assessment: Internal",
}


# ---------------------------------------------------------------------------
# Dataclasses
# ---------------------------------------------------------------------------

@dataclass
class StateTransitionInput:
    """Input for update_assessment_state_activity."""
    assessment_id: str
    new_status: str
    event_data: Optional[Dict[str, Any]] = None


@dataclass
class ScanOrchestratorInput:
    """Input for scan_orchestrator_activity."""
    assessment_id: str
    target_ids: list[int]
    scan_type: str
    engine_id: int


@dataclass
class PrepareAssessmentContextInput:
    """Input for PrepareAssessmentContextActivity.

    Args:
        assessment_id (str): UUID of the Assessment record.
        assessment_type (str): Type string, e.g. 'External', 'Web', etc.
        scope_ids (list[str]): UUIDs of AssessmentScope records to include.
                               If empty, all 'In Scope' entries are used.
    """
    assessment_id: str
    assessment_type: str
    scope_ids: List[str] = field(default_factory=list)


# ---------------------------------------------------------------------------
# Activities
# ---------------------------------------------------------------------------

@activity.defn
async def update_assessment_state_activity(input: StateTransitionInput) -> bool:
    """Transition an Assessment to a new status via the AssessmentStateMachine.

    Args:
        input (StateTransitionInput): Contains assessment_id (UUID), new_status,
            and optional event_data dict.

    Returns:
        bool: True on success, raises on failure.
    """
    from engagements.models import Assessment
    from engagements.services.state_machine import AssessmentStateMachine

    @sync_to_async
    def _do_transition():
        try:
            assessment = Assessment.objects.get(uuid=input.assessment_id)
            AssessmentStateMachine.transition_to(
                assessment=assessment,
                new_status=input.new_status,
                event_data=input.event_data,
            )
            return True
        except Exception as e:
            logger.log_line("[ASSESSMENT]", "ERROR", f"State transition failed: {e}", level="error", exc_info=True)
            raise e

    return await _do_transition()


@activity.defn
async def scan_orchestrator_activity(input: ScanOrchestratorInput) -> bool:
    """Orchestrate MasterScanWorkflow instances for each target in an assessment.

    Args:
        input (ScanOrchestratorInput): assessment_id, list of target Domain IDs,
            scan_type string, and engine_id.

    Returns:
        bool: True once all workflows have been started.
    """
    from reNgine.temporal_client import TemporalClientProvider
    from reNgine.temporal.workflows import MasterScanWorkflow

    logger.log_line("[ASSESSMENT]", "ORCHESTRATE", f"Orchestrating scan for assessment {input.assessment_id}")

    client = await TemporalClientProvider.get_client()

    for target_id in input.target_ids:
        workflow_id = f"scan-{target_id}-{_uuid.uuid4().hex[:8]}"

        await client.execute_workflow(
            MasterScanWorkflow.run,
            target_id,
            input.engine_id,
            "subdomain,endpoint,port,vulnerability",
            workflow_id=workflow_id,
            task_queue="python-orchestrator-queue",
        )

    return True


@activity.defn(name="PrepareAssessmentContextActivity")
async def prepare_assessment_context_activity(input: PrepareAssessmentContextInput) -> Dict[str, Any]:
    """Bridge AssessmentInput to a ScanContext dict for use by existing scan activities.

    For each Domain-type in-scope entry attached to the assessment:
    - Resolves or creates a targetApp.Domain record.
    - Creates a ScanHistory record linked to both the Domain and the Assessment.
    - Resolves the EngineType: uses Assessment.preferred_engine if set,
      otherwise looks up the engine by assessment type from ASSESSMENT_TYPE_ENGINE_MAP.
    - Builds and returns a ScanContext-compatible dict.

    Args:
        input (PrepareAssessmentContextInput): assessment_id (UUID string),
            assessment_type, and optional scope_ids filter.

    Returns:
        dict: A populated ScanContext dict with scan_history_id, domain_id,
              engine_id, domain_name, yaml_configuration, tasks, and results_dir.

    Raises:
        ApplicationError: If the assessment is not found, has no in-scope targets,
            or no matching EngineType is found.
    """
    from temporalio.exceptions import ApplicationError

    @sync_to_async
    def _prepare() -> Dict[str, Any]:
        from django.utils import timezone
        from django.contrib.contenttypes.models import ContentType
        from engagements.models import Assessment, AssessmentScope, AssessmentAsset
        from targetApp.models import Domain
        from startScan.models import ScanHistory
        from scanEngine.models import EngineType
        from reNgine.definitions import RUNNING_TASK

        # ------------------------------------------------------------------ #
        # 1. Load the Assessment
        # ------------------------------------------------------------------ #
        try:
            assessment = Assessment.objects.select_related('preferred_engine').get(
                uuid=input.assessment_id
            )
        except Assessment.DoesNotExist:
            raise ApplicationError(f"Assessment {input.assessment_id} not found.", non_retryable=True)

        # ------------------------------------------------------------------ #
        # 2. Resolve EngineType
        #    Precedence: preferred_engine FK > assessment-type default > Full Scan
        # ------------------------------------------------------------------ #
        engine = assessment.preferred_engine
        if engine is None:
            engine_name = ASSESSMENT_TYPE_ENGINE_MAP.get(input.assessment_type)
            if engine_name:
                engine = EngineType.objects.filter(engine_name=engine_name).first()
            if engine is None:
                # Last resort: use the first default engine
                engine = EngineType.objects.filter(default_engine=True).first()
            if engine is None:
                raise ApplicationError(
                    f"No EngineType found for assessment type '{input.assessment_type}'. "
                    "Load web/fixtures/scan_engines/15_assessment_engines.yaml first.",
                    non_retryable=True,
                )

        # Parse YAML to extract task list
        try:
            yaml_cfg = yaml.safe_load(engine.yaml_configuration) or {}
        except Exception:
            yaml_cfg = {}
        task_list = list(yaml_cfg.keys())

        # ------------------------------------------------------------------ #
        # 3. Resolve in-scope Domain targets
        # ------------------------------------------------------------------ #
        scope_qs = AssessmentScope.objects.filter(
            assessment=assessment,
            status="In Scope",
            scope_type__in=["Domain", "IP", "URL"],
        )
        if input.scope_ids:
            scope_qs = scope_qs.filter(uuid__in=input.scope_ids)

        scopes = list(scope_qs)
        if not scopes:
            raise ApplicationError(
                f"Assessment {input.assessment_id} has no in-scope targets.",
                non_retryable=True,
            )

        # Use the first in-scope target. Multi-target fan-out is handled by the
        # parent AssessmentWorkflow launching multiple child workflow sets.
        scope = scopes[0]
        target_value = scope.value.strip().lstrip("https://").lstrip("http://").rstrip("/")

        # ------------------------------------------------------------------ #
        # 4. Get-or-create Domain
        # ------------------------------------------------------------------ #
        domain, _ = Domain.objects.get_or_create(
            name=target_value,
            defaults={"insert_date": timezone.now()},
        )

        # ------------------------------------------------------------------ #
        # 5. Create ScanHistory linked to Assessment
        # ------------------------------------------------------------------ #
        results_dir = f"assessment_{assessment.uuid}_{_uuid.uuid4().hex[:8]}"
        scan = ScanHistory.objects.create(
            domain=domain,
            scan_type=engine,
            assessment=assessment,
            start_scan_date=timezone.now(),
            scan_status=RUNNING_TASK,
            results_dir=results_dir,
            tasks=task_list,
            initiated_by=assessment.created_by,
        )

        # ------------------------------------------------------------------ #
        # 6. Create AssessmentAsset linking Assessment → Domain (if not exists)
        # ------------------------------------------------------------------ #
        try:
            domain_ct = ContentType.objects.get_for_model(Domain)
            AssessmentAsset.objects.get_or_create(
                assessment=assessment,
                content_type=domain_ct,
                object_id=domain.id,
            )
        except Exception as asset_err:
            # Non-fatal: asset linking failure should not block the scan
            logger.log_line("[ASSESSMENT]", "WARN", f"AssessmentAsset link failed: {asset_err}")

        # ------------------------------------------------------------------ #
        # 7. Build and return ScanContext
        # ------------------------------------------------------------------ #
        return {
            "scan_history_id":   scan.id,
            "engine_id":         engine.id,
            "domain_id":         domain.id,
            "domain_name":       domain.name,
            "yaml_configuration": yaml_cfg,
            "tasks":             task_list,
            "results_dir":       results_dir,
            "track":             True,
            "out_of_scope_subdomains": [],
            "starting_point_path": "",
            "excluded_paths":    [],
            "imported_subdomains": [],
            # Assessment metadata for activities that need it
            "assessment_id":     str(assessment.uuid),
            "assessment_type":   input.assessment_type,
        }

    return await _prepare()


@activity.defn(name="auto_validate_findings_activity")
async def auto_validate_findings_activity(assessment_id: str) -> bool:
    """Analyze findings discovered during assessment to auto-verify or queue for review.

    If validation_confidence > 0.8, validation_status becomes 'verified'.
    Otherwise, defaults to 'needs_review'.
    """
    from startScan.models import Vulnerability, ScanHistory
    from engagements.models import Assessment

    @sync_to_async
    def _validate():
        try:
            assessment = Assessment.objects.get(uuid=assessment_id)
            scan_histories = ScanHistory.objects.filter(assessment=assessment)
            vulns = Vulnerability.objects.filter(scan_history__in=scan_histories)
            
            updated = []
            for vuln in vulns:
                # If it's already verified/rejected by analyst, don't overwrite
                if vuln.validation_status in ['verified', 'false_positive', 'accepted_risk']:
                    continue
                
                # Check validation_confidence
                if vuln.validation_confidence and vuln.validation_confidence > 0.8:
                    vuln.validation_status = 'verified'
                else:
                    vuln.validation_status = 'needs_review'
                updated.append(vuln)
                
            if updated:
                Vulnerability.objects.bulk_update(updated, ['validation_status'])
            return True
        except Exception as e:
            logger.log_line("[ASSESSMENT]", "ERROR", f"Auto-validation failed: {e}", level="error", exc_info=True)
            raise e

    return await _validate()

