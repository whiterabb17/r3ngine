from datetime import timedelta
import asyncio
from dataclasses import dataclass
from typing import List, Dict, Any, Optional

from temporalio import workflow
from temporalio.common import RetryPolicy
from temporalio.exceptions import ApplicationError

with workflow.unsafe.imports_passed_through():
    import django
    django.setup()
    from reNgine.temporal.activities.assessment_activities import (
        StateTransitionInput, 
        update_assessment_state_activity,
        scan_orchestrator_activity
    )

@dataclass
class AssessmentInput:
    assessment_id: str
    engagement_id: str
    assessment_type: str
    scope_ids: List[str]

@dataclass
class AssessmentResult:
    assessment_id: str
    status: str
    findings_count: int
    evidence_count: int

# Define standard retry policy for activities
standard_retry_policy = RetryPolicy(
    initial_interval=timedelta(seconds=5),
    backoff_coefficient=2.0,
    maximum_interval=timedelta(seconds=300),
    maximum_attempts=5,
)

# Child Workflows Stubbed
@workflow.defn
class DiscoveryWorkflow:
    @workflow.run
    async def run(self, input: AssessmentInput) -> bool:
        await asyncio.sleep(2) # Stub
        return True

@workflow.defn
class EnumerationWorkflow:
    @workflow.run
    async def run(self, input: AssessmentInput) -> bool:
        await asyncio.sleep(2) # Stub
        return True

@workflow.defn
class AnalysisWorkflow:
    @workflow.run
    async def run(self, input: AssessmentInput) -> bool:
        await asyncio.sleep(2) # Stub
        return True

@workflow.defn
class ValidationWorkflow:
    @workflow.run
    async def run(self, input: AssessmentInput) -> bool:
        await asyncio.sleep(2) # Stub
        return True

@workflow.defn
class ReportingWorkflow:
    @workflow.run
    async def run(self, input: AssessmentInput) -> bool:
        await asyncio.sleep(2) # Stub
        return True

@workflow.defn
class AssessmentWorkflow:
    def __init__(self):
        self._status = "Draft"
        self._progress = 0
        self._current_stage = "Draft"
        self._assets_processed = 0
        self._findings_count = 0
        self._is_paused = False
        self._is_cancelled = False

    @workflow.signal
    def pause_assessment(self) -> None:
        self._is_paused = True

    @workflow.signal
    def resume_assessment(self) -> None:
        self._is_paused = False

    @workflow.signal
    def cancel_assessment(self) -> None:
        self._is_cancelled = True

    @workflow.signal
    def update_scope(self, scope_data: Dict[str, Any]) -> None:
        workflow.logger.info(f"Scope updated: {scope_data}")

    @workflow.query
    def get_status(self) -> str:
        return "Paused" if self._is_paused else self._status

    @workflow.query
    def get_progress(self) -> int:
        return self._progress

    @workflow.query
    def get_current_stage(self) -> str:
        return self._current_stage

    @workflow.query
    def get_assets_processed(self) -> int:
        return self._assets_processed

    @workflow.query
    def get_findings_count(self) -> int:
        return self._findings_count

    async def update_state(self, new_status: str, progress: int = None):
        self._status = new_status
        self._current_stage = new_status
        if progress is not None:
            self._progress = progress
            
        await workflow.execute_activity(
            update_assessment_state_activity,
            StateTransitionInput(
                assessment_id=self._assessment_id, 
                new_status=new_status,
                event_data={"progress_percent": self._progress}
            ),
            start_to_close_timeout=timedelta(seconds=10),
            retry_policy=standard_retry_policy
        )

    async def wait_if_paused(self):
        while self._is_paused:
            await asyncio.sleep(5)
            if self._is_cancelled:
                break

    @workflow.run
    async def run(self, input: AssessmentInput) -> AssessmentResult:
        self._assessment_id = input.assessment_id
        workflow.logger.info(f"Starting AssessmentWorkflow for assessment UUID: {self._assessment_id}")
        
        try:
            # Stage: Discovery
            await self.update_state("Discovery", 10)
            await self.wait_if_paused()
            if self._is_cancelled:
                raise ApplicationError("Assessment Cancelled")
                
            await workflow.execute_child_workflow(
                DiscoveryWorkflow.run,
                input,
                id=f"{workflow.info().workflow_id}-discovery",
                task_queue=workflow.info().task_queue
            )
            
            # Stage: Enumeration
            await self.update_state("Enumeration", 30)
            await self.wait_if_paused()
            if self._is_cancelled:
                raise ApplicationError("Assessment Cancelled")
                
            await workflow.execute_child_workflow(
                EnumerationWorkflow.run,
                input,
                id=f"{workflow.info().workflow_id}-enumeration",
                task_queue=workflow.info().task_queue
            )
            
            # Stage: Analysis
            await self.update_state("Analysis", 60)
            await self.wait_if_paused()
            if self._is_cancelled:
                raise ApplicationError("Assessment Cancelled")
                
            await workflow.execute_child_workflow(
                AnalysisWorkflow.run,
                input,
                id=f"{workflow.info().workflow_id}-analysis",
                task_queue=workflow.info().task_queue
            )
            
            # Stage: Validation
            await self.update_state("Validation", 80)
            await self.wait_if_paused()
            if self._is_cancelled:
                raise ApplicationError("Assessment Cancelled")
                
            await workflow.execute_child_workflow(
                ValidationWorkflow.run,
                input,
                id=f"{workflow.info().workflow_id}-validation",
                task_queue=workflow.info().task_queue
            )
            
            # Stage: Reporting
            await self.update_state("Reporting", 90)
            await self.wait_if_paused()
            if self._is_cancelled:
                raise ApplicationError("Assessment Cancelled")
                
            await workflow.execute_child_workflow(
                ReportingWorkflow.run,
                input,
                id=f"{workflow.info().workflow_id}-reporting",
                task_queue=workflow.info().task_queue
            )
            
            # Finalize
            await self.update_state("Complete", 100)
            
            return AssessmentResult(
                assessment_id=self._assessment_id,
                status="Complete",
                findings_count=self._findings_count,
                evidence_count=0
            )
            
        except Exception as e:
            await self.update_state("Failed")
            workflow.logger.error(f"AssessmentWorkflow failed: {str(e)}")
            raise e
