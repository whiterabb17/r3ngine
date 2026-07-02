from temporalio import activity
from asgiref.sync import sync_to_async
from dataclasses import dataclass
from typing import Dict, Any, Optional

@dataclass
class StateTransitionInput:
    assessment_id: str
    new_status: str
    event_data: Optional[Dict[str, Any]] = None

@dataclass
class ScanOrchestratorInput:
    assessment_id: str
    target_ids: list[int]
    scan_type: str
    engine_id: int

@activity.defn
async def update_assessment_state_activity(input: StateTransitionInput) -> bool:
    from engagements.models import Assessment
    from engagements.services.state_machine import AssessmentStateMachine
    
    @sync_to_async
    def _do_transition():
        try:
            assessment = Assessment.objects.get(uuid=input.assessment_id)
            AssessmentStateMachine.transition_to(
                assessment=assessment, 
                new_status=input.new_status,
                event_data=input.event_data
            )
            return True
        except Exception as e:
            activity.logger.error(f"State transition failed: {e}")
            raise e
            
    return await _do_transition()

@activity.defn
async def scan_orchestrator_activity(input: ScanOrchestratorInput) -> bool:
    from reNgine.temporal_client import TemporalClientProvider
    from reNgine.temporal.workflows import MasterScanWorkflow
    import uuid
    
    activity.logger.info(f"Orchestrating scan for assessment {input.assessment_id}")
    
    client = await TemporalClientProvider.get_client()
    
    for target_id in input.target_ids:
        workflow_id = f"scan-{target_id}-{uuid.uuid4().hex[:8]}"
        
        # Start MasterScanWorkflow for each target
        await client.execute_workflow(
            MasterScanWorkflow.run,
            target_id, 
            input.engine_id, 
            "subdomain,endpoint,port,vulnerability", 
            workflow_id=workflow_id,
            task_queue="rengine-tasks",
        )
    
    return True
