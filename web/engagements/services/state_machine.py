from django.utils import timezone
from asgiref.sync import async_to_sync
from channels.layers import get_channel_layer
from engagements.models import Assessment, AssessmentEvent, AssessmentWorkflowState
from reNgine.utils.logger import get_module_logger

logger = get_module_logger(__name__)

class AssessmentEventPublisher:
    """Helper class to publish real-time assessment events over WebSockets."""
    
    @staticmethod
    def publish(assessment_id, event_type, payload):
        channel_layer = get_channel_layer()
        if channel_layer:
            group_name = f"assessment_{assessment_id}"
            async_to_sync(channel_layer.group_send)(
                group_name,
                {
                    'type': 'assessment_message',
                    'event': event_type,
                    'data': payload
                }
            )

class AssessmentStateMachine:
    """Manages the state transitions and audit trail for Assessments."""

    # Map of allowed transitions (Current State -> List of Allowed Next States)
    VALID_TRANSITIONS = {
        'Draft': ['Ready', 'Cancelled'],
        'Ready': ['Discovery', 'Cancelled'],
        'Discovery': ['Enumeration', 'Failed', 'Cancelled'],
        'Enumeration': ['Analysis', 'Failed', 'Cancelled'],
        'Analysis': ['Validation', 'Failed', 'Cancelled'],
        'Validation': ['Reporting', 'Failed', 'Cancelled'],
        'Reporting': ['Review', 'Complete', 'Failed', 'Cancelled'],
        'Review': ['Complete', 'Cancelled'],
        'Complete': [],
        'Failed': ['Ready', 'Cancelled'], # Can retry from failed back to Ready
        'Cancelled': [],
    }

    @classmethod
    def transition_to(cls, assessment, new_status, user=None, event_data=None):
        """
        Attempt to transition an assessment to a new status.
        Raises ValueError if the transition is invalid.
        """
        current_status = assessment.status
        
        if new_status not in cls.VALID_TRANSITIONS.get(current_status, []):
            logger.log_line("[ASSESSMENT]", "ERROR", f"Invalid transition for {assessment.uuid} from {current_status} to {new_status}", level="error")
            raise ValueError(f"Invalid transition from {current_status} to {new_status}")
            
        logger.log_line("[ASSESSMENT]", "TRANSITION", f"Transitioning {assessment.uuid} from {current_status} to {new_status}")
            
        # Update the Assessment status
        assessment.status = new_status
        
        # Set timestamps based on state
        if new_status == 'Discovery' and current_status == 'Ready':
            assessment.started_at = timezone.now()
        elif new_status in ['Complete', 'Failed', 'Cancelled']:
            if not assessment.completed_at:
                assessment.completed_at = timezone.now()

        assessment.save()
        
        # Update or create Workflow State for fast querying
        state, created = AssessmentWorkflowState.objects.get_or_create(assessment=assessment)
        state.current_stage = new_status
        if event_data and 'progress_percent' in event_data:
            state.progress_percent = event_data['progress_percent']
        if new_status == 'Complete':
            state.progress_percent = 100
        state.save()

        # Audit Trail
        AssessmentEvent.objects.create(
            assessment=assessment,
            user=user,
            event_type=f"Status Changed: {new_status}",
            event_data=event_data or {"previous": current_status, "new": new_status}
        )
        
        # Publish to WebSockets
        payload = {
            'assessment_id': str(assessment.uuid),
            'stage': new_status,
            'progress': state.progress_percent,
            'timestamp': timezone.now().isoformat()
        }
        if event_data:
            payload.update(event_data)
            
        AssessmentEventPublisher.publish(
            assessment_id=str(assessment.uuid),
            event_type='assessment_progress',
            payload=payload
        )
        
        return assessment
