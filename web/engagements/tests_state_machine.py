from django.test import TestCase
from django.contrib.auth.models import User
from .models import Client, Engagement, Assessment, AssessmentWorkflowState, AssessmentEvent
from .services.state_machine import AssessmentStateMachine
from unittest.mock import patch

class AssessmentStateMachineTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpassword')
        self.client_obj = Client.objects.create(name='Test Client', created_by=self.user)
        self.engagement_obj = Engagement.objects.create(
            client=self.client_obj,
            name='Test Engagement',
            status='Draft',
            created_by=self.user
        )
        self.assessment_obj = Assessment.objects.create(
            engagement=self.engagement_obj,
            name='Test Assessment',
            assessment_type='Web',
            status='Draft',
            created_by=self.user
        )
        self.state_obj, _ = AssessmentWorkflowState.objects.get_or_create(assessment=self.assessment_obj)

    @patch('engagements.services.state_machine.AssessmentEventPublisher.publish')
    def test_transition_to_ready(self, mock_publish):
        success = AssessmentStateMachine.transition_to(self.assessment_obj, 'Ready', user=self.user)
        self.assertTrue(success)
        self.assertEqual(self.assessment_obj.status, 'Ready')
        
        # Check event
        event = AssessmentEvent.objects.last()
        self.assertIsNotNone(event)
        self.assertEqual(event.event_type, 'Status Changed: Ready')
        
        # Check publisher called
        mock_publish.assert_called_once()

    @patch('engagements.services.state_machine.AssessmentEventPublisher.publish')
    def test_invalid_transition(self, mock_publish):
        # Draft -> Discovery is invalid without Ready
        with self.assertRaises(ValueError):
            AssessmentStateMachine.transition_to(self.assessment_obj, 'Discovery', user=self.user)
        
        self.assertEqual(self.assessment_obj.status, 'Draft')
        mock_publish.assert_not_called()
