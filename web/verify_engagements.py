import os
import django
from django.contrib.auth.models import User
from engagements.models import Client, Engagement, Assessment, AssessmentWorkflowState, AssessmentEvent
from engagements.services.state_machine import AssessmentStateMachine

def run_verification():
    print("Starting Engagement and Assessment Verification...")
    
    # 1. Setup User
    user, created = User.objects.get_or_create(username='verify_user')
    if created:
        user.set_password('verify_password')
        user.save()
        print("Created test user 'verify_user'")
        
    # 2. Create Client
    client, created = Client.objects.get_or_create(
        name='Verification Client',
        defaults={'created_by': user, 'description': 'Client for testing end-to-end flow'}
    )
    print(f"Client '{client.name}' is ready (ID: {client.id})")
    
    # 3. Create Engagement
    engagement, created = Engagement.objects.get_or_create(
        name='Verification Engagement',
        client=client,
        defaults={
            'engagement_type': 'Penetration Test',
            'status': 'Draft',
            'created_by': user
        }
    )
    print(f"Engagement '{engagement.name}' is ready (ID: {engagement.id}, Status: {engagement.status})")
    
    import uuid
    unique_suffix = str(uuid.uuid4())[:8]
    
    # 4. Create Assessment
    assessment, created = Assessment.objects.get_or_create(
        name=f'Verification Assessment {unique_suffix}',
        engagement=engagement,
        defaults={
            'assessment_type': 'Web',
            'status': 'Draft',
            'created_by': user
        }
    )
    
    # Ensure a workflow state exists
    state, _ = AssessmentWorkflowState.objects.get_or_create(assessment=assessment)
    
    print(f"Assessment '{assessment.name}' created (ID: {assessment.id}, Status: {assessment.status})")
    
    # 5. Test Transitions
    print("\nTesting State Transitions:")
    
    phases = [
        'Ready',
        'Discovery',
        'Enumeration',
        'Analysis',
        'Validation',
        'Reporting',
        'Review',
        'Complete'
    ]
    
    for phase in phases:
        try:
            success = AssessmentStateMachine.transition_to(assessment, phase, user=user)
            if success:
                print(f"[\u2713] Transitioned to {phase}")
                
                # Check DB event
                event = AssessmentEvent.objects.filter(assessment=assessment).order_by('-timestamp').first()
                if event:
                    print(f"    -> Event logged: {event.event_type}")
            else:
                print(f"[x] Failed to transition to {phase}")
                
        except Exception as e:
            print(f"[!] Error transitioning to {phase}: {e}")
            
    # Clean up (Optional, but good practice for verify scripts so they can run multiple times cleanly if needed)
    # Actually, we can leave it in DB to verify it manually if needed, or delete.
    print("\nVerification Complete.")

if __name__ == '__main__':
    run_verification()
