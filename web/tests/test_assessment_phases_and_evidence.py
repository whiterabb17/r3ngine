"""Assessment Phase Transition Tests.

Covers:
  1. Full happy-path phase walk: Draft → Ready → Discovery → Enumeration
     → Analysis → Validation → Reporting → Complete
  2. All invalid transitions are rejected
  3. Cancel from every non-terminal state
  4. Failed → Ready retry path
  5. New model fields: preferred_engine, retention_days
  6. Timestamps: started_at set on Discovery, completed_at set on Complete/Failed/Cancelled
  7. AssessmentWorkflowState progress_percent updates
  8. AssessmentEvent audit trail entries per transition
  9. Evidence collection get_or_create tied to assessment
 10. Evidence create with SHA-256 hash and chain-of-custody event
 11. Evidence integrity verification (pass + fail cases)
 12. Evidence archive + purge lifecycle
 13. EvidenceRetentionPolicy created with collection
 14. REST API: GET /assessments/ returns new fields
 15. REST API: Evidence collection list + item list endpoints
"""
import hashlib
import io
from datetime import timedelta
from unittest.mock import patch, MagicMock

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient

from engagements.models import (
    Assessment, AssessmentEvent, AssessmentWorkflowState,
    AssessmentScope, Client, Engagement,
)
from engagements.services.state_machine import AssessmentStateMachine
from evidence.models import (
    EvidenceCollection, Evidence, EvidenceEvent,
    EvidenceRetentionPolicy,
)
from evidence.services import EvidenceService
from evidence.hashing import compute_sha256


# ===========================================================================
# Helpers
# ===========================================================================

def make_assessment(user, engagement, name='Test Assessment', assessment_type='Web', status='Draft'):
    """Create a minimal Assessment in the given state."""
    return Assessment.objects.create(
        engagement=engagement,
        name=name,
        assessment_type=assessment_type,
        status=status,
        created_by=user,
    )


def walk_to(assessment, target_status, user):
    """Drive an assessment through the full phase chain up to target_status."""
    path = ['Draft', 'Ready', 'Discovery', 'Enumeration', 'Analysis', 'Validation', 'Reporting', 'Complete']
    if target_status not in path:
        raise ValueError(f"walk_to: unknown target {target_status}")
    start_idx = path.index(assessment.status) + 1
    end_idx = path.index(target_status) + 1
    for state in path[start_idx:end_idx]:
        AssessmentStateMachine.transition_to(assessment, state, user=user)
    return assessment


# ===========================================================================
# 1. State Machine: Happy Path Full Walk
# ===========================================================================

class TestAssessmentFullPhaseWalk(TestCase):
    """Walk Draft → Complete through all phases and verify each state."""

    def setUp(self):
        self.user = User.objects.create_user('walker', password='pass')
        self.client_obj = Client.objects.create(name='WalkCo', created_by=self.user)
        self.engagement = Engagement.objects.create(
            client=self.client_obj, name='Walk Eng', status='Draft', created_by=self.user
        )
        self.assessment = make_assessment(self.user, self.engagement)
        AssessmentWorkflowState.objects.get_or_create(assessment=self.assessment)

    @patch('engagements.services.state_machine.AssessmentEventPublisher.publish')
    def test_full_phase_walk(self, mock_publish):
        """Each transition should succeed and persist the correct status."""
        phases = ['Ready', 'Discovery', 'Enumeration', 'Analysis', 'Validation', 'Reporting', 'Complete']

        for phase in phases:
            with self.subTest(phase=phase):
                result = AssessmentStateMachine.transition_to(self.assessment, phase, user=self.user)
                self.assessment.refresh_from_db()
                self.assertEqual(self.assessment.status, phase, f"Expected status={phase}, got {self.assessment.status}")
                self.assertIsNotNone(result)

        # Final state should be Complete
        self.assertEqual(self.assessment.status, 'Complete')

    @patch('engagements.services.state_machine.AssessmentEventPublisher.publish')
    def test_started_at_set_on_discovery(self, _):
        """started_at must be populated when first entering Discovery."""
        self.assertIsNone(self.assessment.started_at)
        walk_to(self.assessment, 'Discovery', self.user)
        self.assessment.refresh_from_db()
        self.assertIsNotNone(self.assessment.started_at)

    @patch('engagements.services.state_machine.AssessmentEventPublisher.publish')
    def test_completed_at_set_on_complete(self, _):
        """completed_at must be populated when entering Complete."""
        self.assertIsNone(self.assessment.completed_at)
        walk_to(self.assessment, 'Complete', self.user)
        self.assessment.refresh_from_db()
        self.assertIsNotNone(self.assessment.completed_at)

    @patch('engagements.services.state_machine.AssessmentEventPublisher.publish')
    def test_workflow_state_updated_each_transition(self, _):
        """AssessmentWorkflowState.current_stage must track every transition."""
        phases = ['Ready', 'Discovery', 'Enumeration', 'Analysis']
        for phase in phases:
            AssessmentStateMachine.transition_to(self.assessment, phase, user=self.user)
            state = AssessmentWorkflowState.objects.get(assessment=self.assessment)
            self.assertEqual(state.current_stage, phase)

    @patch('engagements.services.state_machine.AssessmentEventPublisher.publish')
    def test_complete_sets_progress_100(self, _):
        """Progress percent must be 100 on Complete."""
        walk_to(self.assessment, 'Complete', self.user)
        state = AssessmentWorkflowState.objects.get(assessment=self.assessment)
        self.assertEqual(state.progress_percent, 100)

    @patch('engagements.services.state_machine.AssessmentEventPublisher.publish')
    def test_audit_events_created_for_each_transition(self, _):
        """One AssessmentEvent per transition must be written."""
        initial_count = AssessmentEvent.objects.filter(assessment=self.assessment).count()
        phases = ['Ready', 'Discovery', 'Enumeration']
        for phase in phases:
            AssessmentStateMachine.transition_to(self.assessment, phase, user=self.user)
        event_count = AssessmentEvent.objects.filter(assessment=self.assessment).count()
        self.assertEqual(event_count, initial_count + len(phases))

    @patch('engagements.services.state_machine.AssessmentEventPublisher.publish')
    def test_websocket_publish_called_per_transition(self, mock_publish):
        """AssessmentEventPublisher.publish must be called for each transition."""
        phases = ['Ready', 'Discovery']
        for phase in phases:
            AssessmentStateMachine.transition_to(self.assessment, phase, user=self.user)
        self.assertEqual(mock_publish.call_count, len(phases))


# ===========================================================================
# 2. State Machine: Invalid Transitions
# ===========================================================================

class TestInvalidTransitions(TestCase):
    """Invalid transitions must raise ValueError and leave status unchanged."""

    def setUp(self):
        self.user = User.objects.create_user('invalid_user', password='pass')
        self.client_obj = Client.objects.create(name='InvalidCo', created_by=self.user)
        self.engagement = Engagement.objects.create(
            client=self.client_obj, name='Invalid Eng', status='Draft', created_by=self.user
        )
        self.assessment = make_assessment(self.user, self.engagement)
        AssessmentWorkflowState.objects.get_or_create(assessment=self.assessment)

    @patch('engagements.services.state_machine.AssessmentEventPublisher.publish')
    def test_draft_cannot_skip_to_discovery(self, _):
        with self.assertRaises(ValueError):
            AssessmentStateMachine.transition_to(self.assessment, 'Discovery', user=self.user)
        self.assessment.refresh_from_db()
        self.assertEqual(self.assessment.status, 'Draft')

    @patch('engagements.services.state_machine.AssessmentEventPublisher.publish')
    def test_draft_cannot_go_to_complete(self, _):
        with self.assertRaises(ValueError):
            AssessmentStateMachine.transition_to(self.assessment, 'Complete', user=self.user)

    @patch('engagements.services.state_machine.AssessmentEventPublisher.publish')
    def test_complete_is_terminal(self, _):
        """Complete should have no valid outgoing transitions."""
        walk_to(self.assessment, 'Complete', self.user)
        for next_state in ['Ready', 'Draft', 'Discovery', 'Failed', 'Cancelled']:
            with self.assertRaises(ValueError):
                AssessmentStateMachine.transition_to(self.assessment, next_state, user=self.user)

    @patch('engagements.services.state_machine.AssessmentEventPublisher.publish')
    def test_cancelled_is_terminal(self, _):
        """Cancelled should have no valid outgoing transitions."""
        AssessmentStateMachine.transition_to(self.assessment, 'Cancelled', user=self.user)
        with self.assertRaises(ValueError):
            AssessmentStateMachine.transition_to(self.assessment, 'Ready', user=self.user)

    @patch('engagements.services.state_machine.AssessmentEventPublisher.publish')
    def test_cannot_go_backwards(self, _):
        """Enumeration cannot go back to Discovery."""
        walk_to(self.assessment, 'Enumeration', self.user)
        with self.assertRaises(ValueError):
            AssessmentStateMachine.transition_to(self.assessment, 'Discovery', user=self.user)


# ===========================================================================
# 3. Cancel from Every Non-Terminal State
# ===========================================================================

class TestCancelFromAnyState(TestCase):
    """Cancel must be valid from every non-terminal state."""

    CANCELLABLE_STATES = ['Draft', 'Ready', 'Discovery', 'Enumeration', 'Analysis', 'Validation', 'Reporting', 'Review', 'Failed']

    def setUp(self):
        self.user = User.objects.create_user('canceller', password='pass')
        self.client_obj = Client.objects.create(name='CancelCo', created_by=self.user)
        self.engagement = Engagement.objects.create(
            client=self.client_obj, name='Cancel Eng', status='Draft', created_by=self.user
        )

    @patch('engagements.services.state_machine.AssessmentEventPublisher.publish')
    def test_cancel_from_each_state(self, _):
        """Each cancellable state must allow transition → Cancelled."""
        for state in self.CANCELLABLE_STATES:
            with self.subTest(from_state=state):
                assessment = make_assessment(self.user, self.engagement, name=f'Cancel from {state}', status=state)
                AssessmentWorkflowState.objects.get_or_create(assessment=assessment)
                result = AssessmentStateMachine.transition_to(assessment, 'Cancelled', user=self.user)
                assessment.refresh_from_db()
                self.assertEqual(assessment.status, 'Cancelled')
                self.assertIsNotNone(assessment.completed_at)


# ===========================================================================
# 4. Failed → Ready Retry
# ===========================================================================

class TestFailedRetry(TestCase):
    """Failed assessments must be retryable via → Ready."""

    def setUp(self):
        self.user = User.objects.create_user('retrier', password='pass')
        self.client_obj = Client.objects.create(name='RetryCo', created_by=self.user)
        self.engagement = Engagement.objects.create(
            client=self.client_obj, name='Retry Eng', status='Draft', created_by=self.user
        )
        self.assessment = make_assessment(self.user, self.engagement, status='Failed')
        AssessmentWorkflowState.objects.get_or_create(assessment=self.assessment)

    @patch('engagements.services.state_machine.AssessmentEventPublisher.publish')
    def test_failed_can_retry_to_ready(self, _):
        """Failed → Ready must succeed."""
        AssessmentStateMachine.transition_to(self.assessment, 'Ready', user=self.user)
        self.assessment.refresh_from_db()
        self.assertEqual(self.assessment.status, 'Ready')

    @patch('engagements.services.state_machine.AssessmentEventPublisher.publish')
    def test_failed_retry_then_full_walk(self, _):
        """Failed → Ready → Discovery → … → Complete must complete successfully."""
        AssessmentStateMachine.transition_to(self.assessment, 'Ready', user=self.user)
        walk_to(self.assessment, 'Complete', self.user)
        self.assessment.refresh_from_db()
        self.assertEqual(self.assessment.status, 'Complete')


# ===========================================================================
# 5. New Model Fields
# ===========================================================================

class TestAssessmentNewFields(TestCase):
    """Test preferred_engine and retention_days fields added in migration 0003."""

    def setUp(self):
        self.user = User.objects.create_user('fielduser', password='pass')
        self.client_obj = Client.objects.create(name='FieldCo', created_by=self.user)
        self.engagement = Engagement.objects.create(
            client=self.client_obj, name='Field Eng', status='Draft', created_by=self.user
        )

    def test_preferred_engine_defaults_null(self):
        """preferred_engine should default to None."""
        assessment = make_assessment(self.user, self.engagement)
        self.assertIsNone(assessment.preferred_engine)

    def test_retention_days_defaults_365(self):
        """retention_days should default to 365."""
        assessment = make_assessment(self.user, self.engagement)
        self.assertEqual(assessment.retention_days, 365)

    def test_retention_days_choices(self):
        """retention_days must only accept valid choices."""
        for days in [90, 180, 365, 0]:
            assessment = Assessment.objects.create(
                engagement=self.engagement,
                name=f'Ret {days}',
                assessment_type='Web',
                status='Draft',
                created_by=self.user,
                retention_days=days,
            )
            self.assertEqual(assessment.retention_days, days)


# ===========================================================================
# 6. Evidence: Collection and Item CRUD
# ===========================================================================

class TestEvidenceCRUD(TestCase):
    """Test EvidenceService create, hash verification, archive, purge lifecycle."""

    SAMPLE_CONTENT = b'EVIDENCE FILE CONTENT FOR TESTING'

    def setUp(self):
        self.user = User.objects.create_user('evidencer', password='pass')
        self.client_obj = Client.objects.create(name='EvidCo', created_by=self.user)
        self.engagement = Engagement.objects.create(
            client=self.client_obj, name='Evid Eng', status='Draft', created_by=self.user
        )
        self.assessment = make_assessment(self.user, self.engagement)

    def test_get_or_create_collection_creates_on_first_call(self):
        """First call must create a new collection and retention policy."""
        collection = EvidenceService.get_or_create_collection(self.assessment)
        self.assertIsNotNone(collection)
        self.assertEqual(collection.assessment, self.assessment)
        self.assertEqual(collection.status, 'Active')
        # Retention policy should be created
        self.assertTrue(hasattr(collection, 'retention_policy'))

    def test_get_or_create_collection_idempotent(self):
        """Second call must return the same collection."""
        c1 = EvidenceService.get_or_create_collection(self.assessment)
        c2 = EvidenceService.get_or_create_collection(self.assessment)
        self.assertEqual(c1.pk, c2.pk)
        self.assertEqual(EvidenceCollection.objects.filter(assessment=self.assessment).count(), 1)

    def test_retention_policy_inherits_assessment_retention_days(self):
        """Retention policy archive_after_days must equal assessment.retention_days."""
        self.assessment.retention_days = 180
        self.assessment.save()
        collection = EvidenceService.get_or_create_collection(self.assessment)
        policy = EvidenceRetentionPolicy.objects.get(collection=collection)
        self.assertEqual(policy.archive_after_days, 180)

    def test_create_evidence_persists_with_hash(self):
        """create_evidence must store the file and compute a valid SHA-256."""
        collection = EvidenceService.get_or_create_collection(self.assessment)
        expected_hash = compute_sha256(self.SAMPLE_CONTENT)

        evidence = EvidenceService.create_evidence(
            collection=collection,
            content=self.SAMPLE_CONTENT,
            filename='test_file.txt',
            evidence_type='CommandOutput',
            title='Test command output',
            collected_by=self.user,
        )

        self.assertEqual(evidence.sha256_hash, expected_hash)
        self.assertEqual(evidence.file_size, len(self.SAMPLE_CONTENT))
        self.assertEqual(evidence.status, 'Active')

    def test_create_evidence_writes_created_event(self):
        """create_evidence must write a Created chain-of-custody event."""
        collection = EvidenceService.get_or_create_collection(self.assessment)
        evidence = EvidenceService.create_evidence(
            collection=collection,
            content=self.SAMPLE_CONTENT,
            filename='test_file.txt',
            evidence_type='CommandOutput',
            title='Test output',
            skip_validation=True,
        )
        events = EvidenceEvent.objects.filter(evidence=evidence, event_type='Created')
        self.assertEqual(events.count(), 1)
        self.assertEqual(events.first().hash_at_event, evidence.sha256_hash)

    def test_create_evidence_links_vulnerability(self):
        """vulnerability_ids should create the M2M link."""
        from startScan.models import Vulnerability, ScanHistory
        from targetApp.models import Domain

        # We need a minimal ScanHistory and Vulnerability for the M2M
        # Use raw creation since we don't need a full scan setup
        from scanEngine.models import EngineType
        try:
            engine = EngineType.objects.first()
            if not engine:
                raise EngineType.DoesNotExist
        except Exception:
            self.skipTest("No EngineType available — skip vulnerability linking test")

        from targetApp.models import Domain
        domain, _ = Domain.objects.get_or_create(name='test.example.com', defaults={'insert_date': timezone.now().date()})
        history = ScanHistory.objects.create(
            domain=domain,
            scan_type=engine,
            start_scan_date=timezone.now(),
        )
        vuln = Vulnerability.objects.create(
            name='Test Vuln',
            scan_history=history,
            severity=2,
        )

        collection = EvidenceService.get_or_create_collection(self.assessment)
        evidence = EvidenceService.create_evidence(
            collection=collection,
            content=self.SAMPLE_CONTENT,
            filename='vuln_proof.txt',
            evidence_type='CommandOutput',
            title='Vulnerability proof',
            vulnerability_ids=[vuln.id],
            skip_validation=True,
        )
        self.assertIn(vuln, evidence.vulnerabilities.all())

    def test_integrity_verify_passes_for_fresh_evidence(self):
        """Freshly created evidence must pass integrity verification."""
        collection = EvidenceService.get_or_create_collection(self.assessment)
        evidence = EvidenceService.create_evidence(
            collection=collection,
            content=self.SAMPLE_CONTENT,
            filename='integrity_test.txt',
            evidence_type='CommandOutput',
            title='Integrity test',
            skip_validation=True,
        )
        passed = EvidenceService.verify_integrity(evidence)
        self.assertTrue(passed)

    def test_integrity_verify_fails_after_hash_tamper(self):
        """Manually altering sha256_hash must cause verification to fail."""
        collection = EvidenceService.get_or_create_collection(self.assessment)
        evidence = EvidenceService.create_evidence(
            collection=collection,
            content=self.SAMPLE_CONTENT,
            filename='tamper_test.txt',
            evidence_type='CommandOutput',
            title='Tamper test',
            skip_validation=True,
        )
        # Corrupt the stored hash
        evidence.sha256_hash = 'a' * 64  # wrong hash
        evidence.save()
        passed = EvidenceService.verify_integrity(evidence)
        self.assertFalse(passed)

    def test_archive_evidence_transitions_status(self):
        """archive_evidence must set status to Archived and write event."""
        collection = EvidenceService.get_or_create_collection(self.assessment)
        evidence = EvidenceService.create_evidence(
            collection=collection,
            content=self.SAMPLE_CONTENT,
            filename='archive_test.txt',
            evidence_type='Log',
            title='Archive test',
            skip_validation=True,
        )
        EvidenceService.archive_evidence(evidence, actor=self.user, note='Test archive')
        evidence.refresh_from_db()
        self.assertEqual(evidence.status, 'Archived')
        archived_event = EvidenceEvent.objects.filter(evidence=evidence, event_type='Archived').first()
        self.assertIsNotNone(archived_event)

    def test_purge_evidence_sets_purged_status(self):
        """purge_evidence must set status to Purged and clear file_path."""
        collection = EvidenceService.get_or_create_collection(self.assessment)
        evidence = EvidenceService.create_evidence(
            collection=collection,
            content=self.SAMPLE_CONTENT,
            filename='purge_test.txt',
            evidence_type='Log',
            title='Purge test',
            skip_validation=True,
        )
        EvidenceService.purge_evidence(evidence, actor=self.user, delete_file=False)
        evidence.refresh_from_db()
        self.assertEqual(evidence.status, 'Purged')
        self.assertIsNone(evidence.file_path)
        purge_event = EvidenceEvent.objects.filter(evidence=evidence, event_type='Purged').first()
        self.assertIsNotNone(purge_event)

    def test_archive_collection_archives_all_active_items(self):
        """archive_collection must archive every Active item in the collection."""
        collection = EvidenceService.get_or_create_collection(self.assessment)
        for i in range(3):
            EvidenceService.create_evidence(
                collection=collection,
                content=self.SAMPLE_CONTENT,
                filename=f'item_{i}.txt',
                evidence_type='CommandOutput',
                title=f'Item {i}',
                skip_validation=True,
            )
        EvidenceService.archive_collection(collection, actor=self.user)
        collection.refresh_from_db()
        self.assertEqual(collection.status, 'Archived')
        active_items = collection.evidence_items.filter(status='Active')
        self.assertEqual(active_items.count(), 0)


# ===========================================================================
# 7. Evidence Hashing Unit Tests
# ===========================================================================

class TestEvidenceHashing(TestCase):
    """Unit tests for the hashing service."""

    def test_compute_sha256_produces_correct_hash(self):
        """compute_sha256 must produce a known-good hash."""
        content = b'hello world'
        expected = hashlib.sha256(content).hexdigest()
        self.assertEqual(compute_sha256(content), expected)

    def test_compute_sha256_is_lowercase_hex(self):
        """Hash must be 64 lowercase hex characters."""
        result = compute_sha256(b'test data')
        self.assertEqual(len(result), 64)
        self.assertTrue(all(c in '0123456789abcdef' for c in result))

    def test_compute_sha256_is_deterministic(self):
        """Same input must always produce the same hash."""
        content = b'deterministic test content'
        self.assertEqual(compute_sha256(content), compute_sha256(content))

    def test_different_content_produces_different_hash(self):
        """Different content must produce different hashes."""
        self.assertNotEqual(compute_sha256(b'aaa'), compute_sha256(b'bbb'))


# ===========================================================================
# 8. Evidence Validator Unit Tests
# ===========================================================================

class TestEvidenceValidator(TestCase):
    """Unit tests for the evidence file validator."""

    def test_valid_screenshot_passes(self):
        from evidence.validators import validate_evidence_upload
        errors = validate_evidence_upload(b'x' * 100, 'shot.png', 'Screenshot')
        self.assertEqual(errors, [])

    def test_oversized_file_fails(self):
        from evidence.validators import validate_evidence_upload
        from django.conf import settings
        big = b'x' * (settings.EVIDENCE_MAX_SIZE_BYTES + 1)
        errors = validate_evidence_upload(big, 'big.png', 'Screenshot')
        self.assertTrue(any('too large' in e for e in errors))

    def test_wrong_extension_for_type_fails(self):
        from evidence.validators import validate_evidence_upload
        errors = validate_evidence_upload(b'x' * 100, 'file.exe', 'Screenshot')
        self.assertTrue(any('not allowed' in e for e in errors))

    def test_other_type_allows_any_extension(self):
        from evidence.validators import validate_evidence_upload
        # 'Other' type has empty allowed list → any extension is permitted
        errors = validate_evidence_upload(b'x' * 100, 'weird.xyz', 'Other')
        # Extension-specific error should not be present
        self.assertFalse(any('not allowed' in e for e in errors))


# ===========================================================================
# 9. REST API: Assessment endpoints still return expected fields
# ===========================================================================

class TestAssessmentAPIFields(TestCase):
    """REST API must include preferred_engine and retention_days in responses."""

    def setUp(self):
        self.user = User.objects.create_user('api_user', password='pass')
        self.api_client = APIClient()
        self.api_client.login(username='api_user', password='pass')
        self.api_client.force_authenticate(user=self.user)
        self.client_obj = Client.objects.create(name='APICo', created_by=self.user)
        self.engagement = Engagement.objects.create(
            client=self.client_obj, name='API Eng', status='Draft', created_by=self.user
        )
        self.assessment = make_assessment(self.user, self.engagement)

    def test_get_assessments_returns_200(self):
        response = self.api_client.get('/api/engagements/assessments/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_assessment_response_includes_retention_days(self):
        response = self.api_client.get('/api/engagements/assessments/')
        results = response.data.get('results', response.data)
        self.assertTrue(len(results) > 0)
        first = results[0]
        self.assertIn('retention_days', first)
        self.assertEqual(first['retention_days'], 365)

    def test_assessment_detail_returns_correct_status(self):
        response = self.api_client.get(f'/api/engagements/assessments/{self.assessment.id}/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['status'], 'Draft')
        self.assertEqual(response.data['assessment_type'], 'Web')


# ===========================================================================
# 10. REST API: Evidence endpoints
# ===========================================================================

class TestEvidenceAPI(TestCase):
    """REST API tests for Evidence Platform endpoints."""

    SAMPLE_CONTENT = b'API EVIDENCE TEST CONTENT'

    def setUp(self):
        self.user = User.objects.create_user('evidence_api', password='pass')
        self.api_client = APIClient()
        self.api_client.login(username='evidence_api', password='pass')
        self.api_client.force_authenticate(user=self.user)

        self.client_obj = Client.objects.create(name='EvidAPICo', created_by=self.user)
        self.engagement = Engagement.objects.create(
            client=self.client_obj, name='EvidAPI Eng', status='Draft', created_by=self.user
        )
        self.assessment = make_assessment(self.user, self.engagement)
        self.collection = EvidenceService.get_or_create_collection(self.assessment)

    def test_list_collections_returns_200(self):
        response = self.api_client.get('/api/evidence/collections/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_list_collections_filtered_by_assessment(self):
        response = self.api_client.get(
            '/api/evidence/collections/',
            {'assessment': str(self.assessment.uuid)}
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        results = response.data.get('results', response.data)
        self.assertTrue(len(results) >= 1)

    def test_collection_detail_returns_200(self):
        response = self.api_client.get(f'/api/evidence/collections/{self.collection.uuid}/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response.data['uuid'], str(self.collection.uuid))
        self.assertIn('item_count', response.data)

    def test_collection_items_endpoint_returns_200(self):
        response = self.api_client.get(f'/api/evidence/collections/{self.collection.uuid}/items/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_evidence_upload_endpoint(self):
        """Uploading a file should create an Evidence record and return 201."""
        file_content = b'UPLOAD TEST CONTENT'
        from django.core.files.uploadedfile import SimpleUploadedFile
        upload = SimpleUploadedFile('upload_test.txt', file_content, content_type='text/plain')
        response = self.api_client.post('/api/evidence/upload/', {
            'file': upload,
            'title': 'API upload test',
            'evidence_type': 'CommandOutput',
            'collection_uuid': str(self.collection.uuid),
        }, format='multipart')
        self.assertEqual(response.status_code, status.HTTP_201_CREATED, response.data)
        self.assertIn('uuid', response.data)
        self.assertEqual(response.data['title'], 'API upload test')
        # SHA-256 must be set
        self.assertIsNotNone(response.data['sha256_hash'])

    def test_evidence_list_returns_200(self):
        response = self.api_client.get('/api/evidence/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)

    def test_evidence_detail_after_upload(self):
        """GET /api/evidence/{uuid}/ must return full detail including events."""
        evidence = EvidenceService.create_evidence(
            collection=self.collection,
            content=self.SAMPLE_CONTENT,
            filename='detail_test.txt',
            evidence_type='Log',
            title='Detail API test',
            skip_validation=True,
        )
        response = self.api_client.get(f'/api/evidence/{evidence.uuid}/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('events', response.data)
        self.assertIn('annotations', response.data)
        self.assertEqual(response.data['sha256_hash'], evidence.sha256_hash)

    def test_evidence_verify_endpoint(self):
        """POST /api/evidence/{uuid}/verify/ must return passed=True for fresh evidence."""
        evidence = EvidenceService.create_evidence(
            collection=self.collection,
            content=self.SAMPLE_CONTENT,
            filename='verify_api.txt',
            evidence_type='Log',
            title='Verify API',
            skip_validation=True,
        )
        response = self.api_client.post(f'/api/evidence/{evidence.uuid}/verify/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertIn('passed', response.data)
        self.assertTrue(response.data['passed'])

    def test_evidence_archive_endpoint(self):
        """POST /api/evidence/{uuid}/archive/ must set status to Archived."""
        evidence = EvidenceService.create_evidence(
            collection=self.collection,
            content=self.SAMPLE_CONTENT,
            filename='archive_api.txt',
            evidence_type='Log',
            title='Archive API',
            skip_validation=True,
        )
        response = self.api_client.post(f'/api/evidence/{evidence.uuid}/archive/', {'note': 'API archive'})
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        evidence.refresh_from_db()
        self.assertEqual(evidence.status, 'Archived')

    def test_evidence_add_annotation(self):
        """POST /api/evidence/{uuid}/annotations/ must create an annotation."""
        evidence = EvidenceService.create_evidence(
            collection=self.collection,
            content=self.SAMPLE_CONTENT,
            filename='annotate_api.txt',
            evidence_type='Log',
            title='Annotate API',
            skip_validation=True,
        )
        response = self.api_client.post(
            f'/api/evidence/{evidence.uuid}/annotations/',
            {'annotation_type': 'Note', 'content': 'This is a test note'},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(response.data['content'], 'This is a test note')

    def test_unauthenticated_request_rejected(self):
        """Evidence endpoints must reject unauthenticated requests."""
        unauth = APIClient()
        response = unauth.get('/api/evidence/collections/')
        self.assertIn(response.status_code, [status.HTTP_401_UNAUTHORIZED, status.HTTP_403_FORBIDDEN, status.HTTP_302_FOUND])
