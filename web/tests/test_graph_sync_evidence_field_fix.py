"""Regression test for the 2026-07-05 sync_all_scans FieldError bug.

The old code queried Evidence.objects.values('uuid', 'type', 'description',
'integrity_hash') which raised FieldError because Evidence has no fields
named `type` or `integrity_hash` — they are `evidence_type` and
`sha256_hash`. It also called self._batch_merge_evidence which was never
defined.

This test guards against both regressions.
"""
from unittest.mock import patch, MagicMock
from django.test import TestCase
from django.utils import timezone

from engagements.models import Client, Engagement, Assessment
from evidence.models import EvidenceCollection, Evidence
from startScan.models import ScanHistory
from dashboard.models import Project
from targetApp.models import Domain
from scanEngine.models import EngineType


class TestGraphSyncEvidenceFieldFix(TestCase):
    def setUp(self):
        self.project = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.domain = Domain.objects.create(name='example.test', project=self.project)
        self.client_obj = Client.objects.create(name='ClientA')
        self.eng = Engagement.objects.create(
            client=self.client_obj, name='E1', engagement_type='Penetration Test',
        )
        self.assessment = Assessment.objects.create(
            engagement=self.eng, name='A1', assessment_type='External',
        )
        self.engine = EngineType.objects.create(
            engine_name='TestEngine',
            yaml_configuration='tasks: []',
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            assessment=self.assessment,
            start_scan_date=timezone.now(),
            scan_status=0,
            scan_type=self.engine,
        )
        self.collection = EvidenceCollection.objects.create(
            assessment=self.assessment, scan_history=self.scan, name='C1',
        )
        Evidence.objects.create(
            collection=self.collection,
            evidence_type='Screenshot',
            title='shot',
            sha256_hash='deadbeef' * 8,
        )

    @patch('reNgine.utils.graph.GraphDatabase.driver')
    def test_sync_scan_results_does_not_raise_field_error(self, mock_driver):
        """Sync must not raise FieldError('type') or AttributeError('_batch_merge_evidence')."""
        from reNgine.utils.graph import Neo4jManager

        mock_session = MagicMock()
        mock_driver.return_value.session.return_value.__enter__.return_value = mock_session

        mgr = Neo4jManager()
        mgr.driver = mock_driver.return_value

        try:
            mgr.sync_scan_results(self.scan.id)
        except Exception as exc:
            self.fail(f"sync_scan_results raised {type(exc).__name__}: {exc}")

    def test_batch_merge_evidence_exists(self):
        """The static method that the sync path calls must exist."""
        from reNgine.utils.graph import Neo4jManager
        self.assertTrue(
            hasattr(Neo4jManager, '_batch_merge_evidence'),
            "Neo4jManager._batch_merge_evidence must be defined",
        )
