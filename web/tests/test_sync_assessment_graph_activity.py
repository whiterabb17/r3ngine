"""Test the Phase 5 assessment graph sync activity."""
import asyncio
from unittest.mock import patch, MagicMock
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from engagements.models import Client, Engagement, Assessment, AssessmentEvent
from evidence.models import EvidenceCollection, Evidence
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Vulnerability
from targetApp.models import Project, Domain


class TestSyncAssessmentGraphActivity(TransactionTestCase):
    def setUp(self):
        Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        Domain.objects.create(name='x.test', insert_date=timezone.now())
        self.client_obj = Client.objects.create(name='C')
        self.eng = Engagement.objects.create(
            client=self.client_obj, name='E', engagement_type='Penetration Test',
        )
        self.assessment = Assessment.objects.create(
            engagement=self.eng, name='A', assessment_type='External',
        )
        engine_type = EngineType.objects.create(
            engine_name='engine', yaml_configuration='',
        )
        self.scan = ScanHistory.objects.create(
            domain=Domain.objects.first(), assessment=self.assessment,
            scan_type=engine_type, start_scan_date=timezone.now(),
        )
        # Verified finding (should sync)
        self.verified = Vulnerability.objects.create(
            scan_history=self.scan, name='SSRF', severity=3,
            validation_status='verified',
        )
        # New finding (should NOT sync — filtered out)
        self.raw = Vulnerability.objects.create(
            scan_history=self.scan, name='XSS', severity=2,
            validation_status='new',
        )
        # False positive (should NOT sync)
        self.fp = Vulnerability.objects.create(
            scan_history=self.scan, name='Info', severity=0,
            validation_status='false_positive',
        )
        collection = EvidenceCollection.objects.create(
            assessment=self.assessment, name='C',
        )
        self.evidence = Evidence.objects.create(
            collection=collection, evidence_type='Screenshot', title='shot',
        )
        self.evidence.vulnerabilities.add(self.verified)

    @override_settings(ASSESSMENT_GRAPH_SYNC_ENABLED=False)
    def test_flag_off_skips(self):
        from reNgine.temporal.activities.graph_activities import (
            sync_assessment_graph_activity,
        )
        result = asyncio.run(sync_assessment_graph_activity(str(self.assessment.uuid)))
        self.assertEqual(result['status'], 'skipped_flag_off')

    @override_settings(ASSESSMENT_GRAPH_SYNC_ENABLED=True)
    @patch('reNgine.temporal.activities.graph_activities.GraphBuilder')
    def test_only_live_findings_are_synced(self, mock_builder_cls):
        builder = MagicMock()
        builder.merge_finding_nodes.return_value = 1
        builder.merge_evidence_nodes.return_value = 1
        mock_builder_cls.return_value = builder

        from reNgine.temporal.activities.graph_activities import (
            sync_assessment_graph_activity,
        )
        result = asyncio.run(sync_assessment_graph_activity(str(self.assessment.uuid)))

        # merge_finding_nodes should be called with only the verified finding
        finding_call = builder.merge_finding_nodes.call_args
        synced_vulns = list(finding_call.args[0])
        synced_ids = {v.id for v in synced_vulns}
        self.assertIn(self.verified.id, synced_ids)
        self.assertNotIn(self.raw.id, synced_ids)
        self.assertNotIn(self.fp.id, synced_ids)
        self.assertEqual(result['status'], 'ok')

    @override_settings(ASSESSMENT_GRAPH_SYNC_ENABLED=True)
    @patch('reNgine.temporal.activities.graph_activities.GraphBuilder')
    def test_emits_graph_synced_event(self, mock_builder_cls):
        mock_builder_cls.return_value = MagicMock(
            merge_finding_nodes=MagicMock(return_value=1),
            merge_evidence_nodes=MagicMock(return_value=1),
        )
        from reNgine.temporal.activities.graph_activities import (
            sync_assessment_graph_activity,
        )
        asyncio.run(sync_assessment_graph_activity(str(self.assessment.uuid)))
        self.assertTrue(
            AssessmentEvent.objects.filter(
                assessment=self.assessment, event_type='graph_synced',
            ).exists()
        )
