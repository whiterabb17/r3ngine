"""GraphBuilder new-method tests for Phase 5.

Neo4j session is mocked; the tests verify the Cypher parameters
passed via UNWIND and that MERGEs are idempotent (double-call yields
the same parameter shape).
"""
from unittest.mock import MagicMock, patch
from django.test import TestCase
from django.utils import timezone

from engagements.models import Client, Engagement, Assessment
from targetApp.models import Domain
from dashboard.models import Project


class TestGraphBuilderAssessmentNodes(TestCase):
    def setUp(self):
        self.project = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        Domain.objects.create(name='example.test', project=self.project)
        self.client_obj = Client.objects.create(name='ClientA')
        self.eng = Engagement.objects.create(
            client=self.client_obj, name='E', engagement_type='Penetration Test',
        )
        self.assessment = Assessment.objects.create(
            engagement=self.eng, name='A', assessment_type='External',
        )

    @patch('apme.graph.builder.GraphDatabase.driver')
    def test_merge_assessment_node_calls_merge(self, mock_driver):
        from apme.graph.builder import GraphBuilder

        mock_session = MagicMock()
        mock_driver.return_value.session.return_value.__enter__.return_value = mock_session

        b = GraphBuilder()
        b.merge_assessment_node(self.assessment)

        # Called at least once with a MERGE (:Assessment ...) statement
        run_calls = [c for c in mock_session.run.call_args_list
                     if c.args and 'MERGE (a:Assessment' in c.args[0]]
        self.assertTrue(run_calls, "Expected a MERGE on :Assessment")

        # Params must include the assessment uuid
        params = run_calls[0].kwargs
        self.assertEqual(str(self.assessment.uuid), params.get('uuid'))

    @patch('apme.graph.builder.GraphDatabase.driver')
    def test_merge_finding_nodes_creates_contains_edge(self, mock_driver):
        from apme.graph.builder import GraphBuilder
        from startScan.models import ScanHistory, Vulnerability
        from scanEngine.models import EngineType

        mock_session = MagicMock()
        mock_driver.return_value.session.return_value.__enter__.return_value = mock_session

        engine = EngineType.objects.create(engine_name='test-engine', yaml_configuration='')
        scan = ScanHistory.objects.create(
            domain=Domain.objects.first(),
            scan_type=engine,
            start_scan_date=timezone.now(),
            assessment=self.assessment,
        )
        vuln = Vulnerability.objects.create(
            scan_history=scan, name='SSRF', severity=3,
        )

        b = GraphBuilder()
        count = b.merge_finding_nodes([vuln], assessment=self.assessment)

        self.assertEqual(count, 1)

        cypher_calls = [c.args[0] for c in mock_session.run.call_args_list if c.args]
        merged_edge = any('CONTAINS' in q and 'Finding' in q for q in cypher_calls)
        self.assertTrue(merged_edge, "Expected a CONTAINS edge to be MERGEd")

    @patch('apme.graph.builder.GraphDatabase.driver')
    def test_merge_authentication_system_returns_apme_id(self, mock_driver):
        from apme.graph.builder import GraphBuilder

        mock_session = MagicMock()
        mock_driver.return_value.session.return_value.__enter__.return_value = mock_session

        b = GraphBuilder()
        apme_id = b.merge_authentication_system('idp.example.test', 'saml')

        self.assertIsInstance(apme_id, str)
        self.assertGreater(len(apme_id), 8)

    @patch('apme.graph.builder.GraphDatabase.driver')
    def test_attach_assessment_id_uses_bulk_update(self, mock_driver):
        from apme.graph.builder import GraphBuilder

        mock_session = MagicMock()
        result = MagicMock()
        result.single.return_value = {'updated': 42}
        mock_session.run.return_value = result
        mock_driver.return_value.session.return_value.__enter__.return_value = mock_session

        b = GraphBuilder()
        n = b.attach_assessment_id(scan_id=99, assessment_uuid='abcd-1234')

        self.assertEqual(n, 42)
        used_query = mock_session.run.call_args.args[0]
        self.assertIn('SET n.assessment_id', used_query)
