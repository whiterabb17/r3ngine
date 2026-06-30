from django.test import TestCase
from django.contrib.auth.models import User
from django.utils import timezone
from startScan.models import ScanHistory, ImpactAssessment
from targetApp.models import Domain
from dashboard.models import Project
from scanEngine.models import EngineType


class APMEMobileViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('tester', password='x')
        self.client.force_login(self.user)
        self.project = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.domain = Domain.objects.create(name='example.test', project=self.project)
        self.engine = EngineType.objects.create(engine_name='test-engine', yaml_configuration='')
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=2,
            start_scan_date='2026-06-20T00:00:00Z',
        )
        self.assessment = ImpactAssessment.objects.create(
            scan_history=self.scan,
            potential_attack_chain={
                'apme_path_id': 'path-1',
                'risk': 'critical',
                'score': 92.0,
                'steps': [{'from': 'a', 'to': 'b', 'action': 'exploit', 'confidence': 0.9, 'edge_type': 'RCE', 'validated': True}],
            },
            potential_impact='Remote code execution on edge host',
            remediation_priority=4,
        )

    def test_risk_summary_returns_score_and_priority(self):
        resp = self.client.get(f'/mapi/apme/risk-summary/?scan_id={self.scan.id}')
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn('score', data)
        self.assertIn('priority', data)
        self.assertIn(data['priority'], ['P0', 'P1', 'P2', 'P3'])
        self.assertEqual(data['path_count'], 1)

    def test_risk_summary_requires_scan_id(self):
        resp = self.client.get('/mapi/apme/risk-summary/')
        self.assertEqual(resp.status_code, 400)

    def test_impact_detail_returns_assessment(self):
        resp = self.client.get('/mapi/apme/impact/path-1/')
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn('business_impact', data)
        self.assertIn('technical_impact', data)

    def test_impact_detail_404_on_unknown_path(self):
        resp = self.client.get('/mapi/apme/impact/nonexistent/')
        self.assertEqual(resp.status_code, 404)

    def test_attack_tree_returns_paths(self):
        resp = self.client.get('/mapi/apme/tree/example.test/')
        self.assertEqual(resp.status_code, 200)
        self.assertIn('paths', resp.json())

    def test_dismiss_path_sets_dismissed(self):
        resp = self.client.patch(
            '/mapi/apme/path/path-1/dismiss/',
            data='{"reason": "false alarm"}',
            content_type='application/json',
        )
        self.assertEqual(resp.status_code, 200)
        self.assessment.refresh_from_db()
        self.assertTrue(self.assessment.dismissed)
        self.assertEqual(self.assessment.dismiss_reason, 'false alarm')

    def test_dismiss_path_404_on_unknown(self):
        resp = self.client.patch(
            '/mapi/apme/path/unknown-path/dismiss/',
            data='{}',
            content_type='application/json',
        )
        self.assertEqual(resp.status_code, 404)

    def test_unauthenticated_blocked(self):
        # Create a fresh client with no session to simulate an unauthenticated request
        from django.test import Client
        anon_client = Client()
        resp = anon_client.get(f'/mapi/apme/risk-summary/?scan_id={self.scan.id}')
        self.assertIn(resp.status_code, [401, 403])
