from django.test import TestCase
from django.contrib.auth.models import User
from django.utils import timezone
from startScan.models import ScanHistory, IdentityInfraDiscovery
from targetApp.models import Domain
from dashboard.models import Project
from scanEngine.models import EngineType


def _make_identity(scan):
    return IdentityInfraDiscovery.objects.create(
        scan_history=scan,
        target_domain=scan.domain,
        host='login.target.test',
        url='https://login.target.test',
        infra_type='generic_auth_portal',
        detection_method='header_analysis',
        confidence_score=0.85,
        is_externally_accessible=True,
        additional_signals={'x-okta-version': '1.0'},
    )


class IdentityMobileViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('tester4', password='x')
        self.client.force_login(self.user)
        self.project = Project.objects.create(name='p4', slug='p4', insert_date=timezone.now())
        self.domain = Domain.objects.create(name='target.test', project=self.project)
        self.engine = EngineType.objects.create(engine_name='test-engine4', yaml_configuration='')
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=2,
            start_scan_date='2026-06-20T00:00:00Z',
        )
        self.discovery = _make_identity(self.scan)

    def test_detail_returns_discovery(self):
        resp = self.client.get(f'/mapi/identity/{self.discovery.id}/')
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data['id'], self.discovery.id)
        self.assertIn('provider', data)
        self.assertIn('match_strength', data)
        self.assertIn('detection_signals', data)

    def test_detail_response_shape(self):
        resp = self.client.get(f'/mapi/identity/{self.discovery.id}/')
        data = resp.json()
        self.assertIn('matched_urls', data['detection_signals'])
        self.assertIn('matched_titles', data['detection_signals'])
        self.assertIn('matched_headers', data['detection_signals'])

    def test_detail_404_on_missing(self):
        resp = self.client.get('/mapi/identity/99999/')
        self.assertEqual(resp.status_code, 404)

    def test_confirm_sets_confirmed(self):
        resp = self.client.patch(
            f'/mapi/identity/{self.discovery.id}/confirm/',
            data='{"confirmed": true}',
            content_type='application/json',
        )
        self.assertEqual(resp.status_code, 200)
        self.discovery.refresh_from_db()
        self.assertTrue(self.discovery.confirmed)

    def test_confirm_false_clears_confirmed(self):
        self.discovery.confirmed = True
        self.discovery.save()
        resp = self.client.patch(
            f'/mapi/identity/{self.discovery.id}/confirm/',
            data='{"confirmed": false}',
            content_type='application/json',
        )
        self.assertEqual(resp.status_code, 200)
        self.discovery.refresh_from_db()
        self.assertFalse(self.discovery.confirmed)

    def test_dismiss_sets_dismissed(self):
        resp = self.client.patch(
            f'/mapi/identity/{self.discovery.id}/dismiss/',
            data='{"reason": "not an IdP"}',
            content_type='application/json',
        )
        self.assertEqual(resp.status_code, 200)
        self.discovery.refresh_from_db()
        self.assertTrue(self.discovery.dismissed)
        self.assertEqual(self.discovery.dismiss_reason, 'not an IdP')

    def test_unauthenticated_blocked(self):
        from django.test import Client
        anon_client = Client()
        resp = anon_client.get(f'/mapi/identity/{self.discovery.id}/')
        self.assertIn(resp.status_code, [401, 403])
