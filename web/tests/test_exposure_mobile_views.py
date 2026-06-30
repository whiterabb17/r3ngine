from django.test import TestCase
from django.contrib.auth.models import User
from django.utils import timezone
from startScan.models import ScanHistory, Exposure, Subdomain
from targetApp.models import Domain
from dashboard.models import Project
from scanEngine.models import EngineType


def _make_exposure(scan, subdomain, status='open', risk_score=7.5):
    return Exposure.objects.create(
        scan_history=scan,
        target_domain=scan.domain,
        subdomain=subdomain,
        status=status,
        risk_score=risk_score,
    )


class ExposureMobileListViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('tester2', password='x')
        self.client.force_login(self.user)
        self.project = Project.objects.create(name='p2', slug='p2', insert_date=timezone.now())
        self.domain = Domain.objects.create(name='target.test', project=self.project)
        self.engine = EngineType.objects.create(engine_name='test-engine2', yaml_configuration='')
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=2,
            start_scan_date='2026-06-20T00:00:00Z',
        )
        self.subdomain = Subdomain.objects.create(
            name='api.target.test',
            target_domain=self.domain,
            scan_history=self.scan,
        )
        self.e1 = _make_exposure(self.scan, self.subdomain, 'open', 8.0)
        self.e2 = _make_exposure(self.scan, self.subdomain, 'resolved', 3.0)

    def test_list_returns_exposures(self):
        resp = self.client.get(f'/mapi/exposures/?scan_id={self.scan.id}')
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 2)

    def test_list_filters_by_status(self):
        resp = self.client.get(f'/mapi/exposures/?scan_id={self.scan.id}&status=open')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.json()), 1)

    def test_list_response_shape(self):
        resp = self.client.get(f'/mapi/exposures/?scan_id={self.scan.id}')
        item = resp.json()[0]
        for key in ('id', 'title', 'status', 'severity', 'asset_summary', 'evidence_data',
                    'linked_vulnerability_ids', 'created_at'):
            self.assertIn(key, item, f'Missing key: {key}')

    def test_detail_returns_single(self):
        resp = self.client.get(f'/mapi/exposures/{self.e1.id}/')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['id'], self.e1.id)

    def test_detail_404_on_missing(self):
        resp = self.client.get('/mapi/exposures/99999/')
        self.assertEqual(resp.status_code, 404)

    def test_stats_returns_counts(self):
        resp = self.client.get(f'/mapi/exposures/stats/?scan_id={self.scan.id}')
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        for key in ('total', 'open', 'resolved', 'accepted', 'false_positive', 'by_severity'):
            self.assertIn(key, data)
        self.assertEqual(data['total'], 2)
        self.assertEqual(data['open'], 1)
        self.assertEqual(data['resolved'], 1)

    def test_status_update_patch(self):
        resp = self.client.patch(
            f'/mapi/exposures/{self.e1.id}/status/',
            data='{"status": "accepted", "note": "risk accepted by team"}',
            content_type='application/json',
        )
        self.assertEqual(resp.status_code, 200)
        self.e1.refresh_from_db()
        self.assertEqual(self.e1.status, 'accepted')
        self.assertEqual(self.e1.status_note, 'risk accepted by team')

    def test_status_update_rejects_invalid_status(self):
        resp = self.client.patch(
            f'/mapi/exposures/{self.e1.id}/status/',
            data='{"status": "bogus"}',
            content_type='application/json',
        )
        self.assertEqual(resp.status_code, 400)

    def test_bulk_status_update(self):
        resp = self.client.post(
            '/mapi/exposures/bulk-status/',
            data=f'{{"ids": [{self.e1.id}, {self.e2.id}], "status": "resolved"}}',
            content_type='application/json',
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn('updated', data)
        self.assertIn('rejected', data)
        self.assertIn(self.e1.id, data['updated'])
        self.e1.refresh_from_db()
        self.assertEqual(self.e1.status, 'resolved')

    def test_unauthenticated_blocked(self):
        # Create a fresh client with no session to simulate an unauthenticated request
        from django.test import Client
        anon_client = Client()
        resp = anon_client.get(f'/mapi/exposures/?scan_id={self.scan.id}')
        self.assertIn(resp.status_code, [401, 403])
