from django.test import TestCase
from django.contrib.auth.models import User
from django.utils import timezone
from unittest.mock import patch, MagicMock
from startScan.models import ScanHistory, CertificateIntelligence
from targetApp.models import Domain
from dashboard.models import Project
from scanEngine.models import EngineType


def _make_cert(scan):
    return CertificateIntelligence.objects.create(
        scan_history=scan,
        target_domain=scan.domain,
        host='api.target.test',
        port=443,
        subject_cn='api.target.test',
        subject_an=['api.target.test', 'www.target.test'],
        issuer_cn="Let's Encrypt",
        issuer_org="Let's Encrypt",
        not_before=timezone.now(),
        not_after=timezone.now(),
        tls_version='TLSv1.3',
        cipher='TLS_AES_256_GCM_SHA384',
        fingerprint_sha256='aa:bb:cc:dd',
        self_signed=False,
        mismatched=False,
        is_expired=False,
        has_weak_cipher=False,
        trust_chain=[],
        raw_json={},
    )


class CertMobileViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user('tester3', password='x')
        self.client.force_login(self.user)
        self.project = Project.objects.create(name='p3', slug='p3', insert_date=timezone.now())
        self.domain = Domain.objects.create(name='target.test', project=self.project)
        self.engine = EngineType.objects.create(engine_name='test-engine3', yaml_configuration='')
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=2,
            start_scan_date='2026-06-20T00:00:00Z',
        )
        self.cert = _make_cert(self.scan)

    def test_list_returns_certs(self):
        resp = self.client.get('/mapi/certificates/')
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIsInstance(data, list)
        self.assertEqual(len(data), 1)

    def test_list_filters_by_scan_id(self):
        resp = self.client.get(f'/mapi/certificates/?scan_id={self.scan.id}')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(len(resp.json()), 1)

    def test_list_response_shape(self):
        resp = self.client.get('/mapi/certificates/')
        item = resp.json()[0]
        for key in ('id', 'subject_cn', 'issuer_cn', 'san', 'sha256_fingerprint',
                    'sha1_fingerprint', 'is_self_signed', 'is_expired', 'chain'):
            self.assertIn(key, item, f'Missing key: {key}')

    def test_detail_returns_single(self):
        resp = self.client.get(f'/mapi/certificates/{self.cert.id}/')
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(resp.json()['id'], self.cert.id)

    def test_detail_404_on_missing(self):
        resp = self.client.get('/mapi/certificates/99999/')
        self.assertEqual(resp.status_code, 404)

    def test_flag_patches_cert(self):
        resp = self.client.patch(
            f'/mapi/certificates/{self.cert.id}/flag/',
            data='{"flag": "weak-key", "note": "RSA 1024"}',
            content_type='application/json',
        )
        self.assertEqual(resp.status_code, 200)
        self.cert.refresh_from_db()
        self.assertEqual(self.cert.flag_type, 'weak-key')
        self.assertEqual(self.cert.flag_note, 'RSA 1024')

    def test_flag_rejects_invalid_flag(self):
        resp = self.client.patch(
            f'/mapi/certificates/{self.cert.id}/flag/',
            data='{"flag": "bogus"}',
            content_type='application/json',
        )
        self.assertEqual(resp.status_code, 400)

    def test_unauthenticated_blocked(self):
        from django.test import Client
        anon_client = Client()
        resp = anon_client.get('/mapi/certificates/')
        self.assertIn(resp.status_code, [401, 403])

    @patch('asyncio.new_event_loop')
    @patch('reNgine.job_tracker.create_job', return_value='job-abc')
    def test_resync_queues_workflow(self, mock_create_job, mock_new_event_loop):
        """POST /mapi/certificates/<pk>/resync/ returns 202 with queued=True and job_id."""
        mock_loop = MagicMock()
        mock_new_event_loop.return_value = mock_loop
        resp = self.client.post(f'/mapi/certificates/{self.cert.id}/resync/')
        self.assertEqual(resp.status_code, 202)
        data = resp.json()
        self.assertTrue(data.get('queued'))
        self.assertEqual(data.get('job_id'), 'job-abc')

    def test_resync_404_on_missing_cert(self):
        """POST to a non-existent certificate pk returns 404."""
        resp = self.client.post('/mapi/certificates/99999/resync/')
        self.assertEqual(resp.status_code, 404)

    @patch('asyncio.new_event_loop')
    @patch('reNgine.job_tracker.update_job')
    @patch('reNgine.job_tracker.create_job', return_value='job-xyz')
    def test_resync_returns_202_even_if_workflow_start_fails(
        self, mock_create_job, mock_update_job, mock_new_event_loop
    ):
        """If workflow dispatch raises, view still returns 202 (fire-and-forget)."""
        mock_loop = MagicMock()
        mock_loop.run_until_complete.side_effect = Exception("Temporal unavailable")
        mock_new_event_loop.return_value = mock_loop
        resp = self.client.post(f'/mapi/certificates/{self.cert.id}/resync/')
        self.assertEqual(resp.status_code, 202)
        mock_update_job.assert_called_once()

    def test_resync_unauthenticated_blocked(self):
        """Anonymous users cannot POST to the resync endpoint."""
        from django.test import Client
        anon_client = Client()
        resp = anon_client.post(f'/mapi/certificates/{self.cert.id}/resync/')
        self.assertIn(resp.status_code, [401, 403])
