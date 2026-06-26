"""Tests for email discovery and manual email add API endpoints."""
import json
import uuid
from unittest.mock import patch, MagicMock
from django.test import TestCase
from django.contrib.auth.models import User
from django.utils import timezone
from rolepermissions.roles import assign_role

from scanEngine.models import EngineType
from startScan.models import ScanHistory
from targetApp.models import Domain


class EmailDiscoveryAPITestCase(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='tester',
            password='pass',
            is_staff=True,
            is_superuser=True,
        )
        assign_role(self.user, 'sys_admin')
        self.client.force_login(self.user)

        self.engine = EngineType.objects.create(
            engine_name='Test Engine',
            yaml_configuration='',
        )
        self.domain = Domain.objects.create(name='example.com')
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            start_scan_date=timezone.now(),
            scan_status=2,
        )

    def test_manual_add_valid_emails(self):
        resp = self.client.post(
            '/api/emails/manual/',
            data=json.dumps({
                'scan_id': self.scan.id,
                'addresses': ['a@example.com', 'b@example.com'],
            }),
            content_type='application/json',
        )
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertEqual(data['added'], 2)
        self.assertEqual(data['skipped'], 0)

    def test_manual_add_invalid_emails_skipped(self):
        resp = self.client.post(
            '/api/emails/manual/',
            data=json.dumps({
                'scan_id': self.scan.id,
                'addresses': ['valid@example.com', 'not-an-email', ''],
            }),
            content_type='application/json',
        )
        self.assertEqual(resp.status_code, 207)
        data = resp.json()
        self.assertEqual(data['added'], 1)
        self.assertEqual(data['skipped'], 2)

    def test_manual_add_missing_scan_id_returns_400(self):
        resp = self.client.post(
            '/api/emails/manual/',
            data=json.dumps({'addresses': ['a@example.com']}),
            content_type='application/json',
        )
        self.assertEqual(resp.status_code, 400)

    @patch('api.views.recon._get_active_job', return_value=None)
    @patch('api.views.recon._set_active')
    @patch('api.views.recon.threading.Thread')
    def test_start_discovery_returns_job_id(self, mock_thread, mock_set, mock_get):
        mock_thread.return_value = MagicMock()
        resp = self.client.post(
            '/api/emailDiscovery/start/',
            data=json.dumps({'scan_id': self.scan.id}),
            content_type='application/json',
        )
        self.assertEqual(resp.status_code, 202)
        data = resp.json()
        self.assertIn('job_id', data)

    @patch('api.views.recon._get_active_job', return_value='existing-job-id')
    def test_start_discovery_conflict_when_running(self, mock_get):
        resp = self.client.post(
            '/api/emailDiscovery/start/',
            data=json.dumps({'scan_id': self.scan.id}),
            content_type='application/json',
        )
        self.assertEqual(resp.status_code, 409)
        self.assertEqual(resp.json()['job_id'], 'existing-job-id')

    @patch('api.views.recon._email_redis')
    def test_stop_discovery_sets_stop_key(self, mock_redis_fn):
        mock_r = MagicMock()
        mock_redis_fn.return_value = mock_r
        job_id = str(uuid.uuid4())
        resp = self.client.post(
            '/api/emailDiscovery/stop/',
            data=json.dumps({'job_id': job_id}),
            content_type='application/json',
        )
        self.assertEqual(resp.status_code, 200)
        mock_r.set.assert_called_once_with(f'email_discovery:{job_id}:stop', '1', ex=3600)

    @patch('api.views.recon._email_redis')
    def test_replay_returns_events_and_complete_flag(self, mock_redis_fn):
        job_id = str(uuid.uuid4())
        complete_event = {'type': 'email_discovery_complete', 'job_id': job_id, 'total_found': 5}
        mock_r = MagicMock()
        mock_r.get.return_value = str(self.scan.id)
        mock_r.xread.return_value = [(
            f'scan:logs:{self.scan.id}',
            [
                ('1-0', {'data': json.dumps({
                    'type': 'email_discovery_progress',
                    'job_id': job_id,
                    'tool': 'hunter',
                    'status': 'done',
                    'found': 3,
                    'message': '',
                })}),
                ('2-0', {'data': json.dumps(complete_event)}),
            ]
        )]
        mock_redis_fn.return_value = mock_r
        resp = self.client.get(f'/api/emailDiscovery/{job_id}/replay/')
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertTrue(data['complete'])
        self.assertEqual(len(data['events']), 2)
