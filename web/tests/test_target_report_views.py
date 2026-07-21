import json
from django.test import TestCase, Client
from django.utils import timezone
from unittest.mock import patch
from datetime import timedelta
from rolepermissions.roles import assign_role
from startScan.models import ScanHistory, EngineType, TargetReport
from targetApp.models import Domain
from dashboard.models import Project
from django.contrib.auth import get_user_model

User = get_user_model()


class TargetReportViewTest(TestCase):
    def setUp(self):
        self.client = Client()
        self.user = User.objects.create_user(username='testuser_trv', password='testpass123')
        assign_role(self.user, 'sys_admin')
        self.client.force_login(self.user)
        self.project = Project.objects.create(
            name='Test Project Views',
            slug='test-project-views',
            insert_date=timezone.now(),
        )
        self.domain = Domain.objects.create(
            name='view.example.com',
            project=self.project,
            insert_date=timezone.now(),
        )
        self.engine = EngineType.objects.create(
            engine_name='test-engine-views',
            yaml_configuration='',
        )
        self.scan1 = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=2,
            start_scan_date=timezone.now() - timedelta(days=7),
        )
        self.scan2 = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=2,
            start_scan_date=timezone.now(),
        )

    @patch('startScan.views.threading.Thread')
    def test_create_target_report_returns_report_id(self, mock_thread):
        mock_thread.return_value.start.return_value = None
        response = self.client.get(
            f'/scan/target/create_report/{self.domain.id}/',
            {'scan_ids': f'{self.scan1.id},{self.scan2.id}', 'included_sections': 'subdomain_changes'},
        )
        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertTrue(data['status'])
        self.assertIn('report_id', data)

    @patch('startScan.views.threading.Thread')
    def test_create_target_report_rejects_single_scan(self, _):
        response = self.client.get(
            f'/scan/target/create_report/{self.domain.id}/',
            {'scan_ids': str(self.scan1.id)},
        )
        self.assertEqual(response.status_code, 400)

    @patch('startScan.views.threading.Thread')
    def test_create_target_report_rejects_foreign_scan(self, _):
        other_project = Project.objects.create(
            name='Other Project',
            slug='other-project-trv',
            insert_date=timezone.now(),
        )
        other_domain = Domain.objects.create(
            name='other.example.com',
            project=other_project,
            insert_date=timezone.now(),
        )
        other_scan = ScanHistory.objects.create(
            domain=other_domain,
            scan_type=self.engine,
            scan_status=2,
            start_scan_date=timezone.now(),
        )
        response = self.client.get(
            f'/scan/target/create_report/{self.domain.id}/',
            {'scan_ids': f'{self.scan1.id},{other_scan.id}'},
        )
        self.assertEqual(response.status_code, 400)

    def test_get_status_running(self):
        report = TargetReport.objects.create(
            domain=self.domain, selected_scan_ids=[self.scan1.id, self.scan2.id], status=1,
        )
        response = self.client.get(f'/scan/target/report/status/{report.id}/')
        data = json.loads(response.content)
        self.assertEqual(data['status'], 1)
        self.assertIsNone(data['report_url'])

    def test_get_status_complete(self):
        report = TargetReport.objects.create(
            domain=self.domain, selected_scan_ids=[self.scan1.id, self.scan2.id],
            status=2, completed_at=timezone.now(),
        )
        response = self.client.get(f'/scan/target/report/status/{report.id}/')
        data = json.loads(response.content)
        self.assertEqual(data['status'], 2)

    def test_get_status_stuck_recovery(self):
        report = TargetReport.objects.create(
            domain=self.domain, selected_scan_ids=[self.scan1.id, self.scan2.id], status=1,
        )
        TargetReport.objects.filter(id=report.id).update(
            created_at=timezone.now() - timedelta(minutes=35)
        )
        response = self.client.get(f'/scan/target/report/status/{report.id}/')
        data = json.loads(response.content)
        self.assertEqual(data['status'], 0)
        self.assertIn('timed out', data['error_message'])
