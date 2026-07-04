import json
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework import status
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role

from dashboard.models import Project
from scanEngine.models import EngineType
from startScan.models import ScanHistory
from targetApp.models import Domain

User = get_user_model()


class EmployeeIntelApiTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='emp-intel-tester',
            password='testpassword',
            email='emp-intel@example.com',
            is_staff=True,
            is_superuser=True,
        )
        self.client.force_authenticate(user=self.user)
        self.client.force_login(self.user)
        assign_role(self.user, 'sys_admin')

        self.project = Project.objects.create(
            name='Emp Intel Project',
            slug='emp-intel-project',
            insert_date=timezone.now(),
        )
        self.engine = EngineType.objects.create(
            engine_name='Emp Intel Engine',
            yaml_configuration='',
        )
        self.domain = Domain.objects.create(
            name='emp-intel.example',
            project=self.project,
            insert_date=timezone.now(),
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=2,
            start_scan_date=timezone.now(),
        )

    @patch('api.views.recon.threading.Thread')
    @patch('api.views.recon._get_active_emp_job', return_value=None)
    @patch('api.views.recon._set_emp_active')
    def test_start_returns_job_id(self, mock_set, mock_get, mock_thread):
        mock_thread.return_value = mock_thread
        response = self.client.post(
            '/api/employeeIntel/start/',
            {'scan_id': self.scan.id},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertIn('job_id', data)
        self.assertTrue(mock_set.called)
        self.assertTrue(mock_thread.called)

    @patch('api.views.recon._get_active_emp_job', return_value='existing-job-id')
    def test_start_returns_existing_job_if_already_running(self, mock_get):
        response = self.client.post(
            '/api/employeeIntel/start/',
            {'scan_id': self.scan.id},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertEqual(data['job_id'], 'existing-job-id')
        self.assertTrue(data.get('already_running'))

    def test_start_returns_400_without_scan_id(self):
        response = self.client.post('/api/employeeIntel/start/', {}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    def test_start_returns_404_for_missing_scan(self):
        response = self.client.post(
            '/api/employeeIntel/start/',
            {'scan_id': 99999},
            format='json',
        )
        self.assertEqual(response.status_code, status.HTTP_404_NOT_FOUND)

    def test_stop_returns_400_without_job_id(self):
        response = self.client.post('/api/employeeIntel/stop/', {}, format='json')
        self.assertEqual(response.status_code, status.HTTP_400_BAD_REQUEST)

    @patch('api.views.recon._emp_redis')
    def test_replay_returns_empty_for_unknown_job(self, mock_redis):
        mock_redis.return_value.get.return_value = None
        response = self.client.get('/api/employeeIntel/unknown-job/replay/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        data = response.json()
        self.assertEqual(data['events'], [])
        self.assertFalse(data['complete'])
