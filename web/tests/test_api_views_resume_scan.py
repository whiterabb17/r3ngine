"""POST /api/action/resume/scan/ — resume a stopped scan from its unfinished tasks.

All domains and users here are anonymised (RFC 2606).
"""
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role

from reNgine.definitions import (
    ABORTED_TASK, FAILED_TASK, INTERNAL_ERROR_MESSAGE, PARTIALLY_COMPLETE_TASK,
    PAUSED_TASK, RUNNING_TASK, SUCCESS_TASK,
)
from scanEngine.models import EngineType
from startScan.models import ScanHistory
from targetApp.models import Domain

User = get_user_model()


@patch('reNgine.tasks.resume_scan_temporal')
class ResumeScanTests(TestCase):

    def setUp(self) -> None:
        self.client = APIClient()
        user = User.objects.create_user(username='resume-admin', password='pass', email='admin@test.example')
        assign_role(user, 'sys_admin')
        self.client.force_authenticate(user=user)
        self.client.force_login(user)
        engine = EngineType.objects.create(engine_name='resume-engine', yaml_configuration='')
        domain = Domain.objects.create(name='resume.test.example', insert_date=timezone.now())
        self.scan = ScanHistory.objects.create(
            domain=domain, scan_type=engine, scan_status=FAILED_TASK, start_scan_date=timezone.now(),
        )

    def _post(self):
        return self.client.post(reverse('api:resume_scan'), {'scan_id': self.scan.id}, format='json')

    def _set(self, **fields) -> None:
        ScanHistory.objects.filter(pk=self.scan.pk).update(**fields)

    def test_stopped_scans_are_resumed(self, mock_resume) -> None:
        for status in (FAILED_TASK, ABORTED_TASK, PARTIALLY_COMPLETE_TASK):
            self._set(scan_status=status)
            self.assertTrue(self._post().json()['status'], status)
        self.assertEqual(mock_resume.call_count, 3)

    def test_a_scan_that_still_has_a_workflow_is_not_resumed(self, mock_resume) -> None:
        for status in (RUNNING_TASK, PAUSED_TASK, SUCCESS_TASK):
            self._set(scan_status=status)
            self.assertFalse(self._post().json()['status'], status)
        mock_resume.assert_not_called()

    def test_manual_resume_is_not_blocked_by_the_automatic_recovery_cap(self, mock_resume) -> None:
        self._set(recovery_count=3)
        self.assertTrue(self._post().json()['status'])
        mock_resume.assert_called_once_with(self.scan.id)

    def test_a_failure_returns_the_generic_message(self, mock_resume) -> None:
        mock_resume.side_effect = RuntimeError('temporal://internal-host:7233 refused')
        payload = self._post().json()
        self.assertFalse(payload['status'])
        self.assertEqual(payload['message'], INTERNAL_ERROR_MESSAGE)
