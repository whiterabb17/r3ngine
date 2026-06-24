"""
Tests for two timeline display bugs found in scan 4:
  1. update_scan_activity(SUCCESS_TASK) must clear stale error_message/traceback
     from a previous failed attempt on the same record.
  2. Timeline API must exclude unclaimed INITIATED rows (time_started=None) left
     over from a prior failed workflow run.
"""
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role

from dashboard.models import Project
from scanEngine.models import EngineType
from startScan.models import ScanActivity, ScanHistory
from targetApp.models import Domain

User = get_user_model()


class TestUpdateScanActivityClearsError(TestCase):
    """update_scan_activity(SUCCESS_TASK) must clear stale error fields."""

    def _make_proxy(self, activity_row):
        from reNgine.temporal_activities import TemporalTaskProxy
        proxy = TemporalTaskProxy.__new__(TemporalTaskProxy)
        proxy.task_name = 'test_task'
        proxy.activity = activity_row
        return proxy

    def setUp(self):
        project = Project.objects.create(name='err-test', slug='err-test', insert_date=timezone.now())
        engine = EngineType.objects.create(engine_name='err-engine', yaml_configuration='')
        domain = Domain.objects.create(name='err.example', project=project, insert_date=timezone.now())
        self.scan = ScanHistory.objects.create(
            domain=domain, scan_type=engine, scan_status=1, start_scan_date=timezone.now()
        )

    def test_success_clears_stale_error_message(self):
        """A SUCCESS update on a record that previously held an error_message must clear it."""
        from reNgine.definitions import SUCCESS_TASK, FAILED_TASK
        act = ScanActivity.objects.create(
            scan_of=self.scan,
            name='nuclei_scan',
            title='Nuclei Scan',
            status=FAILED_TASK,
            error_message='Activity task failed',
            traceback='some traceback',
            time=timezone.now(),
        )
        proxy = self._make_proxy(act)
        with patch('temporalio.activity.logger'):
            proxy.update_scan_activity(SUCCESS_TASK)
        act.refresh_from_db()
        self.assertEqual(act.status, SUCCESS_TASK)
        self.assertEqual(act.error_message, '')
        self.assertEqual(act.traceback, '')

    def test_success_with_explicit_error_preserves_it(self):
        """Passing an explicit error_message to a SUCCESS update still stores it (edge case guard)."""
        from reNgine.definitions import SUCCESS_TASK
        act = ScanActivity.objects.create(
            scan_of=self.scan,
            name='nuclei_scan',
            title='Nuclei Scan',
            status=1,
            time=timezone.now(),
        )
        proxy = self._make_proxy(act)
        with patch('temporalio.activity.logger'):
            proxy.update_scan_activity(SUCCESS_TASK, error_message='partial failure note')
        act.refresh_from_db()
        self.assertEqual(act.error_message, 'partial failure note')

    def test_failed_update_sets_error_message(self):
        """FAILED_TASK update must set the error_message as before."""
        from reNgine.definitions import FAILED_TASK
        act = ScanActivity.objects.create(
            scan_of=self.scan,
            name='wpscan_scan',
            title='WPScan',
            status=1,
            time=timezone.now(),
        )
        proxy = self._make_proxy(act)
        with patch('temporalio.activity.logger'):
            proxy.update_scan_activity(FAILED_TASK, error_message='subprocess timeout')
        act.refresh_from_db()
        self.assertEqual(act.status, FAILED_TASK)
        self.assertEqual(act.error_message, 'subprocess timeout')


class TestTimelineExcludesGhostInitiated(TestCase):
    """Timeline API must exclude unclaimed INITIATED rows (time_started=None)."""

    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='timeline-user', password='pass', email='tl@example.com',
            is_staff=True, is_superuser=True,
        )
        self.client.force_authenticate(user=self.user)
        self.client.force_login(self.user)
        assign_role(self.user, 'sys_admin')

        self.project = Project.objects.create(name='tl-proj', slug='tl-proj', insert_date=timezone.now())
        engine = EngineType.objects.create(engine_name='tl-engine', yaml_configuration='')
        self.domain = Domain.objects.create(name='tl.example', project=self.project, insert_date=timezone.now())
        self.scan = ScanHistory.objects.create(
            domain=self.domain, scan_type=engine, scan_status=2, start_scan_date=timezone.now()
        )

    def _create_activity(self, name, status, time_started=None, error_message=''):
        from reNgine.definitions import INITIATED_TASK
        return ScanActivity.objects.create(
            scan_of=self.scan,
            name=name,
            title=name.replace('_', ' ').title(),
            status=status,
            time=timezone.now(),
            time_started=time_started,
            error_message=error_message,
        )

    def test_ghost_initiated_row_excluded_from_timeline(self):
        """An INITIATED activity with no time_started must not appear in the timeline response."""
        from reNgine.definitions import INITIATED_TASK, SUCCESS_TASK
        ghost = self._create_activity('web_api_discovery', INITIATED_TASK, time_started=None)
        real = self._create_activity('web_api_discovery', SUCCESS_TASK, time_started=timezone.now())

        url = reverse('api:scan_summary_api', kwargs={'slug': self.project.slug, 'id': self.scan.id})
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)
        timeline_ids = [a['id'] for a in resp.json().get('timeline', [])]

        self.assertNotIn(ghost.id, timeline_ids, 'Ghost INITIATED row must be excluded from timeline')
        self.assertIn(real.id, timeline_ids, 'Successful activity must still appear in timeline')

    def test_started_initiated_row_included(self):
        """An INITIATED activity that has time_started set is in-progress and must be shown."""
        from reNgine.definitions import INITIATED_TASK
        active = self._create_activity('param_discovery', INITIATED_TASK, time_started=timezone.now())

        url = reverse('api:scan_summary_api', kwargs={'slug': self.project.slug, 'id': self.scan.id})
        resp = self.client.get(url)
        self.assertEqual(resp.status_code, 200)
        timeline_ids = [a['id'] for a in resp.json().get('timeline', [])]

        self.assertIn(active.id, timeline_ids, 'In-progress INITIATED row must still appear')
