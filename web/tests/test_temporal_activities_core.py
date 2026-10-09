"""TemporalTaskProxy resolves the scan's hardware profile when each activity starts.

The workflow input freezes ``ctx['hardware_profile']`` at scan start. Reading the
profile from the scan row instead lets an operator switch (or edit) the profile of
a running scan and have the next steps pick it up.

All domains here are anonymised (RFC 2606).
"""
import tempfile

from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from reNgine.definitions import RUNNING_TASK
from reNgine.temporal.activities.core import TemporalTaskProxy
from scanEngine.models import EngineType, HardwareProfile
from startScan.models import ScanHistory, Subdomain, SubScan
from targetApp.models import Domain

FROZEN = {'id': 0, 'name': 'frozen', 'threads': 4, 'rate_limit': 50, 'timeout': 10, 'delay': 0.1, 'retries': 1}


class ProxyHardwareProfileTests(TestCase):

    def setUp(self) -> None:
        HardwareProfile.objects.all().delete()
        self.results_dir = tempfile.mkdtemp()
        self.weak = HardwareProfile.objects.create(name='hp-weak', threads=4, rate_limit=50, delay=0.1, retries=1)
        self.strong = HardwareProfile.objects.create(name='hp-strong', threads=64, rate_limit=1000, delay=0.0, retries=3)
        engine = EngineType.objects.create(engine_name='hp-engine', yaml_configuration='')
        domain = Domain.objects.create(name='hp.test.example', insert_date=timezone.now())
        self.scan = ScanHistory.objects.create(
            domain=domain,
            scan_type=engine,
            scan_status=RUNNING_TASK,
            start_scan_date=timezone.now(),
            hardware_profile=self.weak,
        )

    def _ctx(self, **extra) -> dict:
        ctx = {
            'scan_history_id': self.scan.id,
            'engine_id': self.scan.scan_type_id,
            'domain_id': self.scan.domain_id,
            'results_dir': self.results_dir,
            'yaml_configuration': {'port_scan': {}, 'nuclei_scan': {'threads': 7}},
            'hardware_profile': FROZEN,
            'track': False,
        }
        ctx.update(extra)
        return ctx

    def test_profile_switched_after_start_is_used(self) -> None:
        self.scan.hardware_profile = self.strong
        self.scan.save(update_fields=['hardware_profile'])

        proxy = TemporalTaskProxy(self._ctx(), task_name='port_scan')

        self.assertEqual(proxy.hardware_profile['name'], 'hp-strong')
        self.assertEqual(proxy.yaml_configuration['port_scan']['threads'], 64)
        self.assertEqual(proxy.yaml_configuration['port_scan']['rate_limit'], 1000)
        # Engine section values still win over the profile.
        self.assertEqual(proxy.yaml_configuration['nuclei_scan']['threads'], 7)

    def test_profile_values_edited_after_start_are_used(self) -> None:
        HardwareProfile.objects.filter(pk=self.weak.pk).update(threads=12)

        proxy = TemporalTaskProxy(self._ctx(), task_name='port_scan')

        self.assertEqual(proxy.yaml_configuration['port_scan']['threads'], 12)

    def test_subscan_reads_the_parent_scan_profile(self) -> None:
        subdomain = Subdomain.objects.create(
            name='app.hp.test.example', scan_history=self.scan, target_domain=self.scan.domain,
        )
        subscan = SubScan.objects.create(
            scan_history=self.scan, subdomain=subdomain, type='port_scan',
            status=RUNNING_TASK, start_scan_date=timezone.now(),
        )
        self.scan.hardware_profile = self.strong
        self.scan.save(update_fields=['hardware_profile'])

        proxy = TemporalTaskProxy(self._ctx(subscan_id=subscan.id), task_name='port_scan')

        self.assertEqual(proxy.yaml_configuration['port_scan']['rate_limit'], 1000)

    def test_scan_without_profile_uses_the_current_default(self) -> None:
        self.scan.hardware_profile = None
        self.scan.save(update_fields=['hardware_profile'])
        HardwareProfile.objects.filter(pk=self.strong.pk).update(is_default=True)

        proxy = TemporalTaskProxy(self._ctx(), task_name='port_scan')

        self.assertEqual(proxy.hardware_profile['name'], 'hp-strong')

    def test_missing_scan_falls_back_to_the_workflow_input(self) -> None:
        with self.assertLogs('reNgine.temporal.activities.core', level='WARNING') as logs:
            proxy = TemporalTaskProxy(self._ctx(scan_history_id=987654), task_name='port_scan')

        self.assertEqual(proxy.hardware_profile, FROZEN)
        self.assertEqual(proxy.yaml_configuration['port_scan']['threads'], 4)
        self.assertIn('987654', logs.output[0])

    def test_no_resolvable_profile_keeps_the_workflow_input(self) -> None:
        self.scan.hardware_profile = None
        self.scan.save(update_fields=['hardware_profile'])
        HardwareProfile.objects.all().delete()

        with self.assertLogs('reNgine.temporal.activities.core', level='WARNING'):
            proxy = TemporalTaskProxy(self._ctx(), task_name='port_scan')

        self.assertEqual(proxy.hardware_profile, FROZEN)

    def test_profile_costs_no_extra_query_when_the_scan_has_one(self) -> None:
        base_ctx = self._ctx(hardware_profile=None)
        with CaptureQueriesContext(connection) as captured:
            TemporalTaskProxy(base_ctx, task_name='port_scan')
        profile_queries = [q['sql'] for q in captured if 'scanengine_hardwareprofile' in q['sql'].lower()]
        # The profile is joined into the single ScanHistory lookup.
        self.assertEqual(len(profile_queries), 1)
        self.assertIn('startscan_scanhistory', profile_queries[0].lower())


class InterruptedAttemptTimelineTests(TestCase):
    """A retry after the worker died must not leave the dead attempt's row RUNNING."""

    def setUp(self) -> None:
        from startScan.models import ScanActivity
        self.ScanActivity = ScanActivity
        self.results_dir = tempfile.mkdtemp()
        engine = EngineType.objects.create(engine_name='retry-engine', yaml_configuration='')
        domain = Domain.objects.create(name='retry.test.example', insert_date=timezone.now())
        self.scan = ScanHistory.objects.create(
            domain=domain, scan_type=engine, scan_status=RUNNING_TASK, start_scan_date=timezone.now(),
        )

    def _start(self, activity_id: str, attempt: int, task_name: str = 'dir_file_fuzz') -> TemporalTaskProxy:
        from unittest.mock import MagicMock, patch
        info = MagicMock(activity_id=activity_id, attempt=attempt)
        ctx = {
            'scan_history_id': self.scan.id,
            'engine_id': self.scan.scan_type_id,
            'domain_id': self.scan.domain_id,
            'results_dir': self.results_dir,
            'yaml_configuration': {},
            'track': True,
        }
        with patch('reNgine.temporal.activities.core.activity.info', return_value=info):
            return TemporalTaskProxy(ctx, task_name=task_name, description='Directory & File Fuzz')

    def _running(self, name: str, execution_id: str):
        return self.ScanActivity.objects.create(
            scan_of=self.scan, name=name, title='Directory & File Fuzzing', status=RUNNING_TASK,
            time=timezone.now(), time_started=timezone.now(), execution_id=execution_id,
        )

    def test_retry_marks_the_dead_attempt_as_interrupted(self) -> None:
        from reNgine.definitions import FAILED_TASK
        proxy = self._start('7', attempt=1)
        dead = proxy.activity

        retry = self._start('7', attempt=2)

        dead.refresh_from_db()
        self.assertEqual(dead.status, FAILED_TASK)
        self.assertIsNotNone(dead.time_ended)
        self.assertIn('attempt 2', dead.error_message)
        self.assertNotEqual(retry.activity.pk, dead.pk)
        self.assertEqual(retry.activity.status, RUNNING_TASK)
        running = self.ScanActivity.objects.filter(scan_of=self.scan, status=RUNNING_TASK)
        self.assertEqual(list(running), [retry.activity])

    def test_other_running_rows_are_left_alone(self) -> None:
        name = self._start('1', attempt=1).scan_activity_name
        other_activity = self._running(name, 'temporal-8')
        other_task = self._running('port_scan', 'temporal-9')

        self._start('9', attempt=2)

        for row in (other_activity, other_task):
            row.refresh_from_db()
            self.assertEqual(row.status, RUNNING_TASK)

    def test_first_attempt_touches_nothing(self) -> None:
        name = self._start('1', attempt=1).scan_activity_name
        stale = self._running(name, 'temporal-5')

        self._start('5', attempt=1)

        stale.refresh_from_db()
        self.assertEqual(stale.status, RUNNING_TASK)
