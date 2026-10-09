"""Failures on scan paths are either ignored on purpose or reported, never both hidden and counted.

Each case here used to sit behind ``except Exception: pass``: a schedule that
Temporal could not delete, a hardware-profile lookup, a feroxbuster batch that
failed to save, a scan the bulk stop could not abort.
"""
import asyncio
from types import SimpleNamespace
from unittest import TestCase as PlainTestCase
from unittest.mock import AsyncMock, MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIRequestFactory, force_authenticate
from temporalio.service import RPCError, RPCStatusCode

from api.scan_history import ScanHistoryViewSet
from reNgine.definitions import RUNNING_TASK
from reNgine.tasks.fuzzing import _parse_ferox_response_line
from reNgine.tasks.scan_init import hardware_profile_context
from reNgine.temporal_schedule_utils import delete_schedule_if_exists
from scanEngine.models import EngineType, HardwareProfile
from startScan.models import ScanHistory
from targetApp.models import Domain


def _client_whose_delete(side_effect=None) -> MagicMock:
    client = MagicMock()
    client.get_schedule_handle.return_value.delete = AsyncMock(side_effect=side_effect)
    return client


class DeleteScheduleIfExistsTests(PlainTestCase):

    def test_deletes_and_reports_it(self):
        client = _client_whose_delete()
        self.assertTrue(asyncio.run(delete_schedule_if_exists(client, 'scan-1')))
        client.get_schedule_handle.assert_called_once_with('scan-1')

    def test_missing_schedule_is_not_an_error(self):
        missing = RPCError('not found', RPCStatusCode.NOT_FOUND, b'')
        self.assertFalse(asyncio.run(delete_schedule_if_exists(_client_whose_delete(missing), 'scan-1')))

    def test_other_failures_are_raised(self):
        # A schedule that survives keeps starting scans, so the caller must know.
        unavailable = RPCError('unavailable', RPCStatusCode.UNAVAILABLE, b'')
        with self.assertRaises(RPCError):
            asyncio.run(delete_schedule_if_exists(_client_whose_delete(unavailable), 'scan-1'))


class ParseFeroxResponseLineTests(PlainTestCase):

    def test_response_record_is_returned(self):
        line = '{"type": "response", "url": "https://app.example.test/admin", "status": 200}'
        self.assertEqual(_parse_ferox_response_line(line)['status'], 200)

    def test_statistics_record_is_skipped(self):
        self.assertIsNone(_parse_ferox_response_line('{"type": "statistics", "requests": 10}'))

    def test_truncated_or_non_object_lines_are_skipped(self):
        self.assertIsNone(_parse_ferox_response_line('{"type": "resp'))
        self.assertIsNone(_parse_ferox_response_line('["response"]'))


class HardwareProfileContextTests(TestCase):

    def setUp(self):
        HardwareProfile.objects.all().delete()

    def test_scan_profile_wins(self):
        own = HardwareProfile.objects.create(name='own', threads=3)
        HardwareProfile.objects.create(name='default', threads=50, is_default=True)
        ctx = hardware_profile_context(SimpleNamespace(id=1, hardware_profile=own))
        self.assertEqual((ctx['name'], ctx['threads']), ('own', 3))

    def test_falls_back_to_the_active_default(self):
        HardwareProfile.objects.create(name='other', threads=5)
        HardwareProfile.objects.create(name='retired', threads=9, is_default=True, is_active=False)
        HardwareProfile.objects.create(name='default', threads=7, is_default=True)
        ctx = hardware_profile_context(SimpleNamespace(id=1, hardware_profile=None))
        self.assertEqual(ctx['name'], 'default')

    def test_no_profile_means_engine_defaults(self):
        self.assertIsNone(hardware_profile_context(SimpleNamespace(id=1, hardware_profile=None)))

    def test_lookup_failure_is_logged(self):
        with patch.object(HardwareProfile.objects, 'filter', side_effect=RuntimeError('db down')), \
                self.assertLogs('reNgine.tasks.scan_init', level='WARNING') as logs:
            ctx = hardware_profile_context(SimpleNamespace(id=42, hardware_profile=None))
        self.assertIsNone(ctx)
        self.assertIn('scan 42', logs.output[0])


class BulkStopTests(TestCase):

    def setUp(self):
        self.user = get_user_model().objects.create_superuser('bulk-admin', 'bulk@example.test', 'x')
        domain = Domain.objects.create(name='bulk.example.test', insert_date=timezone.now())
        engine = EngineType.objects.create(engine_name='bulk-engine', yaml_configuration='')
        self.scans = [
            ScanHistory.objects.create(
                domain=domain, scan_type=engine, scan_status=RUNNING_TASK, start_scan_date=timezone.now(),
            )
            for _ in range(2)
        ]

    def test_counts_only_the_scans_it_stopped(self):
        failing_id = self.scans[0].id

        def abort(scan, aborted_by=None):
            if scan.id == failing_id:
                raise RuntimeError('temporal unavailable')

        request = APIRequestFactory().post(
            '/api/listScans/bulk_stop/', {'ids': [s.id for s in self.scans]}, format='json',
        )
        force_authenticate(request, user=self.user)
        with patch('reNgine.utils.scan_cancellation.abort_scan_history', side_effect=abort), \
                self.assertLogs('api.scan_history', level='ERROR'):
            response = ScanHistoryViewSet.as_view({'post': 'bulk_stop'})(request)

        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['message'], '1 scans stopped')
