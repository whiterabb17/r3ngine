"""Elapsed time must freeze once a scan/subscan has stop_scan_date."""
from datetime import timedelta
from unittest.mock import patch

from django.test import SimpleTestCase
from django.utils import timezone

from reNgine.definitions import PAUSED_TASK, RUNNING_TASK, SUCCESS_TASK
from startScan.models import ScanHistory, SubScan


class ScanElapsedTimeTests(SimpleTestCase):
    def test_completed_scan_elapsed_uses_stop_not_now(self):
        start = timezone.now() - timedelta(hours=2)
        stop = start + timedelta(minutes=30)
        scan = ScanHistory(
            start_scan_date=start,
            stop_scan_date=stop,
            scan_status=SUCCESS_TASK,
        )
        later = stop + timedelta(hours=5)
        with patch('startScan.models.timezone.now', return_value=later):
            self.assertEqual(scan.get_elapsed_time(), '30 minutes')

    def test_running_scan_elapsed_uses_now(self):
        start = timezone.now() - timedelta(minutes=12)
        scan = ScanHistory(
            start_scan_date=start,
            stop_scan_date=None,
            scan_status=RUNNING_TASK,
        )
        now = start + timedelta(minutes=12, seconds=5)
        with patch('startScan.models.timezone.now', return_value=now):
            self.assertEqual(scan.get_elapsed_time(), '12 minutes')

    def test_paused_scan_elapsed_freezes_at_stop(self):
        start = timezone.now() - timedelta(hours=1)
        paused_at = start + timedelta(minutes=20)
        scan = ScanHistory(
            start_scan_date=start,
            stop_scan_date=paused_at,
            scan_status=PAUSED_TASK,
        )
        later = paused_at + timedelta(hours=2)
        with patch('startScan.models.timezone.now', return_value=later):
            self.assertEqual(scan.get_elapsed_time(), '20 minutes')

    def test_completed_subscan_elapsed_freezes(self):
        start = timezone.now() - timedelta(hours=1)
        stop = start + timedelta(minutes=5)
        subscan = SubScan(
            start_scan_date=start,
            stop_scan_date=stop,
            status=SUCCESS_TASK,
            type='port_scan',
        )
        later = stop + timedelta(hours=3)
        with patch('startScan.models.timezone.now', return_value=later):
            self.assertEqual(subscan.get_elapsed_time(), '5 minutes')
