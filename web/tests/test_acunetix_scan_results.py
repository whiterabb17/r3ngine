"""acunetix_scan imports what AWVS found however the scan ended, and reuses a scan
already started for the target instead of launching another one.

All hosts are anonymised (RFC 2606); AWVS is never contacted.
"""
from datetime import timedelta
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from django.test import TestCase
from django.utils import timezone

from dashboard.models import AcunetixAPIKey
from reNgine.definitions import RUNNING_TASK
from reNgine.tasks.acunetix import acunetix_scan
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Vulnerability
from targetApp.models import Domain

BASE = 'https://awvs.test.example:3443'
TARGET = 'acu.test.example'


def _resp(payload: dict, status: int = 200) -> MagicMock:
    resp = MagicMock()
    resp.status_code = status
    resp.json.return_value = payload
    return resp


class AcunetixScanOutcomeTests(TestCase):

    def setUp(self) -> None:
        AcunetixAPIKey.objects.create(server_url=BASE, api_key='test-key')
        engine = EngineType.objects.create(engine_name='acu-engine', yaml_configuration='')
        self.domain = Domain.objects.create(name=TARGET, insert_date=timezone.now())
        self.scan = ScanHistory.objects.create(
            domain=self.domain, scan_type=engine, scan_status=RUNNING_TASK, start_scan_date=timezone.now(),
        )
        self.task = SimpleNamespace(subdomain=None, subscan=None)
        self.existing_scans: list = []
        self.status = 'completed'

    def _session_start(self, offset: timedelta) -> str:
        return (self.scan.start_scan_date + offset).isoformat()

    def _get(self, url: str, **_kwargs) -> MagicMock:
        if url.endswith('/api/v1/targets') or '/api/v1/targets?' in url:
            return _resp({'targets': [{'address': TARGET, 'target_id': 'target-1'}]})
        if '/api/v1/scans?q=target_id:' in url:
            return _resp({'scans': self.existing_scans})
        if '/api/v1/scanning_profiles' in url:
            return _resp({'scanning_profiles': [{'name': 'Full Scan', 'profile_id': 'full'}]})
        if '/vulnerabilities/vuln-1' in url:
            return _resp({'vt_name': 'Reflected XSS', 'severity': 3, 'affects_url': f'https://{TARGET}/q', 'references': []})
        if '/vulnerabilities' in url:
            return _resp({'vulnerabilities': [{'vuln_id': 'vuln-1'}], 'pagination': {}})
        if '/api/v1/scans/' in url:
            return _resp({'current_session': {'status': self.status, 'scan_session_id': 'session-1'}})
        raise AssertionError(f'unexpected GET {url}')

    def _run(self):
        start = _resp({'scan_id': 'scan-new', 'target_id': 'target-1'}, status=201)
        with patch('reNgine.tasks.acunetix.requests.get', side_effect=self._get), \
                patch('reNgine.tasks.acunetix.requests.post', return_value=start) as mock_post, \
                patch('reNgine.tasks.acunetix.time.sleep'):
            result = acunetix_scan(self.task, self.domain.id, self.scan.id)
        started = [c for c in mock_post.call_args_list if c.args[0].endswith('/api/v1/scans')]
        return result, started

    def _imported(self) -> list:
        return list(Vulnerability.objects.filter(scan_history=self.scan, source='Acunetix').values_list('name', flat=True))

    def test_an_aborted_scan_keeps_its_findings_and_succeeds(self) -> None:
        self.status = 'aborted'
        result, _ = self._run()
        self.assertTrue(result)
        self.assertEqual(self._imported(), ['Reflected XSS'])

    def test_a_failed_scan_keeps_its_findings_but_fails_the_step(self) -> None:
        self.status = 'failed'
        result, _ = self._run()
        self.assertFalse(result)
        self.assertIn('imported 1 finding', self.task.error)
        self.assertEqual(self._imported(), ['Reflected XSS'])

    def test_a_scan_still_running_for_the_target_is_waited_for_not_restarted(self) -> None:
        self.existing_scans = [{
            'scan_id': 'scan-running',
            'current_session': {'status': 'processing', 'start_date': self._session_start(timedelta(minutes=5))},
        }]
        result, started = self._run()
        self.assertTrue(result)
        self.assertEqual(started, [])
        self.assertEqual(self._imported(), ['Reflected XSS'])

    def test_a_scan_the_operator_aborted_is_imported_on_retry(self) -> None:
        self.existing_scans = [{
            'scan_id': 'scan-aborted',
            'current_session': {'status': 'aborted', 'start_date': self._session_start(timedelta(hours=4))},
        }]
        self.status = 'aborted'
        result, started = self._run()
        self.assertTrue(result)
        self.assertEqual(started, [])
        self.assertEqual(self._imported(), ['Reflected XSS'])

    def test_a_failed_scan_or_one_from_before_this_scan_is_not_reused(self) -> None:
        for existing in (
            {'scan_id': 'scan-failed', 'current_session': {'status': 'failed', 'start_date': self._session_start(timedelta(minutes=5))}},
            {'scan_id': 'scan-old', 'current_session': {'status': 'completed', 'start_date': self._session_start(-timedelta(days=1))}},
        ):
            self.existing_scans = [existing]
            _, started = self._run()
            self.assertEqual(len(started), 1, existing['scan_id'])

    def test_the_latest_scan_started_during_this_scan_is_the_one_reused(self) -> None:
        self.existing_scans = [
            {'scan_id': 'scan-first', 'current_session': {'status': 'aborted', 'start_date': self._session_start(timedelta(minutes=1))}},
            {'scan_id': 'scan-second', 'current_session': {'status': 'processing', 'start_date': self._session_start(timedelta(hours=4))}},
        ]
        polled = []
        original = self._get

        def spy(url: str, **kwargs):
            if '/api/v1/scans/' in url and '/vulnerabilities' not in url:
                polled.append(url)
            return original(url, **kwargs)

        self._get = spy
        _, started = self._run()
        self.assertEqual(started, [])
        self.assertTrue(polled and all('/scans/scan-second' in url for url in polled))

    def test_a_naive_awvs_start_date_is_read_as_utc(self) -> None:
        naive = (self.scan.start_scan_date + timedelta(minutes=5)).replace(tzinfo=None).isoformat()
        self.existing_scans = [{'scan_id': 'scan-naive', 'current_session': {'status': 'processing', 'start_date': naive}}]
        result, started = self._run()
        self.assertTrue(result)
        self.assertEqual(started, [])
