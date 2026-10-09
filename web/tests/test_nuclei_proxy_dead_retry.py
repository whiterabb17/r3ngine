"""Tests for nuclei 'all proxies are dead' detection and retry behaviour."""
import os
import tempfile
from unittest.mock import MagicMock, patch

from django.test import TestCase
from django.utils import timezone

from reNgine.definitions import NUCLEI_PROXY_DEAD_MAX_ATTEMPTS
from reNgine.failure_reasons import classify_failure
from reNgine.tasks.vuln import _nuclei_line_is_proxy_dead, _refresh_nuclei_proxy_file
from scanEngine.models import EngineType, Proxy
from startScan.models import Domain, ScanHistory


FTL_LINE = (
    '[FTL] Program exiting: cause="all proxies are dead got : '
    'dial tcp 203.0.113.10:443: i/o timeout"'
)
FTL_LINE_ANSI = (
    '[\x1b[1;31mFTL\x1b[0m] Program exiting: cause="all proxies are dead got : '
    'dial tcp 203.0.113.10:443: i/o timeout"'
)


class TestNucleiProxyDeadHelpers(TestCase):
    """Unit checks for the dead-proxy detector and proxy-file refresh."""

    def test_detects_ftl_line(self):
        self.assertTrue(_nuclei_line_is_proxy_dead(FTL_LINE))

    def test_detects_ansi_ftl_line(self):
        self.assertTrue(_nuclei_line_is_proxy_dead(FTL_LINE_ANSI))

    def test_ignores_normal_lines_and_dicts(self):
        self.assertFalse(_nuclei_line_is_proxy_dead('[INF] Templates loaded'))
        self.assertFalse(_nuclei_line_is_proxy_dead({'template-id': 'x'}))
        self.assertFalse(_nuclei_line_is_proxy_dead(None))

    def test_refresh_rewrites_proxy_file(self):
        Proxy.objects.all().delete()
        Proxy.objects.create(
            use_proxy=True,
            proxies='127.0.0.1:8080\nsocks5://127.0.0.1:1080\n127.0.0.1:8081',
        )
        fd, path = tempfile.mkstemp(suffix='.txt')
        os.write(fd, b'http://old.example:1\n')
        os.close(fd)
        try:
            self.assertTrue(_refresh_nuclei_proxy_file(path))
            with open(path) as f:
                body = f.read()
            self.assertIn('http://127.0.0.1:8080', body)
            self.assertIn('socks5://127.0.0.1:1080', body)
            self.assertIn('http://127.0.0.1:8081', body)
            self.assertNotIn('old.example', body)
        finally:
            os.unlink(path)

    def test_failure_reason_classifies_proxy_dead(self):
        result = classify_failure(f'Exception({FTL_LINE!r})', '')
        self.assertIsNotNone(result)
        self.assertEqual(result['category'], 'proxy_failure')


class TestNucleiProxyDeadRetry(TestCase):
    """nuclei_scan retries on FTL proxy death, then skips after the budget."""

    def setUp(self):
        self.domain = Domain.objects.create(name='example.com')
        self.engine = EngineType.objects.create(
            engine_name='Test Engine',
            yaml_configuration={},
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=1,
            start_scan_date=timezone.now(),
        )
        self.results_dir = tempfile.mkdtemp()
        self.output_path = os.path.join(self.results_dir, 'nuclei.json')

    def _self_proxy(self):
        proxy = MagicMock()
        proxy.yaml_configuration = {
            'vulnerability_scan': {
                'intensity': 'aggressive',
                'nuclei': {'auto_update_templates': False},
            }
        }
        proxy.results_dir = self.results_dir
        proxy.output_path = self.output_path
        proxy.scan_id = self.scan.id
        proxy.scan = self.scan
        proxy.domain = self.domain
        proxy.subscan = None
        proxy.history_file = None
        proxy.activity_id = None
        proxy.activity = None
        proxy.notify = MagicMock()
        return proxy

    def _run(self, mock_stream, proxy_path):
        from reNgine.tasks import nuclei_scan

        nuclei_scan(
            self._self_proxy(),
            urls=['http://example.com'],
            proxies_file_path=proxy_path,
            ctx={'scan_history_id': self.scan.id},
            tags_override=[],
        )
        return mock_stream.call_count

    @patch('reNgine.tasks.vuln.OpenAiAPIKey.objects')
    @patch('reNgine.tasks.vuln.run_command')
    @patch('reNgine.tasks.vuln.stream_command')
    @patch('scanEngine.models.Notification.objects')
    def test_retries_three_times_then_skips(
        self, mock_notif, mock_stream, _mock_run, mock_openai
    ):
        mock_notif.first.return_value = None
        mock_openai.all.return_value.first.return_value = None
        mock_stream.side_effect = [
            iter([FTL_LINE]),
            iter([FTL_LINE_ANSI]),
            iter([FTL_LINE]),
        ]

        fd, proxy_path = tempfile.mkstemp(suffix='.txt')
        os.write(fd, b'http://127.0.0.1:8080\n')
        os.close(fd)
        Proxy.objects.all().delete()
        Proxy.objects.create(use_proxy=True, proxies='127.0.0.1:8080')

        try:
            calls = self._run(mock_stream, proxy_path)
        finally:
            if os.path.exists(proxy_path):
                os.unlink(proxy_path)

        self.assertEqual(calls, NUCLEI_PROXY_DEAD_MAX_ATTEMPTS)
        self.assertTrue(os.path.exists(self.output_path))
        with open(self.output_path) as f:
            self.assertEqual(f.read().strip(), '[]')

    @patch('reNgine.tasks.vuln.OpenAiAPIKey.objects')
    @patch('reNgine.tasks.vuln.run_command')
    @patch('reNgine.tasks.vuln.stream_command')
    @patch('scanEngine.models.Notification.objects')
    def test_stops_retrying_after_success(
        self, mock_notif, mock_stream, _mock_run, mock_openai
    ):
        mock_notif.first.return_value = None
        mock_openai.all.return_value.first.return_value = None
        mock_stream.side_effect = [
            iter([FTL_LINE]),
            iter([]),
        ]

        fd, proxy_path = tempfile.mkstemp(suffix='.txt')
        os.write(fd, b'http://127.0.0.1:8080\n')
        os.close(fd)
        Proxy.objects.all().delete()
        Proxy.objects.create(use_proxy=True, proxies='127.0.0.1:8080')

        try:
            calls = self._run(mock_stream, proxy_path)
        finally:
            if os.path.exists(proxy_path):
                os.unlink(proxy_path)

        self.assertEqual(calls, 2)

    @patch('reNgine.tasks.vuln.OpenAiAPIKey.objects')
    @patch('reNgine.tasks.vuln.run_command')
    @patch('reNgine.tasks.vuln.stream_command', return_value=iter([]))
    @patch('scanEngine.models.Notification.objects')
    def test_no_retry_when_proxies_survive(
        self, mock_notif, mock_stream, _mock_run, mock_openai
    ):
        mock_notif.first.return_value = None
        mock_openai.all.return_value.first.return_value = None

        fd, proxy_path = tempfile.mkstemp(suffix='.txt')
        os.write(fd, b'http://127.0.0.1:8080\n')
        os.close(fd)

        try:
            calls = self._run(mock_stream, proxy_path)
        finally:
            os.unlink(proxy_path)

        self.assertEqual(calls, 1)

    @patch('reNgine.tasks.vuln.OpenAiAPIKey.objects')
    @patch('reNgine.tasks.vuln.run_command')
    @patch('reNgine.tasks.vuln.stream_command')
    @patch('scanEngine.models.Notification.objects')
    def test_reuses_proxy_file_when_pool_empty(
        self, mock_notif, mock_stream, _mock_run, mock_openai
    ):
        """If get_proxy_list is empty on refresh, still retry with the existing file."""
        mock_notif.first.return_value = None
        mock_openai.all.return_value.first.return_value = None
        mock_stream.side_effect = [
            iter([FTL_LINE]),
            iter([FTL_LINE]),
            iter([FTL_LINE]),
        ]

        fd, proxy_path = tempfile.mkstemp(suffix='.txt')
        os.write(fd, b'http://127.0.0.1:8080\n')
        os.close(fd)
        Proxy.objects.all().delete()
        Proxy.objects.create(use_proxy=True, proxies='')

        with patch(
            'reNgine.tasks.vuln._refresh_nuclei_proxy_file', return_value=False
        ):
            try:
                calls = self._run(mock_stream, proxy_path)
            finally:
                if os.path.exists(proxy_path):
                    os.unlink(proxy_path)

        self.assertEqual(calls, NUCLEI_PROXY_DEAD_MAX_ATTEMPTS)
