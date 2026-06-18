"""Tests for nuclei proxy concurrency capping behaviour.

Verifies that nuclei_scan() reduces -c and -rl flags when a proxy file
is active, preventing the AdaptiveWaitGroup deadlock observed in scan 37.
"""
import re
import tempfile
import os
from unittest.mock import patch, MagicMock
from django.test import TestCase
from django.utils import timezone
from startScan.models import ScanHistory, Domain
from scanEngine.models import EngineType

from reNgine.definitions import NUCLEI_PROXY_MAX_CONCURRENCY, NUCLEI_PROXY_MAX_RATE_LIMIT


class TestNucleiProxyConcurrencyCap(TestCase):
    """nuclei_scan() must cap concurrency and rate when proxy file is active."""

    def setUp(self):
        """Create test fixtures."""
        self.domain = Domain.objects.create(
            name='example.com'
        )
        self.engine = EngineType.objects.create(
            engine_name='Test Engine',
            yaml_configuration={}
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=1,
            start_scan_date=timezone.now()
        )

    @patch('reNgine.tasks.stream_command', return_value=iter([]))
    @patch('reNgine.tasks.Notification.objects')
    def test_proxy_file_caps_concurrency(self, mock_notif, mock_stream):
        """When proxies_file_path is set, -c must be <= NUCLEI_PROXY_MAX_CONCURRENCY."""
        from reNgine.tasks import nuclei_scan

        # Write a real temp file so os.path.exists() returns True
        fd, proxy_path = tempfile.mkstemp(suffix='.txt')
        os.write(fd, b'http://127.0.0.1:8080\n')
        os.close(fd)

        mock_notif.first.return_value = None

        # Build a minimal self proxy
        proxy = MagicMock()
        proxy.yaml_configuration = {}
        proxy.results_dir = '/tmp'
        proxy.scan_id = self.scan.id
        proxy.scan = self.scan
        proxy.history_file = None
        proxy.activity_id = None
        proxy.activity = None

        try:
            nuclei_scan(proxy, urls=['http://example.com'], proxies_file_path=proxy_path,
                        ctx={'scan_history_id': self.scan.id})
        except Exception:
            pass  # we only care about the command that was built

        os.unlink(proxy_path)

        # The stream_command must have been called with a command that has
        # -c <= NUCLEI_PROXY_MAX_CONCURRENCY
        self.assertTrue(mock_stream.called, "stream_command was not called — command was never built")
        cmd_arg = mock_stream.call_args[0][0]
        # Extract -c value
        m = re.search(r'-c\s+(\d+)', cmd_arg)
        self.assertIsNotNone(m, f"Expected flag not found in command: {cmd_arg}")
        c_val = int(m.group(1))
        self.assertLessEqual(
            c_val,
            NUCLEI_PROXY_MAX_CONCURRENCY,
            f"Expected -c <= {NUCLEI_PROXY_MAX_CONCURRENCY}, got {c_val}",
        )

    @patch('reNgine.tasks.stream_command', return_value=iter([]))
    @patch('reNgine.tasks.Notification.objects')
    def test_proxy_file_caps_rate_limit(self, mock_notif, mock_stream):
        """When proxies_file_path is set, -rl must be <= NUCLEI_PROXY_MAX_RATE_LIMIT."""
        from reNgine.tasks import nuclei_scan

        fd, proxy_path = tempfile.mkstemp(suffix='.txt')
        os.write(fd, b'http://127.0.0.1:8080\n')
        os.close(fd)

        mock_notif.first.return_value = None

        proxy = MagicMock()
        proxy.yaml_configuration = {}
        proxy.results_dir = '/tmp'
        proxy.scan_id = self.scan.id
        proxy.scan = self.scan
        proxy.history_file = None
        proxy.activity_id = None
        proxy.activity = None

        try:
            nuclei_scan(proxy, urls=['http://example.com'], proxies_file_path=proxy_path,
                        ctx={'scan_history_id': self.scan.id})
        except Exception:
            pass

        os.unlink(proxy_path)

        self.assertTrue(mock_stream.called, "stream_command was not called — command was never built")
        cmd_arg = mock_stream.call_args[0][0]
        m = re.search(r'-rl\s+(\d+)', cmd_arg)
        self.assertIsNotNone(m, f"Expected flag not found in command: {cmd_arg}")
        rl_val = int(m.group(1))
        self.assertLessEqual(
            rl_val,
            NUCLEI_PROXY_MAX_RATE_LIMIT,
            f"Expected -rl <= {NUCLEI_PROXY_MAX_RATE_LIMIT}, got {rl_val}",
        )

    @patch('reNgine.tasks.stream_command', return_value=iter([]))
    @patch('reNgine.tasks.Notification.objects')
    def test_no_proxy_file_does_not_cap(self, mock_notif, mock_stream):
        """Without a proxy file, concurrency must not be artificially capped."""
        from reNgine.tasks import nuclei_scan

        mock_notif.first.return_value = None

        proxy = MagicMock()
        proxy.yaml_configuration = {'vulnerability_scan': {'concurrency': 30}}
        proxy.results_dir = '/tmp'
        proxy.scan_id = self.scan.id
        proxy.scan = self.scan
        proxy.history_file = None
        proxy.activity_id = None
        proxy.activity = None

        try:
            nuclei_scan(proxy, urls=['http://example.com'],
                        proxies_file_path=None, ctx={'scan_history_id': self.scan.id})
        except Exception:
            pass

        self.assertTrue(mock_stream.called, "stream_command was not called — command was never built")
        cmd_arg = mock_stream.call_args[0][0]
        m = re.search(r'-c\s+(\d+)', cmd_arg)
        self.assertIsNotNone(m, f"Expected flag not found in command: {cmd_arg}")
        c_val = int(m.group(1))
        self.assertGreater(
            c_val,
            NUCLEI_PROXY_MAX_CONCURRENCY,
            "Concurrency should not be capped when no proxy file is active",
        )
