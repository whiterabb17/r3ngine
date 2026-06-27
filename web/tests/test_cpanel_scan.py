"""Tests for cPanel scan gating logic added in v3.5.0.

cpanel_scan() must only run against subdomains that are cPanel/WHM
infrastructure — either by subdomain name pattern or by detected technology.
All other subdomains must be skipped with a log message.

These are unit tests; they call the task function directly with a mock
self-proxy and patch stream_command to prevent real subprocess execution.
"""

from unittest.mock import MagicMock, patch
from django.test import TestCase
from django.utils import timezone

from startScan.models import ScanHistory, Subdomain, Technology
from targetApp.models import Domain
from scanEngine.models import EngineType


def _make_proxy(scan, subdomain=None, subscan=None, yaml_config=None):
    """Build a minimal task-proxy mock for cpanel_scan / wpscan_scan."""
    proxy = MagicMock()
    proxy.scan = scan
    proxy.scan_id = scan.id
    proxy.subdomain = subdomain
    proxy.subscan = subscan
    proxy.yaml_configuration = yaml_config or {
        'vulnerability_scan': {
            'cpanel_scanner': {'run_cpanel2shell': True},
        }
    }
    proxy.results_dir = '/tmp/rengine_test_cpanel'
    proxy.activity_id = None
    return proxy


class TestCpanelScanGating(TestCase):
    def setUp(self):
        self.domain = Domain.objects.create(name='cpanel-gate.example.com')
        self.engine = EngineType.objects.create(engine_name='CPanel Gate Test Engine')
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_status=1,
            start_scan_date=timezone.now(),
            scan_type=self.engine,
        )

    def _make_subdomain(self, name):
        return Subdomain.objects.create(
            name=name,
            scan_history=self.scan,
            target_domain=self.domain,
        )

    def _add_tech(self, subdomain, tech_name):
        tech, _ = Technology.objects.get_or_create(name=tech_name)
        subdomain.technologies.add(tech)
        subdomain.save()

    # ------------------------------------------------------------------
    # Skipped — no cPanel indicators
    # ------------------------------------------------------------------

    @patch('reNgine.tasks.stream_command', return_value=iter([]))
    def test_skips_when_no_cpanel_subdomains(self, _mock_stream):
        """No cPanel-named or cPanel-tech subdomains → scan skipped without error."""
        self._make_subdomain('app.cpanel-gate.example.com')
        self._make_subdomain('api.cpanel-gate.example.com')
        proxy = _make_proxy(self.scan)

        from reNgine.tasks.vulnerability import cpanel_scan
        result = cpanel_scan(proxy)

        self.assertIsNone(result)
        _mock_stream.assert_not_called()

    @patch('reNgine.tasks.stream_command', return_value=iter([]))
    def test_skips_when_disabled_in_config(self, _mock_stream):
        """run_cpanel2shell=False skips immediately regardless of subdomain names."""
        self._make_subdomain('cpanel.cpanel-gate.example.com')
        proxy = _make_proxy(self.scan, yaml_config={
            'vulnerability_scan': {'cpanel_scanner': {'run_cpanel2shell': False}},
        })

        from reNgine.tasks.vulnerability import cpanel_scan
        result = cpanel_scan(proxy)

        self.assertIsNone(result)
        _mock_stream.assert_not_called()

    # ------------------------------------------------------------------
    # Runs — cPanel detected by subdomain name
    # ------------------------------------------------------------------

    @patch('reNgine.tasks.vulnerability.parse_cpanel_results')
    @patch('reNgine.tasks.stream_command', return_value=iter([]))
    def test_runs_on_cpanel_subdomain_name(self, mock_stream, mock_parse):
        """Subdomain named cpanel.* triggers cPanel scan."""
        self._make_subdomain('cpanel.cpanel-gate.example.com')
        self._make_subdomain('app.cpanel-gate.example.com')  # should be excluded
        proxy = _make_proxy(self.scan)

        from reNgine.tasks.vulnerability import cpanel_scan
        result = cpanel_scan(proxy)

        self.assertIsNotNone(result)
        # stream_command called once — only the cpanel. subdomain
        mock_stream.assert_called_once()
        call_args = mock_stream.call_args[0][0]
        self.assertIn('cpanel.cpanel-gate.example.com', call_args)

    @patch('reNgine.tasks.vulnerability.parse_cpanel_results')
    @patch('reNgine.tasks.stream_command', return_value=iter([]))
    def test_runs_on_whm_subdomain_name(self, mock_stream, mock_parse):
        """Subdomain named whm.* also triggers cPanel scan."""
        self._make_subdomain('whm.cpanel-gate.example.com')
        proxy = _make_proxy(self.scan)

        from reNgine.tasks.vulnerability import cpanel_scan
        result = cpanel_scan(proxy)

        self.assertIsNotNone(result)
        mock_stream.assert_called_once()

    # ------------------------------------------------------------------
    # Runs — cPanel detected via technology fingerprint
    # ------------------------------------------------------------------

    @patch('reNgine.tasks.vulnerability.parse_cpanel_results')
    @patch('reNgine.tasks.stream_command', return_value=iter([]))
    def test_runs_when_cpanel_tech_detected(self, mock_stream, mock_parse):
        """Subdomain with cPanel technology triggers scan even without cpanel.* name."""
        sub = self._make_subdomain('hosting.cpanel-gate.example.com')
        self._add_tech(sub, 'cPanel')
        proxy = _make_proxy(self.scan)

        from reNgine.tasks.vulnerability import cpanel_scan
        result = cpanel_scan(proxy)

        self.assertIsNotNone(result)
        mock_stream.assert_called_once()

    @patch('reNgine.tasks.vulnerability.parse_cpanel_results')
    @patch('reNgine.tasks.stream_command', return_value=iter([]))
    def test_runs_when_whm_tech_detected(self, mock_stream, mock_parse):
        """Subdomain with WHM technology triggers scan."""
        sub = self._make_subdomain('manage.cpanel-gate.example.com')
        self._add_tech(sub, 'WHM')
        proxy = _make_proxy(self.scan)

        from reNgine.tasks.vulnerability import cpanel_scan
        result = cpanel_scan(proxy)

        self.assertIsNotNone(result)
        mock_stream.assert_called_once()

    # ------------------------------------------------------------------
    # Subscan mode
    # ------------------------------------------------------------------

    @patch('reNgine.tasks.stream_command', return_value=iter([]))
    def test_subscan_non_cpanel_subdomain_skipped(self, mock_stream):
        """In subscan mode, a non-cPanel subdomain is skipped."""
        sub = self._make_subdomain('api.cpanel-gate.example.com')
        subscan_mock = MagicMock()
        proxy = _make_proxy(self.scan, subdomain=sub, subscan=subscan_mock)

        from reNgine.tasks.vulnerability import cpanel_scan
        result = cpanel_scan(proxy)

        self.assertIsNone(result)
        mock_stream.assert_not_called()

    @patch('reNgine.tasks.vulnerability.parse_cpanel_results')
    @patch('reNgine.tasks.stream_command', return_value=iter([]))
    def test_subscan_cpanel_named_subdomain_runs(self, mock_stream, mock_parse):
        """In subscan mode, a cpanel.* named subdomain triggers the scan."""
        sub = self._make_subdomain('cpanel.cpanel-gate.example.com')
        subscan_mock = MagicMock()
        proxy = _make_proxy(self.scan, subdomain=sub, subscan=subscan_mock)

        from reNgine.tasks.vulnerability import cpanel_scan
        result = cpanel_scan(proxy)

        self.assertIsNotNone(result)
        mock_stream.assert_called_once()
