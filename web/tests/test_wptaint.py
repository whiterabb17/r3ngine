"""Tests for wptaint_scan plugin discovery logic.

This module tests that plugins are correctly extracted from various sources
(Vulnerabilities, EndPoints) and mapped to their respective subdomains
before running the static analysis.
"""

import json
import os
from unittest.mock import MagicMock, patch
from django.test import TestCase
from django.utils import timezone

from startScan.models import ScanHistory, Subdomain, EndPoint, Vulnerability
from targetApp.models import Domain
from scanEngine.models import EngineType
from reNgine.definitions import NUCLEI_SEVERITY_MAP


def _make_proxy(scan, yaml_config=None):
    """Creates a mock task proxy representing the running scan execution.

    Args:
        scan (ScanHistory): The scan history instance.
        yaml_config (dict, optional): Scan configurations override.

    Returns:
        MagicMock: A mock object matching the task context signature.
    """
    proxy = MagicMock()
    proxy.scan = scan
    proxy.scan.results_dir = '/tmp/rengine_test_wptaint'
    proxy.scan_id = scan.id
    proxy.domain = scan.domain
    proxy.subdomain = None
    proxy.subscan = None
    proxy.yaml_configuration = yaml_config or {
        'vulnerability_scan': {'run_wptaint_scan': True},
    }
    proxy.activity_id = None
    return proxy


class TestWptaintPluginDiscovery(TestCase):
    """Unit tests for the wp-taint plugin discovery layer."""

    def setUp(self):
        """Prepares database objects for testing."""
        self.domain = Domain.objects.create(name='wptaint-test.example.com')
        self.engine = EngineType.objects.create(engine_name='WPTaint Test Engine')
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_status=1,
            start_scan_date=timezone.now(),
            scan_type=self.engine,
        )
        self.subdomain = Subdomain.objects.create(
            name='wptaint-test.example.com',
            scan_history=self.scan,
            target_domain=self.domain,
        )

    def _make_vuln(self, name):
        """Helper to create a vulnerability database record."""
        return Vulnerability.objects.create(
            name=name,
            severity=0,
            type='WordPress',
            source='WPScan',
            scan_history=self.scan,
            subdomain=self.subdomain,
            target_domain=self.domain,
            http_url=f'http://{self.subdomain.name}',
        )

    def _make_endpoint(self, url):
        """Helper to create an endpoint database record."""
        return EndPoint.objects.create(
            scan_history=self.scan,
            subdomain=self.subdomain,
            target_domain=self.domain,
            http_url=url,
        )

    # ------------------------------------------------------------------
    # Existing behaviour — must not break
    # ------------------------------------------------------------------

    @patch('reNgine.tasks.wptaint.stream_command', return_value=iter([]))
    def test_legacy_plugin_vuln_name_discovered(self, mock_stream):
        """Existing 'WordPress Plugin: {slug}' vuln names are still discovered."""
        self._make_vuln('WordPress Plugin: akismet')
        proxy = _make_proxy(self.scan)

        from reNgine.tasks.wptaint import wptaint_scan
        with patch('os.path.exists', return_value=False):
            wptaint_scan(proxy)

        # Should have attempted to download akismet
        calls = [str(c) for c in mock_stream.call_args_list]
        self.assertTrue(any('akismet' in c for c in calls),
                        f"Expected akismet download attempt. Calls: {calls}")

    @patch('reNgine.tasks.wptaint.stream_command', return_value=iter([]))
    def test_plugin_detected_name_discovered(self, mock_stream):
        """'WordPress Plugin Detected: {slug}' vuln names are discovered."""
        self._make_vuln('WordPress Plugin Detected: woocommerce')
        proxy = _make_proxy(self.scan)

        from reNgine.tasks.wptaint import wptaint_scan
        with patch('os.path.exists', return_value=False):
            wptaint_scan(proxy)

        calls = [str(c) for c in mock_stream.call_args_list]
        self.assertTrue(any('woocommerce' in c for c in calls),
                        f"Expected woocommerce download attempt. Calls: {calls}")

    @patch('reNgine.tasks.wptaint.stream_command', return_value=iter([]))
    def test_plugin_discovered_from_endpoint_url(self, mock_stream):
        """Plugin slug extracted from /wp-content/plugins/{slug}/ in EndPoint URLs."""
        self._make_endpoint(
            'https://wptaint-test.example.com/wp-content/plugins/contact-form-7/includes/js/index.js?ver=6.1.1'
        )
        proxy = _make_proxy(self.scan)

        from reNgine.tasks.wptaint import wptaint_scan
        with patch('os.path.exists', return_value=False):
            wptaint_scan(proxy)

        calls = [str(c) for c in mock_stream.call_args_list]
        self.assertTrue(any('contact-form-7' in c for c in calls),
                        f"Expected contact-form-7 download attempt. Calls: {calls}")

    @patch('reNgine.tasks.wptaint.stream_command', return_value=iter([]))
    def test_slug_not_duplicated_from_multiple_sources(self, mock_stream):
        """Same slug from both Vulnerability and EndPoint is not scanned twice."""
        self._make_vuln('WordPress Plugin Detected: woocommerce')
        self._make_endpoint(
            'https://wptaint-test.example.com/wp-content/plugins/woocommerce/assets/js/frontend.js'
        )
        proxy = _make_proxy(self.scan)

        from reNgine.tasks.wptaint import wptaint_scan
        with patch('os.path.exists', return_value=False):
            wptaint_scan(proxy)

        download_calls = [c for c in mock_stream.call_args_list
                          if 'downloads.wordpress.org' in str(c)
                          and 'woocommerce' in str(c)]
        self.assertEqual(len(download_calls), 1, "Plugin should only be downloaded once")

    @patch('reNgine.tasks.wptaint.stream_command', return_value=iter([]))
    def test_plugin_with_vuln_suffix_slug_extracted_correctly(self, mock_stream):
        """'WordPress Plugin: {slug} - {vuln title}' correctly extracts just the slug."""
        self._make_vuln('WordPress Plugin: contact-form-7 - Reflected XSS via _wpcf7')
        proxy = _make_proxy(self.scan)

        from reNgine.tasks.wptaint import wptaint_scan
        with patch('os.path.exists', return_value=False):
            wptaint_scan(proxy)

        calls = [str(c) for c in mock_stream.call_args_list]
        self.assertTrue(any('contact-form-7' in c for c in calls),
                        f"Expected contact-form-7 download. Calls: {calls}")
        # Slug must not include the vuln title
        self.assertFalse(any('Reflected' in c and 'downloads.wordpress.org' in c for c in calls),
                         "Vuln title must not appear in download URL")

    @patch('reNgine.tasks.wptaint.stream_command', return_value=iter([]))
    def test_no_plugins_skips_scan(self, mock_stream):
        """With no plugins from any source, scan is skipped."""
        proxy = _make_proxy(self.scan)

        from reNgine.tasks.wptaint import wptaint_scan
        result = wptaint_scan(proxy)

        self.assertIsNone(result)
        mock_stream.assert_not_called()
