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


class TestWptaintParser(TestCase):
    """Tests for parse_wptaint_results helper converting temp file paths to URL paths."""

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
        self.scan.results_dir = '/tmp/rengine_test_wptaint'
        self.subdomain = Subdomain.objects.create(
            name='wptaint-test.example.com',
            scan_history=self.scan,
            target_domain=self.domain,
        )

    def test_parse_wptaint_results_converts_temp_path_to_url_path(self):
        from reNgine.tasks.wptaint import parse_wptaint_results
        
        # Create a mock taint-results.json file
        import tempfile
        import json
        
        results_data = {
            "results": [
                {
                    "check_id": "wp-request-sensitive-action-without-cap-check",
                    "path": "/usr/src/scan_results/zuydam.co.za_22/temp_wptaint/advanced-access-manager/advanced-access-manager/application/Backend/tmpl/partial/content-access-form.php",
                    "start": {"line": 138},
                    "extra": {
                        "message": "Found a sensitive action call without a capability check.",
                        "dataflow_trace": {
                            "source": {"snippet": "$_POST['action']"},
                            "sink": {"snippet": "update_option(...)"}
                        }
                    }
                }
            ]
        }
        
        with tempfile.NamedTemporaryFile(mode='w', delete=False, suffix='.json') as tf:
            json.dump(results_data, tf)
            temp_file_name = tf.name
            
        try:
            task_instance = MagicMock()
            task_instance.scan = self.scan
            task_instance.domain = self.domain
            
            parse_wptaint_results(
                task_instance=task_instance,
                output_file=temp_file_name,
                subdomains=[self.subdomain],
                plugin_name="advanced-access-manager"
            )
            
            # Query the vulnerability created
            vulns = Vulnerability.objects.filter(
                scan_history=self.scan,
                source='WPTaintScan'
            )
            self.assertEqual(len(vulns), 1)
            vuln = vulns[0]
            
            # Assert that the http_url has the url path and not the temp file path
            expected_url = "http://wptaint-test.example.com/wp-content/plugins/advanced-access-manager/application/Backend/tmpl/partial/content-access-form.php"
            self.assertEqual(vuln.http_url, expected_url)
            
            # Assert that the description does not contain the temp file path, but instead the url path
            self.assertIn("**File**: `/wp-content/plugins/advanced-access-manager/application/Backend/tmpl/partial/content-access-form.php` (Line 138)", vuln.description)
            self.assertNotIn("temp_wptaint", vuln.description)
            
        finally:
            import os
            if os.path.exists(temp_file_name):
                os.remove(temp_file_name)


class TestWordpressOrgDownloadCandidates(TestCase):
    """Unit tests for installed-version zip URL selection."""

    def test_prefers_installed_version_zip_then_latest_fallback(self):
        from reNgine.tasks.wordpress_version import wordpress_org_plugin_download_candidates

        candidates = wordpress_org_plugin_download_candidates('elementor', '3.20.2')
        self.assertEqual(len(candidates), 2)
        self.assertEqual(
            candidates[0][0],
            'https://downloads.wordpress.org/plugin/elementor.3.20.2.zip',
        )
        self.assertEqual(candidates[0][1:], ('3.20.2', 'installed'))
        self.assertEqual(
            candidates[1][0],
            'https://downloads.wordpress.org/plugin/elementor.zip',
        )
        self.assertEqual(candidates[1][1:], ('latest', 'latest_fallback'))

    def test_unknown_installed_uses_latest_only(self):
        from reNgine.tasks.wordpress_version import wordpress_org_plugin_download_candidates

        candidates = wordpress_org_plugin_download_candidates('akismet', None)
        self.assertEqual(len(candidates), 1)
        self.assertEqual(candidates[0][0], 'https://downloads.wordpress.org/plugin/akismet.zip')
        self.assertEqual(candidates[0][1:], ('latest', 'latest'))

    def test_rejects_unsafe_plugin_slug(self):
        from reNgine.tasks.wordpress_version import (
            is_safe_wordpress_plugin_slug,
            wordpress_org_plugin_download_candidates,
        )

        self.assertFalse(is_safe_wordpress_plugin_slug('../evil'))
        self.assertFalse(is_safe_wordpress_plugin_slug('Foo_Bar'))
        self.assertEqual(wordpress_org_plugin_download_candidates('../evil', '1.0'), [])


class TestWptaintWpscanCorrelator(TestCase):
    """WPTaint findings inherit WPScan version guidance after correlation."""

    def setUp(self):
        self.domain = Domain.objects.create(name='wptaint-corr.example.com')
        self.engine = EngineType.objects.create(engine_name='WPTaint Corr Engine')
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_status=1,
            start_scan_date=timezone.now(),
            scan_type=self.engine,
        )
        self.subdomain = Subdomain.objects.create(
            name='wptaint-corr.example.com',
            scan_history=self.scan,
            target_domain=self.domain,
        )

    def test_correlate_stamps_installed_fixed_in_and_tainted_meta(self):
        Vulnerability.objects.create(
            name='WordPress Plugin Detected: elementor',
            severity=2,
            type='WordPress',
            source='WPScan',
            scan_history=self.scan,
            subdomain=self.subdomain,
            target_domain=self.domain,
            http_url=f'http://{self.subdomain.name}',
            description='Plugin **elementor** v3.20.2 detected at `/wp-content/plugins/elementor/`. Plugin is **outdated** (installed: 3.20.2, latest: 4.3.6).',
            extracted_results=['plugin:elementor', 'installed:3.20.2', 'latest:4.3.6', 'outdated:True'],
            agent_enrichment={
                'version_guidance': {
                    'component': 'plugin',
                    'slug': 'elementor',
                    'installed': '3.20.2',
                    'latest': '4.3.6',
                    'outdated': True,
                }
            },
            remediation='**Version guidance:** `elementor`; installed `3.20.2`; latest `4.3.6`.',
        )
        Vulnerability.objects.create(
            name='WordPress Plugin: elementor - Elementor < 4.3.6 - Stored XSS',
            severity=0,
            type='WordPress',
            source='WPScan',
            scan_history=self.scan,
            subdomain=self.subdomain,
            target_domain=self.domain,
            http_url=f'http://{self.subdomain.name}',
            description='Advisory',
            extracted_results=['plugin:elementor', 'installed:3.20.2', 'fixed_in:4.3.6'],
            agent_enrichment={
                'version_guidance': {
                    'component': 'plugin',
                    'slug': 'elementor',
                    'installed': '3.20.2',
                    'fixed_in': '4.3.6',
                }
            },
        )
        taint = Vulnerability.objects.create(
            name='WP Taint (elementor): Unauthorized File Upload',
            severity=3,
            type='WordPress',
            source='WPTaintScan',
            scan_history=self.scan,
            subdomain=self.subdomain,
            target_domain=self.domain,
            http_url=f'http://{self.subdomain.name}/wp-content/plugins/elementor/x.php',
            description='static taint',
        )

        from reNgine.tasks.wptaint import correlate_wptaint_with_wpscan
        updated = correlate_wptaint_with_wpscan(
            self.scan,
            taint_run_meta={
                'elementor': {
                    'tainted_version': '3.20.2',
                    'tainted_source': 'installed',
                }
            },
        )
        self.assertEqual(updated, 1)
        taint.refresh_from_db()
        vg = (taint.agent_enrichment or {}).get('version_guidance') or {}
        self.assertEqual(vg.get('installed'), '3.20.2')
        self.assertEqual(vg.get('fixed_in'), '4.3.6')
        self.assertEqual(vg.get('tainted_version'), '3.20.2')
        self.assertEqual(vg.get('tainted_source'), 'installed')
        self.assertIn('installed:3.20.2', taint.extracted_results or [])
        self.assertIn('**Version guidance:**', taint.remediation or '')
        self.assertIn('4.3.6', taint.remediation or '')

    @patch('reNgine.tasks.wptaint.stream_command', return_value=iter([]))
    def test_wptaint_prefers_installed_version_download_url(self, mock_stream):
        Vulnerability.objects.create(
            name='WordPress Plugin Detected: elementor',
            severity=2,
            type='WordPress',
            source='WPScan',
            scan_history=self.scan,
            subdomain=self.subdomain,
            target_domain=self.domain,
            http_url=f'http://{self.subdomain.name}',
            extracted_results=['plugin:elementor', 'installed:3.20.2'],
            agent_enrichment={
                'version_guidance': {
                    'component': 'plugin',
                    'slug': 'elementor',
                    'installed': '3.20.2',
                }
            },
        )
        proxy = _make_proxy(self.scan)
        from reNgine.tasks.wptaint import wptaint_scan
        with patch('os.path.exists', return_value=False):
            wptaint_scan(proxy)

        download_calls = [str(c) for c in mock_stream.call_args_list if 'downloads.wordpress.org' in str(c)]
        self.assertTrue(
            any('elementor.3.20.2.zip' in c for c in download_calls),
            f'Expected installed-version zip first. Calls: {download_calls}',
        )

    def test_tainted_version_not_backfilled_from_installed_on_latest_fallback(self):
        """When latest_fallback succeeds, meta must not claim installed version was analyzed."""
        from reNgine.tasks.wordpress_version import format_version_patch_line

        line = format_version_patch_line({
            'slug': 'elementor',
            'installed': '3.20.2',
            'tainted_version': 'latest',
            'tainted_source': 'latest_fallback',
        })
        self.assertIn('latest_fallback', line)
        self.assertIn('WPTaint analyzed `latest`', line)

        # Source-only (no version label) still records provenance.
        line2 = format_version_patch_line({
            'slug': 'elementor',
            'installed': '3.20.2',
            'tainted_source': 'latest_fallback',
        })
        self.assertIn('latest_fallback', line2)
        self.assertIn('installed version unconfirmed', line2)

    @patch('reNgine.tasks.wptaint.stream_command', return_value=iter([]))
    def test_download_meta_uses_latest_label_not_installed_on_fallback(self, mock_stream):
        """Installed zip fails, latest succeeds → tainted_version is 'latest', not installed."""
        from reNgine.tasks.wptaint import _download_plugin_zip
        import tempfile
        import os

        with tempfile.TemporaryDirectory() as tmp:
            plugin_zip = os.path.join(tmp, 'elementor.zip')

            def _fake_exists(path):
                # After second wget (latest), pretend the zip is present/non-empty.
                return path == plugin_zip and mock_stream.call_count >= 2

            def _fake_getsize(path):
                return 10 if path == plugin_zip and mock_stream.call_count >= 2 else 0

            with patch('os.path.exists', side_effect=_fake_exists), \
                 patch('os.path.getsize', side_effect=_fake_getsize), \
                 patch('os.remove'):
                ok, tainted_version, tainted_source = _download_plugin_zip(
                    'elementor', plugin_zip, '3.20.2', scan_id=1, activity_id=None,
                )
            self.assertTrue(ok)
            self.assertEqual(tainted_source, 'latest_fallback')
            self.assertEqual(tainted_version, 'latest')
            self.assertNotEqual(tainted_version, '3.20.2')

    def test_correlate_keeps_latest_when_installed_missing(self):
        Vulnerability.objects.create(
            name='WordPress Plugin Detected: woocommerce',
            severity=2,
            type='WordPress',
            source='WPScan',
            scan_history=self.scan,
            subdomain=self.subdomain,
            target_domain=self.domain,
            http_url=f'http://{self.subdomain.name}',
            extracted_results=['plugin:woocommerce', 'latest:9.0.0', 'outdated:True'],
            agent_enrichment={
                'version_guidance': {
                    'component': 'plugin',
                    'slug': 'woocommerce',
                    'latest': '9.0.0',
                    'outdated': True,
                }
            },
        )
        taint = Vulnerability.objects.create(
            name='WP Taint (woocommerce): Missing Capability Check',
            severity=2,
            type='WordPress',
            source='WPTaintScan',
            scan_history=self.scan,
            subdomain=self.subdomain,
            target_domain=self.domain,
            http_url=f'http://{self.subdomain.name}/wp-content/plugins/woocommerce/x.php',
            description='static taint',
        )
        from reNgine.tasks.wptaint import correlate_wptaint_with_wpscan
        correlate_wptaint_with_wpscan(
            self.scan,
            taint_run_meta={'woocommerce': {'tainted_version': 'latest', 'tainted_source': 'latest'}},
        )
        taint.refresh_from_db()
        vg = (taint.agent_enrichment or {}).get('version_guidance') or {}
        self.assertEqual(vg.get('latest'), '9.0.0')
        self.assertTrue(vg.get('outdated'))
        self.assertEqual(vg.get('tainted_source'), 'latest')
        self.assertIn('9.0.0', taint.remediation or '')

