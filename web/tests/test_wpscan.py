"""Tests for WPScan gating logic added in v3.5.0.

wpscan_scan() must only run when WordPress indicators are present — either
via technology fingerprinting on a subdomain, or via wp-like paths discovered
by fetch_url / dir_file_fuzz and stored in EndPoint.http_url.

These are unit tests; they call the task function directly with a mock
self-proxy and patch stream_command to prevent real subprocess execution.
"""

import json
import os
import tempfile
from unittest.mock import MagicMock, patch
from django.test import TestCase
from django.utils import timezone

from startScan.models import ScanHistory, Subdomain, Technology, EndPoint
from targetApp.models import Domain
from scanEngine.models import EngineType, Proxy


def _make_proxy(scan, subdomain=None, subscan=None, yaml_config=None):
    """Build a minimal task-proxy mock for wpscan_scan."""
    proxy = MagicMock()
    proxy.scan = scan
    proxy.scan.results_dir = '/tmp/rengine_test_wpscan'
    proxy.scan_id = scan.id
    proxy.subdomain = subdomain
    proxy.subscan = subscan
    proxy.yaml_configuration = yaml_config or {
        'vulnerability_scan': {
            'run_wpscan': True,
        }
    }
    proxy.results_dir = '/tmp/rengine_test_wpscan'
    proxy.activity_id = None
    return proxy


class TestWpscanGating(TestCase):
    def setUp(self):
        self.domain = Domain.objects.create(name='wpscan-gate.example.com')
        self.engine = EngineType.objects.create(engine_name='WPScan Gate Test Engine')
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

    def _make_endpoint(self, subdomain, path):
        return EndPoint.objects.create(
            scan_history=self.scan,
            subdomain=subdomain,
            http_url=f'https://{subdomain.name}/{path}',
            target_domain=self.domain,
        )

    # ------------------------------------------------------------------
    # Skipped — no WordPress indicators
    # ------------------------------------------------------------------

    @patch('reNgine.tasks.stream_command', return_value=iter([]))
    def test_skips_when_no_wordpress_indicators(self, mock_stream):
        """No WP tech and no wp-like paths → scan skipped."""
        self._make_subdomain('app.wpscan-gate.example.com')
        proxy = _make_proxy(self.scan)

        from reNgine.tasks.wpscan import wpscan_scan
        result = wpscan_scan(proxy, urls=[])

        self.assertIsNone(result)
        mock_stream.assert_not_called()

    @patch('reNgine.tasks.stream_command', return_value=iter([]))
    def test_skips_when_disabled_in_config(self, mock_stream):
        """run_wpscan=False skips immediately even when WordPress is detected."""
        sub = self._make_subdomain('blog.wpscan-gate.example.com')
        self._add_tech(sub, 'WordPress')
        proxy = _make_proxy(self.scan, yaml_config={
            'vulnerability_scan': {'run_wpscan': False},
        })

        from reNgine.tasks.wpscan import wpscan_scan
        result = wpscan_scan(proxy, urls=[])

        self.assertIsNone(result)
        mock_stream.assert_not_called()

    # ------------------------------------------------------------------
    # Runs — WordPress detected via technology fingerprint
    # ------------------------------------------------------------------

    @patch('reNgine.tasks.wpscan.parse_wpscan_results')
    @patch('reNgine.tasks.stream_command', return_value=iter([]))
    def test_runs_when_wordpress_tech_detected(self, mock_stream, mock_parse):
        """Subdomain with WordPress technology triggers WPScan."""
        sub = self._make_subdomain('blog.wpscan-gate.example.com')
        self._add_tech(sub, 'WordPress')
        proxy = _make_proxy(self.scan)

        from reNgine.tasks.wpscan import wpscan_scan
        result = wpscan_scan(proxy, urls=[])

        self.assertIsNotNone(result)
        # stream_command is called twice (1. update, 2. scan)
        self.assertEqual(mock_stream.call_count, 2)
        cmd_update = mock_stream.call_args_list[0][0][0]
        cmd_scan = mock_stream.call_args_list[1][0][0]
        self.assertIn('wpscan --update', cmd_update)
        self.assertIn('https://blog.wpscan-gate.example.com', cmd_scan)
        self.assertNotIn('https://blog.wpscan-gate.example.com/', cmd_scan)

    @patch('reNgine.tasks.wpscan.parse_wpscan_results')
    @patch('reNgine.tasks.stream_command', return_value=iter([]))
    def test_only_wordpress_subdomains_are_targeted(self, mock_stream, mock_parse):
        """Only WordPress-positive subdomains appear in scan targets."""
        wp_sub = self._make_subdomain('blog.wpscan-gate.example.com')
        self._add_tech(wp_sub, 'WordPress')
        # Non-WP subdomain should not be targeted
        self._make_subdomain('api.wpscan-gate.example.com')
        proxy = _make_proxy(self.scan)

        from reNgine.tasks.wpscan import wpscan_scan
        wpscan_scan(proxy, urls=[])

        # stream_command called 2 times (1. update, 2. target)
        self.assertEqual(mock_stream.call_count, 2)
        cmd_update = mock_stream.call_args_list[0][0][0]
        self.assertIn('wpscan --update', cmd_update)
        cmd_scan = mock_stream.call_args_list[1][0][0]
        self.assertIn('blog.wpscan-gate.example.com', cmd_scan)
        self.assertNotIn('api.wpscan-gate.example.com', cmd_scan)

    # ------------------------------------------------------------------
    # Runs — WordPress detected via wp-like paths in EndPoint
    # ------------------------------------------------------------------

    @patch('reNgine.tasks.wpscan.parse_wpscan_results')
    @patch('reNgine.tasks.stream_command', return_value=iter([]))
    def test_runs_when_wp_login_path_discovered(self, mock_stream, mock_parse):
        """Subdomain with /wp-login.php endpoint triggers WPScan even without tech tag."""
        sub = self._make_subdomain('site.wpscan-gate.example.com')
        self._make_endpoint(sub, 'wp-login.php')
        proxy = _make_proxy(self.scan)

        from reNgine.tasks.wpscan import wpscan_scan
        result = wpscan_scan(proxy, urls=[])

        self.assertIsNotNone(result)
        # stream_command called 2 times (1. update, 2. target)
        self.assertEqual(mock_stream.call_count, 2)
        cmd_update = mock_stream.call_args_list[0][0][0]
        self.assertIn('wpscan --update', cmd_update)
        cmd_scan = mock_stream.call_args_list[1][0][0]
        self.assertIn('site.wpscan-gate.example.com', cmd_scan)

    @patch('reNgine.tasks.wpscan.parse_wpscan_results')
    @patch('reNgine.tasks.stream_command', return_value=iter([]))
    def test_runs_when_wp_admin_path_discovered(self, mock_stream, mock_parse):
        """Subdomain with /wp-admin endpoint triggers WPScan."""
        sub = self._make_subdomain('site2.wpscan-gate.example.com')
        self._make_endpoint(sub, 'wp-admin/')
        proxy = _make_proxy(self.scan)

        from reNgine.tasks.wpscan import wpscan_scan
        result = wpscan_scan(proxy, urls=[])

        self.assertIsNotNone(result)
        self.assertEqual(mock_stream.call_count, 2)
        cmd_scan = mock_stream.call_args_list[1][0][0]
        self.assertIn('site2.wpscan-gate.example.com', cmd_scan)

    @patch('reNgine.tasks.wpscan.parse_wpscan_results')
    @patch('reNgine.tasks.stream_command', return_value=iter([]))
    def test_runs_when_xmlrpc_path_discovered(self, mock_stream, mock_parse):
        """Subdomain with /xmlrpc.php endpoint triggers WPScan."""
        sub = self._make_subdomain('site3.wpscan-gate.example.com')
        self._make_endpoint(sub, 'xmlrpc.php')
        proxy = _make_proxy(self.scan)

        from reNgine.tasks.wpscan import wpscan_scan
        result = wpscan_scan(proxy, urls=[])

        self.assertIsNotNone(result)
        self.assertEqual(mock_stream.call_count, 2)
        cmd_scan = mock_stream.call_args_list[1][0][0]
        self.assertIn('site3.wpscan-gate.example.com', cmd_scan)

    # ------------------------------------------------------------------
    # Subscan mode
    # ------------------------------------------------------------------

    @patch('reNgine.tasks.stream_command', return_value=iter([]))
    def test_subscan_non_wordpress_subdomain_skipped(self, mock_stream):
        """In subscan mode, a subdomain with no WP indicators is skipped."""
        sub = self._make_subdomain('api.wpscan-gate.example.com')
        subscan_mock = MagicMock()
        proxy = _make_proxy(self.scan, subdomain=sub, subscan=subscan_mock)

        from reNgine.tasks.wpscan import wpscan_scan
        result = wpscan_scan(proxy, urls=[])

        self.assertIsNone(result)
        mock_stream.assert_not_called()

    @patch('reNgine.tasks.wpscan.parse_wpscan_results')
    @patch('reNgine.tasks.stream_command', return_value=iter([]))
    def test_subscan_wordpress_subdomain_runs(self, mock_stream, mock_parse):
        """In subscan mode, a WordPress subdomain triggers the scan."""
        sub = self._make_subdomain('blog.wpscan-gate.example.com')
        self._add_tech(sub, 'WordPress')
        subscan_mock = MagicMock()
        proxy = _make_proxy(self.scan, subdomain=sub, subscan=subscan_mock)

        from reNgine.tasks.wpscan import wpscan_scan
        result = wpscan_scan(proxy, urls=[])

        self.assertIsNotNone(result)
        self.assertEqual(mock_stream.call_count, 2)
        cmd_scan = mock_stream.call_args_list[1][0][0]
        self.assertIn('blog.wpscan-gate.example.com', cmd_scan)

    @patch('reNgine.tasks.wpscan.parse_wpscan_results')
    @patch('reNgine.tasks.stream_command', return_value=iter([]))
    def test_subscan_wp_path_endpoint_runs(self, mock_stream, mock_parse):
        """In subscan mode, a subdomain with a wp-like endpoint triggers the scan."""
        sub = self._make_subdomain('site.wpscan-gate.example.com')
        self._make_endpoint(sub, 'wp-content/uploads/file.jpg')
        subscan_mock = MagicMock()
        proxy = _make_proxy(self.scan, subdomain=sub, subscan=subscan_mock)

        from reNgine.tasks.wpscan import wpscan_scan
        result = wpscan_scan(proxy, urls=[])

        self.assertIsNotNone(result)
        self.assertEqual(mock_stream.call_count, 2)
        cmd_scan = mock_stream.call_args_list[1][0][0]
        self.assertIn('site.wpscan-gate.example.com', cmd_scan)

    # ------------------------------------------------------------------
    # WPScan Update & Retry Logic Tests
    # ------------------------------------------------------------------

    @patch('reNgine.tasks.wpscan.parse_wpscan_results')
    @patch('reNgine.tasks.wpscan.time.sleep')
    @patch('reNgine.tasks.stream_command')
    def test_wpscan_ssl_error_retry_and_success(self, mock_stream, mock_sleep, mock_parse):
        """WPScan retries on SSL metadata fetch error and then succeeds."""
        sub = self._make_subdomain('blog.wpscan-gate.example.com')
        self._add_tech(sub, 'WordPress')
        proxy = _make_proxy(self.scan)
        
        attempts = []
        
        def stream_command_side_effect(cmd, *args, **kwargs):
            if '--update' in cmd:
                return iter([])
            
            attempts.append(cmd)
            output_file = '/tmp/rengine_test_wpscan/vulnerability/wpscan/blog.wpscan-gate.example.com_wpscan.json'
            os.makedirs(os.path.dirname(output_file), exist_ok=True)
            
            if len(attempts) == 1:
                # First attempt: SSL/metadata error JSON
                error_data = {
                    "db_update_started": True,
                    "scan_aborted": "Unable to get https://data.wpscan.org/metadata.json.sha512 (SSL peer certificate or SSH remote key was not OK)",
                    "target_url": "https://blog.wpscan-gate.example.com"
                }
                with open(output_file, 'w') as f:
                    json.dump(error_data, f)
            else:
                # Second attempt: Successful dummy scan result
                success_data = {
                    "start_time": 12345,
                    "interesting_findings": []
                }
                with open(output_file, 'w') as f:
                    json.dump(success_data, f)
            return iter([])

        mock_stream.side_effect = stream_command_side_effect

        from reNgine.tasks.wpscan import wpscan_scan
        wpscan_scan(proxy, urls=[])

        # Total calls to stream_command: 1 (update) + 2 (scans) = 3 calls
        self.assertEqual(mock_stream.call_count, 3)
        self.assertEqual(len(attempts), 2)
        self.assertIn('https://blog.wpscan-gate.example.com', attempts[0])
        self.assertNotIn('https://blog.wpscan-gate.example.com/', attempts[0])
        self.assertIn('https://blog.wpscan-gate.example.com', attempts[1])

    @patch('reNgine.tasks.wpscan.parse_wpscan_results')
    @patch('reNgine.tasks.wpscan.time.sleep')
    @patch('reNgine.tasks.stream_command')
    @patch('reNgine.tasks.wpscan.get_random_proxy', return_value='127.0.0.1:8080')
    def test_wpscan_ssl_error_max_retries_fail(self, mock_get_proxy, mock_stream, mock_sleep, mock_parse):
        """WPScan retries up to max attempts, and final attempt runs without proxy."""
        Proxy.objects.create(use_proxy=True)
        sub = self._make_subdomain('blog.wpscan-gate.example.com')
        self._add_tech(sub, 'WordPress')
        proxy = _make_proxy(self.scan)

        attempts = []

        def stream_command_side_effect(cmd, *args, **kwargs):
            if '--update' in cmd:
                return iter([])

            attempts.append(cmd)
            output_file = '/tmp/rengine_test_wpscan/vulnerability/wpscan/blog.wpscan-gate.example.com_wpscan.json'
            os.makedirs(os.path.dirname(output_file), exist_ok=True)

            # Always write SSL error JSON
            error_data = {
                "db_update_started": True,
                "scan_aborted": "Unable to get https://data.wpscan.org/metadata.json.sha512 (SSL peer certificate or SSH remote key was not OK)",
                "target_url": "https://blog.wpscan-gate.example.com"
            }
            with open(output_file, 'w') as f:
                json.dump(error_data, f)
            return iter([])

        mock_stream.side_effect = stream_command_side_effect

        from reNgine.tasks.wpscan import wpscan_scan
        wpscan_scan(proxy, urls=[])

        # Total calls to stream_command: 1 (update) + 4 (scans) = 5 calls
        self.assertEqual(mock_stream.call_count, 5)
        self.assertEqual(len(attempts), 4)

        # Verify first 3 scan attempts included proxy
        for i in range(3):
            self.assertIn('--proxy 127.0.0.1:8080', attempts[i])

        # Verify 4th (final) attempt did NOT include proxy
        self.assertNotIn('--proxy', attempts[3])


class TestWpscanParser(TestCase):
    def setUp(self):
        self.domain = Domain.objects.create(name='parser-test.example.com')
        self.engine = EngineType.objects.create(engine_name='Parser Test Engine')
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_status=1,
            start_scan_date=timezone.now(),
            scan_type=self.engine,
        )
        self.subdomain = Subdomain.objects.create(
            name='parser-test.example.com',
            scan_history=self.scan,
            target_domain=self.domain,
        )
        self.proxy = MagicMock()
        self.proxy.scan = self.scan
        self.proxy.domain = self.domain

    def _write_json(self, data):
        f = tempfile.NamedTemporaryFile(suffix='.json', delete=False, mode='w')
        json.dump(data, f)
        f.close()
        return f.name

    def test_xmlrpc_finding_maps_to_high_severity(self):
        payload = {
            'interesting_findings': [{
                'type': 'xmlrpc',
                'to_s': 'XML-RPC seems to be enabled: https://parser-test.example.com/xmlrpc.php',
                'found_by': 'Direct Access',
                'confidence': 100,
                'confirmed_by': {},
                'references': {'url': ['http://codex.wordpress.org/XML-RPC_Pingback_API']},
                'interesting_entries': [],
            }],
        }
        path = self._write_json(payload)
        try:
            from reNgine.tasks.wpscan import parse_wpscan_results
            parse_wpscan_results(self.proxy, path, self.subdomain)
        finally:
            os.unlink(path)

        from startScan.models import Vulnerability
        vuln = Vulnerability.objects.filter(scan_history=self.scan, name__icontains='XML-RPC').first()
        self.assertIsNotNone(vuln, "Expected XML-RPC finding to be stored")
        self.assertEqual(vuln.severity, 3, "XML-RPC should map to High (3)")
        self.assertNotEqual(vuln.name, 'WPScan Finding', "Name must not be generic fallback")

    def test_upload_directory_listing_maps_to_medium(self):
        payload = {
            'interesting_findings': [{
                'type': 'upload_directory_listing',
                'to_s': 'Upload directory has listing enabled: https://parser-test.example.com/wp-content/uploads/',
                'found_by': 'Direct Access',
                'confidence': 100,
                'confirmed_by': {},
                'references': {},
                'interesting_entries': [],
            }],
        }
        path = self._write_json(payload)
        try:
            from reNgine.tasks.wpscan import parse_wpscan_results
            parse_wpscan_results(self.proxy, path, self.subdomain)
        finally:
            os.unlink(path)

        from startScan.models import Vulnerability
        vuln = Vulnerability.objects.filter(scan_history=self.scan, name__icontains='Upload Directory').first()
        self.assertIsNotNone(vuln)
        self.assertEqual(vuln.severity, 2)

    def test_readme_maps_to_info(self):
        payload = {
            'interesting_findings': [{
                'type': 'readme',
                'to_s': 'WordPress readme found: https://parser-test.example.com/readme.html',
                'found_by': 'Direct Access',
                'confidence': 100,
                'confirmed_by': {},
                'references': {},
                'interesting_entries': [],
            }],
        }
        path = self._write_json(payload)
        try:
            from reNgine.tasks.wpscan import parse_wpscan_results
            parse_wpscan_results(self.proxy, path, self.subdomain)
        finally:
            os.unlink(path)

        from startScan.models import Vulnerability
        vuln = Vulnerability.objects.filter(scan_history=self.scan, name__icontains='Readme').first()
        self.assertIsNotNone(vuln)
        self.assertEqual(vuln.severity, 0)

    def test_wordpress_version_stored_as_info_when_latest(self):
        payload = {
            'version': {
                'number': '7.0',
                'status': 'latest',
                'vulnerabilities': [],
            },
        }
        path = self._write_json(payload)
        try:
            from reNgine.tasks.wpscan import parse_wpscan_results
            parse_wpscan_results(self.proxy, path, self.subdomain)
        finally:
            os.unlink(path)

        from startScan.models import Vulnerability
        vuln = Vulnerability.objects.filter(scan_history=self.scan, name__startswith='WordPress Core Detected').first()
        self.assertIsNotNone(vuln)
        self.assertEqual(vuln.severity, 0)

    def test_outdated_wordpress_version_stored_as_medium(self):
        payload = {
            'version': {
                'number': '5.9.0',
                'status': 'outdated',
                'vulnerabilities': [],
            },
        }
        path = self._write_json(payload)
        try:
            from reNgine.tasks.wpscan import parse_wpscan_results
            parse_wpscan_results(self.proxy, path, self.subdomain)
        finally:
            os.unlink(path)

        from startScan.models import Vulnerability
        vuln = Vulnerability.objects.filter(scan_history=self.scan, name__startswith='WordPress Core Detected').first()
        self.assertIsNotNone(vuln)
        self.assertEqual(vuln.severity, 2)

    def test_plugin_without_vuln_stored_as_detection_finding(self):
        """Non-vulnerable plugin must be stored so wp-taint can find it."""
        payload = {
            'plugins': {
                'woocommerce': {
                    'location': 'https://parser-test.example.com/wp-content/plugins/woocommerce/',
                    'outdated': False,
                    'version': {'number': '8.0.0'},
                    'latest_version': '8.0.0',
                    'vulnerabilities': [],
                },
            },
        }
        path = self._write_json(payload)
        try:
            from reNgine.tasks.wpscan import parse_wpscan_results
            parse_wpscan_results(self.proxy, path, self.subdomain)
        finally:
            os.unlink(path)

        from startScan.models import Vulnerability
        vuln = Vulnerability.objects.filter(
            scan_history=self.scan,
            name='WordPress Plugin Detected: woocommerce',
        ).first()
        self.assertIsNotNone(vuln, "Non-vulnerable plugin must be stored for wp-taint discovery")
        self.assertEqual(vuln.severity, 0)

    def test_outdated_plugin_stored_as_medium(self):
        payload = {
            'plugins': {
                'contact-form-7': {
                    'location': 'https://parser-test.example.com/wp-content/plugins/contact-form-7/',
                    'outdated': True,
                    'version': {'number': '5.0.0'},
                    'latest_version': '6.1.1',
                    'vulnerabilities': [],
                },
            },
        }
        path = self._write_json(payload)
        try:
            from reNgine.tasks.wpscan import parse_wpscan_results
            parse_wpscan_results(self.proxy, path, self.subdomain)
        finally:
            os.unlink(path)

        from startScan.models import Vulnerability
        vuln = Vulnerability.objects.filter(
            scan_history=self.scan,
            name='WordPress Plugin Detected: contact-form-7',
        ).first()
        self.assertIsNotNone(vuln)
        self.assertEqual(vuln.severity, 2)
        self.assertIn('outdated', vuln.description)

    def test_plugin_with_vuln_stores_detection_finding_and_vuln(self):
        """A plugin with vulnerabilities must store BOTH a detection finding AND the CVE finding."""
        payload = {
            'plugins': {
                'akismet': {
                    'location': 'https://parser-test.example.com/wp-content/plugins/akismet/',
                    'outdated': False,
                    'version': {'number': '5.3.1'},
                    'latest_version': '5.3.1',
                    'vulnerabilities': [{
                        'title': 'Akismet Reflected XSS',
                        'references': {'cve': ['CVE-2024-12345'], 'url': ['https://example.com/advisory']},
                    }],
                },
            },
        }
        path = self._write_json(payload)
        try:
            from reNgine.tasks.wpscan import parse_wpscan_results
            parse_wpscan_results(self.proxy, path, self.subdomain)
        finally:
            os.unlink(path)

        from startScan.models import Vulnerability
        detection = Vulnerability.objects.filter(
            scan_history=self.scan,
            name='WordPress Plugin Detected: akismet',
        ).first()
        self.assertIsNotNone(detection, "Detection finding must exist")

        vuln_finding = Vulnerability.objects.filter(
            scan_history=self.scan,
            name__startswith='WordPress Plugin: akismet',
        ).first()
        self.assertIsNotNone(vuln_finding, "CVE finding must exist separately")
        self.assertIn('Reflected XSS', vuln_finding.name)

    def test_main_theme_outdated_stored_as_medium(self):
        payload = {
            'main_theme': {
                'slug': 'twentytwentyfive',
                'location': 'https://parser-test.example.com/wp-content/themes/twentytwentyfive/',
                'outdated': True,
                'version': {'number': '1.1'},
                'latest_version': '1.5',
                'vulnerabilities': [],
            },
        }
        path = self._write_json(payload)
        try:
            from reNgine.tasks.wpscan import parse_wpscan_results
            parse_wpscan_results(self.proxy, path, self.subdomain)
        finally:
            os.unlink(path)

        from startScan.models import Vulnerability
        vuln = Vulnerability.objects.filter(
            scan_history=self.scan,
            name='WordPress Theme Detected: twentytwentyfive',
        ).first()
        self.assertIsNotNone(vuln)
        self.assertEqual(vuln.severity, 2)
        self.assertIn('outdated', vuln.description)

    def test_users_stored_as_medium_enumeration_findings(self):
        payload = {
            'users': {
                'WebDeveloper': {
                    'id': None,
                    'found_by': 'Rss Generator (Passive Detection)',
                    'confidence': 100,
                },
                'webdeveloper': {
                    'id': 1,
                    'found_by': 'Author Id Brute Forcing',
                    'confidence': 100,
                },
            },
        }
        path = self._write_json(payload)
        try:
            from reNgine.tasks.wpscan import parse_wpscan_results
            parse_wpscan_results(self.proxy, path, self.subdomain)
        finally:
            os.unlink(path)

        from startScan.models import Vulnerability
        vulns = Vulnerability.objects.filter(
            scan_history=self.scan,
            name__startswith='WordPress User Enumerated:',
        )
        self.assertEqual(vulns.count(), 2, "Both users must be stored")
        for v in vulns:
            self.assertEqual(v.severity, 2, "User enumeration must be Medium")

    def test_unrecognized_finding_type_records_metadata_in_description(self):
        payload = {
            'interesting_findings': [{
                'type': 'some_exotic_new_finding',
                'to_s': 'Some Exotic New Finding: https://parser-test.example.com/',
                'found_by': 'Fuzzy Magic',
                'confidence': 90,
                'confirmed_by': {},
                'references': {},
                'interesting_entries': ['Secret header found'],
                'custom_field_one': 'some_val',
                'custom_field_two': 12345,
            }],
        }
        path = self._write_json(payload)
        try:
            from reNgine.tasks.wpscan import parse_wpscan_results
            parse_wpscan_results(self.proxy, path, self.subdomain)
        finally:
            os.unlink(path)

        from startScan.models import Vulnerability
        vuln = Vulnerability.objects.filter(scan_history=self.scan, name__icontains='Exotic').first()
        self.assertIsNotNone(vuln)
        self.assertEqual(vuln.severity, 0, "Unrecognized finding should default to info (0)")
        self.assertIn('Secret header found', vuln.description)
        self.assertIn('**custom_field_one**: some_val', vuln.description)
        self.assertIn('**custom_field_two**: 12345', vuln.description)
        self.assertIn('**confidence**: 90', vuln.description)

    def test_full_wpscan_json_produces_expected_findings(self):
        """Integration test: the sample JSON from a real WPScan run produces all expected findings."""
        payload = {
            'interesting_findings': [
                {'type': 'headers', 'to_s': 'Headers', 'found_by': 'Headers',
                 'confidence': 100, 'confirmed_by': {}, 'references': {},
                 'interesting_entries': ['Server: Apache']},
                {'type': 'xmlrpc', 'to_s': 'XML-RPC seems to be enabled: https://parser-test.example.com/xmlrpc.php',
                 'found_by': 'Direct Access', 'confidence': 100,
                 'confirmed_by': {}, 'references': {}, 'interesting_entries': []},
                {'type': 'readme', 'to_s': 'WordPress readme found: https://parser-test.example.com/readme.html',
                 'found_by': 'Direct Access', 'confidence': 100,
                 'confirmed_by': {}, 'references': {}, 'interesting_entries': []},
                {'type': 'upload_directory_listing',
                 'to_s': 'Upload directory has listing enabled: https://parser-test.example.com/wp-content/uploads/',
                 'found_by': 'Direct Access', 'confidence': 100,
                 'confirmed_by': {}, 'references': {}, 'interesting_entries': []},
                {'type': 'wp_cron',
                 'to_s': 'The external WP-Cron seems to be enabled: https://parser-test.example.com/wp-cron.php',
                 'found_by': 'Direct Access', 'confidence': 60,
                 'confirmed_by': {}, 'references': {}, 'interesting_entries': []},
            ],
            'version': {'number': '7.0', 'status': 'latest', 'vulnerabilities': []},
            'main_theme': {
                'slug': 'twentytwentyfive',
                'location': 'https://parser-test.example.com/wp-content/themes/twentytwentyfive/',
                'outdated': True,
                'version': {'number': '1.1'},
                'latest_version': '1.5',
                'vulnerabilities': [],
            },
            'plugins': {},
            'themes': {},
            'users': {
                'WebDeveloper': {'id': None, 'found_by': 'Rss Generator', 'confidence': 100},
                'webdeveloper': {'id': 1, 'found_by': 'Author Id Brute Forcing', 'confidence': 100},
            },
        }
        path = self._write_json(payload)
        try:
            from reNgine.tasks.wpscan import parse_wpscan_results
            parse_wpscan_results(self.proxy, path, self.subdomain)
        finally:
            os.unlink(path)

        from startScan.models import Vulnerability
        vulns = Vulnerability.objects.filter(scan_history=self.scan)
        names = list(vulns.values_list('name', flat=True))

        # Check each expected finding exists
        self.assertTrue(any('xml-rpc' in n.lower() for n in names), f"Missing XML-RPC finding in: {names}")
        self.assertTrue(any('upload directory' in n.lower() for n in names), f"Missing upload listing in: {names}")
        self.assertTrue(any('readme' in n.lower() for n in names), f"Missing readme finding in: {names}")
        self.assertTrue(any('wp-cron' in n.lower() for n in names), f"Missing wp-cron finding in: {names}")
        self.assertTrue(any('wordpress core detected' in n.lower() for n in names), f"Missing version finding in: {names}")
        self.assertTrue(any('twentytwentyfive' in n.lower() for n in names), f"Missing theme finding in: {names}")
        self.assertEqual(vulns.filter(name__startswith='WordPress User Enumerated:').count(), 2)

        # Severity spot-checks
        xmlrpc = vulns.get(name='XML-RPC seems to be enabled')
        self.assertEqual(xmlrpc.severity, 3)
        theme = vulns.get(name='WordPress Theme Detected: twentytwentyfive')
        self.assertEqual(theme.severity, 2)

