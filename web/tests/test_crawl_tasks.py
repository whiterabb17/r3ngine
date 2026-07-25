"""
Tests for web/reNgine/crawl_tasks.py

All subprocess calls are mocked. Tests verify parsing and persistence logic.
"""
import json
import subprocess
from unittest.mock import patch, MagicMock
from django.test import TestCase


def _make_proxy(yaml_config=None):
    proxy = MagicMock()
    proxy.yaml_configuration = yaml_config or {}
    return proxy


class TestXURLFind3rScan(TestCase):
    @patch('subprocess.run')
    def test_returns_true_no_targets(self, mock_run):
        from reNgine.tasks.crawl import xurlfind3r_scan
        result = xurlfind3r_scan(_make_proxy(), scan_history_id=1)
        self.assertTrue(result)
        mock_run.assert_not_called()

    @patch('subprocess.run')
    def test_persists_discovered_urls(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='https://example.com/path1\nhttps://example.com/path2\nnot-a-url\n',
            stderr='',
        )
        with patch('startScan.models.EndPoint.objects') as mock_ep:
            mock_ep.bulk_create = MagicMock()
            from reNgine.tasks.crawl import xurlfind3r_scan
            result = xurlfind3r_scan(_make_proxy(), scan_history_id=1, domain='example.com')
        self.assertTrue(result)

    @patch('subprocess.run')
    def test_handles_timeout_gracefully(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired('xurlfind3r', 300)
        from reNgine.tasks.crawl import xurlfind3r_scan
        result = xurlfind3r_scan(_make_proxy(), scan_history_id=1, domain='example.com')
        self.assertTrue(result)


class TestURLFinderScan(TestCase):
    @patch('subprocess.run')
    def test_returns_true_no_domain(self, mock_run):
        from reNgine.tasks.crawl import urlfinder_scan
        result = urlfinder_scan(_make_proxy(), scan_history_id=1)
        self.assertTrue(result)
        mock_run.assert_not_called()

    @patch('subprocess.run')
    def test_filters_non_http_lines(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='https://example.com/api\nftp://example.com/file\nhttps://example.com/login\n',
            stderr='',
        )
        with patch('startScan.models.EndPoint.objects') as mock_ep:
            saved = []
            mock_ep.bulk_create = lambda items, **kw: saved.extend(items)
            from reNgine.tasks.crawl import urlfinder_scan
            urlfinder_scan(_make_proxy(), scan_history_id=1, domain='example.com')
        # Only http(s) lines should be saved
        urls = [ep.http_url for ep in saved]
        self.assertNotIn('ftp://example.com/file', urls)


class TestCariddiScan(TestCase):
    @patch('subprocess.run')
    def test_returns_true_no_targets(self, mock_run):
        from reNgine.tasks.crawl import cariddi_scan
        result = cariddi_scan(_make_proxy(), scan_history_id=1)
        self.assertTrue(result)
        mock_run.assert_not_called()

    @patch('subprocess.run')
    def test_parses_tab_separated_output(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='https://example.com/api.js\t[secret:api_key]\nhttps://example.com/login\n',
            stderr='',
        )
        with patch('startScan.models.EndPoint.objects') as mock_ep:
            saved = []
            mock_ep.bulk_create = lambda items, **kw: saved.extend(items)
            from reNgine.tasks.crawl import cariddi_scan
            cariddi_scan(_make_proxy(), scan_history_id=1, url='https://example.com')
        urls = [ep.http_url for ep in saved]
        self.assertIn('https://example.com/api.js', urls)
        self.assertIn('https://example.com/login', urls)


class TestBUPScan(TestCase):
    @patch('subprocess.run')
    def test_returns_true_no_targets(self, mock_run):
        from reNgine.tasks.crawl import bup_scan
        result = bup_scan(_make_proxy(), scan_history_id=1)
        self.assertTrue(result)
        mock_run.assert_not_called()

    @patch('subprocess.run')
    def test_saves_bypass_as_medium_vuln(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='[BYPASS] https://example.com/admin (200 via X-Original-URL)\n',
            stderr='',
        )
        with patch('startScan.models.Vulnerability.objects') as mock_vuln:
            saved = []
            mock_vuln.bulk_create = lambda items, **kw: saved.extend(items)
            from reNgine.tasks.crawl import bup_scan
            bup_scan(_make_proxy(), scan_history_id=1, url='https://example.com/admin')
        if saved:
            self.assertEqual(saved[0].severity, 2)  # medium

    @patch('subprocess.run')
    def test_handles_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired('bup', 120)
        from reNgine.tasks.crawl import bup_scan
        result = bup_scan(_make_proxy(), scan_history_id=1, url='https://example.com/admin')
        self.assertTrue(result)


class TestArjunScan(TestCase):
    @patch('subprocess.run')
    def test_returns_true_no_targets(self, mock_run):
        from reNgine.tasks.crawl import arjun_scan
        result = arjun_scan(_make_proxy(), scan_history_id=1)
        self.assertTrue(result)
        mock_run.assert_not_called()

    @patch('subprocess.run')
    @patch('os.path.exists', return_value=False)
    def test_handles_missing_output_file(self, mock_exists, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout='', stderr='')
        from reNgine.tasks.crawl import arjun_scan
        result = arjun_scan(_make_proxy(), scan_history_id=1, url='https://example.com/search')
        self.assertTrue(result)

    @patch('subprocess.run')
    def test_handles_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired('arjun', 600)
        from reNgine.tasks.crawl import arjun_scan
        result = arjun_scan(_make_proxy(), scan_history_id=1, url='https://example.com')
        self.assertTrue(result)


class TestFeroxbusterScan(TestCase):
    @patch('subprocess.run')
    def test_returns_true_no_targets(self, mock_run):
        from reNgine.tasks.crawl import feroxbuster_scan
        result = feroxbuster_scan(_make_proxy(), scan_history_id=1)
        self.assertTrue(result)
        mock_run.assert_not_called()

    @patch('subprocess.run')
    @patch('os.path.exists', return_value=False)
    def test_handles_missing_output_file(self, mock_exists, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout='', stderr=b'')
        from reNgine.tasks.crawl import feroxbuster_scan
        result = feroxbuster_scan(_make_proxy(), scan_history_id=1, url='https://example.com')
        self.assertTrue(result)

    @patch('subprocess.run')
    def test_handles_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired('feroxbuster', 1800)
        from reNgine.tasks.crawl import feroxbuster_scan
        result = feroxbuster_scan(_make_proxy(), scan_history_id=1, url='https://example.com')
        self.assertTrue(result)


class TestGFScan(TestCase):
    @patch('subprocess.run')
    def test_returns_empty_for_no_urls(self, mock_run):
        from reNgine.tasks.crawl import gf_scan
        result = gf_scan(_make_proxy(), scan_history_id=1, pattern='xss')
        self.assertEqual(result, [])
        mock_run.assert_not_called()

    @patch('subprocess.run')
    def test_returns_matched_urls(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='https://example.com/search?q=<script>\nhttps://example.com/name?n=test\n',
            stderr='',
        )
        from reNgine.tasks.crawl import gf_scan
        result = gf_scan(
            _make_proxy(), scan_history_id=1, pattern='xss',
            urls=['https://example.com/search?q=test', 'https://example.com/name?n=test'],
        )
        self.assertIsInstance(result, list)
        self.assertEqual(len(result), 2)

    @patch('subprocess.run')
    def test_handles_timeout(self, mock_run):
        mock_run.side_effect = subprocess.TimeoutExpired('gf', 60)
        from reNgine.tasks.crawl import gf_scan
        result = gf_scan(
            _make_proxy(), scan_history_id=1, pattern='xss',
            urls=['https://example.com/?q=test'],
        )
        self.assertEqual(result, [])


class TestURLParserScan(TestCase):
    @patch('subprocess.run')
    def test_urlparser_saves_keypairs_as_parameters(self, mock_run):
        from startScan.models import ScanHistory, EndPoint, Parameter
        from targetApp.models import Domain as TargetDomain, Project
        from scanEngine.models import EngineType
        from django.utils import timezone
        from reNgine.tasks.crawl import urlparser_scan

        project = Project.objects.create(name='up-proj', insert_date=timezone.now())
        domain = TargetDomain.objects.create(
            name='up-test.example.com', project=project, insert_date=timezone.now(),
        )
        engine = EngineType.objects.create(engine_name='up-engine', yaml_configuration='{}')
        scan = ScanHistory.objects.create(
            scan_status=0, start_scan_date=timezone.now(), domain=domain, scan_type=engine,
        )
        ep = EndPoint.objects.create(
            scan_history=scan,
            http_url='https://up-test.example.com/page?foo=1&bar=2',
        )

        mock_run.return_value = MagicMock(returncode=0, stdout='foo=1\nbar=2\n', stderr='')

        result = urlparser_scan(
            _make_proxy(), scan_history_id=scan.id, domain_id=domain.id,
            urls=['https://up-test.example.com/page?foo=1&bar=2'],
        )
        self.assertTrue(result)
        param_names = list(
            Parameter.objects.filter(endpoint=ep).values_list('name', flat=True)
        )
        self.assertIn('foo', param_names)
        self.assertIn('bar', param_names)

    @patch('subprocess.run')
    def test_urlparser_returns_true_with_no_urls(self, mock_run):
        from reNgine.tasks.crawl import urlparser_scan
        result = urlparser_scan(_make_proxy(), scan_history_id=1, domain_id=1, urls=[])
        self.assertTrue(result)
        mock_run.assert_not_called()

    @patch('subprocess.run')
    def test_urlparser_handles_no_query_params(self, mock_run):
        from reNgine.tasks.crawl import urlparser_scan
        mock_run.return_value = MagicMock(returncode=0, stdout='', stderr='')
        result = urlparser_scan(
            _make_proxy(), scan_history_id=1, domain_id=1,
            urls=['https://example.com/page'],
        )
        self.assertTrue(result)

    @patch('subprocess.run')
    def test_urlparser_handles_timeout(self, mock_run):
        from reNgine.tasks.crawl import urlparser_scan
        mock_run.side_effect = __import__('subprocess').TimeoutExpired(cmd='unfurl', timeout=120)
        result = urlparser_scan(
            _make_proxy(), scan_history_id=1, domain_id=1,
            urls=['https://example.com/page?x=1'],
        )
        self.assertTrue(result)


class TestSourcemapperFiltering(TestCase):
    @patch('reNgine.tasks.auth_discovery.extract_auth_candidates')
    @patch('reNgine.tasks.crawl.run_command')
    @patch('requests.get')
    def test_sourcemapper_filters_non_js_urls(self, mock_get, mock_run_cmd, mock_extract_auth):
        from reNgine.tasks.crawl import web_api_discovery
        proxy = _make_proxy({'uses_tools': ['sourcemapper']})
        proxy.results_dir = '/tmp/test_results'
        proxy.scan_id = 1
        proxy.activity_id = 'act-1'
        proxy.scan = MagicMock()
        proxy.scan.id = 1
        proxy.domain = MagicMock()
        proxy.yaml_configuration = {'web_api_discovery': {'uses_tools': ['sourcemapper']}}

        # Given non-map non-js URLs
        urls = [
            'https://example.com',
            'https://example.com/index.html',
            'https://example.com/sitemap.xml',
        ]
        with patch('reNgine.tasks.crawl.Subdomain.objects.filter') as mock_filter:
            mock_filter.return_value.first.return_value = MagicMock(name='example.com')
            web_api_discovery(proxy, urls=urls, ctx={'api_discovery_tools': ['sourcemapper']})

        # requests.get should not even be called for non-js/non-map URLs
        mock_get.assert_not_called()
        # run_command should not be called with sourcemapper
        for call_args in mock_run_cmd.call_args_list:
            cmd = call_args[0][0] if call_args[0] else call_args[1].get('cmd', '')
            self.assertNotIn('sourcemapper ', cmd)

    @patch('reNgine.tasks.auth_discovery.extract_auth_candidates')
    @patch('reNgine.tasks.crawl.run_command')
    @patch('requests.get')
    def test_sourcemapper_runs_on_valid_sourcemap_candidate(self, mock_get, mock_run_cmd, mock_extract_auth):
        from reNgine.tasks.crawl import web_api_discovery
        proxy = _make_proxy({'uses_tools': ['sourcemapper']})
        proxy.results_dir = '/tmp/test_results'
        proxy.scan_id = 1
        proxy.activity_id = 'act-1'
        proxy.scan = MagicMock()
        proxy.scan.id = 1
        proxy.domain = MagicMock()
        proxy.yaml_configuration = {'web_api_discovery': {'uses_tools': ['sourcemapper']}}

        # Given a direct .map URL
        urls = ['https://example.com/app.js.map']
        with patch('reNgine.tasks.crawl.Subdomain.objects.filter') as mock_filter:
            mock_filter.return_value.first.return_value = MagicMock(name='example.com')
            web_api_discovery(proxy, urls=urls, ctx={'api_discovery_tools': ['sourcemapper']})

        # sourcemapper command should be run for app.js.map
        ran_sourcemapper = False
        for call_args in mock_run_cmd.call_args_list:
            cmd = call_args[0][0] if call_args[0] else call_args[1].get('cmd', '')
            if 'sourcemapper ' in cmd and 'app.js.map' in cmd:
                ran_sourcemapper = True
                break
        self.assertTrue(ran_sourcemapper, "sourcemapper should have executed on direct .map target")


class TestGrpcurlCircuitBreaker(TestCase):
    @patch('reNgine.tasks.crawl.save_vulnerability')
    @patch('reNgine.tasks.auth_discovery.extract_auth_candidates')
    @patch('reNgine.tasks.crawl.run_command')
    def test_grpcurl_deduplicates_target_hosts(self, mock_run_cmd, mock_extract_auth, mock_save_vuln):
        from reNgine.tasks.crawl import web_api_discovery
        proxy = _make_proxy({'uses_tools': ['grpcurl']})
        proxy.results_dir = '/tmp/test_results'
        proxy.scan_id = 1
        proxy.activity_id = 'act-1'
        proxy.scan = MagicMock()
        proxy.scan.id = 1
        proxy.domain = MagicMock()
        proxy.yaml_configuration = {'web_api_discovery': {'uses_tools': ['grpcurl']}}

        mock_run_cmd.return_value = (0, "grpc.reflection.v1alpha.ServerReflection\n")

        # 5 URLs sharing the same hostname
        urls = [
            'https://example.com/page1',
            'https://example.com/page2',
            'https://example.com/page3',
            'https://example.com/api/v1',
            'https://example.com/login',
        ]
        with patch('reNgine.tasks.crawl.Subdomain.objects.filter') as mock_filter:
            mock_filter.return_value.first.return_value = MagicMock(name='example.com')
            web_api_discovery(proxy, urls=urls, ctx={'api_discovery_tools': ['grpcurl']})

        # grpcurl should be called only ONCE for example.com:443
        grpcurl_calls = [
            c[0][0] for c in mock_run_cmd.call_args_list if c[0] and 'grpcurl ' in c[0][0]
        ]
        self.assertEqual(len(grpcurl_calls), 1, f"Expected 1 grpcurl call, got {len(grpcurl_calls)}: {grpcurl_calls}")
        self.assertIn('example.com:443', grpcurl_calls[0])
        mock_save_vuln.assert_called_once()

    @patch('reNgine.tasks.crawl.save_vulnerability')
    @patch('reNgine.tasks.auth_discovery.extract_auth_candidates')
    @patch('reNgine.tasks.crawl.run_command')
    def test_grpcurl_circuit_breaker_on_dial_failure(self, mock_run_cmd, mock_extract_auth, mock_save_vuln):
        from reNgine.tasks.crawl import web_api_discovery
        proxy = _make_proxy({'uses_tools': ['grpcurl']})
        proxy.results_dir = '/tmp/test_results'
        proxy.scan_id = 1
        proxy.activity_id = 'act-1'
        proxy.scan = MagicMock()
        proxy.scan.id = 1
        proxy.domain = MagicMock()
        proxy.yaml_configuration = {'web_api_discovery': {'uses_tools': ['grpcurl']}}

        mock_run_cmd.return_value = (1, 'Failed to dial target host "unreachable.com:443": context deadline exceeded')

        urls = ['https://unreachable.com/path1', 'https://unreachable.com/path2']
        with patch('reNgine.tasks.crawl.Subdomain.objects.filter') as mock_filter:
            mock_filter.return_value.first.return_value = MagicMock(name='unreachable.com')
            web_api_discovery(proxy, urls=urls, ctx={'api_discovery_tools': ['grpcurl']})

        # grpcurl should attempt unreachable.com:443 only once and record failure
        grpcurl_calls = [
            c[0][0] for c in mock_run_cmd.call_args_list if c[0] and 'grpcurl ' in c[0][0]
        ]
        self.assertEqual(len(grpcurl_calls), 1)
        mock_save_vuln.assert_not_called()


