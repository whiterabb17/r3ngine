"""Tests for second-order scan parser and integration."""
import json
import os
import tempfile
from unittest import TestCase as UnitTestCase
from unittest.mock import MagicMock, patch
from django.test import TestCase


class TestParseSecondOrderFinding(UnitTestCase):

    def _call(self, mode, page_url, element_key, values):
        from reNgine.tasks.parsers import parse_second_order_finding
        return parse_second_order_finding(mode, page_url, element_key, values)

    # --- LogNon200Queries (HIGH severity) ---

    def test_non200_returns_high_severity(self):
        result = self._call(
            'LogNon200Queries',
            'https://example.com/',
            'img[src]',
            ['https://cdn.gone.io/logo.png'],
        )
        self.assertEqual(result['severity'], 3)

    def test_non200_vuln_type(self):
        result = self._call('LogNon200Queries', 'https://example.com/', 'a[href]', ['https://dead.io/'])
        self.assertEqual(result['type'], 'Potential Resource Takeover')
        self.assertEqual(result['source'], 'Second-Order')

    def test_non200_includes_page_url_as_http_url(self):
        result = self._call('LogNon200Queries', 'https://example.com/page', 'script[src]', ['https://x.io/a.js'])
        self.assertEqual(result['http_url'], 'https://example.com/page')

    def test_non200_description_contains_selector_and_values(self):
        result = self._call('LogNon200Queries', 'https://example.com/', 'form[action]', ['/upload', '/delete'])
        self.assertIn('form[action]', result['description'])
        self.assertIn('/upload', result['description'])

    # --- LogQueries (INFO severity) ---

    def test_queries_returns_info_severity(self):
        result = self._call('LogQueries', 'https://example.com/', 'input[name]', ['email', 'password'])
        self.assertEqual(result['severity'], 0)

    def test_queries_vuln_type(self):
        result = self._call('LogQueries', 'https://example.com/', 'script[src]', ['https://cdn.example.com/app.js'])
        self.assertEqual(result['type'], 'External Resource Reference')

    def test_queries_extracted_results_equals_values_list(self):
        values = ['https://cdn.example.com/a.js', 'https://cdn.example.com/b.js']
        result = self._call('LogQueries', 'https://example.com/', 'script[src]', values)
        self.assertEqual(result['extracted_results'], values)

    # --- LogInline (INFO severity) ---

    def test_inline_returns_info_severity(self):
        result = self._call('LogInline', 'https://example.com/', 'title', ['Home – Example'])
        self.assertEqual(result['severity'], 0)

    def test_inline_vuln_type(self):
        result = self._call('LogInline', 'https://example.com/', 'script', ['!function(o,c){...}'])
        self.assertEqual(result['type'], 'Inline Content Discovered')

    def test_inline_description_contains_element_key(self):
        result = self._call('LogInline', 'https://example.com/', 'script', ['console.log("x")'])
        self.assertIn('script', result['description'])

    # --- Unknown mode fallback ---

    def test_unknown_mode_returns_info_severity(self):
        result = self._call('SomeFutureMode', 'https://example.com/', 'x[y]', ['v'])
        self.assertEqual(result['severity'], 0)
        self.assertEqual(result['source'], 'Second-Order')


def _make_scan_proxy(domain_name='test.example.com'):
    proxy = MagicMock()
    proxy.scan_id = 99
    proxy.activity_id = 1
    proxy.results_dir = tempfile.mkdtemp()
    domain = MagicMock()
    domain.name = domain_name
    proxy.domain = domain
    proxy.scan = MagicMock()
    proxy.subscan = None
    return proxy


class TestSecondOrderScan(TestCase):

    def _run(self, proxy, urls=None, output_files=None):
        from reNgine.tasks.vuln import second_order_scan

        out_dir = os.path.join(proxy.results_dir, 'second_order_out')
        os.makedirs(out_dir, exist_ok=True)
        for fname, content in (output_files or {}).items():
            with open(os.path.join(out_dir, fname), 'w') as fh:
                json.dump(content, fh)

        with patch('reNgine.tasks.vuln.run_command'), \
             patch('reNgine.common_func.save_vulnerability') as mock_save:
            second_order_scan(proxy, urls=urls or [])
            return mock_save

    def test_non200_finding_saved_with_high_severity(self):
        proxy = _make_scan_proxy()
        output = {
            'non-200-url-attributes.json': {
                'LogNon200Queries': {
                    'https://test.example.com/': {
                        'img[src]': ['https://cdn.gone.io/logo.png']
                    }
                }
            }
        }
        mock_save = self._run(proxy, output_files=output)
        self.assertTrue(mock_save.called)
        call_kwargs = mock_save.call_args[1]
        self.assertEqual(call_kwargs['severity'], 3)
        self.assertEqual(call_kwargs['type'], 'Potential Resource Takeover')

    def test_queries_finding_saved_with_info_severity(self):
        proxy = _make_scan_proxy()
        output = {
            'attributes.json': {
                'LogQueries': {
                    'https://test.example.com/': {
                        'script[src]': ['https://cdn.example.com/app.js']
                    }
                }
            }
        }
        mock_save = self._run(proxy, output_files=output)
        call_kwargs = mock_save.call_args[1]
        self.assertEqual(call_kwargs['severity'], 0)

    def test_inline_finding_saved_with_info_severity(self):
        proxy = _make_scan_proxy()
        output = {
            'inline.json': {
                'LogInline': {
                    'https://test.example.com/': {
                        'title': ['Home – Test']
                    }
                }
            }
        }
        mock_save = self._run(proxy, output_files=output)
        call_kwargs = mock_save.call_args[1]
        self.assertEqual(call_kwargs['severity'], 0)
        self.assertEqual(call_kwargs['type'], 'Inline Content Discovered')

    def test_empty_output_saves_nothing(self):
        proxy = _make_scan_proxy()
        output = {
            'attributes.json': {'LogQueries': {}},
            'inline.json': {'LogInline': {}},
            'non-200-url-attributes.json': {'LogNon200Queries': {}},
        }
        mock_save = self._run(proxy, output_files=output)
        mock_save.assert_not_called()

    def test_malformed_json_does_not_raise(self):
        proxy = _make_scan_proxy()
        out_dir = os.path.join(proxy.results_dir, 'second_order_out')
        os.makedirs(out_dir, exist_ok=True)
        with open(os.path.join(out_dir, 'bad.json'), 'w') as fh:
            fh.write('this is not json')

        from reNgine.tasks.vuln import second_order_scan
        with patch('reNgine.tasks.vuln.run_command'), \
             patch('reNgine.common_func.save_vulnerability'):
            second_order_scan(proxy, urls=[])

    def test_embedded_config_written_to_disk(self):
        proxy = _make_scan_proxy()
        config_path = '/usr/local/config/second_order_merged.json'
        with patch('reNgine.tasks.vuln.run_command'), \
             patch('reNgine.common_func.save_vulnerability'):
            from reNgine.tasks.vuln import second_order_scan
            second_order_scan(proxy, urls=[])
        self.assertTrue(os.path.exists(config_path))
        with open(config_path) as fh:
            cfg = json.load(fh)
        self.assertIn('LogNon200Queries', cfg)
        self.assertIn('LogQueries', cfg)
        self.assertIn('LogInline', cfg)


class TestNucleiDastProxyFilter(TestCase):

    def _build_cmd(self, proxy_url):
        from reNgine.tasks.vuln import nuclei_dast_scan

        proxy = _make_scan_proxy()
        proxy.yaml_configuration = {}
        proxy.history_file = os.path.join(proxy.results_dir, 'history.txt')

        captured_cmds = []

        def fake_stream(cmd, **kwargs):
            captured_cmds.append(cmd)
            return iter([])

        with patch('reNgine.tasks.vuln.get_random_proxy', return_value=proxy_url), \
             patch('reNgine.tasks.vuln.stream_command', side_effect=fake_stream), \
             patch('reNgine.tasks.vuln.Proxy') as mock_proxy_cls, \
             patch('reNgine.tasks.vuln.get_http_urls'):
            mock_proxy_obj = MagicMock()
            mock_proxy_obj.use_proxy = True
            mock_proxy_cls.objects.first.return_value = mock_proxy_obj
            input_path = os.path.join(proxy.results_dir, 'input_endpoints_nuclei_dast.txt')
            with open(input_path, 'w') as fh:
                fh.write('https://example.com/\n')
            nuclei_dast_scan(proxy, urls=['https://example.com/'])

        return captured_cmds[0] if captured_cmds else ''

    def test_socks5_proxy_is_used(self):
        cmd = self._build_cmd('socks5://1.2.3.4:1080')
        self.assertIn('-proxy socks5://1.2.3.4:1080', cmd)

    def test_http_proxy_is_used(self):
        cmd = self._build_cmd('http://1.2.3.4:8080')
        self.assertIn('-proxy http://1.2.3.4:8080', cmd)

    def test_socks4_proxy_is_excluded(self):
        cmd = self._build_cmd('socks4://1.2.3.4:1080')
        self.assertNotIn('-proxy', cmd)

    def test_socks4a_proxy_is_excluded(self):
        cmd = self._build_cmd('socks4a://1.2.3.4:1080')
        self.assertNotIn('-proxy', cmd)
