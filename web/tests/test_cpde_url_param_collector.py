"""Tests for CPDE url_param_collector module."""
import json
import os
import tempfile
from django.test import TestCase


class TestCollectFromUrlFiles(TestCase):

    def _write_file(self, dirpath, filename, lines):
        path = os.path.join(dirpath, filename)
        with open(path, 'w') as fh:
            fh.write('\n'.join(lines) + '\n')
        return path

    def test_extracts_query_params_from_katana_file(self):
        from reNgine.cpde.url_param_collector import collect_from_url_files
        with tempfile.TemporaryDirectory() as d:
            self._write_file(d, 'urls_katana.txt', [
                'https://example.com/search?q=test&page=2',
                'https://example.com/api/users?id=5',
            ])
            findings = collect_from_url_files(d)
        names = {f['name'] for f in findings}
        self.assertIn('q', names)
        self.assertIn('page', names)
        self.assertIn('id', names)

    def test_skips_js_urls(self):
        from reNgine.cpde.url_param_collector import collect_from_url_files
        with tempfile.TemporaryDirectory() as d:
            self._write_file(d, 'urls_katana.txt', [
                'https://example.com/app.js?v=3',
                'https://example.com/chunk.mjs?hash=abc',
            ])
            findings = collect_from_url_files(d)
        self.assertEqual(findings, [])

    def test_skips_urls_without_query_string(self):
        from reNgine.cpde.url_param_collector import collect_from_url_files
        with tempfile.TemporaryDirectory() as d:
            self._write_file(d, 'urls_katana.txt', [
                'https://example.com/api/users',
                'https://example.com/about',
            ])
            findings = collect_from_url_files(d)
        self.assertEqual(findings, [])

    def test_reads_multiple_url_files(self):
        from reNgine.cpde.url_param_collector import collect_from_url_files
        with tempfile.TemporaryDirectory() as d:
            self._write_file(d, 'urls_katana.txt', ['https://example.com/?a=1'])
            self._write_file(d, 'urls_gau.txt', ['https://example.com/?b=2'])
            self._write_file(d, 'urls_gospider.txt', ['https://example.com/?c=3'])
            findings = collect_from_url_files(d)
        names = {f['name'] for f in findings}
        self.assertIn('a', names)
        self.assertIn('b', names)
        self.assertIn('c', names)

    def test_empty_dir_returns_empty(self):
        from reNgine.cpde.url_param_collector import collect_from_url_files
        with tempfile.TemporaryDirectory() as d:
            findings = collect_from_url_files(d)
        self.assertEqual(findings, [])

    def test_context_contains_tool_name(self):
        from reNgine.cpde.url_param_collector import collect_from_url_files
        with tempfile.TemporaryDirectory() as d:
            self._write_file(d, 'urls_gau.txt', ['https://example.com/?x=1'])
            findings = collect_from_url_files(d)
        self.assertTrue(any('gau' in f['context'] for f in findings))

    def test_confidence_is_50(self):
        from reNgine.cpde.url_param_collector import collect_from_url_files
        with tempfile.TemporaryDirectory() as d:
            self._write_file(d, 'urls_katana.txt', ['https://example.com/?x=1'])
            findings = collect_from_url_files(d)
        self.assertEqual(findings[0]['confidence'], 50)

    def test_skips_static_asset_extensions(self):
        from reNgine.cpde.url_param_collector import collect_from_url_files
        with tempfile.TemporaryDirectory() as d:
            self._write_file(d, 'urls_katana.txt', [
                'https://example.com/logo.png?v=2',
                'https://example.com/style.css?ver=1.2',
                'https://example.com/font.woff2?v=3',
            ])
            findings = collect_from_url_files(d)
        self.assertEqual(findings, [])


class TestCollectFromArjunFiles(TestCase):

    def _write_arjun(self, dirpath, name, data):
        path = os.path.join(dirpath, f'arjun_{name}.json')
        with open(path, 'w') as fh:
            json.dump(data, fh)

    def test_extracts_params_dict_format(self):
        from reNgine.cpde.url_param_collector import collect_from_arjun_files
        with tempfile.TemporaryDirectory() as d:
            self._write_arjun(d, 'example.com', {
                'https://example.com/login': {
                    'params': {'GET': ['redirect'], 'POST': ['username', 'password']}
                }
            })
            findings = collect_from_arjun_files(d)
        names = {f['name'] for f in findings}
        self.assertIn('redirect', names)
        self.assertIn('username', names)
        self.assertIn('password', names)

    def test_extracts_params_list_format(self):
        from reNgine.cpde.url_param_collector import collect_from_arjun_files
        with tempfile.TemporaryDirectory() as d:
            self._write_arjun(d, 'example.com', {
                'https://example.com/search': {
                    'method': 'GET',
                    'params': ['q', 'page', 'per_page']
                }
            })
            findings = collect_from_arjun_files(d)
        names = {f['name'] for f in findings}
        self.assertIn('q', names)
        self.assertIn('page', names)

    def test_confidence_is_75(self):
        from reNgine.cpde.url_param_collector import collect_from_arjun_files
        with tempfile.TemporaryDirectory() as d:
            self._write_arjun(d, 'example.com', {
                'https://example.com/api': {'params': {'GET': ['id']}}
            })
            findings = collect_from_arjun_files(d)
        self.assertEqual(findings[0]['confidence'], 75)

    def test_corrupt_json_handled_gracefully(self):
        from reNgine.cpde.url_param_collector import collect_from_arjun_files
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'arjun_bad.json')
            with open(path, 'w') as fh:
                fh.write('{not valid json')
            findings = collect_from_arjun_files(d)
        self.assertEqual(findings, [])

    def test_get_method_sets_query_string_location(self):
        from reNgine.cpde.url_param_collector import collect_from_arjun_files
        with tempfile.TemporaryDirectory() as d:
            self._write_arjun(d, 'example.com', {
                'https://example.com/api': {'params': {'GET': ['id']}}
            })
            findings = collect_from_arjun_files(d)
        self.assertEqual(findings[0]['location'], 'query_string')

    def test_post_method_sets_form_data_location(self):
        from reNgine.cpde.url_param_collector import collect_from_arjun_files
        with tempfile.TemporaryDirectory() as d:
            self._write_arjun(d, 'example.com', {
                'https://example.com/api': {'params': {'POST': ['username']}}
            })
            findings = collect_from_arjun_files(d)
        self.assertEqual(findings[0]['location'], 'form_data')


class TestCollectFromParamSpiderFiles(TestCase):

    def test_extracts_query_params(self):
        from reNgine.cpde.url_param_collector import collect_from_paramspider_files
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'ps_example.com.txt')
            with open(path, 'w') as fh:
                fh.write('https://example.com/search?q=FUZZ&page=FUZZ\n')
                fh.write('https://example.com/api?id=FUZZ&sort=FUZZ\n')
            findings = collect_from_paramspider_files(d)
        names = {f['name'] for f in findings}
        self.assertIn('q', names)
        self.assertIn('page', names)
        self.assertIn('id', names)
        self.assertIn('sort', names)

    def test_confidence_is_55(self):
        from reNgine.cpde.url_param_collector import collect_from_paramspider_files
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'ps_example.com.txt')
            with open(path, 'w') as fh:
                fh.write('https://example.com/?x=FUZZ\n')
            findings = collect_from_paramspider_files(d)
        self.assertEqual(findings[0]['confidence'], 55)

    def test_non_url_lines_skipped(self):
        from reNgine.cpde.url_param_collector import collect_from_paramspider_files
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'ps_example.com.txt')
            with open(path, 'w') as fh:
                fh.write('[*] Running ParamSpider...\n')
                fh.write('https://example.com/?real=FUZZ\n')
            findings = collect_from_paramspider_files(d)
        names = {f['name'] for f in findings}
        self.assertIn('real', names)
        self.assertEqual(len([f for f in findings if 'Running' in f['name']]), 0)


class TestCollectFromKiterunnerFiles(TestCase):

    def test_extracts_params_from_path_with_query(self):
        from reNgine.cpde.url_param_collector import collect_from_kiterunner_files
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'kr_example.com.json')
            with open(path, 'w') as fh:
                fh.write(json.dumps({'path': '/api/users?include=profile&expand=roles', 'responses': [{'sc': 200}]}) + '\n')
                fh.write(json.dumps({'path': '/api/items', 'responses': [{'sc': 200}]}) + '\n')
            findings = collect_from_kiterunner_files(d)
        names = {f['name'] for f in findings}
        self.assertIn('include', names)
        self.assertIn('expand', names)
        self.assertNotIn('', names)

    def test_paths_without_query_produce_no_findings(self):
        from reNgine.cpde.url_param_collector import collect_from_kiterunner_files
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'kr_example.com.json')
            with open(path, 'w') as fh:
                fh.write(json.dumps({'path': '/api/users', 'responses': [{'sc': 200}]}) + '\n')
            findings = collect_from_kiterunner_files(d)
        self.assertEqual(findings, [])

    def test_confidence_is_65(self):
        from reNgine.cpde.url_param_collector import collect_from_kiterunner_files
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'kr_example.com.json')
            with open(path, 'w') as fh:
                fh.write(json.dumps({'path': '/api?x=1', 'responses': [{'sc': 200}]}) + '\n')
            findings = collect_from_kiterunner_files(d)
        self.assertEqual(findings[0]['confidence'], 65)


class TestCollectFromLinkfinderFiles(TestCase):

    def test_extracts_params_from_urls(self):
        from reNgine.cpde.url_param_collector import collect_from_linkfinder_files
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'lf_example.com.txt')
            with open(path, 'w') as fh:
                fh.write('/api/v1/users?id=FUZZ&role=admin\n')
                fh.write('https://example.com/search?q=test\n')
                fh.write('/static/bundle.js\n')
            findings = collect_from_linkfinder_files(d)
        names = {f['name'] for f in findings}
        self.assertIn('id', names)
        self.assertIn('role', names)
        self.assertIn('q', names)

    def test_confidence_is_60(self):
        from reNgine.cpde.url_param_collector import collect_from_linkfinder_files
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'lf_example.com.txt')
            with open(path, 'w') as fh:
                fh.write('/api?x=1\n')
            findings = collect_from_linkfinder_files(d)
        self.assertEqual(findings[0]['confidence'], 60)


class TestCollectAll(TestCase):

    def test_aggregates_all_sources(self):
        from reNgine.cpde.url_param_collector import collect_all
        with tempfile.TemporaryDirectory() as d:
            # URL file
            with open(os.path.join(d, 'urls_katana.txt'), 'w') as fh:
                fh.write('https://example.com/?url_param=1\n')
            # Arjun
            with open(os.path.join(d, 'arjun_example.com.json'), 'w') as fh:
                json.dump({'https://example.com/api': {'params': {'GET': ['arjun_param']}}}, fh)
            # ParamSpider
            with open(os.path.join(d, 'ps_example.com.txt'), 'w') as fh:
                fh.write('https://example.com/?ps_param=FUZZ\n')
            findings = collect_all(d)
        names = {f['name'] for f in findings}
        self.assertIn('url_param', names)
        self.assertIn('arjun_param', names)
        self.assertIn('ps_param', names)

    def test_empty_dir_returns_empty_list(self):
        from reNgine.cpde.url_param_collector import collect_all
        with tempfile.TemporaryDirectory() as d:
            findings = collect_all(d)
        self.assertEqual(findings, [])
