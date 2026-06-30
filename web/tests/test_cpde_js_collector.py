"""Tests for CPDE js_collector module."""
import os
import tempfile
from django.test import TestCase


class TestGetJsUrlsFromResultsDir(TestCase):

    def _write(self, dirpath, filename, lines):
        path = os.path.join(dirpath, filename)
        with open(path, 'w') as fh:
            fh.write('\n'.join(lines) + '\n')

    def test_reads_katana_file(self):
        from reNgine.cpde.js_collector import get_js_urls_from_results_dir
        with tempfile.TemporaryDirectory() as d:
            self._write(d, 'urls_katana.txt', [
                'https://example.com/app.js',
                'https://example.com/page.html',
            ])
            urls = get_js_urls_from_results_dir(d)
        self.assertIn('https://example.com/app.js', urls)
        self.assertNotIn('https://example.com/page.html', urls)

    def test_reads_non_katana_tool_files(self):
        """JS URLs in gau/gospider files must be collected."""
        from reNgine.cpde.js_collector import get_js_urls_from_results_dir
        with tempfile.TemporaryDirectory() as d:
            self._write(d, 'urls_gau.txt', [
                'https://example.com/bundle.min.js',
            ])
            self._write(d, 'urls_gospider.txt', [
                'https://example.com/vendor.js',
            ])
            urls = get_js_urls_from_results_dir(d)
        self.assertIn('https://example.com/bundle.min.js', urls)
        self.assertIn('https://example.com/vendor.js', urls)

    def test_matches_js_ver_query_string(self):
        """.js?ver=x URLs (e.g. WordPress assets) must be collected."""
        from reNgine.cpde.js_collector import get_js_urls_from_results_dir
        with tempfile.TemporaryDirectory() as d:
            self._write(d, 'urls_waybackurls.txt', [
                'https://example.com/wp-includes/js/jquery.min.js?ver=3.6.0',
                'https://example.com/bundle.min.js',
            ])
            urls = get_js_urls_from_results_dir(d)
        self.assertIn('https://example.com/wp-includes/js/jquery.min.js?ver=3.6.0', urls)
        self.assertIn('https://example.com/bundle.min.js', urls)

    def test_deduplicates_across_files(self):
        from reNgine.cpde.js_collector import get_js_urls_from_results_dir
        with tempfile.TemporaryDirectory() as d:
            self._write(d, 'urls_katana.txt', ['https://example.com/app.js'])
            self._write(d, 'urls_gau.txt',    ['https://example.com/app.js'])
            urls = get_js_urls_from_results_dir(d)
        self.assertEqual(urls.count('https://example.com/app.js'), 1)

    def test_empty_results_dir_returns_empty_list(self):
        from reNgine.cpde.js_collector import get_js_urls_from_results_dir
        with tempfile.TemporaryDirectory() as d:
            urls = get_js_urls_from_results_dir(d)
        self.assertEqual(urls, [])

    def test_skips_non_js_urls(self):
        from reNgine.cpde.js_collector import get_js_urls_from_results_dir
        with tempfile.TemporaryDirectory() as d:
            self._write(d, 'urls_katana.txt', [
                'https://example.com/page.html',
                'https://example.com/style.css',
                'https://example.com/image.png',
            ])
            urls = get_js_urls_from_results_dir(d)
        self.assertEqual(urls, [])
