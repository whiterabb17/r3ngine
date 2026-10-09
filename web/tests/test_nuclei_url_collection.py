"""Tests for collect_all_scan_urls() in reNgine/common_func/db_queries.py."""
import os
import tempfile

from django.test import TestCase
from unittest.mock import patch

from reNgine.common_func import collect_all_scan_urls


class CollectAllScanUrlsTests(TestCase):
    """Unit tests for collect_all_scan_urls()."""

    def _make_ctx(self, scan_id=None, domain_id=None):
        return {'scan_history_id': scan_id, 'domain_id': domain_id}

    def _write_file(self, directory, filename, urls):
        path = os.path.join(directory, filename)
        with open(path, 'w') as fh:
            fh.write('\n'.join(urls))
        return path

    # ------------------------------------------------------------------
    # Test 1: Only DB endpoints, no result files
    # ------------------------------------------------------------------
    @patch('reNgine.common_func.db_queries.get_http_urls')
    def test_returns_db_urls_when_no_files(self, mock_get_http):
        mock_get_http.return_value = [
            'https://example.com/page1',
            'https://example.com/page2',
        ]
        result = collect_all_scan_urls(
            ctx=self._make_ctx(),
            results_dir='/nonexistent_dir_xyz',
        )
        self.assertEqual(result, [
            'https://example.com/page1',
            'https://example.com/page2',
        ])

    # ------------------------------------------------------------------
    # Test 2: Only file URLs, no DB endpoints
    # ------------------------------------------------------------------
    @patch('reNgine.common_func.db_queries.get_http_urls')
    def test_returns_file_urls_when_no_db(self, mock_get_http):
        mock_get_http.return_value = []
        with tempfile.TemporaryDirectory() as tmpdir:
            self._write_file(tmpdir, 'fetch_url.txt', [
                'https://example.com/from-file',
                'https://example.com/also-from-file',
            ])
            result = collect_all_scan_urls(
                ctx=self._make_ctx(),
                results_dir=tmpdir,
                ignore_files=False,
            )
        self.assertIn('https://example.com/from-file', result)
        self.assertIn('https://example.com/also-from-file', result)

    # ------------------------------------------------------------------
    # Test 3: Deduplication — same URL in DB and file appears once
    # ------------------------------------------------------------------
    @patch('reNgine.common_func.db_queries.get_http_urls')
    def test_deduplicates_across_sources(self, mock_get_http):
        mock_get_http.return_value = ['https://example.com/dup']
        with tempfile.TemporaryDirectory() as tmpdir:
            self._write_file(tmpdir, 'fetch_url.txt', [
                'https://example.com/dup',
                'https://example.com/unique',
            ])
            result = collect_all_scan_urls(
                ctx=self._make_ctx(),
                results_dir=tmpdir,
                ignore_files=False,
            )
        self.assertEqual(result.count('https://example.com/dup'), 1)
        self.assertIn('https://example.com/unique', result)

    # ------------------------------------------------------------------
    # Test 4: Reads urls_*.txt wildcard files and deduplicates across them
    # ------------------------------------------------------------------
    @patch('reNgine.common_func.db_queries.get_http_urls')
    def test_reads_urls_wildcard_files(self, mock_get_http):
        mock_get_http.return_value = []
        with tempfile.TemporaryDirectory() as tmpdir:
            self._write_file(tmpdir, 'urls_katana.txt', ['https://example.com/katana'])
            self._write_file(tmpdir, 'urls_gau.txt', ['https://example.com/gau'])
            # Same URL in two files — should appear once
            self._write_file(tmpdir, 'urls_gospider.txt', ['https://example.com/katana'])
            result = collect_all_scan_urls(
                ctx=self._make_ctx(),
                results_dir=tmpdir,
                ignore_files=False,
            )
        self.assertIn('https://example.com/katana', result)
        self.assertIn('https://example.com/gau', result)
        self.assertEqual(result.count('https://example.com/katana'), 1)

    # ------------------------------------------------------------------
    # Test 5: Invalid / non-HTTP URLs are excluded
    # ------------------------------------------------------------------
    @patch('reNgine.common_func.db_queries.get_http_urls')
    def test_excludes_invalid_urls(self, mock_get_http):
        mock_get_http.return_value = []
        with tempfile.TemporaryDirectory() as tmpdir:
            self._write_file(tmpdir, 'fetch_url.txt', [
                'not-a-url',
                '',
                'ftp://example.com/file',
                'https://example.com/valid',
            ])
            result = collect_all_scan_urls(
                ctx=self._make_ctx(),
                results_dir=tmpdir,
                ignore_files=False,
            )
        self.assertEqual(result, ['https://example.com/valid'])

    # ------------------------------------------------------------------
    # Test 6: Unreadable file is skipped gracefully (no exception raised)
    # ------------------------------------------------------------------
    @patch('reNgine.common_func.db_queries.get_http_urls')
    def test_gracefully_skips_unreadable_file(self, mock_get_http):
        mock_get_http.return_value = ['https://example.com/db']
        with tempfile.TemporaryDirectory() as tmpdir:
            path = os.path.join(tmpdir, 'fetch_url.txt')
            with open(path, 'w') as fh:
                fh.write('https://example.com/file\n')
            os.chmod(path, 0o000)
            try:
                result = collect_all_scan_urls(
                    ctx=self._make_ctx(),
                    results_dir=tmpdir,
                    ignore_files=False,
                )
                self.assertIn('https://example.com/db', result)
            finally:
                os.chmod(path, 0o644)

    # ------------------------------------------------------------------
    # Test 7: Result is always sorted
    # ------------------------------------------------------------------
    @patch('reNgine.common_func.db_queries.get_http_urls')
    def test_result_is_sorted(self, mock_get_http):
        mock_get_http.return_value = ['https://example.com/z', 'https://example.com/a']
        with tempfile.TemporaryDirectory() as tmpdir:
            self._write_file(tmpdir, 'fetch_url.txt', ['https://example.com/m'])
            result = collect_all_scan_urls(
                ctx=self._make_ctx(),
                results_dir=tmpdir,
                ignore_files=False,
            )
        self.assertEqual(result, sorted(result))
