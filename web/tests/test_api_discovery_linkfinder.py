"""LinkFinder in web_api_discovery: scope, parsing, JS downloads and the output file."""
import hashlib
import itertools
import os
import tempfile
import unittest
from unittest.mock import MagicMock, patch

import requests
import urllib3

from reNgine.tasks.crawl.api_discovery import (
    _LINKFINDER_FETCH_BUDGET,
    _LINKFINDER_FETCH_DEADLINE,
    _LINKFINDER_MAX_JS_BYTES,
    _fetch_js_file,
    _linkfinder_url,
    _run_linkfinder,
    _save_linkfinder_results,
)

MODULE = 'reNgine.tasks.crawl.api_discovery'

BASE = 'https://app.example.test/'
SCOPE = 'example.test'


class LinkFinderUrlTests(unittest.TestCase):

    def test_absolute_path_resolves_against_the_page(self) -> None:
        self.assertEqual(_linkfinder_url('/api/users?id=1', BASE, SCOPE), 'https://app.example.test/api/users?id=1')

    def test_protocol_relative_url_takes_the_page_scheme(self) -> None:
        self.assertEqual(_linkfinder_url('//cdn.example.test/x.json', BASE, SCOPE), 'https://cdn.example.test/x.json')

    def test_relative_api_path_is_kept(self) -> None:
        self.assertEqual(_linkfinder_url('api/v2/orders', BASE, SCOPE), 'https://app.example.test/api/v2/orders')
        self.assertEqual(_linkfinder_url('./login.php', BASE, SCOPE), 'https://app.example.test/login.php')

    def test_noise_is_dropped(self) -> None:
        for line in ('application/json', 'text/html', 'dd/mm/yyyy', 'and/or', 'Usage: linkfinder.py', ''):
            with self.subTest(line=line):
                self.assertIsNone(_linkfinder_url(line, BASE, SCOPE))

    def test_other_domains_are_dropped(self) -> None:
        for line in ('https://cdn.vendor.test/lib.js', 'https://example.test.attacker.test/x', 'https://notexample.test/'):
            with self.subTest(line=line):
                self.assertIsNone(_linkfinder_url(line, BASE, SCOPE))

    def test_scope_is_the_scanned_domain_not_its_parent(self) -> None:
        # Scanning the apex must not put every host under its TLD in scope.
        self.assertIsNone(_linkfinder_url('https://other.test/', 'https://example.test/', SCOPE))
        self.assertEqual(_linkfinder_url('https://example.test/a', 'https://example.test/', SCOPE), 'https://example.test/a')

    def test_nothing_is_in_scope_without_a_domain(self) -> None:
        self.assertIsNone(_linkfinder_url('/api', BASE, ''))

    def test_malformed_host_is_noise(self) -> None:
        # urlparse raises ValueError on these; one bad line must not abort the file.
        for line in ('http://[x/', 'https://[::1/api', '//[bad/x.json'):
            with self.subTest(line=line):
                self.assertIsNone(_linkfinder_url(line, BASE, SCOPE))

    def test_malformed_base_url_is_noise(self) -> None:
        self.assertIsNone(_linkfinder_url('/api', 'http://[x/', SCOPE))

    def test_result_maps_to_itself(self) -> None:
        # lf_output holds these results and is read back through the same function.
        for line in ('/api/users?id=1', '//cdn.example.test/x.json', 'api/v2/orders', 'https://example.test/a'):
            with self.subTest(line=line):
                url = _linkfinder_url(line, BASE, SCOPE)
                self.assertEqual(_linkfinder_url(url, BASE, SCOPE), url)


@patch('reNgine.tasks.crawl.api_discovery.save_parameter')
@patch('reNgine.tasks.crawl.api_discovery.save_endpoint')
@patch('reNgine.tasks.crawl.api_discovery.save_subdomain')
class SaveLinkFinderResultsTests(unittest.TestCase):

    def _run(self, lines: list[str], subdomain) -> tuple[int, int, int]:
        with tempfile.TemporaryDirectory() as d:
            path = os.path.join(d, 'lf_app.example.test.txt')
            with open(path, 'w') as fh:
                fh.write('\n'.join(lines) + '\n')
            return _save_linkfinder_results(path, BASE, SCOPE, subdomain, ctx={'scan_history_id': 1})

    def test_new_in_scope_host_is_added_and_owns_its_endpoint(self, mock_sub, mock_ep, mock_param) -> None:
        page_sub = MagicMock()
        page_sub.name = 'app.example.test'
        new_sub = MagicMock()
        mock_sub.return_value = (new_sub, True)
        mock_ep.return_value = (MagicMock(), True)

        counts = self._run(['https://jenkins.example.test/job', '/api?id=1'], page_sub)

        mock_sub.assert_called_once_with('jenkins.example.test', ctx={'scan_history_id': 1})
        self.assertIs(mock_ep.call_args_list[0].kwargs['subdomain'], new_sub)
        self.assertIs(mock_ep.call_args_list[1].kwargs['subdomain'], page_sub)
        self.assertEqual(counts, (2, 1, 1))

    def test_out_of_scope_host_rejected_by_save_subdomain_saves_nothing(self, mock_sub, mock_ep, mock_param) -> None:
        mock_sub.return_value = (None, False)

        counts = self._run(['https://blocked.example.test/a', 'https://blocked.example.test/b'], None)

        mock_sub.assert_called_once()
        mock_ep.assert_not_called()
        self.assertEqual(counts, (0, 0, 0))

    def test_duplicates_and_foreign_hosts_are_skipped(self, mock_sub, mock_ep, mock_param) -> None:
        page_sub = MagicMock()
        page_sub.name = 'app.example.test'
        mock_ep.return_value = (None, False)

        self._run(['/a?x=1', '/a?x=1', 'https://s3.amazonaws.test/bucket'], page_sub)

        mock_sub.assert_not_called()
        mock_ep.assert_called_once()
        mock_param.assert_not_called()


def _response(status: int = 200, chunks=()) -> MagicMock:
    """A streamed response whose raw.read1 returns each chunk, then b'' at the end like urllib3 2."""
    resp = MagicMock()
    resp.__enter__.return_value = resp
    resp.status_code = status
    remaining = iter(chunks)
    resp.raw.read1.side_effect = lambda *args, **kwargs: next(remaining, b'')
    return resp


@patch(f'{MODULE}.time')
@patch(f'{MODULE}.requests.get')
class FetchJsFileTests(unittest.TestCase):

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.dest = os.path.join(self._tmp.name, 'js_0123.js')

    def _assert_nothing_written(self) -> None:
        self.assertFalse(os.path.exists(self.dest))
        self.assertFalse(os.path.exists(f'{self.dest}.part'))

    def test_success_renames_the_part_file(self, mock_get, mock_time) -> None:
        mock_time.monotonic.return_value = 0
        mock_get.return_value = _response(chunks=[b'fetch("/api/a");', b'x'])

        self.assertTrue(_fetch_js_file('https://app.example.test/a.js', self.dest, None))

        with open(self.dest, 'rb') as fh:
            self.assertEqual(fh.read(), b'fetch("/api/a");x')
        self.assertFalse(os.path.exists(f'{self.dest}.part'))

    def test_size_cap_is_honoured(self, mock_get, mock_time) -> None:
        mock_time.monotonic.return_value = 0
        mock_get.return_value = _response(chunks=[b'a' * 300_000, b'b' * 300_000, b'c' * 300_000])

        self.assertTrue(_fetch_js_file('https://app.example.test/big.js', self.dest, None))

        self.assertEqual(os.path.getsize(self.dest), _LINKFINDER_MAX_JS_BYTES)

    def test_non_200_writes_nothing(self, mock_get, mock_time) -> None:
        mock_time.monotonic.return_value = 0
        mock_get.return_value = _response(status=403, chunks=[b'denied'])

        self.assertFalse(_fetch_js_file('https://app.example.test/a.js', self.dest, None))
        self._assert_nothing_written()

    def test_empty_body_writes_nothing(self, mock_get, mock_time) -> None:
        mock_time.monotonic.return_value = 0
        mock_get.return_value = _response(chunks=[])

        self.assertFalse(_fetch_js_file('https://app.example.test/a.js', self.dest, None))
        self._assert_nothing_written()

    def test_non_http_scheme_is_rejected_without_a_request(self, mock_get, mock_time) -> None:
        for url in ('file:///etc/passwd', 'ftp://app.example.test/a.js', 'javascript:alert(1)', 'http://[x/'):
            with self.subTest(url=url):
                self.assertFalse(_fetch_js_file(url, self.dest, None))
        mock_get.assert_not_called()
        self._assert_nothing_written()

    def test_request_exception_returns_false(self, mock_get, mock_time) -> None:
        mock_time.monotonic.return_value = 0
        mock_get.side_effect = requests.ConnectionError('refused')

        self.assertFalse(_fetch_js_file('https://app.example.test/a.js', self.dest, None))
        self._assert_nothing_written()

    def test_error_mid_stream_leaves_no_part_file(self, mock_get, mock_time) -> None:
        mock_time.monotonic.return_value = 0

        def chunks():
            yield b'partial'
            raise urllib3.exceptions.ProtocolError('Connection broken')

        mock_get.return_value = _response(chunks=chunks())

        self.assertFalse(_fetch_js_file('https://app.example.test/a.js', self.dest, None))
        self._assert_nothing_written()

    def test_urllib3_without_read1_falls_back_to_iter_content(self, mock_get, mock_time) -> None:
        mock_time.monotonic.return_value = 0
        resp = _response()
        resp.raw = MagicMock(spec=[])
        resp.iter_content.return_value = iter([b'var a = "/api/x";'])
        mock_get.return_value = resp

        self.assertTrue(_fetch_js_file('https://app.example.test/a.js', self.dest, None))

        with open(self.dest, 'rb') as fh:
            self.assertEqual(fh.read(), b'var a = "/api/x";')

    def test_deadline_stops_a_trickling_download(self, mock_get, mock_time) -> None:
        # Start at 0, then one clock reading per chunk: 10, 20, 30 reaches the deadline.
        mock_time.monotonic.side_effect = itertools.count(0, 10)
        endless = itertools.repeat(b'x')
        mock_get.return_value = _response(chunks=endless)

        with self.assertLogs(MODULE, level='WARNING') as logs:
            self.assertTrue(_fetch_js_file('https://app.example.test/slow.js', self.dest, None, max_seconds=30))

        self.assertEqual(os.path.getsize(self.dest), 3)
        self.assertIn('cut off', '\n'.join(logs.output))


@patch(f'{MODULE}.get_random_proxy', return_value=None)
@patch(f'{MODULE}._fetch_js_file')
@patch(f'{MODULE}.EndPoint')
@patch(f'{MODULE}.run_command')
class RunLinkFinderTests(unittest.TestCase):

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.scan_root = self._tmp.name
        self.results_dir = os.path.join(self.scan_root, 'web_api_discovery')
        os.makedirs(self.results_dir)
        self.lf_output = os.path.join(self.results_dir, 'lf_app.example.test.txt')
        self.task = MagicMock(results_dir=self.scan_root, scan_id=1, activity_id=None)
        self.fetched: list[str] = []

    def _known_js(self, mock_endpoint, urls: list[str]) -> None:
        qs = mock_endpoint.objects.filter.return_value.filter.return_value
        qs.values_list.return_value.distinct.return_value = urls

    def _tool_prints(self, *outputs: list[str]):
        """run_command side effect: each call appends one LinkFinder output to the .part file."""
        outputs_iter = iter(outputs)

        def run(cmd, **kwargs):
            with open(f'{self.lf_output}.part', 'a') as fh:
                fh.write(''.join(f'{line}\n' for line in next(outputs_iter, [])))
            return 0, ''
        return run

    def _fetch_ok(self, js_url: str, dest: str, proxy, max_seconds: float) -> bool:
        self.fetched.append(dest)
        with open(dest, 'w') as fh:
            fh.write('// js')
        return True

    def test_output_holds_only_deduplicated_in_scope_urls(self, mock_run, mock_endpoint, mock_fetch, _proxy) -> None:
        self._known_js(mock_endpoint, ['https://app.example.test/static/app.js'])
        mock_fetch.side_effect = self._fetch_ok
        mock_run.side_effect = self._tool_prints(
            ['Running against: https://app.example.test/', '', '/api/users?id=1', 'application/json',
             'https://www.google-analytics.test/collect?tid=UA-1', 'dd/mm/yyyy', 'http://[x/'],
            ['/api/users?id=1', 'https://app.example.test/api/users?id=1', '//cdn.example.test/cfg.json',
             'https://tracker.vendor.test/p?uid=1', 'api/v2/orders'],
        )

        _run_linkfinder(self.task, BASE, MagicMock(), self.results_dir, self.lf_output, SCOPE)

        with open(self.lf_output) as fh:
            self.assertEqual(fh.read().splitlines(), [
                'https://app.example.test/api/users?id=1',
                'https://cdn.example.test/cfg.json',
                'https://app.example.test/api/v2/orders',
            ])
        self.assertFalse(os.path.exists(f'{self.lf_output}.part'))
        self.assertEqual(mock_run.call_count, 2)

    def test_js_files_land_outside_web_api_discovery(self, mock_run, mock_endpoint, mock_fetch, _proxy) -> None:
        self._known_js(mock_endpoint, ['https://app.example.test/a.js', 'https://app.example.test/b.js?v=2'])
        mock_fetch.side_effect = self._fetch_ok
        mock_run.side_effect = self._tool_prints()

        _run_linkfinder(self.task, BASE, MagicMock(), self.results_dir, self.lf_output, SCOPE)

        self.assertEqual(len(self.fetched), 2)
        js_dir = os.path.join(self.scan_root, 'linkfinder_js')
        for dest in self.fetched:
            self.assertEqual(os.path.dirname(dest), js_dir)
            self.assertRegex(os.path.basename(dest), r'^js_[0-9a-f]{16}\.js$')
        self.assertEqual([n for n in os.listdir(self.results_dir) if n.endswith('.js')], [])
        self.assertTrue(any(self.fetched[0] in c.args[0] for c in mock_run.call_args_list))

    def test_empty_run_still_writes_the_retry_guard(self, mock_run, mock_endpoint, mock_fetch, _proxy) -> None:
        self._known_js(mock_endpoint, [])
        mock_run.return_value = (0, '')

        _run_linkfinder(self.task, BASE, MagicMock(), self.results_dir, self.lf_output, SCOPE)

        self.assertTrue(os.path.exists(self.lf_output))
        self.assertEqual(os.path.getsize(self.lf_output), 0)

    @patch(f'{MODULE}.time')
    def test_budget_stops_further_downloads(self, mock_time, mock_run, mock_endpoint, mock_fetch, _proxy) -> None:
        urls = [f'https://app.example.test/{n}.js' for n in range(4)]
        self._known_js(mock_endpoint, urls)
        # Budget starts at 0; the checks before files 0, 1 and 2 read 0, 20 s
        # before the budget ends (so file 1 gets only those 20 s) and past it.
        mock_time.monotonic.side_effect = [0, 0, _LINKFINDER_FETCH_BUDGET - 20, _LINKFINDER_FETCH_BUDGET + 1]
        mock_fetch.side_effect = self._fetch_ok
        mock_run.side_effect = self._tool_prints()
        # A file kept by an earlier attempt is still read once the budget is spent.
        js_dir = os.path.join(self.scan_root, 'linkfinder_js')
        os.makedirs(js_dir)
        cached = os.path.join(js_dir, f'js_{hashlib.sha256(urls[3].encode()).hexdigest()[:16]}.js')
        with open(cached, 'w') as fh:
            fh.write('// cached')

        with self.assertLogs(MODULE, level='WARNING') as logs:
            _run_linkfinder(self.task, BASE, MagicMock(), self.results_dir, self.lf_output, SCOPE)

        self.assertEqual(mock_fetch.call_count, 2)
        self.assertEqual(mock_fetch.call_args_list[0].args[3], _LINKFINDER_FETCH_DEADLINE)
        self.assertEqual(mock_fetch.call_args_list[1].args[3], 20)
        self.assertIn('budget', '\n'.join(logs.output))
        # Root page, the two fetched files and the cached one.
        self.assertEqual(mock_run.call_count, 4)
        self.assertIn(cached, mock_run.call_args_list[-1].args[0])
        self.assertTrue(os.path.exists(self.lf_output))
