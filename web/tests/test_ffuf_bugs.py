"""
Tests for ffuf rate-limiting bugs:
  Bug #1 — fuzzing_tasks.py used -p (per-thread delay) instead of -rate N
  Bug #2 — opsec.py _apply_ffuf appended a second -p flag
"""
import types
from unittest.mock import MagicMock, patch

from django.test import TestCase

from reNgine.tasks.fuzzing import dir_file_fuzz


# ---------------------------------------------------------------------------
# Shared helpers
# ---------------------------------------------------------------------------

def _make_proxy(yaml_config=None):
    """Minimal scan proxy for prepare_only=True tests."""
    proxy = types.SimpleNamespace(
        yaml_configuration=yaml_config or {},
        results_dir='/tmp/test_ffuf',
        scan=MagicMock(),
        scan_id=1,
        activity_id=1,
        history_file='/tmp/test_ffuf_history.txt',
        subscan=None,
    )
    return proxy


def _prepare(yaml_config, ctx_override=None):
    """Call dir_file_fuzz with prepare_only=True, returning the built command dict."""
    proxy = _make_proxy(yaml_config)
    ctx = {"urls_override": ctx_override or ["http://example.com/"]}

    def _fake_ensure(task_proxy, func, ctx, description=None):
        return func(ctx=ctx, description=description)

    with patch('reNgine.tasks.fuzzing.ensure_endpoints_crawled_and_execute',
               side_effect=_fake_ensure), \
         patch('os.path.exists', return_value=True), \
         patch('reNgine.api_tasks.resolve_wordlist_path',
               side_effect=lambda cfg, path: path):
        return dir_file_fuzz(proxy, ctx=ctx, prepare_only=True)


# ---------------------------------------------------------------------------
# Test class
# ---------------------------------------------------------------------------

class TestFfufRateLimiting(TestCase):
    """Bug #1 + #2: rate limiting uses -p (wrong) instead of -rate (correct)."""

    BASE_CONFIG = {
        'dir_file_fuzz': {
            'auto_calibration': False,
            'rate_limit': 150,
            'threads': 30,
            'wordlist_name': 'dicc',
            'extensions': [],
            'match_http_status': [200],
            'recursive_level': 0,
            'max_time': 0,
            'stop_on_error': False,
            'follow_redirect': False,
            'timeout': 10,
        }
    }

    def test_ffuf_base_cmd_uses_rate_flag(self):
        result = _prepare(self.BASE_CONFIG)
        self.assertIsNotNone(result, "_prepare() must return a dict, not None")
        self.assertIn('ffuf_base_cmd', result, "prepare_only=True must return ffuf_base_cmd key")
        cmd = result['ffuf_base_cmd']
        self.assertIn('-rate 150', cmd,
                      "ffuf base command must use -rate, not -p")

    def test_ffuf_base_cmd_no_p_flag(self):
        result = _prepare(self.BASE_CONFIG)
        self.assertIsNotNone(result, "_prepare() must return a dict, not None")
        self.assertIn('ffuf_base_cmd', result, "prepare_only=True must return ffuf_base_cmd key")
        cmd = result['ffuf_base_cmd']
        self.assertNotIn(' -p ', cmd,
                         f"ffuf command must not contain -p flag, got: {cmd}")
        self.assertFalse(cmd.endswith(' -p'),
                         f"ffuf command must not end with -p flag, got: {cmd}")

    def test_opsec_apply_ffuf_uses_rate_not_p(self):
        from reNgine.utils.opsec import OpSecManager
        opsec = OpSecManager.__new__(OpSecManager)
        opsec.settings = MagicMock()
        opsec.settings.enable_random_ua = False
        opsec.settings.enable_rate_limit = True
        opsec.settings.max_rps = 150
        opsec.get_random_ua = MagicMock(return_value='UA')

        cmd = 'ffuf -w /usr/src/wordlist/dicc.txt -u http://example.com/FUZZ -json'
        result = opsec._apply_ffuf(cmd)
        self.assertIn('-rate 150', result)
        self.assertNotIn(' -p ', result)

    def test_opsec_apply_ffuf_no_duplicate_rate(self):
        """If -rate already exists in cmd, opsec must not add a second one."""
        from reNgine.utils.opsec import OpSecManager
        opsec = OpSecManager.__new__(OpSecManager)
        opsec.settings = MagicMock()
        opsec.settings.enable_random_ua = False
        opsec.settings.enable_rate_limit = True
        opsec.settings.max_rps = 150
        opsec.get_random_ua = MagicMock(return_value='UA')

        cmd = 'ffuf -w /usr/src/wordlist/dicc.txt -rate 150 -u http://example.com/FUZZ -json'
        result = opsec._apply_ffuf(cmd)
        self.assertEqual(result.count('-rate'), 1,
                         "opsec must not add a second -rate flag")


class TestFfufAcMcConflict(TestCase):
    """Bug #3: -ac and -mc must not both appear in the same command."""

    def _config(self, auto_calibration, match_statuses=None):
        return {
            'dir_file_fuzz': {
                'auto_calibration': auto_calibration,
                'rate_limit': 0,
                'threads': 10,
                'wordlist_name': 'dicc',
                'extensions': [],
                'match_http_status': match_statuses if match_statuses is not None else [200, 204],
                'recursive_level': 0,
                'max_time': 0,
                'stop_on_error': False,
                'follow_redirect': False,
                'timeout': 10,
            }
        }

    def test_auto_calibration_true_omits_mc(self):
        result = _prepare(self._config(auto_calibration=True))
        self.assertIsNotNone(result, "_prepare() must return a dict, not None")
        self.assertIn('ffuf_base_cmd', result, "prepare_only=True must return ffuf_base_cmd key")
        cmd = result['ffuf_base_cmd']
        self.assertIn('-ac', cmd)
        self.assertNotIn('-mc', cmd,
                         "When auto_calibration=True, -mc must be omitted")

    def test_auto_calibration_false_adds_mc(self):
        result = _prepare(self._config(auto_calibration=False))
        self.assertIsNotNone(result, "_prepare() must return a dict, not None")
        self.assertIn('ffuf_base_cmd', result, "prepare_only=True must return ffuf_base_cmd key")
        cmd = result['ffuf_base_cmd']
        self.assertNotIn('-ac', cmd)
        self.assertIn('-mc 200,204', cmd,
                      "When auto_calibration=False, -mc must be present")

    def test_auto_calibration_true_never_has_both(self):
        result = _prepare(self._config(auto_calibration=True, match_statuses=[200, 301, 403]))
        self.assertIsNotNone(result, "_prepare() must return a dict, not None")
        self.assertIn('ffuf_base_cmd', result, "prepare_only=True must return ffuf_base_cmd key")
        cmd = result['ffuf_base_cmd']
        self.assertFalse('-ac' in cmd and '-mc' in cmd,
                         "Command must never contain both -ac and -mc")


class TestFfufDefaultMatchStatus(TestCase):
    """Bug #4: default match status must include discovery-relevant codes."""

    REQUIRED_CODES = [200, 204, 301, 302, 307, 401, 403, 405]

    def test_default_match_status_includes_discovery_codes(self):
        from reNgine.definitions import FFUF_DEFAULT_MATCH_HTTP_STATUS
        for code in self.REQUIRED_CODES:
            self.assertIn(code, FFUF_DEFAULT_MATCH_HTTP_STATUS,
                          f"HTTP {code} must be in FFUF_DEFAULT_MATCH_HTTP_STATUS")

    def test_no_duplicate_status_codes(self):
        from reNgine.definitions import FFUF_DEFAULT_MATCH_HTTP_STATUS
        self.assertEqual(
            len(FFUF_DEFAULT_MATCH_HTTP_STATUS),
            len(set(FFUF_DEFAULT_MATCH_HTTP_STATUS)),
            "FFUF_DEFAULT_MATCH_HTTP_STATUS must not contain duplicates"
        )


class TestFfufUrlAndHeaderConstruction(TestCase):
    """Bug #5: FUZZ must always follow a /. Bug #6: header values must be single-quoted."""

    BASE_CONFIG = {
        'dir_file_fuzz': {
            'auto_calibration': False,
            'rate_limit': 0,
            'threads': 10,
            'wordlist_name': 'dicc',
            'extensions': [],
            'match_http_status': [200],
            'recursive_level': 0,
            'max_time': 0,
            'stop_on_error': False,
            'follow_redirect': False,
            'timeout': 10,
            'custom_header': [],
        }
    }

    # --- Bug #5: URL path separator ---

    def test_fuzz_keyword_has_leading_slash_when_url_has_no_trailing_slash(self):
        """URLs without trailing slash must get / inserted before FUZZ."""
        captured_cmds = []

        def fake_stream(cmd, **kwargs):
            captured_cmds.append(cmd)
            return iter([])

        config = {'dir_file_fuzz': {**self.BASE_CONFIG['dir_file_fuzz']}}
        proxy = _make_proxy(config)
        ctx = {"urls_override": ["http://example.com/api"]}  # no trailing slash

        def _fake_ensure(task_proxy, func, ctx, description=None):
            return func(ctx=ctx, description=description)

        with patch('reNgine.tasks.fuzzing.ensure_endpoints_crawled_and_execute',
                   side_effect=_fake_ensure), \
             patch('os.path.exists', return_value=False), \
             patch('reNgine.api_tasks.resolve_wordlist_path',
                   side_effect=lambda cfg, path: path), \
             patch('reNgine.tasks.fuzzing.stream_command', side_effect=fake_stream), \
             patch('reNgine.tasks.fuzzing.run_command', return_value=None), \
             patch('reNgine.tasks.fuzzing.DirectoryScan') as mock_ds, \
             patch('reNgine.tasks.fuzzing.Subdomain'), \
             patch('reNgine.tasks.fuzzing.ScanHistory'), \
             patch('reNgine.tasks.fuzzing.Redis'), \
             patch('reNgine.tasks.fuzzing.OpSecManager') as mock_opsec, \
             patch('reNgine.tasks.fuzzing.get_random_proxy', return_value=None), \
             patch('reNgine.tasks.fuzzing._fuzz_target_marker', return_value='/tmp/no_marker'), \
             patch('reNgine.tasks.http_crawl', return_value=None), \
             patch('builtins.open', MagicMock()):
            mock_ds.objects.create.return_value = MagicMock()
            mock_opsec.return_value.apply_stealth = MagicMock(side_effect=lambda t, c, proxy=None: c)
            dir_file_fuzz(proxy, ctx=ctx)

        self.assertTrue(len(captured_cmds) > 0, "stream_command should have been called")
        for cmd in captured_cmds:
            self.assertIn('/FUZZ', cmd,
                          f"FUZZ must be preceded by /. Got: {cmd}")
            self.assertNotIn('apiFUZZ', cmd,
                             f"FUZZ must not be appended directly to path segment. Got: {cmd}")

    # --- Bug #6: Custom header quoting ---

    def test_custom_header_uses_single_quotes(self):
        """Custom headers must be wrapped in single quotes to avoid shell breakage."""
        config = {
            'dir_file_fuzz': {
                **self.BASE_CONFIG['dir_file_fuzz'],
                'custom_header': ['Authorization: Bearer mytoken'],
            }
        }
        result = _prepare(config)
        self.assertIsNotNone(result, "_prepare() must return a dict, not None")
        self.assertIn('ffuf_base_cmd', result, "prepare_only=True must return ffuf_base_cmd key")
        cmd = result['ffuf_base_cmd']
        self.assertIn("-H 'Authorization: Bearer mytoken'", cmd,
                      f"Header must use single quotes. Got: {cmd}")

    def test_custom_header_double_quote_in_value_is_safe(self):
        """A header value containing a double-quote must be safely wrapped in single quotes."""
        config = {
            'dir_file_fuzz': {
                **self.BASE_CONFIG['dir_file_fuzz'],
                'custom_header': ['X-Test: val"ue'],
            }
        }
        result = _prepare(config)
        self.assertIsNotNone(result, "_prepare() must return a dict, not None")
        self.assertIn('ffuf_base_cmd', result, "prepare_only=True must return ffuf_base_cmd key")
        cmd = result['ffuf_base_cmd']
        self.assertIn("-H 'X-Test: val\"ue'", cmd,
                      f"Double-quote inside value must remain inside single quotes. Got: {cmd}")


class TestFfufMaxtimeJob(TestCase):
    """Bug #8: -maxtime-job must be less than -maxtime when recursion is enabled."""

    def _config(self, max_time, recursive_level):
        return {
            'dir_file_fuzz': {
                'auto_calibration': False,
                'rate_limit': 0,
                'threads': 10,
                'wordlist_name': 'dicc',
                'extensions': [],
                'match_http_status': [200],
                'recursive_level': recursive_level,
                'max_time': max_time,
                'stop_on_error': False,
                'follow_redirect': False,
                'timeout': 10,
            }
        }

    def test_maxtime_job_less_than_maxtime_for_recursive_scan(self):
        result = _prepare(self._config(max_time=300, recursive_level=2))
        self.assertIsNotNone(result, "_prepare() must return a dict, not None")
        self.assertIn('ffuf_base_cmd', result, "prepare_only=True must return ffuf_base_cmd key")
        cmd = result['ffuf_base_cmd']
        import re
        maxtime_match = re.search(r'-maxtime (\d+)', cmd)
        maxtime_job_match = re.search(r'-maxtime-job (\d+)', cmd)
        self.assertIsNotNone(maxtime_match, "Command must contain -maxtime")
        self.assertIsNotNone(maxtime_job_match, "Command must contain -maxtime-job when recursive")
        maxtime = int(maxtime_match.group(1))
        maxtime_job = int(maxtime_job_match.group(1))
        self.assertLess(maxtime_job, maxtime,
                        f"-maxtime-job ({maxtime_job}) must be < -maxtime ({maxtime})")

    def test_maxtime_job_has_floor_of_30(self):
        """Even with high depth and low max_time, -maxtime-job must not drop below 30s."""
        result = _prepare(self._config(max_time=60, recursive_level=10))
        self.assertIsNotNone(result, "_prepare() must return a dict, not None")
        self.assertIn('ffuf_base_cmd', result, "prepare_only=True must return ffuf_base_cmd key")
        cmd = result['ffuf_base_cmd']
        import re
        maxtime_job_match = re.search(r'-maxtime-job (\d+)', cmd)
        self.assertIsNotNone(maxtime_job_match, "Command must contain -maxtime-job when recursive")
        self.assertGreaterEqual(int(maxtime_job_match.group(1)), 30,
                                "-maxtime-job floor must be at least 30 seconds")

    def test_no_recursion_no_maxtime_job(self):
        """When recursive_level=0, -maxtime-job must not appear."""
        result = _prepare(self._config(max_time=300, recursive_level=0))
        self.assertIsNotNone(result, "_prepare() must return a dict, not None")
        self.assertIn('ffuf_base_cmd', result, "prepare_only=True must return ffuf_base_cmd key")
        cmd = result['ffuf_base_cmd']
        self.assertNotIn('-maxtime-job', cmd,
                         "Non-recursive scan must not have -maxtime-job flag")


class TestFeroxbusterConfig(TestCase):
    """run_feroxbuster config key: command construction and prepare_only contract."""

    BASE_CONFIG = {
        'dir_file_fuzz': {
            'auto_calibration': True,
            'rate_limit': 100,
            'threads': 20,
            'extensions': ['.php', '.html'],
            'match_http_status': [200],
            'recursive_level': 2,
            'max_time': 0,
            'stop_on_error': False,
            'follow_redirect': True,
            'timeout': 10,
            'run_feroxbuster': True,
        }
    }

    def test_disabled_by_default(self):
        """run_feroxbuster defaults to False; ferox_base_cmd must be None."""
        config = {
            'dir_file_fuzz': {
                'auto_calibration': True,
                'rate_limit': 0,
                'threads': 10,
                'extensions': [],
                'match_http_status': [200],
                'recursive_level': 0,
                'max_time': 0,
                'stop_on_error': False,
                'follow_redirect': False,
                'timeout': 10,
                # run_feroxbuster intentionally absent
            }
        }
        result = _prepare(config)
        self.assertIsNotNone(result)
        self.assertIn('ferox_base_cmd', result)
        self.assertIsNone(result['ferox_base_cmd'],
                          "ferox_base_cmd must be None when run_feroxbuster is absent/False")

    def test_enabled_returns_non_none_cmd(self):
        """When run_feroxbuster=True, ferox_base_cmd must be a non-empty string."""
        result = _prepare(self.BASE_CONFIG)
        self.assertIsNotNone(result)
        self.assertIn('ferox_base_cmd', result)
        self.assertIsNotNone(result['ferox_base_cmd'],
                             "ferox_base_cmd must be set when run_feroxbuster=True")
        self.assertIsInstance(result['ferox_base_cmd'], str)

    def test_command_includes_no_state_and_json(self):
        result = _prepare(self.BASE_CONFIG)
        cmd = result['ferox_base_cmd']
        self.assertIn('--no-state', cmd)
        self.assertIn('--json', cmd)

    def test_wordlist_propagated(self):
        result = _prepare(self.BASE_CONFIG)
        cmd = result['ferox_base_cmd']
        self.assertIn('--wordlist', cmd)

    def test_threads_propagated(self):
        result = _prepare(self.BASE_CONFIG)
        cmd = result['ferox_base_cmd']
        self.assertIn('--threads 20', cmd)

    def test_rate_limit_propagated(self):
        result = _prepare(self.BASE_CONFIG)
        cmd = result['ferox_base_cmd']
        self.assertIn('--rate-limit 100', cmd)

    def test_timeout_propagated(self):
        result = _prepare(self.BASE_CONFIG)
        cmd = result['ferox_base_cmd']
        self.assertIn('--timeout 10', cmd)

    def test_extensions_propagated(self):
        result = _prepare(self.BASE_CONFIG)
        cmd = result['ferox_base_cmd']
        self.assertIn('--extensions', cmd)
        self.assertIn('.php', cmd)
        self.assertIn('.html', cmd)

    def test_follow_redirects_when_enabled(self):
        result = _prepare(self.BASE_CONFIG)
        cmd = result['ferox_base_cmd']
        self.assertIn('--follow-redirects', cmd)

    def test_no_follow_redirects_when_disabled(self):
        config = {
            'dir_file_fuzz': {
                **self.BASE_CONFIG['dir_file_fuzz'],
                'follow_redirect': False,
            }
        }
        result = _prepare(config)
        self.assertNotIn('--follow-redirects', result['ferox_base_cmd'])

    def test_depth_set_when_recursive(self):
        result = _prepare(self.BASE_CONFIG)
        cmd = result['ferox_base_cmd']
        self.assertIn('--depth 2', cmd)
        self.assertNotIn('--no-recursion', cmd)

    def test_no_recursion_when_level_zero(self):
        config = {
            'dir_file_fuzz': {
                **self.BASE_CONFIG['dir_file_fuzz'],
                'recursive_level': 0,
            }
        }
        result = _prepare(config)
        cmd = result['ferox_base_cmd']
        self.assertIn('--no-recursion', cmd)
        self.assertNotIn('--depth', cmd)

    def test_auto_calibration_adds_flag(self):
        result = _prepare(self.BASE_CONFIG)
        cmd = result['ferox_base_cmd']
        self.assertIn('--auto-calibration', cmd)

    def test_no_auto_calibration_omits_flag(self):
        config = {
            'dir_file_fuzz': {
                **self.BASE_CONFIG['dir_file_fuzz'],
                'auto_calibration': False,
            }
        }
        result = _prepare(config)
        self.assertNotIn('--auto-calibration', result['ferox_base_cmd'])

    def test_custom_headers_included(self):
        config = {
            'dir_file_fuzz': {
                **self.BASE_CONFIG['dir_file_fuzz'],
                'custom_header': ['Authorization: Bearer token123'],
            }
        }
        result = _prepare(config)
        cmd = result['ferox_base_cmd']
        self.assertIn("-H 'Authorization: Bearer token123'", cmd)

    def test_prepare_only_always_returns_ferox_key(self):
        """prepare_only=True must always return ferox_base_cmd key, value may be None."""
        result = _prepare({'dir_file_fuzz': {}})
        self.assertIn('ferox_base_cmd', result,
                      "prepare_only dict must contain ferox_base_cmd key")

class TestFfufStreamingHeartbeat(TestCase):
    """Bug #7: ffuf must not be routed to Go executor (blocks heartbeats)."""

    BASE_CONFIG = {
        'dir_file_fuzz': {
            'auto_calibration': False,
            'rate_limit': 0,
            'threads': 10,
            'wordlist_name': 'dicc',
            'extensions': [],
            'match_http_status': [200],
            'recursive_level': 0,
            'max_time': 0,
            'stop_on_error': False,
            'follow_redirect': False,
            'timeout': 10,
        }
    }

    def _run_with_fake_stream(self, stream_side_effect):
        """Helper: run dir_file_fuzz with a fake stream_command and return captured kwargs."""
        captured_kwargs = {}

        def fake_stream(cmd, **kwargs):
            captured_kwargs.update(kwargs)
            if callable(stream_side_effect):
                return stream_side_effect()
            return iter(stream_side_effect)

        proxy = _make_proxy(self.BASE_CONFIG)
        ctx = {"urls_override": ["http://example.com/"]}

        def _fake_ensure(task_proxy, func, ctx, description=None):
            return func(ctx=ctx, description=description)

        # _fuzz_target_marker returns a path ending in .marker so the
        # os.path.exists patch (which returns False for .marker paths) prevents
        # the "already fuzzed" skip, while returning True for wordlist paths.
        with patch('reNgine.tasks.fuzzing.ensure_endpoints_crawled_and_execute',
                   side_effect=_fake_ensure), \
             patch('os.path.exists', side_effect=lambda p: not p.endswith('.marker')), \
             patch('reNgine.api_tasks.resolve_wordlist_path',
                   side_effect=lambda cfg, path: path), \
             patch('reNgine.tasks.fuzzing.stream_command', side_effect=fake_stream), \
             patch('reNgine.tasks.fuzzing.DirectoryScan') as mock_ds, \
             patch('reNgine.tasks.fuzzing.Subdomain'), \
             patch('reNgine.tasks.fuzzing.ScanHistory'), \
             patch('reNgine.tasks.fuzzing.Redis'), \
             patch('reNgine.tasks.fuzzing.OpSecManager') as mock_opsec, \
             patch('reNgine.tasks.fuzzing.get_random_proxy', return_value=None), \
             patch('reNgine.tasks.fuzzing._fuzz_target_marker',
                   return_value='/tmp/no_marker.marker'), \
             patch('reNgine.tasks.fuzzing.run_command'), \
             patch('reNgine.tasks.http_crawl'), \
             patch('builtins.open', MagicMock()):
            mock_ds.objects.create.return_value = MagicMock()
            mock_opsec.return_value.apply_stealth = MagicMock(
                side_effect=lambda t, c, proxy=None: c)
            dir_file_fuzz(proxy, ctx=ctx)

        return captured_kwargs

    def test_stream_command_not_routed_to_executor(self):
        """stream_command must be called with route_to_executor=False for ffuf."""
        captured_kwargs = self._run_with_fake_stream([])

        self.assertIn('route_to_executor', captured_kwargs,
                      "stream_command must receive route_to_executor kwarg")
        self.assertFalse(captured_kwargs['route_to_executor'],
                         "ffuf stream_command must have route_to_executor=False")

    def test_heartbeat_fires_after_batch_fills(self):
        """activity_heartbeat_safe must be called after every 100 results."""
        fake_result = {
            'url': 'http://example.com/found',
            'status': 200,
            'length': 512,
            'words': 20,
            'lines': 10,
            'content-type': 'text/html',
            'duration': 1000000,
        }
        # 101 results so the first batch of 100 flushes and heartbeat fires
        fake_results = [dict(fake_result, url=f'http://example.com/found{i}')
                        for i in range(101)]

        proxy = _make_proxy(self.BASE_CONFIG)
        ctx = {"urls_override": ["http://example.com/"]}

        def _fake_ensure(task_proxy, func, ctx, description=None):
            return func(ctx=ctx, description=description)

        with patch('reNgine.tasks.fuzzing.ensure_endpoints_crawled_and_execute',
                   side_effect=_fake_ensure), \
             patch('os.path.exists', side_effect=lambda p: not p.endswith('.marker')), \
             patch('reNgine.api_tasks.resolve_wordlist_path',
                   side_effect=lambda cfg, path: path), \
             patch('reNgine.tasks.fuzzing.stream_command', return_value=iter(fake_results)), \
             patch('reNgine.tasks.fuzzing.DirectoryScan') as mock_ds, \
             patch('reNgine.tasks.fuzzing.Subdomain'), \
             patch('reNgine.tasks.fuzzing.ScanHistory'), \
             patch('reNgine.tasks.fuzzing.Redis'), \
             patch('reNgine.tasks.fuzzing.OpSecManager') as mock_opsec, \
             patch('reNgine.tasks.fuzzing.get_random_proxy', return_value=None), \
             patch('reNgine.tasks.fuzzing._fuzz_target_marker',
                   return_value='/tmp/no_marker.marker'), \
             patch('reNgine.tasks.fuzzing.run_command'), \
             patch('reNgine.tasks.http_crawl'), \
             patch('builtins.open', MagicMock()), \
             patch('reNgine.tasks.fuzzing._flush_ffuf_batch'), \
             patch('reNgine.tasks.fuzzing.activity_heartbeat_safe') as mock_heartbeat:
            mock_ds.objects.create.return_value = MagicMock()
            mock_opsec.return_value.apply_stealth = MagicMock(
                side_effect=lambda t, c, proxy=None: c)
            dir_file_fuzz(proxy, ctx=ctx)

        mock_heartbeat.assert_called()
