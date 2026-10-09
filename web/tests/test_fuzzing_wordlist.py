"""Tests for the %EXT% wordlist expansion used by ffuf and feroxbuster in dir_file_fuzz."""
import os
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock, patch

from django.test import TestCase

from reNgine.tasks.fuzzing import dir_file_fuzz, expand_ext_wordlist, selected_fuzzers
from startScan.models import DirectoryScan
from tests.test_ffuf_bugs import _make_proxy, _prepare

DICC_LIKE = (
    'admin/\n'
    '/index.%EXT%\n'
    '\n'
    'config.%EXT%.bak\n'
    '/admin/\n'
    '.git/HEAD\n'
    'index.php\n'
)
PLAIN = 'admin\nlogin\nbackup\n'


class _TempDirMixin:
    def setUp(self):
        super().setUp()
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.tmp = Path(tmp.name)
        self.out_dir = self.tmp / 'results'

    def _wordlist(self, content: str, name: str = 'words.txt') -> str:
        path = self.tmp / name
        path.write_text(content, encoding='utf-8')
        return str(path)


class TestExpandExtWordlist(_TempDirMixin, unittest.TestCase):

    def _expand(self, content: str, extensions=('.php', '.bak')) -> tuple[str, bool]:
        return expand_ext_wordlist(self._wordlist(content), list(extensions), str(self.out_dir))

    def _lines(self, path: str) -> list[str]:
        return Path(path).read_text(encoding='utf-8').splitlines()

    def test_placeholder_expanded_once_per_extension_without_dot(self):
        path, expanded = self._expand('index.%EXT%\n')
        self.assertTrue(expanded)
        self.assertEqual(self._lines(path), ['index.php', 'index.bak'])

    def test_plain_words_kept_blank_lines_dropped_leading_slash_stripped_deduped(self):
        path, _ = self._expand(DICC_LIKE)
        self.assertEqual(self._lines(path), [
            'admin/',
            'index.php',
            'index.bak',
            'config.php.bak',
            'config.bak.bak',
            '.git/HEAD',
        ])

    def test_written_under_output_dir_without_leftover_part_file(self):
        path, _ = self._expand(DICC_LIKE)
        self.assertEqual(Path(path).parent, self.out_dir)
        self.assertEqual([p.name for p in self.out_dir.iterdir()], [Path(path).name])

    def test_existing_expansion_reused(self):
        wordlist = self._wordlist(DICC_LIKE)
        first, _ = expand_ext_wordlist(wordlist, ['.php'], str(self.out_dir))
        Path(first).write_text('sentinel\n', encoding='utf-8')
        second, expanded = expand_ext_wordlist(wordlist, ['.php'], str(self.out_dir))
        self.assertTrue(expanded)
        self.assertEqual(first, second)
        self.assertEqual(self._lines(second), ['sentinel'])

    def test_different_extensions_get_their_own_file(self):
        wordlist = self._wordlist(DICC_LIKE)
        php, _ = expand_ext_wordlist(wordlist, ['.php'], str(self.out_dir))
        asp, _ = expand_ext_wordlist(wordlist, ['.asp'], str(self.out_dir))
        self.assertNotEqual(php, asp)
        self.assertIn('index.asp', self._lines(asp))

    def test_wordlist_without_placeholder_passes_through(self):
        wordlist = self._wordlist(PLAIN)
        path, expanded = expand_ext_wordlist(wordlist, ['.php'], str(self.out_dir))
        self.assertFalse(expanded)
        self.assertEqual(path, wordlist)
        self.assertFalse(self.out_dir.exists())

    def test_missing_wordlist_passes_through(self):
        missing = str(self.tmp / 'missing.txt')
        self.assertEqual(expand_ext_wordlist(missing, ['.php'], str(self.out_dir)), (missing, False))


class TestDirFileFuzzWordlistCommands(_TempDirMixin, TestCase):

    CONFIG = {
        'dir_file_fuzz': {
            'extensions': ['php', 'bak'],
            'recursive_level': 0,
            'run_dirsearch': True,
            'run_feroxbuster': True,
        }
    }

    def _run(self, content: str, config=None) -> tuple[dict, str]:
        wordlist = self._wordlist(content)
        self.out_dir.mkdir()
        result = _prepare(config or self.CONFIG, wordlist_path=wordlist, results_dir=str(self.out_dir))
        return result, wordlist

    def test_dicc_like_list_ffuf_uses_expanded_list_without_e(self):
        result, wordlist = self._run(DICC_LIKE)
        cmd = result['ffuf_base_cmd']
        self.assertNotIn(f'-w {wordlist}', cmd)
        self.assertIn(f'-w {self.out_dir}{os.sep}ffuf_wordlist_', cmd)
        self.assertNotIn(' -e ', cmd)

    def test_dicc_like_list_dirsearch_keeps_original_list_and_e(self):
        result, wordlist = self._run(DICC_LIKE)
        cmd = result['dirsearch_base_cmd']
        self.assertIn(f'-w {wordlist}', cmd)
        self.assertIn(' -e php,bak', cmd)

    def test_dicc_like_list_feroxbuster_uses_expanded_list_without_extensions(self):
        result, _ = self._run(DICC_LIKE)
        cmd = result['ferox_base_cmd']
        self.assertIn(f'--wordlist {self.out_dir}{os.sep}ffuf_wordlist_', cmd)
        self.assertNotIn('--extensions', cmd)

    def test_plain_list_keeps_extension_flags(self):
        result, wordlist = self._run(PLAIN)
        self.assertIn(f'-w {wordlist} -e .php,.bak', result['ffuf_base_cmd'])
        self.assertIn('--extensions .php,.bak', result['ferox_base_cmd'])
        self.assertIn(f'-w {wordlist}', result['dirsearch_base_cmd'])

    def test_dirsearch_off_when_key_absent(self):
        config = {'dir_file_fuzz': {'extensions': ['php'], 'recursive_level': 0}}
        result, _ = self._run(PLAIN, config)
        self.assertIsNone(result['dirsearch_base_cmd'])
        self.assertTrue(result['ffuf_base_cmd'].startswith('ffuf '))


class TestSelectedFuzzers(unittest.TestCase):

    def test_ffuf_on_and_extra_passes_off_when_keys_absent(self):
        self.assertEqual(selected_fuzzers({}), (True, False, False))

    def test_null_run_ffuf_keeps_default(self):
        self.assertEqual(selected_fuzzers({'run_ffuf': None})[0], True)

    def test_explicit_values_honoured(self):
        config = {'run_ffuf': False, 'run_dirsearch': True, 'run_feroxbuster': True}
        self.assertEqual(selected_fuzzers(config), (False, True, True))

    def test_singular_tool_run_forces_ffuf(self):
        config = {'run_ffuf': False}
        self.assertEqual(selected_fuzzers(config, {'singular_tool_run': True}), (True, False, False))


class TestRunFfufPrepare(_TempDirMixin, TestCase):

    def _run(self, config: dict, extra_ctx=None) -> dict:
        wordlist = self._wordlist(DICC_LIKE)
        self.out_dir.mkdir()
        return _prepare(
            {'dir_file_fuzz': {'extensions': ['php'], 'recursive_level': 0, **config}},
            wordlist_path=wordlist,
            results_dir=str(self.out_dir),
            extra_ctx=extra_ctx,
        )

    def test_default_builds_ffuf_command(self):
        self.assertTrue(self._run({})['ffuf_base_cmd'].startswith('ffuf '))

    def test_run_ffuf_false_builds_no_ffuf_command(self):
        result = self._run({'run_ffuf': False, 'run_dirsearch': True})
        self.assertIsNone(result['ffuf_base_cmd'])
        self.assertTrue(result['dirsearch_base_cmd'].startswith('dirsearch '))

    def test_run_ffuf_false_with_dirsearch_only_skips_expansion(self):
        with patch('reNgine.tasks.fuzzing.expand_ext_wordlist') as mock_expand:
            self._run({'run_ffuf': False, 'run_dirsearch': True})
        mock_expand.assert_not_called()
        self.assertEqual(list(self.out_dir.iterdir()), [])

    def test_feroxbuster_still_gets_expanded_list_without_ffuf(self):
        result = self._run({'run_ffuf': False, 'run_feroxbuster': True})
        self.assertIsNone(result['ffuf_base_cmd'])
        self.assertIn(f'--wordlist {self.out_dir}{os.sep}ffuf_wordlist_', result['ferox_base_cmd'])

    def test_singular_tool_run_builds_ffuf_despite_run_ffuf_false(self):
        result = self._run(
            {'run_ffuf': False},
            extra_ctx={'singular_tool_run': True, 'extra_cli_args': ['-t', '5']},
        )
        self.assertTrue(result['ffuf_base_cmd'].startswith('ffuf '))
        self.assertIn(' -t 5', result['ffuf_base_cmd'])


class TestRunFfufExecution(_TempDirMixin, TestCase):
    """Full (non-prepare) runs with every tool invocation mocked."""

    def _run(self, config: dict, extra_ctx=None):
        wordlist = self._wordlist(PLAIN)
        self.out_dir.mkdir()
        proxy = _make_proxy(
            {'dir_file_fuzz': {'extensions': ['php'], 'recursive_level': 0,
                               'enable_http_crawl': False, **config}},
            results_dir=str(self.out_dir),
        )
        ctx = {'urls_override': ['http://app.example.test/'], **(extra_ctx or {})}

        def _fake_ensure(task_proxy, func, ctx, description=None):
            return func(ctx=ctx, description=description)

        opsec = MagicMock()
        opsec.apply_stealth.side_effect = lambda tool, cmd, proxy=None: cmd
        self.mock_ensure = MagicMock(side_effect=_fake_ensure)
        with patch('reNgine.tasks.fuzzing.ensure_endpoints_crawled_and_execute', self.mock_ensure), \
             patch('reNgine.tasks.api.resolve_wordlist_path', side_effect=lambda cfg, path: wordlist), \
             patch('reNgine.tasks.fuzzing.stream_command', return_value=iter([])) as self.mock_stream, \
             patch('reNgine.tasks.fuzzing.run_command', return_value=(0, '')) as self.mock_run, \
             patch('reNgine.tasks.fuzzing.Subdomain'), \
             patch('reNgine.tasks.fuzzing.Redis'), \
             patch('reNgine.tasks.fuzzing.get_opsec_manager', return_value=opsec), \
             patch('reNgine.tasks.fuzzing.get_random_proxy', return_value=None):
            return dir_file_fuzz(proxy, ctx=ctx)

    def _commands(self, mock) -> list[str]:
        return [c.args[0] for c in mock.call_args_list]

    def test_default_runs_ffuf(self):
        self._run({})
        cmds = self._commands(self.mock_stream)
        self.assertEqual(len(cmds), 1)
        self.assertTrue(cmds[0].startswith('ffuf '))
        self.assertEqual(DirectoryScan.objects.count(), 1)

    def test_run_ffuf_false_runs_feroxbuster_only(self):
        self._run({'run_ffuf': False, 'run_feroxbuster': True})
        self.mock_stream.assert_not_called()
        cmds = self._commands(self.mock_run)
        self.assertEqual(len(cmds), 1)
        self.assertTrue(cmds[0].startswith('feroxbuster '))
        self.assertFalse(DirectoryScan.objects.filter(command_line__startswith='ffuf').exists())

    def test_all_tools_off_is_a_logged_no_op(self):
        config = {'run_ffuf': False, 'run_dirsearch': False, 'run_feroxbuster': False}
        with self.assertLogs('reNgine.tasks.fuzzing', level='WARNING') as logs:
            result = self._run(config)
        self.assertEqual(result, [])
        self.assertTrue(any('run_ffuf, run_dirsearch and run_feroxbuster are all off' in line
                            for line in logs.output))
        self.mock_ensure.assert_not_called()
        self.mock_stream.assert_not_called()
        self.mock_run.assert_not_called()
        self.assertEqual(DirectoryScan.objects.count(), 0)
        self.assertEqual(list(self.out_dir.iterdir()), [])

    def test_all_tools_off_prepare_only_returns_empty_plan(self):
        proxy = types.SimpleNamespace(yaml_configuration={'dir_file_fuzz': {'run_ffuf': False}}, scan_id=1)
        result = dir_file_fuzz(proxy, ctx={}, prepare_only=True)
        self.assertEqual(result['urls'], [])
        self.assertIsNone(result['ffuf_base_cmd'])

    def test_singular_tool_run_runs_ffuf_despite_run_ffuf_false(self):
        self._run({'run_ffuf': False}, extra_ctx={'singular_tool_run': True})
        cmds = self._commands(self.mock_stream)
        self.assertEqual(len(cmds), 1)
        self.assertTrue(cmds[0].startswith('ffuf '))
