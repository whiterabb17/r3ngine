"""Values that come from the target (crawled URLs, hostnames) must reach tools as
single shell words, never as shell syntax.

A scanned site controls the URLs it links to, so an unquoted URL in a
``shell=True`` command lets the target run commands on the scanner.
"""
import shlex
import tempfile
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from reNgine.tasks.api import run_jwt_scan
from reNgine.tasks.fuzzing import build_dirsearch_run_cmd

HOSTILE_URL = 'https://target.example/a;touch${IFS}/tmp/pwned|sh $(id) `id`'


def _task_proxy(results_dir: str) -> SimpleNamespace:
    return SimpleNamespace(results_dir=results_dir, history_file=None, scan_id=1, activity_id=None)


class ShellQuotingTests(TestCase):

    def test_dirsearch_url_and_proxy_stay_single_words(self):
        proxy = 'http://proxy.example:8080;id'
        cmd = build_dirsearch_run_cmd('dirsearch', HOSTILE_URL, '/tmp/out.json', proxy=proxy)

        words = shlex.split(cmd)
        self.assertEqual(words[words.index('-u') + 1], HOSTILE_URL.rstrip('/'))
        self.assertEqual(words[words.index('--proxy') + 1], proxy)

    def test_jwt_tool_target_stays_a_single_word(self):
        with tempfile.TemporaryDirectory() as results_dir, \
                patch('reNgine.tasks.api.run_command', return_value=(0, '')) as run:
            run_jwt_scan(_task_proxy(results_dir), {}, HOSTILE_URL, SimpleNamespace(name='app.example.test'), results_dir)

        words = shlex.split(run.call_args[0][0])
        self.assertEqual(words[words.index('-t') + 1], HOSTILE_URL)
        # The only real pipe is the one into tee.
        self.assertEqual(words.count('|'), 1)

    def test_second_order_target_stays_a_single_word(self):
        from reNgine.tasks.vuln import second_order_scan

        with tempfile.TemporaryDirectory() as results_dir, \
                patch('reNgine.tasks.vuln._resolve_scoped_http_targets', return_value=[HOSTILE_URL]), \
                patch('reNgine.tasks.vuln.run_command', return_value=(0, '')) as run:
            second_order_scan(_task_proxy(results_dir), urls=[])

        words = shlex.split(run.call_args[0][0])
        self.assertEqual(words[words.index('-target') + 1], HOSTILE_URL)
