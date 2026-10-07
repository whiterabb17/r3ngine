"""A fuzzing run told to stop leaves its unfinished targets for the retry.

Each target gets a fuzz_done marker so a retry skips it. When the run was
stopped (scan abort or the activity's time limit), the loop used to carry on,
start no tool for the remaining targets, and still mark every one of them done.
"""
import os
import tempfile
import threading
import types
from unittest.mock import MagicMock, patch

from django.test import TestCase

from reNgine.tasks.fuzzing import _fuzz_target_marker, dir_file_fuzz
from reNgine.temporal.activities.core import _task_cancel_local

TARGETS = ['https://a.example.test/', 'https://b.example.test/', 'https://c.example.test/']
CONFIG = {'dir_file_fuzz': {
    'auto_calibration': True, 'rate_limit': 0, 'threads': 5, 'extensions': [],
    'recursive_level': 0, 'max_time': 0, 'enable_http_crawl': True,
}}


class FuzzStopTests(TestCase):

    def setUp(self) -> None:
        self.results_dir = tempfile.mkdtemp()
        self.stop = threading.Event()
        _task_cancel_local.cancel_event = self.stop
        self.addCleanup(lambda: setattr(_task_cancel_local, 'cancel_event', None))

    def _run(self, on_command=None, extra_ctx=None):
        proxy = types.SimpleNamespace(
            yaml_configuration=CONFIG, results_dir=self.results_dir, scan=MagicMock(), scan_id=1,
            activity_id=1, history_file=os.path.join(self.results_dir, 'h.txt'), subscan=None,
        )
        commands = []

        def fake_stream(cmd, **kwargs):
            commands.append(cmd)
            if on_command:
                on_command()
            return iter([])

        with patch('reNgine.tasks.fuzzing.ensure_endpoints_crawled_and_execute',
                   side_effect=lambda task, func, ctx, description=None: func(ctx=ctx, description=description)), \
                patch('reNgine.tasks.fuzzing.expand_ext_wordlist', return_value=('/tmp/wl.txt', False)), \
                patch('reNgine.tasks.api.resolve_wordlist_path', side_effect=lambda cfg, path: path), \
                patch('reNgine.tasks.fuzzing.stream_command', side_effect=fake_stream), \
                patch('reNgine.tasks.fuzzing.DirectoryScan'), \
                patch('reNgine.tasks.fuzzing.Subdomain'), \
                patch('reNgine.tasks.fuzzing.ScanHistory'), \
                patch('reNgine.tasks.fuzzing.Redis'), \
                patch('reNgine.tasks.fuzzing.renewed_lock'), \
                patch('reNgine.tasks.fuzzing.get_random_proxy', return_value=None), \
                patch('reNgine.tasks.http_crawl') as crawl:
            dir_file_fuzz(proxy, ctx={'urls_override': list(TARGETS), **(extra_ctx or {})})
        return commands, crawl

    def _done(self) -> list:
        return [t for t in TARGETS if os.path.exists(_fuzz_target_marker(self.results_dir, t))]

    def test_every_finished_target_is_marked_done(self) -> None:
        commands, crawl = self._run()

        self.assertEqual(len(commands), 3)
        self.assertEqual(self._done(), TARGETS)
        crawl.assert_called_once()

    def test_a_stop_leaves_the_cut_target_and_the_rest_for_the_retry(self) -> None:
        commands, crawl = self._run(on_command=self.stop.set)

        self.assertEqual(len(commands), 1, 'no tool starts after the stop')
        self.assertEqual(self._done(), [], 'the target cut short is not done either')
        crawl.assert_not_called()

    def test_a_batch_leaves_the_crawl_to_its_finalizer(self) -> None:
        _, crawl = self._run(extra_ctx={'skip_post_crawl': True})

        crawl.assert_not_called()
        self.assertEqual(self._done(), TARGETS)
