"""Running a per-host tool in batches of hosts (directory fuzzing first)."""
import json
import os
import tempfile
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from reNgine.temporal.activities import chunked
from reNgine.temporal.activities.chunked import (
    ChunkedTask, plan_chunked_task_activity, run_chunked_task_batch_activity, summarize_batches,
)

HOSTS = [f'https://h{i}.example.test/' for i in range(5)]


class FakeTool:
    """Stand-in tool: a target is done once a batch ran over it."""

    def __init__(self, finish=None, fail=False):
        self.finish = finish
        self.fail = fail
        self.done = set()
        self.runs = []

    def run(self, ctx, targets):
        self.runs.append((ctx, list(targets)))
        if self.fail:
            raise RuntimeError('tool crashed')
        self.done.update(t for t in targets if self.finish is None or t in self.finish)

    def spec(self):
        return ChunkedTask(
            title='Fake', config_key='fake_tool',
            select_targets=lambda proxy, ctx: list(HOSTS),
            run_batch=self.run,
            is_done=lambda results_dir, target: target in self.done,
        )


class ChunkedActivityTests(TestCase):

    def setUp(self):
        self.results_dir = tempfile.mkdtemp()
        self.tool = FakeTool()
        self.recorded = []
        proxy = SimpleNamespace(
            yaml_configuration={'fake_tool': {'batching': {'batch_size': 2}}},
            results_dir=self.results_dir, activity_id=7,
        )
        for target, kwargs in (
            ('reNgine.temporal.activities.chunked.TemporalTaskProxy', {'return_value': proxy}),
            ('reNgine.temporal.activities.chunked._record',
             {'side_effect': lambda *args, **kw: self.recorded.append(args)}),
        ):
            patcher = patch(target, **kwargs)
            patcher.start()
            self.addCleanup(patcher.stop)
        patcher = patch.dict(chunked.CHUNKED_TASKS, {'fake': self.tool.spec()})
        patcher.start()
        self.addCleanup(patcher.stop)

    def _plan(self, **ctx):
        return plan_chunked_task_activity({'scan_history_id': 1, 'seed_urls': ['x'], **ctx}, 'fake')

    def test_the_plan_is_saved_and_reused(self):
        first = self._plan()

        self.assertEqual((first['batches'], first['targets'], first['activity_id']), (3, 5, 7))
        self.assertEqual(first['batch_size'], 2)
        HOSTS.append('https://late.example.test/')
        self.addCleanup(HOSTS.pop)
        again = self._plan()
        self.assertEqual(again['targets'], 5, 'a retry keeps the batches it started with')

        saved_ctx = json.load(open(os.path.join(self.results_dir, 'batches', 'fake', 'ctx.json')))
        self.assertNotIn('seed_urls', saved_ctx)

    def test_a_plan_for_one_host_is_not_reused_for_the_whole_scan(self):
        chunked._write_json(os.path.join(self.results_dir, 'batches', 'fake', 'plan.json'), {
            'version': chunked.PLAN_VERSION,
            'scope': chunked._plan_scope({'subdomain_id': 3}),
            'batches': [[HOSTS[0]]],
        })

        self.assertEqual(self._plan()['targets'], 5)

    def test_a_batch_runs_only_its_unfinished_targets(self):
        self._plan()
        self.tool.done.add(HOSTS[0])

        result = run_chunked_task_batch_activity(self.results_dir, 'fake', 0, 7)

        self.assertEqual(result['status'], 'done')
        ctx, targets = self.tool.runs[0]
        self.assertEqual(targets, [HOSTS[1]])
        self.assertEqual((ctx['track'], ctx['activity_id']), (False, 7))

    def test_a_batch_cut_short_reports_partial(self):
        self.tool.finish = {HOSTS[0]}
        self._plan()

        result = run_chunked_task_batch_activity(self.results_dir, 'fake', 0, 7)

        self.assertEqual((result['status'], result['finished']), ('partial', 1))

    def test_a_failing_batch_raises_so_temporal_retries_it(self):
        self.tool.fail = True
        self._plan()

        with self.assertRaises(RuntimeError):
            run_chunked_task_batch_activity(self.results_dir, 'fake', 1, 7)
        self.assertTrue(any('FAILED' in args[3] for args in self.recorded))


class SummarizeBatchesTests(TestCase):

    def test_outcomes(self):
        self.assertEqual(summarize_batches([{'index': 0, 'status': 'done'}], 1), (True, None))

        ok, note = summarize_batches([{'index': 0, 'status': 'done'}, {'index': 1, 'status': 'skipped'}], 2)
        self.assertTrue(ok)
        self.assertIn('time budget', note)

        ok, note = summarize_batches([{'index': 0, 'status': 'partial'}, {'index': 3, 'status': 'failed'}], 5)
        self.assertFalse(ok)
        self.assertIn('2/5 batches did not finish (1, 4)', note)
