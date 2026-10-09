"""The workflow side of batched steps: _run_chunked in workflows/_common.py.

Exercised with workflow.execute_activity and workflow.now replaced, so no
Temporal test server is needed.
"""
import asyncio
from datetime import datetime, timedelta, timezone
from unittest import TestCase
from unittest.mock import MagicMock, patch

from temporalio.exceptions import ActivityError

from reNgine.temporal.workflows import _common


def _activity_error() -> ActivityError:
    return ActivityError('boom', scheduled_event_id=1, started_event_id=2, identity='w',
                         activity_type='RunChunkedTaskBatchActivity', activity_id='1', retry_state=None)


class FakeWorkflow:
    """Plays the activities: each batch index yields its outcomes in turn."""

    def __init__(self, batches: int, outcomes: dict, max_parallel: int = 2, budget_hours: int = 12,
                 hours_per_run: float = 1):
        self.clock = datetime(2026, 10, 5, tzinfo=timezone.utc)
        self.plan = {'results_dir': '/r', 'activity_id': 7, 'batches': batches, 'max_parallel': max_parallel,
                     'max_total_hours': budget_hours, 'batch_timeout_minutes': 120}
        self.outcomes = {index: list(statuses) for index, statuses in outcomes.items()}
        self.hours_per_run = hours_per_run
        self.calls = []
        self.running = 0
        self.peak = 0
        self.logger = MagicMock()

    def now(self):
        return self.clock

    def info(self):
        return MagicMock(workflow_id='master-scan-6-run-0')

    async def execute_activity(self, name, args=None, **kwargs):
        self.calls.append((name, args))
        if name == 'PlanChunkedTaskActivity':
            return self.plan
        if name != 'RunChunkedTaskBatchActivity':
            return True
        index = args[2]
        self.running += 1
        self.peak = max(self.peak, self.running)
        await asyncio.sleep(0)
        self.running -= 1
        self.clock += timedelta(hours=self.hours_per_run)
        status = self.outcomes.get(index, ['done']).pop(0)
        if status == 'raise':
            raise _activity_error()
        return {'index': index, 'status': status}


class RunChunkedTests(TestCase):

    def _run(self, fake: FakeWorkflow) -> list:
        with patch.object(_common, 'workflow', fake):
            return asyncio.run(_common._run_chunked({'scan_history_id': 1}, 'dir_file_fuzz'))

    def _finalize_results(self, fake):
        return next(args[3] for name, args in fake.calls if name == 'FinalizeChunkedTaskActivity')

    def test_batches_run_a_few_at_a_time_and_every_outcome_is_finalized(self):
        fake = FakeWorkflow(5, {}, max_parallel=2)

        results = self._run(fake)

        self.assertEqual([r['status'] for r in results], ['done'] * 5)
        self.assertEqual(fake.peak, 2)
        self.assertEqual([name for name, _ in fake.calls][-2:],
                         ['FinalizeChunkedTaskActivity', 'RunChunkedTaskFollowUpActivity'])
        self.assertEqual(self._finalize_results(fake), results)

    def test_a_batch_stopped_at_its_limit_runs_again(self):
        fake = FakeWorkflow(1, {0: ['partial', 'done']})

        self.assertEqual(self._run(fake)[0]['status'], 'done')
        self.assertEqual(sum(1 for name, _ in fake.calls if name == 'RunChunkedTaskBatchActivity'), 2)

    def test_a_batch_still_unfinished_after_its_passes_stays_partial(self):
        fake = FakeWorkflow(1, {0: ['partial'] * 3})

        self.assertEqual(self._run(fake)[0]['status'], 'partial')

    def test_a_failed_batch_does_not_stop_the_others(self):
        fake = FakeWorkflow(3, {1: ['raise']})

        self.assertEqual([r['status'] for r in self._run(fake)], ['done', 'failed', 'done'])

    def test_batches_past_the_budget_are_skipped(self):
        fake = FakeWorkflow(4, {}, max_parallel=1, budget_hours=2, hours_per_run=1)

        self.assertEqual([r['status'] for r in self._run(fake)], ['done', 'done', 'skipped', 'skipped'])

    def test_a_failed_follow_up_does_not_fail_the_step(self):
        fake = FakeWorkflow(1, {})
        original = fake.execute_activity

        async def follow_up_fails(name, args=None, **kwargs):
            if name == 'RunChunkedTaskFollowUpActivity':
                raise _activity_error()
            return await original(name, args=args, **kwargs)

        fake.execute_activity = follow_up_fails
        self.assertEqual(self._run(fake)[0]['status'], 'done')

    def test_batching_is_on_unless_the_engine_turns_it_off(self):
        self.assertTrue(_common._batching_enabled({}, 'dir_file_fuzz'))
        self.assertTrue(_common._batching_enabled({'dir_file_fuzz': {'batching': 'x'}}, 'dir_file_fuzz'))
        self.assertFalse(_common._batching_enabled(
            {'dir_file_fuzz': {'batching': {'enabled': False}}}, 'dir_file_fuzz'))
