"""A _run_task activity stops its tool before Temporal times the attempt out.

Temporal times an attempt out on the server but cannot interrupt the worker
thread, so a timed-out fuzzer kept running beside the retry that started the
same hours-long run from scratch, and the scan failed when the retry timed out
too. The activity now stops its tool shortly before the limit and keeps what it
found.
"""
import threading
from datetime import datetime, timedelta, timezone
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock, patch

from temporalio.exceptions import ApplicationError

from reNgine.definitions import FAILED_TASK, SUCCESS_TASK
from reNgine.temporal.activities import core
from reNgine.temporal.activities.core import _attempt_stop_time, _run_task, _task_cancel_local


def _info(started_ago: timedelta, start_to_close: timedelta | None, **extra) -> SimpleNamespace:
    now = datetime.now(timezone.utc)
    return SimpleNamespace(
        started_time=now - started_ago,
        start_to_close_timeout=start_to_close,
        scheduled_time=extra.get('scheduled_time', now - started_ago),
        schedule_to_close_timeout=extra.get('schedule_to_close_timeout'),
        workflow_id='wf-1',
    )


class AttemptStopTimeTests(TestCase):

    def test_stops_a_margin_before_the_limit(self) -> None:
        info = _info(timedelta(0), timedelta(hours=8))
        stop = _attempt_stop_time(info)
        self.assertEqual(info.started_time + timedelta(hours=8) - stop, timedelta(minutes=10), 'margin is capped')

        short = _info(timedelta(0), timedelta(minutes=10))
        self.assertEqual(short.started_time + timedelta(minutes=10) - _attempt_stop_time(short), timedelta(minutes=1))

    def test_the_earlier_of_both_limits_wins(self) -> None:
        info = _info(timedelta(0), timedelta(hours=8), schedule_to_close_timeout=timedelta(hours=2))
        self.assertLess(_attempt_stop_time(info), info.started_time + timedelta(hours=2))

    def test_unbounded_or_mocked_info_has_no_stop_time(self) -> None:
        self.assertIsNone(_attempt_stop_time(_info(timedelta(0), None)))
        self.assertIsNone(_attempt_stop_time(MagicMock()))


class RunTaskTimeLimitTests(TestCase):

    def _run(self, task_func, info):
        proxy = MagicMock()
        with patch.object(core.activity, 'info', return_value=info), \
                patch.object(core.activity, 'heartbeat'), \
                patch.object(core.activity, 'logger'), \
                patch.object(core, 'TemporalTaskProxy', return_value=proxy):
            try:
                return _run_task(task_func, {}, task_name='dir_file_fuzz'), proxy
            except Exception as exc:  # noqa: BLE001 - returned for the assertions
                return exc, proxy

    @staticmethod
    def _tool_until_stopped(result):
        def task(self, ctx=None, description=None):
            stop = getattr(_task_cancel_local, 'cancel_event', None)
            stop.wait(10)
            assert stop.is_set(), 'the tool was not told to stop'
            if isinstance(result, Exception):
                raise result
            return result
        return task

    def test_a_tool_cut_off_at_the_limit_keeps_its_results_and_succeeds(self) -> None:
        past_limit = _info(timedelta(hours=8), timedelta(hours=8))

        result, proxy = self._run(self._tool_until_stopped(False), past_limit)

        self.assertIs(result, True, 'a cut-off tool returning nothing must not trigger a full re-run')
        status, = proxy.update_scan_activity.call_args.args
        self.assertEqual(status, SUCCESS_TASK)
        self.assertIn('Stopped at its 8 h time limit', proxy.update_scan_activity.call_args.kwargs['error_message'])
        self.assertIsNone(
            getattr(_task_cancel_local, 'cancel_event', None),
            'a stale stop signal would block every later command on this worker thread',
        )

    def test_a_failure_after_the_stop_is_not_retried(self) -> None:
        past_limit = _info(timedelta(hours=8), timedelta(hours=8))

        result, proxy = self._run(self._tool_until_stopped(ValueError('truncated output')), past_limit)

        self.assertIsInstance(result, ApplicationError)
        self.assertTrue(result.non_retryable)
        self.assertEqual(proxy.update_scan_activity.call_args.args[0], FAILED_TASK)

    def test_a_task_inside_its_limit_is_untouched(self) -> None:
        stopped = threading.Event()

        def task(self, ctx=None, description=None):
            if _task_cancel_local.cancel_event.is_set():
                stopped.set()
            return True

        result, proxy = self._run(task, _info(timedelta(minutes=1), timedelta(hours=8)))

        self.assertIs(result, True)
        self.assertFalse(stopped.is_set())
        self.assertEqual(proxy.update_scan_activity.call_args.args, (SUCCESS_TASK,))

