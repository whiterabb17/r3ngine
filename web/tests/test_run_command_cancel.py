"""run_command must honor Temporal soft time-limits and abort cancel_event.

Quiet tools (little/no stdout) used to block forever on readline() because the
timeout only started after stdout EOF. smugglex --fuzz on large URL lists was
the production case: TIME_LIMIT fired but the process kept running for hours.
"""
import threading
import time
from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase

from reNgine.temporal.activities.core import _task_cancel_local
from reNgine.utils.task import run_command, _subprocess_timeout_watchdog


class RunCommandCancelTests(SimpleTestCase):

    def tearDown(self):
        _task_cancel_local.cancel_event = None

    def test_no_command_starts_when_the_task_is_already_stopping(self):
        cancel_event = threading.Event()
        cancel_event.set()
        _task_cancel_local.cancel_event = cancel_event

        with patch('reNgine.utils.task.Command.objects.create') as create, \
                patch('reNgine.utils.task.subprocess.Popen') as popen:
            code, output = run_command('smugglex --json -o /tmp/out.json')

        self.assertEqual(code, -1)
        self.assertEqual(output, '')
        create.assert_not_called()
        popen.assert_not_called()

    def test_watchdog_kills_on_cancel_event(self):
        cancel_event = threading.Event()
        proc = MagicMock()
        proc.poll.return_value = None
        proc.pid = 4242
        proc.stdout = MagicMock()
        cancel_event.set()  # already stopping when the watchdog polls

        with patch('reNgine.utils.task.os.getpgid', return_value=4242), \
                patch('reNgine.utils.task.os.killpg') as killpg, \
                patch('time.sleep', return_value=None):
            _subprocess_timeout_watchdog(
                proc, timeout_sec=60, cancel_event=cancel_event, cmd='smugglex --fuzz',
            )

        killpg.assert_called()
        proc.stdout.close.assert_called()

    def test_watchdog_kills_on_wall_clock_timeout(self):
        proc = MagicMock()
        proc.poll.return_value = None
        proc.pid = 4243
        proc.stdout = MagicMock()

        # start → loop check past deadline → post-kill poll
        monotonic_values = iter([100.0, 102.0, 102.0])

        with patch('reNgine.utils.task.os.getpgid', return_value=4243), \
                patch('reNgine.utils.task.os.killpg') as killpg, \
                patch('time.sleep', return_value=None), \
                patch('time.monotonic', side_effect=lambda: next(monotonic_values)):
            _subprocess_timeout_watchdog(
                proc, timeout_sec=1, cancel_event=None, cmd='smugglex --fuzz',
            )

        killpg.assert_called()
        proc.stdout.close.assert_called()

    def test_run_command_wires_watchdog_for_local_tools(self):
        """Local (non-ROUTED) commands start the timeout/cancel watchdog."""
        fake_proc = MagicMock()
        fake_proc.stdout.readline.side_effect = ['line1\n', '']
        fake_proc.wait.return_value = 0
        fake_proc.poll.return_value = 0
        fake_proc.returncode = 0
        fake_proc.pid = 99

        with patch('reNgine.utils.task.Command.objects.create', return_value=MagicMock(id=1)), \
                patch('reNgine.utils.task.persist_command_output'), \
                patch('reNgine.utils.task._init_redis_logging', return_value=(None, None)), \
                patch('reNgine.utils.task.subprocess.Popen', return_value=fake_proc), \
                patch('reNgine.utils.task.threading.Thread') as thread_cls, \
                patch('reNgine.utils.task.is_scan_aborted', return_value=False):
            thread_cls.return_value = MagicMock()
            code, _ = run_command('echo hello', timeout=30)

        self.assertEqual(code, 0)
        watchdog_calls = [
            c for c in thread_cls.call_args_list
            if c.kwargs.get('target') is _subprocess_timeout_watchdog
        ]
        self.assertEqual(len(watchdog_calls), 1)
        self.assertEqual(watchdog_calls[0].kwargs.get('args')[1], 30)

    def test_quiet_tool_db_abort_is_not_reported_as_timeout(self):
        """Watchdog kill on ABORTED_TASK must return -1, not 124."""
        fake_proc = MagicMock()
        # Quiet tool: first readline blocks until stdout is closed by watchdog path;
        # simulate EOF after the child was killed for abort.
        fake_proc.stdout.readline.side_effect = ['']
        fake_proc.wait.return_value = -9
        fake_proc.poll.return_value = -9
        fake_proc.returncode = -9
        fake_proc.pid = 77

        with patch('reNgine.utils.task.Command.objects.create', return_value=MagicMock(id=2)), \
                patch('reNgine.utils.task.persist_command_output'), \
                patch('reNgine.utils.task._init_redis_logging', return_value=(None, None)), \
                patch('reNgine.utils.task.subprocess.Popen', return_value=fake_proc), \
                patch('reNgine.utils.task.threading.Thread') as thread_cls, \
                patch('reNgine.utils.task.is_scan_aborted', return_value=True):
            thread_cls.return_value = MagicMock()
            code, output = run_command('smugglex --fuzz', scan_id=9, timeout=30)

        self.assertEqual(code, -1)
        self.assertNotIn('timed out', output.lower())
