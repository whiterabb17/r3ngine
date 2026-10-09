"""Tests for the time-based output flushing in reNgine.utils.task.stream_command.

The regression these guard against: the output of a streaming tool used to be
written back to its Command row every 10th line with a full-row UPDATE, plus a
SELECT on ScanHistory on the same cadence. A tool emitting 100k lines produced
~10k UPDATEs of a half-megabyte text column. Persisting is now gated on wall
time, so the number of writes depends on how long the tool runs, not on how many
lines it emits.

The clock is faked (never slept on) so the tests stay deterministic.
"""

import unittest
from unittest.mock import MagicMock, patch

from reNgine.utils.task import _COMMAND_OUTPUT_FLUSH_INTERVAL, _COMMAND_OUTPUT_MAX_CHARS


class FakeClock:
    """Monotonic clock whose value only moves when the test says so."""

    def __init__(self, start: float = 1000.0) -> None:
        self.now = start

    def advance(self, seconds: float) -> None:
        self.now += seconds

    def monotonic(self) -> float:
        return self.now


class FakeProcess:
    """Minimal subprocess.Popen stand-in that emits canned lines.

    Reading a line advances the fake clock, which is what lets a test decide how
    long the simulated tool takes without sleeping.
    """

    def __init__(self, lines, clock, seconds_per_line=0.0, returncode=0):
        self._lines = list(lines)
        self._index = 0
        self._clock = clock
        self._seconds_per_line = seconds_per_line
        self.returncode = returncode
        self.pid = 99999
        self.stdout = self

    # -- stdout interface -------------------------------------------------
    def readline(self):
        if self._index >= len(self._lines):
            return ''
        line = self._lines[self._index]
        self._index += 1
        self._clock.advance(self._seconds_per_line)
        return line + '\n'

    def close(self):
        return None

    # -- process interface ------------------------------------------------
    def wait(self, timeout=None):
        return self.returncode

    def poll(self):
        return self.returncode


class StreamCommandFlushTests(unittest.TestCase):
    """stream_command must persist on a timer, not on a line counter."""

    def setUp(self):
        self.clock = FakeClock()
        self.command_obj = MagicMock()
        self.command_obj.id = 1
        self.command_obj.pk = 1
        self.command_obj.output = ''
        self.command_obj.return_code = None

    def _run(self, lines, seconds_per_line, scan_id=None, **kwargs):
        """Drive stream_command over `lines` with a faked clock and subprocess."""
        process = FakeProcess(lines, self.clock, seconds_per_line)
        soc_config = MagicMock(enable_live_log_streaming=False, log_retention_count=1000)
        with patch('subprocess.Popen', return_value=process), \
                patch('time.monotonic', side_effect=self.clock.monotonic), \
                patch('reNgine.utils.task.Command.objects.create', return_value=self.command_obj), \
                patch('reNgine.utils.task.is_scan_aborted', return_value=False) as abort_check, \
                patch('reNgine.utils.task.SOCConfiguration.objects.get_or_create',
                      return_value=(soc_config, False)):
            from reNgine.utils.task import stream_command
            yielded = list(stream_command('echo hello', scan_id=scan_id, **kwargs))
        return yielded, abort_check

    @property
    def _save_calls(self):
        return self.command_obj.save.call_args_list

    def test_save_count_is_bounded_by_elapsed_time_not_line_count(self):
        """500 lines over 62.5 simulated seconds must not mean 50 saves."""
        line_count = 500
        seconds_per_line = 0.125
        lines = [f'result-line-{i:05d}' for i in range(line_count)]

        yielded, _ = self._run(lines, seconds_per_line)

        self.assertEqual(len(yielded), line_count)

        elapsed = line_count * seconds_per_line
        # One save per elapsed flush interval, plus the mandatory final save.
        expected_saves = int(elapsed // _COMMAND_OUTPUT_FLUSH_INTERVAL) + 1
        self.assertEqual(len(self._save_calls), expected_saves)
        # The old behaviour was one save per 10 lines — assert we are well below it.
        self.assertLess(len(self._save_calls), line_count // 10)

    def test_no_intermediate_saves_when_no_time_passes(self):
        """A tool that dumps its whole output instantly costs exactly one write."""
        lines = [f'burst-line-{i:05d}' for i in range(500)]

        self._run(lines, seconds_per_line=0.0)

        self.assertEqual(len(self._save_calls), 1)

    def test_every_save_restricts_update_fields(self):
        """Saves must never rewrite the whole row."""
        lines = [f'result-line-{i:05d}' for i in range(200)]

        self._run(lines, seconds_per_line=0.125)

        self.assertTrue(self._save_calls, "expected at least the final save")
        for call in self._save_calls:
            self.assertIn('update_fields', call.kwargs)
            self.assertIn('output', call.kwargs['update_fields'])
        # Only the final save writes the return code.
        self.assertEqual(
            self._save_calls[-1].kwargs['update_fields'], ['output', 'return_code']
        )

    def test_final_save_contains_the_last_line(self):
        """Whatever the flush cadence, the last line must reach the database."""
        lines = [f'result-line-{i:05d}' for i in range(500)]

        self._run(lines, seconds_per_line=0.125)

        self.assertTrue(self.command_obj.output.endswith('result-line-00499'))
        self.assertIn('result-line-00000', self.command_obj.output)
        self.assertEqual(self.command_obj.return_code, 0)

    def test_output_cap_still_applies_to_the_final_save(self):
        """The 512k cap holds on every persist, including the last one."""
        # ~1 MB of output: twice the cap.
        lines = [f'{i:06d}-' + 'x' * 1000 for i in range(1000)]

        self._run(lines, seconds_per_line=0.125)

        self.assertEqual(len(self.command_obj.output), _COMMAND_OUTPUT_MAX_CHARS)
        self.assertTrue(self.command_obj.output.endswith('x' * 1000))
        # The cap keeps the tail, so the earliest lines are dropped.
        self.assertNotIn('000000-', self.command_obj.output)

    def test_abort_check_runs_on_the_flush_timer(self):
        """The ScanHistory poll shares the flush timer instead of firing per 10 lines."""
        line_count = 500
        seconds_per_line = 0.125
        lines = [f'result-line-{i:05d}' for i in range(line_count)]

        _, abort_check = self._run(lines, seconds_per_line, scan_id=42)

        elapsed = line_count * seconds_per_line
        expected_polls = int(elapsed // _COMMAND_OUTPUT_FLUSH_INTERVAL)
        self.assertEqual(abort_check.call_count, expected_polls)
        self.assertLess(abort_check.call_count, line_count // 10)


if __name__ == '__main__':
    unittest.main()
