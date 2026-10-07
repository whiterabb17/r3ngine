"""Aborting a scan cancels a command running on the Go executor straight away.

_run_task hands stream_command a cancel event through a thread-local. The
lookup used to import it from the shim, which never re-exported the
underscore name, so every poll failed silently and cancellation waited for the
slower database check.
"""
import asyncio
import threading
from unittest.mock import AsyncMock, MagicMock, patch

from django.test import TestCase

from reNgine.temporal.activities.core import _task_cancel_local
from reNgine.utils.task import stream_command


class StreamCommandCancelTests(TestCase):

    def tearDown(self):
        _task_cancel_local.cancel_event = None

    def _client(self):
        async def never_finishes():
            await asyncio.Event().wait()

        handle = MagicMock()
        handle.result = never_finishes
        handle.cancel = AsyncMock()
        client = MagicMock()
        client.start_workflow = AsyncMock(return_value=handle)
        return client, handle

    def test_set_cancel_event_cancels_the_executor_workflow(self):
        cancel_event = threading.Event()
        _task_cancel_local.cancel_event = cancel_event
        client, handle = self._client()
        started = client.start_workflow.return_value

        async def start_then_abort(*args, **kwargs):
            cancel_event.set()  # the abort lands while the tool is running
            return started

        client.start_workflow = AsyncMock(side_effect=start_then_abort)

        with patch('reNgine.temporal_client.TemporalClientProvider.get_client', AsyncMock(return_value=client)), \
                patch('asyncio.wait', AsyncMock(side_effect=RuntimeError('reached the 10 s poll'))) as wait:
            lines = list(stream_command('nuclei -u https://app.example.test'))

        handle.cancel.assert_awaited_once()
        wait.assert_not_awaited()  # cancelled before the first 10 s poll slice
        self.assertEqual(lines, ['Scan aborted'])

    def test_no_command_starts_when_the_task_is_already_stopping(self):
        cancel_event = threading.Event()
        cancel_event.set()
        _task_cancel_local.cancel_event = cancel_event
        client, _ = self._client()

        with patch('reNgine.temporal_client.TemporalClientProvider.get_client', AsyncMock(return_value=client)):
            lines = list(stream_command('nuclei -u https://app.example.test'))

        client.start_workflow.assert_not_awaited()
        self.assertEqual(lines, [])
