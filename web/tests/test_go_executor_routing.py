"""Every tool run targets the Go executor co-located with the Python host.

A remote worker's Python orchestrator writes and parses tool output in its own
scan_results volume, so the GoExecutorTaskWorkflow it starts must run on its
own Python queue and dispatch the subprocess to its own Go executor queue.
Without WORKER_NAME (the master) every name must be exactly what it was.
"""
import asyncio
import os
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

from django.test import TestCase
from rest_framework.test import APIRequestFactory

from api.serializers.scan_workers import ScanWorkerSerializer
from reNgine.temporal.workflows.jobs import GoExecutorTaskWorkflow
from reNgine.utils.task import _execute_go_workflow, run_command, stream_command
from reNgine.utils.task_queues import WORKER_NAME_ENV

GET_CLIENT = 'reNgine.temporal_client.TemporalClientProvider.get_client'
RESULT = {'exit_code': 0, 'stdout': 'one\ntwo', 'stderr': ''}


def _master_env():
    env = {k: v for k, v in os.environ.items() if k != WORKER_NAME_ENV}
    return patch.dict(os.environ, env, clear=True)


def _worker_env(name='w1'):
    return patch.dict(os.environ, {WORKER_NAME_ENV: name})


def _client():
    handle = MagicMock()
    handle.result = AsyncMock(return_value=RESULT)
    handle.cancel = AsyncMock()
    client = MagicMock()
    client.start_workflow = AsyncMock(return_value=handle)
    client.execute_workflow = AsyncMock(return_value=RESULT)
    client.get_workflow_handle = MagicMock(return_value=handle)
    return client


def _routing(call_kwargs_and_input):
    """(python task queue, executor queue in the workflow input)."""
    kwargs, input_data = call_kwargs_and_input
    return kwargs['task_queue'], input_data['executor_task_queue']


def _start_call(client):
    call = client.start_workflow.await_args
    return call.kwargs, call.args[1]


def _execute_call(client):
    call = client.execute_workflow.await_args
    return call.kwargs, call.args[1]


class StreamCommandRoutingTests(TestCase):

    def _run(self):
        client = _client()
        with patch(GET_CLIENT, AsyncMock(return_value=client)):
            lines = list(stream_command('nuclei -u https://app.example.test'))
        self.assertEqual(lines, ['one', 'two'])
        self.assertEqual(client.start_workflow.await_args.args[0], 'GoExecutorTaskWorkflow')
        return client

    def test_master_uses_the_legacy_queues(self):
        with _master_env():
            client = self._run()
        self.assertEqual(_routing(_start_call(client)), ('python-orchestrator-queue', 'go-executor-queue'))

    def test_worker_uses_its_own_queues(self):
        with _worker_env('w1'):
            client = self._run()
        self.assertEqual(_routing(_start_call(client)), ('w1', 'go-executor-queue-w1'))

    def test_local_fallback_never_touches_temporal(self):
        client = _client()
        with tempfile.TemporaryDirectory() as tmp:
            # A stand-in binary with a routed tool's name, run locally.
            fake_nuclei = os.path.join(tmp, 'nuclei')
            with open(fake_nuclei, 'w') as fh:
                fh.write('#!/bin/sh\necho local-run\n')
            os.chmod(fake_nuclei, 0o700)
            with _worker_env('w1'), patch(GET_CLIENT, AsyncMock(return_value=client)):
                lines = list(stream_command(f'{fake_nuclei} -version', route_to_executor=False))
        self.assertEqual(lines, ['local-run'])
        client.start_workflow.assert_not_awaited()


class RunCommandRoutingTests(TestCase):

    def _run(self):
        client = _client()
        with patch(GET_CLIENT, AsyncMock(return_value=client)):
            return_code, output = run_command('nmap -sV 192.0.2.10')
        self.assertEqual(return_code, 0)
        self.assertIn('one', output)
        self.assertEqual(client.execute_workflow.await_args.args[0], 'GoExecutorTaskWorkflow')
        return client

    def test_master_uses_the_legacy_queues(self):
        with _master_env():
            client = self._run()
        self.assertEqual(_routing(_execute_call(client)), ('python-orchestrator-queue', 'go-executor-queue'))

    def test_worker_uses_its_own_queues(self):
        with _worker_env('worker-eu-1'):
            client = self._run()
        self.assertEqual(
            _routing(_execute_call(client)),
            ('worker-eu-1', 'go-executor-queue-worker-eu-1'),
        )

    def test_unrouted_tool_runs_locally(self):
        client = _client()
        with _worker_env('w1'), patch(GET_CLIENT, AsyncMock(return_value=client)):
            return_code, output = run_command('echo local-run')
        self.assertEqual((return_code, output.strip()), (0, 'local-run'))
        client.execute_workflow.assert_not_awaited()


class ExecuteGoWorkflowRoutingTests(TestCase):

    def _run(self):
        client = _client()
        with patch(GET_CLIENT, AsyncMock(return_value=client)):
            result = _execute_go_workflow('ffuf -u https://app.example.test/FUZZ', None, 7, 'ffuf')
        self.assertEqual(result, RESULT)
        return client

    def test_master_uses_the_legacy_queues(self):
        with _master_env():
            client = self._run()
        self.assertEqual(_routing(_start_call(client)), ('python-orchestrator-queue', 'go-executor-queue'))

    def test_worker_uses_its_own_queues(self):
        with _worker_env('w1'):
            client = self._run()
        self.assertEqual(_routing(_start_call(client)), ('w1', 'go-executor-queue-w1'))


class GoExecutorTaskWorkflowTests(TestCase):
    """The workflow dispatches to the queue named in its input, never to env."""

    def _run(self, input_data):
        with patch('temporalio.workflow.execute_activity', new_callable=AsyncMock) as execute:
            execute.return_value = RESULT
            result = asyncio.run(GoExecutorTaskWorkflow().run(input_data))
        self.assertEqual(result, RESULT)
        self.assertEqual(execute.await_args.args[0], 'RunToolSubprocessActivity')
        return execute.await_args.kwargs['task_queue']

    def test_dispatches_to_the_executor_queue_from_the_input(self):
        with _master_env():
            queue = self._run({'command': ['nuclei'], 'executor_task_queue': 'go-executor-queue-w1'})
        self.assertEqual(queue, 'go-executor-queue-w1')

    def test_inputs_recorded_before_the_key_existed_replay_on_the_master_queue(self):
        with _worker_env('w1'):
            queue = self._run({'command': ['nuclei'], 'scan_id': 0, 'command_id': 0})
        self.assertEqual(queue, 'go-executor-queue')

    def test_empty_value_falls_back_to_the_master_queue(self):
        queue = self._run({'command': ['nuclei'], 'executor_task_queue': ''})
        self.assertEqual(queue, 'go-executor-queue')


class ScanWorkerNameValidationTests(TestCase):
    """A registered name must be one both queue derivations accept."""

    def _serializer(self, name):
        request = APIRequestFactory().post('/api/workers/')
        return ScanWorkerSerializer(data={'name': name}, context={'request': request})

    def test_valid_name_passes(self):
        serializer = self._serializer('worker-eu-1')
        self.assertTrue(serializer.is_valid(), serializer.errors)

    def test_invalid_names_are_rejected(self):
        for name in ('has space', '-leading', 'semi;colon', 'x' * 101):
            serializer = self._serializer(name)
            self.assertFalse(serializer.is_valid(), name)
            self.assertIn('name', serializer.errors)
