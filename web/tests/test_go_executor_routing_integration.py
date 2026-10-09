"""Live check: each host's tool runs reach only that host's Go executor.

Needs a reachable Temporal server (``R3NGINE_TEST_TEMPORAL_HOST``, default
``127.0.0.1:17233``), Redis (``R3NGINE_TEST_REDIS_URL``, default
``redis://127.0.0.1:6379/0``) and either the Go toolchain (the executor is
built from ``web/executor``) or a prebuilt binary in ``R3NGINE_TEST_EXECUTOR_BIN``.

Two executor processes are started the way the two composes start them: one
unnamed (the master, ``go-executor-queue``) and one ``--worker-name w1``
(``go-executor-queue-w1``). A Python worker hosts ``GoExecutorTaskWorkflow`` on
both Python queues. The production call path (``stream_command`` /
``run_command`` from ``reNgine.utils.task``) is then exercised with and without
``WORKER_NAME``; each executor process carries a tag in its environment, which
the tool command echoes back, so the output names the executor that ran it.
The executors' own logs are checked as well: the master's log never shows the
worker's command and vice versa.

Run by hand with::

    RENGINE_TEST_DB_NAME=test_rengine_go DJANGO_SETTINGS_MODULE=reNgine.settings_test_local \\
        python manage.py test tests.test_go_executor_routing_integration --keepdb --noinput
"""
import asyncio
import os
import shutil
import subprocess
import tempfile
import threading
import time
from pathlib import Path
from unittest.mock import patch

from django.test import TestCase, tag

from reNgine.temporal.workflows.jobs import GoExecutorTaskWorkflow
from reNgine.utils.task import run_command, stream_command
from reNgine.utils.task_queues import WORKER_NAME_ENV, go_executor_queue, python_orchestrator_queue

TEMPORAL_HOST = os.environ.get('R3NGINE_TEST_TEMPORAL_HOST', '127.0.0.1:17233')
REDIS_URL = os.environ.get('R3NGINE_TEST_REDIS_URL', 'redis://127.0.0.1:6379/0')
EXECUTOR_SRC = Path(__file__).resolve().parent.parent / 'executor'
WORKER = 'w1'
TAG_ENV = 'R3NGINE_TEST_EXECUTOR_TAG'
# ``nuclei`` puts the command on the routed path; the echo is what we read back.
TOOL_CMD = 'nuclei -version >/dev/null 2>&1; echo ran-by=$%s' % TAG_ENV


def _wait_for(predicate, timeout, what):
    deadline = time.monotonic() + timeout
    while time.monotonic() < deadline:
        if predicate():
            return
        time.sleep(0.2)
    raise AssertionError(f'timed out waiting for {what}')


class _PythonWorkers:
    """GoExecutorTaskWorkflow hosted on the master's and the worker's Python queues."""

    def __init__(self):
        self._loop = None
        self._stop = None
        self._ready = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def start(self):
        self._thread.start()
        if not self._ready.wait(60):
            raise AssertionError('Python workers did not connect to Temporal')

    def stop(self):
        if self._loop and self._stop:
            self._loop.call_soon_threadsafe(self._stop.set)
        self._thread.join(30)

    def _run(self):
        asyncio.run(self._main())

    async def _main(self):
        from temporalio.client import Client
        from temporalio.worker import UnsandboxedWorkflowRunner, Worker

        self._loop = asyncio.get_running_loop()
        self._stop = asyncio.Event()
        client = await Client.connect(TEMPORAL_HOST)
        workers = [
            Worker(client, task_queue=queue, workflows=[GoExecutorTaskWorkflow],
                   workflow_runner=UnsandboxedWorkflowRunner())
            for queue in (python_orchestrator_queue(''), python_orchestrator_queue(WORKER))
        ]
        async with workers[0], workers[1]:
            self._ready.set()
            await self._stop.wait()


@tag('integration')
class GoExecutorRoutingIntegrationTests(TestCase):

    @classmethod
    def setUpClass(cls):
        super().setUpClass()
        cls.tmp = Path(tempfile.mkdtemp(prefix='p10go-'))
        cls.binary = cls._executor_binary()
        cls.procs = {}
        cls.logs = {}
        cls.workers = None
        try:
            cls._start_executor('master', [])
            cls._start_executor(WORKER, ['--worker-name', WORKER])
            _wait_for(lambda: all('serving task queue' in cls._log(t) for t in cls.procs), 30, 'executors to start')
            cls.workers = _PythonWorkers()
            cls.workers.start()
        except BaseException:
            # tearDownClass does not run when setUpClass fails; a leaked
            # executor would keep polling the queues and steal the next run's jobs.
            cls._stop_everything()
            raise

    @classmethod
    def tearDownClass(cls):
        cls._stop_everything()
        super().tearDownClass()

    @classmethod
    def _stop_everything(cls):
        if cls.workers:
            cls.workers.stop()
        for proc in cls.procs.values():
            proc.terminate()
            try:
                proc.wait(10)
            except subprocess.TimeoutExpired:
                proc.kill()
        for log in cls.logs.values():
            log.close()
        shutil.rmtree(cls.tmp, ignore_errors=True)

    @classmethod
    def _executor_binary(cls):
        prebuilt = os.environ.get('R3NGINE_TEST_EXECUTOR_BIN')
        if prebuilt:
            return prebuilt
        binary = cls.tmp / 'r3ngine-executor'
        subprocess.run(
            ['go', 'build', '-o', str(binary), '.'],
            cwd=EXECUTOR_SRC, check=True, env={**os.environ, 'CGO_ENABLED': '0'},
        )
        return str(binary)

    @classmethod
    def _start_executor(cls, tag_value, args):
        log = open(cls.tmp / f'{tag_value}.log', 'w+')
        env = {k: v for k, v in os.environ.items() if k != WORKER_NAME_ENV}
        env.update({'TEMPORAL_HOST': TEMPORAL_HOST, 'REDIS_URL': REDIS_URL, TAG_ENV: tag_value})
        cls.logs[tag_value] = log
        cls.procs[tag_value] = subprocess.Popen(
            [cls.binary, *args], env=env, stdout=log, stderr=subprocess.STDOUT,
        )

    @classmethod
    def _log(cls, tag_value):
        with open(cls.logs[tag_value].name) as fh:
            return fh.read()

    def _temporal_env(self, worker_name):
        env = {'TEMPORAL_HOST': TEMPORAL_HOST}
        if worker_name:
            env[WORKER_NAME_ENV] = worker_name
        ctx = patch.dict(os.environ, env)
        ctx.__enter__()
        self.addCleanup(ctx.__exit__, None, None, None)
        if not worker_name:
            os.environ.pop(WORKER_NAME_ENV, None)

    def test_executors_announce_their_queues(self):
        self.assertIn('serving task queue go-executor-queue\n', self._log('master'))
        self.assertIn(f'serving task queue go-executor-queue-{WORKER}\n', self._log(WORKER))

    def test_master_stream_command_runs_on_the_master_executor(self):
        self._temporal_env('')
        lines = list(stream_command(TOOL_CMD))
        self.assertEqual(lines, ['ran-by=master'])

    def test_worker_stream_command_runs_on_the_worker_executor(self):
        self._temporal_env(WORKER)
        lines = list(stream_command(TOOL_CMD))
        self.assertEqual(lines, [f'ran-by={WORKER}'])

    def test_worker_run_command_runs_on_the_worker_executor(self):
        self._temporal_env(WORKER)
        return_code, output = run_command(TOOL_CMD)
        self.assertEqual(return_code, 0)
        self.assertIn(f'ran-by={WORKER}', output)

    def test_master_run_command_runs_on_the_master_executor(self):
        self._temporal_env('')
        return_code, output = run_command(TOOL_CMD)
        self.assertEqual(return_code, 0)
        self.assertIn('ran-by=master', output)

    def test_each_executor_log_shows_only_its_own_jobs(self):
        marker_master = f'marker-{time.time_ns()}-master'
        marker_worker = f'marker-{time.time_ns()}-worker'
        self._temporal_env('')
        list(stream_command(f'nuclei -version >/dev/null 2>&1; echo {marker_master}'))
        self._temporal_env(WORKER)
        list(stream_command(f'nuclei -version >/dev/null 2>&1; echo {marker_worker}'))

        master_log, worker_log = self._log('master'), self._log(WORKER)
        self.assertIn(marker_master, master_log)
        self.assertNotIn(marker_master, worker_log)
        self.assertIn(marker_worker, worker_log)
        self.assertNotIn(marker_worker, master_log)

    def test_helpers_name_the_queues_the_executors_poll(self):
        self.assertEqual(go_executor_queue(''), 'go-executor-queue')
        self.assertEqual(go_executor_queue(WORKER), f'go-executor-queue-{WORKER}')
