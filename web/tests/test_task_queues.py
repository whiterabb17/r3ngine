"""Queue names for the current host (reNgine.utils.task_queues).

The master keeps the historical names exactly; a worker gets its Python queue
named after it and a Go executor queue suffixed with its name. The Go side
(web/executor/queue.go) derives the same names from the same variable, so the
charset and the suffix rule tested here are a contract, not an implementation
detail.
"""
import os
import unittest
from unittest.mock import patch

from reNgine.utils import task_queues
from reNgine.utils.task_queues import (
    GO_EXECUTOR_QUEUE,
    PYTHON_ORCHESTRATOR_QUEUE,
    WORKER_NAME_ENV,
    configure_worker_name,
    get_worker_name,
    go_executor_queue,
    python_orchestrator_queue,
    validate_worker_name,
)


def _env(**values):
    env = {k: v for k, v in os.environ.items() if k != WORKER_NAME_ENV}
    env.update(values)
    return patch.dict(os.environ, env, clear=True)


class MasterQueueNamesTests(unittest.TestCase):

    def test_unset_worker_name_keeps_legacy_names(self):
        with _env():
            self.assertEqual(get_worker_name(), '')
            self.assertEqual(python_orchestrator_queue(), 'python-orchestrator-queue')
            self.assertEqual(go_executor_queue(), 'go-executor-queue')

    def test_blank_worker_name_is_the_master(self):
        with _env(WORKER_NAME='   '):
            self.assertEqual(get_worker_name(), '')
            self.assertEqual(go_executor_queue(), GO_EXECUTOR_QUEUE)
            self.assertEqual(python_orchestrator_queue(), PYTHON_ORCHESTRATOR_QUEUE)

    def test_constants_match_the_go_executor_and_orchestrator_defaults(self):
        self.assertEqual(GO_EXECUTOR_QUEUE, 'go-executor-queue')
        self.assertEqual(PYTHON_ORCHESTRATOR_QUEUE, 'python-orchestrator-queue')


class WorkerQueueNamesTests(unittest.TestCase):

    def test_worker_name_from_env_names_both_queues(self):
        with _env(WORKER_NAME='w1'):
            self.assertEqual(get_worker_name(), 'w1')
            self.assertEqual(python_orchestrator_queue(), 'w1')
            self.assertEqual(go_executor_queue(), 'go-executor-queue-w1')

    def test_env_value_is_stripped(self):
        with _env(WORKER_NAME=' worker-eu-1\n'):
            self.assertEqual(go_executor_queue(), 'go-executor-queue-worker-eu-1')

    def test_explicit_name_overrides_the_environment(self):
        with _env(WORKER_NAME='w1'):
            self.assertEqual(go_executor_queue('w2'), 'go-executor-queue-w2')
            self.assertEqual(python_orchestrator_queue('w2'), 'w2')
            # An explicit empty name means "the master", whatever the env says.
            self.assertEqual(go_executor_queue(''), 'go-executor-queue')
            self.assertEqual(python_orchestrator_queue(''), 'python-orchestrator-queue')

    def test_invalid_env_value_raises_instead_of_routing_nowhere(self):
        with _env(WORKER_NAME='bad name'):
            with self.assertRaises(ValueError):
                get_worker_name()
            with self.assertRaises(ValueError):
                go_executor_queue()


class ValidateWorkerNameTests(unittest.TestCase):

    def test_accepts_the_shared_charset(self):
        for name in ('w1', 'worker-eu-1', 'Node_2.prod', '9', 'x' * 100):
            self.assertEqual(validate_worker_name(name), name)

    def test_rejects_everything_else(self):
        for name in ('', '-leading', '.leading', 'has space', 'semi;colon', 'a/b',
                     'tab\tname', 'ünïcode', 'a$b', 'x' * 101, None, 42):
            with self.assertRaises(ValueError, msg=repr(name)):
                validate_worker_name(name)

    def test_pattern_is_the_one_documented_for_go(self):
        # queue.go compiles the same literal; keep them in step.
        self.assertEqual(task_queues.WORKER_NAME_PATTERN, r'^[A-Za-z0-9][A-Za-z0-9._-]{0,99}$')


class ConfigureWorkerNameTests(unittest.TestCase):

    def test_flag_wins_and_is_exported(self):
        with _env(WORKER_NAME='from-env'):
            self.assertEqual(configure_worker_name('from-flag'), 'from-flag')
            self.assertEqual(os.environ[WORKER_NAME_ENV], 'from-flag')
            self.assertEqual(go_executor_queue(), 'go-executor-queue-from-flag')
            self.assertEqual(python_orchestrator_queue(), 'from-flag')

    def test_falls_back_to_env(self):
        with _env(WORKER_NAME='from-env'):
            self.assertEqual(configure_worker_name(None), 'from-env')
            self.assertEqual(configure_worker_name(''), 'from-env')

    def test_master_has_no_name(self):
        with _env():
            self.assertEqual(configure_worker_name(None), '')
            self.assertNotIn(WORKER_NAME_ENV, os.environ)

    def test_invalid_flag_is_rejected_before_export(self):
        with _env():
            with self.assertRaises(ValueError):
                configure_worker_name('bad name')
            self.assertNotIn(WORKER_NAME_ENV, os.environ)
