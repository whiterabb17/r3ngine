"""Tests for the Docker-API-free service restart (reNgine.utils.process_restart)
and the plugin restart-server endpoint that uses it."""
import signal
import unittest
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient

from reNgine.utils import process_restart

RESTART_URL = '/api/plugins/restart-server/'


def _tree(parents: dict, comm1: str = 'docker-init'):
    """Patch the /proc readers with a fake process tree {pid: ppid}."""
    return (
        patch.object(process_restart, 'parent_pid', side_effect=lambda pid: parents.get(pid)),
        patch.object(process_restart, 'process_comm', side_effect=lambda pid: comm1 if pid == 1 else 'python'),
    )


class ServiceRootPidTests(unittest.TestCase):

    def test_gunicorn_worker_under_tini_targets_the_master(self):
        # tini(1) -> gunicorn master(50) -> worker(100)
        with _tree({100: 50, 50: 1})[0], _tree({100: 50, 50: 1})[1]:
            self.assertEqual(process_restart.service_root_pid(100), 50)

    def test_runserver_child_under_entrypoint_shell_targets_the_shell(self):
        # tini(1) -> bash entrypoint(20) -> autoreloader(30) -> runserver(100)
        parents, comm = _tree({100: 30, 30: 20, 20: 1}, comm1='tini')
        with parents, comm:
            self.assertEqual(process_restart.service_root_pid(100), 20)

    def test_direct_child_of_init_targets_itself(self):
        parents, comm = _tree({100: 1}, comm1='docker-init')
        with parents, comm:
            self.assertEqual(process_restart.service_root_pid(100), 100)

    def test_master_as_pid_one_without_init_targets_pid_one(self):
        # No init layer: gunicorn(1) -> worker(100). Killing the worker would
        # only make the master respawn it.
        parents, comm = _tree({100: 1}, comm1='gunicorn')
        with parents, comm:
            self.assertEqual(process_restart.service_root_pid(100), 1)

    def test_pid_one_targets_itself(self):
        self.assertEqual(process_restart.service_root_pid(1), 1)

    def test_parent_pid_parses_stat_with_spaces_in_comm(self):
        with patch.object(process_restart, '_read_proc', return_value='100 (my prog (x)) S 50 100 100 0 -1'):
            self.assertEqual(process_restart.parent_pid(100), 50)

    def test_parent_pid_is_none_when_proc_unreadable(self):
        with patch.object(process_restart, '_read_proc', return_value=None):
            self.assertIsNone(process_restart.parent_pid(100))


class RestartTests(unittest.TestCase):

    def test_restart_now_sends_sigterm_to_the_service_root(self):
        sent = []
        with patch.object(process_restart, 'service_root_pid', return_value=50), \
                patch.object(process_restart, 'process_comm', return_value='gunicorn'):
            target = process_restart.restart_service_now(kill=lambda pid, sig: sent.append((pid, sig)))
        self.assertEqual(target, 50)
        self.assertEqual(sent, [(50, signal.SIGTERM)])

    def test_scheduled_restart_waits_then_signals(self):
        sent, slept = [], []
        with patch.object(process_restart, 'service_root_pid', return_value=50), \
                patch.object(process_restart, 'process_comm', return_value='gunicorn'):
            thread = process_restart.schedule_service_restart(
                2.5, reason='test', kill=lambda pid, sig: sent.append((pid, sig)), sleep=slept.append,
            )
            thread.join(5)
        self.assertFalse(thread.is_alive())
        self.assertEqual(slept, [2.5])
        self.assertEqual(sent, [(50, signal.SIGTERM)])

    def test_scheduled_restart_logs_and_swallows_kill_errors(self):
        def failing_kill(pid, sig):
            raise ProcessLookupError(pid)

        with patch.object(process_restart, 'service_root_pid', return_value=50), \
                patch.object(process_restart, 'process_comm', return_value=''), \
                self.assertLogs(process_restart.logger, level='ERROR'):
            thread = process_restart.schedule_service_restart(0, kill=failing_kill, sleep=lambda _s: None)
            thread.join(5)
        self.assertFalse(thread.is_alive())


class PluginRestartServerViewTests(TestCase):
    """The endpoint signals the orchestrator over Redis and schedules its own restart."""

    def setUp(self):
        User = get_user_model()
        self.admin = User.objects.create_superuser(username='plugin-admin', password='x', email='a@example.test')
        self.client = APIClient()
        self.client.force_login(self.admin)

    def test_restart_server_uses_process_restart_not_docker(self):
        with patch('redis.StrictRedis') as redis_cls, \
                patch('reNgine.utils.process_restart.schedule_service_restart') as schedule:
            res = self.client.post(RESTART_URL)
        self.assertEqual(res.status_code, 200, res.content)
        self.assertTrue(res.json().get('success'))
        redis_cls.return_value.publish.assert_called_once_with('orchestrator_control', 'restart')
        schedule.assert_called_once()

    def test_restart_server_still_restarts_web_when_redis_is_down(self):
        with patch('redis.StrictRedis', side_effect=ConnectionError('redis down')), \
                patch('reNgine.utils.process_restart.schedule_service_restart') as schedule:
            res = self.client.post(RESTART_URL)
        self.assertEqual(res.status_code, 200, res.content)
        schedule.assert_called_once()
