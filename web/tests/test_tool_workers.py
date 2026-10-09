"""Tests for reNgine.tool_workers: local probes on the tool host and the
Temporal dispatch used by processes that are not the tool host.

No Docker socket is involved any more. Subprocesses, Temporal and the
filesystem are stubbed; the sync path is covered end to end with a fake
orchestrator answer.
"""
import os
import subprocess
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

from django.test import SimpleTestCase, TestCase

from reNgine import tool_workers
from reNgine.tool_workers import (
    ToolProbeError,
    WORKER_ROLE_ENV,
    clear_resolve_cache,
    decode_worker_path,
    dispatch_probe,
    encode_worker_path,
    help_on_path_local,
    probe_is_local,
    resolve_on_workers,
    run_help_on_workers,
    run_probe_op,
    run_version_on_workers,
    version_argv,
    which_local,
    worker_probe_summary,
)


def _completed(stdout='', stderr='', returncode=0):
    return subprocess.CompletedProcess(args=[], returncode=returncode, stdout=stdout, stderr=stderr)


SUBSTANTIVE_HELP = 'Usage: tool [flags]\n\nFlags:\n' + ''.join(f'  --flag{i} int  option {i}\n' for i in range(6))
INDEX_ONLY_HELP = 'Available Commands:\n  scan   run a scan\n  help   help\n\nFlags:\n  -h, --help\n'


class EncodedPathTests(SimpleTestCase):

    def test_roundtrip_and_plain_paths(self):
        self.assertEqual(encode_worker_path('python', '/usr/local/bin/kr'), 'python:/usr/local/bin/kr')
        self.assertEqual(decode_worker_path('python:/usr/local/bin/kr'), ('python', '/usr/local/bin/kr'))
        self.assertEqual(decode_worker_path('go:/usr/local/bin/kr'), ('go', '/usr/local/bin/kr'))
        self.assertEqual(decode_worker_path('/usr/local/bin/nuclei'), (None, '/usr/local/bin/nuclei'))
        self.assertEqual(decode_worker_path(''), (None, None))
        self.assertEqual(decode_worker_path(None), (None, None))

    def test_role_comes_from_the_environment(self):
        with patch.dict(os.environ, {WORKER_ROLE_ENV: 'python'}):
            self.assertTrue(probe_is_local())
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(WORKER_ROLE_ENV, None)
            self.assertFalse(probe_is_local())

    def test_version_argv_reanchors_on_the_resolved_path(self):
        self.assertEqual(version_argv('/opt/bin/naabu', None), ['/opt/bin/naabu', '--version'])
        self.assertEqual(version_argv('/opt/bin/naabu', 'naabu -version'), ['/opt/bin/naabu', '-version'])
        self.assertEqual(version_argv('/opt/bin/naabu', '/usr/bin/naabu -v'), ['/opt/bin/naabu', '-v'])
        self.assertEqual(version_argv('/opt/bin/naabu', '/usr/bin/other -v'), ['/usr/bin/other', '-v'])
        self.assertEqual(version_argv('/opt/bin/naabu', 'python3 -m tool --version'),
                         ['/opt/bin/naabu', '-m', 'tool', '--version'])


class LocalProbeTests(SimpleTestCase):
    """This process is the tool host (R3NGINE_WORKER_ROLE set)."""

    def setUp(self):
        clear_resolve_cache()
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.binary = os.path.join(self.tmp.name, 'theHarvester')
        with open(self.binary, 'w', encoding='utf-8') as fh:
            fh.write('#!/bin/sh\n')
        os.chmod(self.binary, 0o700)  # executable by the owner only
        self.env = patch.dict(os.environ, {WORKER_ROLE_ENV: 'python', 'PATH': '/nonexistent'})
        self.env.start()
        self.addCleanup(self.env.stop)
        self.dirs = patch.object(tool_workers, '_REMOTE_PATH_DIRS', (self.tmp.name,))
        self.dirs.start()
        self.addCleanup(self.dirs.stop)

    def test_which_local_finds_case_insensitive_match_in_probe_dirs(self):
        self.assertEqual(which_local(['theharvester']), self.binary)
        self.assertEqual(which_local(['theHarvester']), self.binary)
        self.assertIsNone(which_local(['nothere']))

    def test_resolve_answers_locally_without_temporal(self):
        with patch.object(tool_workers, 'dispatch_probe') as dispatch:
            found = resolve_on_workers('theHarvester', ['theHarvester', 'theharvester'])
        dispatch.assert_not_called()
        self.assertEqual(found['role'], 'python')
        self.assertEqual(found['path'], self.binary)
        self.assertTrue(found['container'])

    def test_resolve_result_is_cached_per_process(self):
        resolve_on_workers('x', ['theharvester'])
        with patch.object(tool_workers, 'which_local') as which:
            resolve_on_workers('x', ['theharvester'])
        which.assert_not_called()

    def test_version_runs_the_binary_here(self):
        with patch.object(tool_workers.subprocess, 'run', return_value=_completed('theHarvester 4.6.0\n')) as run:
            text, error = run_version_on_workers(role='python', path=self.binary, version_lookup_command='theHarvester --version')
        self.assertIsNone(error)
        self.assertIn('4.6.0', text)
        self.assertEqual(run.call_args[0][0], [self.binary, '--version'])
        self.assertFalse(run.call_args[1]['shell'])

    def test_version_reports_a_missing_binary(self):
        text, error = run_version_on_workers(role='go', path='/nonexistent/kr')
        self.assertEqual(text, '')
        self.assertIn('not present', error)

    def test_version_rejects_unknown_roles(self):
        self.assertEqual(run_version_on_workers(role='ruby', path=self.binary)[1], "unknown worker role 'ruby'")

    def test_help_prefers_substantive_subcommand_help(self):
        calls = []

        def fake_run(argv, **_kwargs):
            calls.append(argv)
            if argv[1:] == ['scan', '--help']:
                return _completed(SUBSTANTIVE_HELP)
            return _completed(INDEX_ONLY_HELP)

        with patch.object(tool_workers.subprocess, 'run', side_effect=fake_run):
            text, flag = help_on_path_local(self.binary, subcommands=('scan',))
        self.assertEqual(flag, 'scan --help')
        self.assertIn('--flag3', text)
        self.assertEqual(calls[0], [self.binary, 'scan', '--help'])

    def test_help_falls_back_to_thin_root_help(self):
        with patch.object(tool_workers.subprocess, 'run', return_value=_completed(INDEX_ONLY_HELP)):
            text, flag = help_on_path_local(self.binary)
        self.assertEqual(flag, '--help')
        self.assertIn('Available Commands', text)

    def test_run_help_on_workers_returns_an_encoded_path(self):
        with patch.object(tool_workers.subprocess, 'run', return_value=_completed(SUBSTANTIVE_HELP)):
            text, flag, encoded = run_help_on_workers(tool_name='theHarvester', candidates=['theharvester'])
        self.assertTrue(text)
        self.assertEqual(encoded, f'python:{self.binary}')

    def test_run_help_on_workers_uses_the_stored_path_first(self):
        with patch.object(tool_workers.subprocess, 'run', return_value=_completed(SUBSTANTIVE_HELP)) as run:
            run_help_on_workers(tool_name='x', candidates=['nothere'], encoded_path=f'go:{self.binary}')
        self.assertEqual(run.call_args_list[0][0][0][0], self.binary)

    def test_help_timeout_and_missing_binary_give_no_text(self):
        with patch.object(tool_workers.subprocess, 'run', side_effect=subprocess.TimeoutExpired('x', 1)):
            self.assertEqual(run_help_on_workers(tool_name='x', candidates=['theharvester']), ('', '', None))
        self.assertEqual(run_help_on_workers(tool_name='x', candidates=['nothere']), ('', '', None))

    def test_summary_is_local(self):
        summary = worker_probe_summary()
        self.assertEqual(summary['mode'], 'local')
        self.assertEqual(summary['role'], 'python')
        self.assertEqual(summary['workers'][0]['role'], 'python')


class ProbeOpTests(SimpleTestCase):
    """run_probe_op is the activity body; each op answers with plain dicts."""

    def setUp(self):
        clear_resolve_cache()
        self.env = patch.dict(os.environ, {WORKER_ROLE_ENV: 'python'})
        self.env.start()
        self.addCleanup(self.env.stop)

    def test_resolve_op(self):
        with patch.object(tool_workers, 'which_local', return_value='/usr/local/bin/kr'):
            result = run_probe_op('resolve', {'candidates': ['kr']})
        self.assertEqual(result['found']['path'], '/usr/local/bin/kr')
        self.assertEqual(result['found']['role'], 'python')
        with patch.object(tool_workers, 'which_local', return_value=None):
            self.assertEqual(run_probe_op('resolve', {'candidates': ['kr']}), {'found': None})

    def test_version_and_help_ops(self):
        with patch.object(tool_workers, '_version_local', return_value=('v1.0.0', None)):
            self.assertEqual(run_probe_op('version', {'path': '/x'}), {'output': 'v1.0.0', 'error': None})
        with patch.object(tool_workers, '_help_local', return_value=('help', '--help', 'python:/x')):
            self.assertEqual(
                run_probe_op('help', {'tool_name': 'x', 'candidates': ['x']}),
                {'help_text': 'help', 'flag': '--help', 'encoded_path': 'python:/x'},
            )

    def test_summary_and_sync_ops(self):
        self.assertEqual(run_probe_op('summary')['mode'], 'local')
        with patch('reNgine.tool_inventory.sync_installed_tools', return_value={'present': 3}) as sync:
            self.assertEqual(run_probe_op('sync', {'probe_versions': False}), {'present': 3})
        sync.assert_called_once_with(probe_versions=False)

    def test_unknown_op_is_rejected(self):
        with self.assertRaises(ValueError):
            run_probe_op('exec', {'argv': ['rm', '-rf', '/']})


class RemoteDispatchTests(SimpleTestCase):
    """This process is not the tool host: every probe goes to the orchestrator."""

    def setUp(self):
        clear_resolve_cache()
        self.env = patch.dict(os.environ, {}, clear=False)
        self.env.start()
        os.environ.pop(WORKER_ROLE_ENV, None)
        self.addCleanup(self.env.stop)

    def test_dispatch_starts_the_probe_workflow_on_the_python_queue(self):
        client = MagicMock()
        client.execute_workflow = AsyncMock(return_value={'mode': 'local', 'role': 'python', 'workers': []})
        with patch('reNgine.temporal_client.TemporalClientProvider.get_client', AsyncMock(return_value=client)):
            result = dispatch_probe('summary', {})
        self.assertEqual(result['role'], 'python')
        kwargs = client.execute_workflow.call_args.kwargs
        self.assertEqual(client.execute_workflow.call_args.args[0], 'ToolProbeWorkflow')
        self.assertEqual(kwargs['args'], ['summary', {}])
        self.assertEqual(kwargs['task_queue'], 'python-orchestrator-queue')
        self.assertTrue(kwargs['id'].startswith('tool-probe-summary-'))

    def test_dispatch_wraps_connection_failures(self):
        with patch('reNgine.temporal_client.TemporalClientProvider.get_client',
                   AsyncMock(side_effect=RuntimeError('no temporal'))):
            with self.assertRaises(ToolProbeError):
                dispatch_probe('summary')

    def test_dispatch_rejects_non_dict_answers(self):
        client = MagicMock()
        client.execute_workflow = AsyncMock(return_value='nope')
        with patch('reNgine.temporal_client.TemporalClientProvider.get_client', AsyncMock(return_value=client)):
            with self.assertRaises(ToolProbeError):
                dispatch_probe('summary')

    def test_resolve_uses_the_orchestrator_answer(self):
        answer = {'found': {'role': 'python', 'container': 'orch', 'path': '/usr/local/bin/kr'}}
        with patch.object(tool_workers, 'dispatch_probe', return_value=answer) as dispatch:
            found = resolve_on_workers('kiterunner', ['kr', 'kiterunner'])
        dispatch.assert_called_once_with('resolve', {'candidates': ['kr', 'kiterunner']})
        self.assertEqual(found['path'], '/usr/local/bin/kr')

    def test_resolve_failure_is_not_cached(self):
        with patch.object(tool_workers, 'dispatch_probe', side_effect=ToolProbeError('down')):
            self.assertIsNone(resolve_on_workers('kiterunner', ['kr']))
        answer = {'found': {'role': 'python', 'container': 'orch', 'path': '/usr/local/bin/kr'}}
        with patch.object(tool_workers, 'dispatch_probe', return_value=answer):
            self.assertEqual(resolve_on_workers('kiterunner', ['kr'])['path'], '/usr/local/bin/kr')

    def test_help_and_version_and_summary_go_remote(self):
        with patch.object(tool_workers, 'dispatch_probe', return_value={
            'help_text': 'Flags:', 'flag': '-h', 'encoded_path': 'python:/usr/local/bin/kr',
        }):
            self.assertEqual(
                run_help_on_workers(tool_name='kr', candidates=['kr']),
                ('Flags:', '-h', 'python:/usr/local/bin/kr'),
            )
        with patch.object(tool_workers, 'dispatch_probe', return_value={'output': 'kr 1.0.2', 'error': None}):
            self.assertEqual(run_version_on_workers(role='go', path='/usr/local/bin/kr'), ('kr 1.0.2', None))
        summary = {'role': 'python', 'workers': [{'role': 'python', 'name': 'orch'}]}
        with patch.object(tool_workers, 'dispatch_probe', return_value=summary):
            self.assertEqual(worker_probe_summary()['mode'], 'remote')

    def test_unreachable_orchestrator_degrades_quietly(self):
        with patch.object(tool_workers, 'dispatch_probe', side_effect=ToolProbeError('down')):
            self.assertEqual(run_help_on_workers(tool_name='kr', candidates=['kr']), ('', '', None))
            self.assertEqual(run_version_on_workers(role='go', path='/x')[0], '')
            self.assertEqual(worker_probe_summary(), {'mode': 'unavailable', 'role': None, 'workers': []})


class InventorySyncDispatchTests(TestCase):

    def setUp(self):
        self.env = patch.dict(os.environ, {}, clear=False)
        self.env.start()
        os.environ.pop(WORKER_ROLE_ENV, None)
        self.addCleanup(self.env.stop)

    def test_sync_from_web_runs_on_the_orchestrator(self):
        from reNgine.tool_inventory import sync_installed_tools

        answer = {'present': 5, 'missing': 1, 'errors': 0, 'total': 6, 'synced_at': 'now',
                  'workers': {'mode': 'local', 'role': 'python', 'workers': []}}
        with patch('reNgine.tool_workers.dispatch_probe', return_value=answer) as dispatch:
            result = sync_installed_tools(probe_versions=False)
        dispatch.assert_called_once_with('sync', {'probe_versions': False})
        self.assertEqual(result['present'], 5)
        self.assertEqual(result['workers']['mode'], 'remote')

    def test_sync_falls_back_to_this_host_when_orchestrator_is_down(self):
        from reNgine.tool_inventory import sync_installed_tools
        from scanEngine.models import InstalledExternalTool

        InstalledExternalTool.objects.create(
            name='__nowhere_tool__', description='x', github_url='https://example.test',
            install_command='echo x', is_default=True,
        )
        with patch('reNgine.tool_workers.dispatch_probe', side_effect=ToolProbeError('down')), \
                patch('reNgine.tool_inventory.resolve_binary_path', return_value=None):
            result = sync_installed_tools(probe_versions=False)
        self.assertEqual(result['workers']['mode'], 'unavailable')
        self.assertGreaterEqual(result['missing'], 1)
        self.assertFalse(InstalledExternalTool.objects.get(name='__nowhere_tool__').is_present)
