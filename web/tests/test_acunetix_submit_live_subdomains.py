"""Automatic submission of live subdomains to Acunetix.

Covers which subdomains qualify as "live and externally reachable", the
re-submission window that stops a daily scan re-registering the same host, and
the timeline record written for every decision.
"""
import unittest
from datetime import timedelta
from unittest.mock import patch

import requests
from django.db import IntegrityError
from django.test import TestCase
from django.utils import timezone

from dashboard.models import AcunetixTargetSubmission
from scanEngine.models import EngineType
from startScan.models import Command, IpAddress, ScanActivity, ScanHistory, Subdomain
from targetApp.models import Domain


class _FakeTask:
    """Minimal stand-in for the Temporal task proxy passed as `self`."""

    def __init__(self, scan=None, activity=None) -> None:
        self.scan = scan
        self.activity = activity
        self.error = None
        self.yaml_configuration = {}


class _FakeResponse:
    """Stand-in for a `requests` response — only what the task reads."""

    def __init__(self, status_code: int, payload: dict = None) -> None:
        self.status_code = status_code
        self._payload = payload or {}
        self.text = ''

    def json(self) -> dict:
        return self._payload


def _creds(server_url: str = 'https://acu.local', api_key: str = 'k'):
    return type('Creds', (), {'server_url': server_url, 'api_key': api_key})()


class LiveSubdomainSelectionTests(TestCase):

    def setUp(self) -> None:
        self.domain = Domain.objects.create(name='test.example', insert_date=timezone.now())
        engine = EngineType.objects.create(engine_name='acu-engine', yaml_configuration='')
        self.scan = ScanHistory.objects.create(
            domain=self.domain, scan_type=engine, scan_status=1,
            start_scan_date=timezone.now(),
        )

    def _subdomain(self, name: str, http_status: int = 200, http_url: str = None, ip: str = None,
                   is_private: bool = False) -> Subdomain:
        sub = Subdomain.objects.create(
            scan_history=self.scan, target_domain=self.domain, name=name,
            http_status=http_status,
            http_url=http_url if http_url is not None else f'https://{name}',
            discovered_date=timezone.now(),
        )
        if ip:
            address = IpAddress.objects.create(address=ip, is_private=is_private)
            sub.ip_addresses.add(address)
        return sub

    def test_only_live_reachable_subdomains_are_selected(self) -> None:
        from reNgine.tasks import get_live_subdomains_for_submission

        alive = self._subdomain('www.test.example', 200, ip='192.0.2.10')
        redirect = self._subdomain('old.test.example', 301, ip='192.0.2.11')
        no_ip = self._subdomain('cdn.test.example', 200)
        self._subdomain('dead.test.example', 0, ip='192.0.2.12')
        self._subdomain('gone.test.example', 404, ip='192.0.2.13')
        self._subdomain('broken.test.example', 500, ip='192.0.2.14')
        self._subdomain('internal.test.example', 200, ip='10.0.0.5', is_private=True)
        self._subdomain('nourl.test.example', 200, http_url='', ip='192.0.2.15')

        selected = {s.name for s in get_live_subdomains_for_submission(self.scan.id)}

        self.assertEqual(
            selected,
            {alive.name, redirect.name, no_ip.name},
            'live = HTTP answered with 0 < status < 500 and not 404, has a URL, '
            'and is not resolved only to private addresses',
        )


class _SubmissionTestBase(TestCase):
    """Two live subdomains, a planned timeline row, and the task plumbing."""

    def setUp(self) -> None:
        self.domain = Domain.objects.create(name='sub.example', insert_date=timezone.now())
        engine = EngineType.objects.create(engine_name='acu-engine2', yaml_configuration='')
        self.scan = ScanHistory.objects.create(
            domain=self.domain, scan_type=engine, scan_status=1,
            start_scan_date=timezone.now(),
        )
        self.activity = ScanActivity.objects.create(
            scan_of=self.scan, name='acunetix_submit', title='Acunetix Target Submission',
            tier=2, status=1, time=timezone.now(), time_started=timezone.now(),
        )
        self._add_live_subdomains('a.sub.example', 'b.sub.example')
        self.ctx = self._ctx()
        # AWVS is never contacted: the target list is empty and batch pauses are instant.
        self.list_targets = self._start_patch('reNgine.tasks.acunetix._list_acunetix_targets', return_value={})
        self.sleep = self._start_patch('reNgine.tasks.acunetix.time.sleep')

    def _start_patch(self, target: str, **kwargs):
        patcher = patch(target, **kwargs)
        self.addCleanup(patcher.stop)
        return patcher.start()

    def _add_live_subdomains(self, *names: str) -> None:
        for name in names:
            Subdomain.objects.create(
                scan_history=self.scan, target_domain=self.domain, name=name,
                http_status=200, http_url=f'https://{name}', discovered_date=timezone.now(),
            )

    def _ctx(self, **acunetix_overrides) -> dict:
        config = {'resubmit_after_days': 3}
        config.update(acunetix_overrides)
        return {
            'scan_history_id': self.scan.id,
            'yaml_configuration': {'vulnerability_scan': {'acunetix': config}},
        }

    def _task(self) -> _FakeTask:
        return _FakeTask(scan=self.scan, activity=self.activity)

    def _run(self, task: _FakeTask, ctx: dict = None):
        from reNgine.tasks import acunetix_submit_live_subdomains
        return acunetix_submit_live_subdomains(task, ctx=ctx or self.ctx)


class AcunetixSubmissionTests(_SubmissionTestBase):

    @patch('reNgine.tasks.acunetix._create_or_reuse_acunetix_target', return_value='tgt-1')
    @patch('reNgine.tasks.acunetix.AcunetixAPIKey')
    def test_each_live_subdomain_is_submitted_once_and_recorded(self, mock_keys, mock_create) -> None:
        mock_keys.objects.first.return_value = type(
            'Creds', (), {'server_url': 'https://acu.local', 'api_key': 'k'}
        )()

        task = self._task()
        self.assertTrue(self._run(task))

        self.assertEqual(mock_create.call_count, 2)
        self.assertEqual(AcunetixTargetSubmission.objects.count(), 2)
        commands = Command.objects.filter(activity=self.activity)
        self.assertEqual(commands.count(), 2)
        self.assertTrue(all('SUBMITTED' in c.output for c in commands))

    @patch('reNgine.tasks.acunetix._create_or_reuse_acunetix_target', return_value='tgt-1')
    @patch('reNgine.tasks.acunetix.AcunetixAPIKey')
    def test_host_submitted_inside_the_window_is_skipped(self, mock_keys, mock_create) -> None:
        mock_keys.objects.first.return_value = type(
            'Creds', (), {'server_url': 'https://acu.local', 'api_key': 'k'}
        )()
        AcunetixTargetSubmission.objects.create(
            host='a.sub.example', acunetix_target_id='old-1',
            last_submitted_at=timezone.now() - timedelta(days=1),
        )

        self._run(self._task())

        self.assertEqual(mock_create.call_count, 1, 'only the host outside the window is sent')
        skipped = Command.objects.filter(activity=self.activity, output__startswith='SKIPPED')
        self.assertEqual(skipped.count(), 1)
        self.assertIn('a.sub.example', skipped.first().command)

    @patch('reNgine.tasks.acunetix._create_or_reuse_acunetix_target', return_value='tgt-2')
    @patch('reNgine.tasks.acunetix.AcunetixAPIKey')
    def test_host_submitted_before_the_window_is_sent_again(self, mock_keys, mock_create) -> None:
        mock_keys.objects.first.return_value = type(
            'Creds', (), {'server_url': 'https://acu.local', 'api_key': 'k'}
        )()
        stale = AcunetixTargetSubmission.objects.create(
            host='a.sub.example', acunetix_target_id='old-1',
            last_submitted_at=timezone.now() - timedelta(days=5),
        )

        self._run(self._task())

        self.assertEqual(mock_create.call_count, 2)
        stale.refresh_from_db()
        self.assertEqual(stale.acunetix_target_id, 'tgt-2')
        self.assertEqual(stale.submission_count, 2)

    @patch('reNgine.tasks.acunetix.AcunetixAPIKey')
    def test_missing_credentials_fail_with_a_reason(self, mock_keys) -> None:
        mock_keys.objects.first.return_value = None

        task = self._task()
        self.assertFalse(self._run(task))
        self.assertIn('Acunetix API keys', task.error or '')


class AcunetixSubmissionIsolationTests(_SubmissionTestBase):
    """One host that fails must not take the rest of the submission run with it."""

    @patch('reNgine.tasks.acunetix._start_acunetix_scan_direct')
    @patch('reNgine.tasks.acunetix._create_or_reuse_acunetix_target', return_value='tgt-1')
    @patch('reNgine.tasks.acunetix.AcunetixAPIKey')
    def test_a_failing_scan_start_does_not_skip_the_remaining_hosts(
            self, mock_keys, mock_create, mock_start) -> None:
        mock_keys.objects.first.return_value = _creds()
        mock_start.side_effect = [
            requests.exceptions.ReadTimeout('Read timed out'),
            {'scan_id': 'scan-2'},
        ]

        task = self._task()
        self.assertTrue(self._run(task, self._ctx(start_scan_on_submit=True)))

        self.assertEqual(mock_start.call_count, 2, 'the second host is still attempted')
        self.assertEqual(
            [r.host for r in AcunetixTargetSubmission.objects.all()],
            ['b.sub.example'],
        )
        failed = Command.objects.filter(activity=self.activity, output__startswith='FAILED')
        self.assertEqual(failed.count(), 1)
        self.assertIn('a.sub.example', failed.first().command)
        self.assertIn('ReadTimeout', failed.first().output)

    @patch('reNgine.tasks.acunetix._start_acunetix_scan_direct')
    @patch('reNgine.tasks.acunetix._create_or_reuse_acunetix_target', return_value='tgt-1')
    @patch('reNgine.tasks.acunetix.AcunetixAPIKey')
    def test_a_scan_that_does_not_start_is_failed_not_submitted(
            self, mock_keys, mock_create, mock_start) -> None:
        mock_keys.objects.first.return_value = _creds()
        mock_start.side_effect = [None, {'scan_id': 'scan-2'}]

        task = self._task()
        self.assertTrue(self._run(task, self._ctx(start_scan_on_submit=True)))

        # Not recorded, so the next scan retries it instead of skipping it as recent.
        self.assertEqual(
            [r.host for r in AcunetixTargetSubmission.objects.all()],
            ['b.sub.example'],
        )
        failed = Command.objects.get(activity=self.activity, output__startswith='FAILED')
        self.assertIn('a.sub.example', failed.command)
        self.assertIn('scan did not start', failed.output)
        self.assertEqual(
            Command.objects.filter(activity=self.activity, output__startswith='SUBMITTED').count(), 1)

    @patch('reNgine.tasks.acunetix._create_or_reuse_acunetix_target', return_value='tgt-1')
    @patch('reNgine.tasks.acunetix.AcunetixAPIKey')
    def test_a_colliding_submission_row_does_not_skip_the_remaining_hosts(
            self, mock_keys, mock_create) -> None:
        mock_keys.objects.first.return_value = _creds()
        real_get_or_create = AcunetixTargetSubmission.objects.get_or_create

        def _collide_on_the_first_host(**kwargs):
            # What a concurrent scan submitting the same host looks like:
            # `host` is unique, so the loser of the race gets an IntegrityError.
            if kwargs.get('host') == 'a.sub.example':
                raise IntegrityError('duplicate key value violates unique constraint')
            return real_get_or_create(**kwargs)

        task = self._task()
        with patch.object(
            AcunetixTargetSubmission.objects, 'get_or_create',
            side_effect=_collide_on_the_first_host,
        ):
            self.assertTrue(self._run(task))

        self.assertEqual(
            [r.host for r in AcunetixTargetSubmission.objects.all()],
            ['b.sub.example'],
        )
        outputs = {
            c.command: c.output
            for c in Command.objects.filter(activity=self.activity)
        }
        self.assertTrue(outputs['acunetix submit a.sub.example'].startswith('FAILED'))
        self.assertIn('IntegrityError', outputs['acunetix submit a.sub.example'])
        self.assertTrue(outputs['acunetix submit b.sub.example'].startswith('SUBMITTED'))

    @patch('reNgine.tasks.acunetix._create_or_reuse_acunetix_target')
    @patch('reNgine.tasks.acunetix.AcunetixAPIKey')
    def test_the_task_fails_only_when_every_host_failed(self, mock_keys, mock_create) -> None:
        mock_keys.objects.first.return_value = _creds()
        mock_create.side_effect = requests.exceptions.ConnectionError('unreachable')

        task = self._task()
        self.assertFalse(self._run(task))
        self.assertIn('All 2', task.error or '')
        self.assertEqual(AcunetixTargetSubmission.objects.count(), 0)


class ResubmitWindowTests(_SubmissionTestBase):
    """The window is the only thing stopping a daily scan re-flooding Acunetix."""

    @patch('reNgine.tasks.acunetix._create_or_reuse_acunetix_target', return_value='tgt-1')
    @patch('reNgine.tasks.acunetix.AcunetixAPIKey')
    def test_a_zero_window_is_clamped_instead_of_resubmitting_everything(
            self, mock_keys, mock_create) -> None:
        mock_keys.objects.first.return_value = _creds()
        AcunetixTargetSubmission.objects.create(
            host='a.sub.example', acunetix_target_id='old-1',
            last_submitted_at=timezone.now() - timedelta(hours=1),
        )

        task = self._task()
        self.assertTrue(self._run(task, self._ctx(resubmit_after_days=0)))

        self.assertEqual(
            mock_create.call_count, 1,
            'a 0 day window would put the cutoff at "now" and re-submit every host',
        )
        skipped = Command.objects.filter(activity=self.activity, output__startswith='SKIPPED')
        self.assertEqual(skipped.count(), 1)
        self.assertIn('a.sub.example', skipped.first().command)

    @patch('reNgine.tasks.acunetix._create_or_reuse_acunetix_target', return_value='tgt-1')
    @patch('reNgine.tasks.acunetix.AcunetixAPIKey')
    def test_a_malformed_window_falls_back_to_the_default(self, mock_keys, mock_create) -> None:
        mock_keys.objects.first.return_value = _creds()
        AcunetixTargetSubmission.objects.create(
            host='a.sub.example', acunetix_target_id='old-1',
            last_submitted_at=timezone.now() - timedelta(days=2),
        )

        task = self._task()
        self.assertTrue(self._run(task, self._ctx(resubmit_after_days='soon')))

        self.assertIsNone(task.error, 'a bad yaml value must not kill the task')
        self.assertEqual(
            mock_create.call_count, 1,
            'the 3 day default still covers a host submitted 2 days ago',
        )


class ResolveResubmitWindowTests(unittest.TestCase):

    def test_values_are_clamped_and_sanitised(self) -> None:
        from reNgine.tasks.acunetix import (
            DEFAULT_RESUBMIT_AFTER_DAYS, MIN_RESUBMIT_AFTER_DAYS,
            _resolve_resubmit_after_days,
        )

        self.assertEqual(_resolve_resubmit_after_days(7), 7)
        self.assertEqual(_resolve_resubmit_after_days('7'), 7)
        self.assertEqual(_resolve_resubmit_after_days(0), MIN_RESUBMIT_AFTER_DAYS)
        self.assertEqual(_resolve_resubmit_after_days(-5), MIN_RESUBMIT_AFTER_DAYS)
        self.assertEqual(_resolve_resubmit_after_days(None), DEFAULT_RESUBMIT_AFTER_DAYS)
        self.assertEqual(_resolve_resubmit_after_days('soon'), DEFAULT_RESUBMIT_AFTER_DAYS)
        self.assertEqual(_resolve_resubmit_after_days([3]), DEFAULT_RESUBMIT_AFTER_DAYS)

    def test_int_options_are_clamped_to_their_range(self) -> None:
        from reNgine.tasks.acunetix import _resolve_int_option

        self.assertEqual(_resolve_int_option(None, 'x', 20, 1, 200), 20)
        self.assertEqual(_resolve_int_option('50', 'x', 20, 1, 200), 50)
        self.assertEqual(_resolve_int_option(0, 'x', 20, 1, 200), 1)
        self.assertEqual(_resolve_int_option(10_000, 'x', 20, 1, 200), 200)
        self.assertEqual(_resolve_int_option('many', 'x', 20, 1, 200), 20)


class SubmissionBatchingTests(_SubmissionTestBase):
    """Many live subdomains go out in small batches, and only a few scans start per run."""

    def setUp(self) -> None:
        super().setUp()
        self._add_live_subdomains('c.sub.example', 'd.sub.example', 'e.sub.example')
        keys = self._start_patch('reNgine.tasks.acunetix.AcunetixAPIKey')
        keys.objects.first.return_value = _creds()
        self.create = self._start_patch(
            'reNgine.tasks.acunetix._create_or_reuse_acunetix_target', return_value='tgt-1')
        self.start = self._start_patch(
            'reNgine.tasks.acunetix._start_acunetix_scan_direct', return_value={'scan_id': 'scan-1'})

    def _outputs(self) -> dict:
        return {c.command.split()[-1]: c.output for c in Command.objects.filter(activity=self.activity)}

    def test_hosts_are_sent_in_batches_with_a_pause_between_them(self) -> None:
        task = self._task()
        self.assertTrue(self._run(task, self._ctx(submission_batch_size=2, submission_batch_pause=7)))

        self.assertEqual(self.create.call_count, 5)
        self.assertEqual([c.args for c in self.sleep.call_args_list], [(7,), (7,)], '3 batches, 2 pauses')
        self.assertEqual(AcunetixTargetSubmission.objects.count(), 5)

    def test_no_pause_when_it_is_zero(self) -> None:
        self.assertTrue(self._run(self._task(), self._ctx(submission_batch_size=1, submission_batch_pause=0)))
        self.sleep.assert_not_called()

    def test_scans_past_the_per_run_limit_are_left_for_the_next_run(self) -> None:
        ctx = self._ctx(start_scan_on_submit=True, max_scans_per_run=2)

        self.assertTrue(self._run(self._task(), ctx))

        self.assertEqual(self.start.call_count, 2)
        self.assertEqual(self.create.call_count, 5, 'every host is still added as a target')
        self.assertEqual(
            sorted(AcunetixTargetSubmission.objects.values_list('host', flat=True)),
            ['a.sub.example', 'b.sub.example'],
        )
        outputs = self._outputs()
        for host in ('c.sub.example', 'd.sub.example', 'e.sub.example'):
            self.assertTrue(outputs[host].startswith('TARGET ADDED'), outputs[host])
            self.assertIn('limit of 2 scans per run', outputs[host])

        Command.objects.all().delete()
        self.start.reset_mock()
        self.assertTrue(self._run(self._task(), ctx))

        self.assertEqual(self.start.call_count, 2, 'the next run starts the next slice')
        self.assertEqual(
            sorted(AcunetixTargetSubmission.objects.values_list('host', flat=True)),
            ['a.sub.example', 'b.sub.example', 'c.sub.example', 'd.sub.example'],
        )

    def test_never_submitted_hosts_get_the_scans_before_returning_ones(self) -> None:
        for host, days_ago in (('a.sub.example', 4), ('b.sub.example', 9)):
            AcunetixTargetSubmission.objects.create(
                host=host, acunetix_target_id='old', last_submitted_at=timezone.now() - timedelta(days=days_ago),
            )

        self.assertTrue(self._run(self._task(), self._ctx(start_scan_on_submit=True, max_scans_per_run=4)))

        submitted_hosts = [c.kwargs['target_name'] for c in self.create.call_args_list]
        self.assertEqual(
            submitted_hosts,
            ['c.sub.example', 'd.sub.example', 'e.sub.example', 'b.sub.example', 'a.sub.example'],
            'new hosts by name, then the longest-waiting first',
        )
        self.assertTrue(self._outputs()['a.sub.example'].startswith('TARGET ADDED'))

    def test_www_is_skipped_when_the_bare_host_is_live(self) -> None:
        self._add_live_subdomains('www.c.sub.example', 'www.only.sub.example')

        self.assertTrue(self._run(self._task()))

        sent = {c.kwargs['target_name'] for c in self.create.call_args_list}
        self.assertNotIn('www.c.sub.example', sent)
        self.assertIn('c.sub.example', sent)
        self.assertIn('www.only.sub.example', sent, 'kept when the bare host is not live')
        self.assertEqual(self._outputs()['www.c.sub.example'], 'SKIPPED — same site as c.sub.example')

    def test_a_scan_that_did_not_start_does_not_use_up_the_limit(self) -> None:
        self.start.side_effect = [None, {'scan_id': 'scan-2'}, {'scan_id': 'scan-3'}]

        self.assertTrue(self._run(self._task(), self._ctx(start_scan_on_submit=True, max_scans_per_run=2)))

        self.assertEqual(self.start.call_count, 3)
        outputs = self._outputs()
        self.assertTrue(outputs['a.sub.example'].startswith('FAILED'))
        self.assertTrue(outputs['c.sub.example'].startswith('SUBMITTED'))
        self.assertTrue(outputs['d.sub.example'].startswith('TARGET ADDED'))

    def test_the_target_list_is_read_once_and_shared_by_every_host(self) -> None:
        self.list_targets.return_value = {'a.sub.example': 'tgt-a'}

        self._run(self._task())

        self.list_targets.assert_called_once()
        self.assertTrue(all(
            c.kwargs['known_targets'] is self.list_targets.return_value for c in self.create.call_args_list
        ))

    def test_an_unreadable_target_list_falls_back_to_per_host_lookups(self) -> None:
        self.list_targets.side_effect = requests.exceptions.ConnectionError('unreachable')

        self.assertTrue(self._run(self._task()))

        self.assertEqual(self.create.call_count, 5)
        self.assertTrue(all(c.kwargs['known_targets'] is None for c in self.create.call_args_list))


class AcunetixTargetListTests(unittest.TestCase):
    """The AWVS target list is paged; a lookup against page one alone duplicates targets."""

    BASE = 'https://acu.local'

    @staticmethod
    def _page(start: int, count: int) -> _FakeResponse:
        return _FakeResponse(200, {'targets': [
            {'target_id': f'tgt-{i}', 'address': f'https://h{i}.sub.example/'} for i in range(start, start + count)
        ]})

    def _list(self, responses):
        from reNgine.tasks.acunetix import _list_acunetix_targets
        with patch('reNgine.tasks.acunetix.requests.get', side_effect=responses) as mock_get:
            return _list_acunetix_targets(self.BASE, {}, False, 5), mock_get

    def test_every_page_is_read(self) -> None:
        targets, mock_get = self._list([self._page(0, 100), self._page(100, 3)])

        self.assertEqual(len(targets), 103)
        self.assertEqual(targets['h102.sub.example'], 'tgt-102')
        self.assertEqual([c.kwargs['params']['c'] for c in mock_get.call_args_list], [0, 100])

    def test_a_server_ignoring_the_offset_does_not_loop(self) -> None:
        targets, mock_get = self._list([self._page(0, 100), self._page(0, 100)])

        self.assertEqual(len(targets), 100)
        self.assertEqual(mock_get.call_count, 2)

    def test_an_error_status_means_no_list(self) -> None:
        targets, _ = self._list([_FakeResponse(401)])
        self.assertIsNone(targets)


class KnownTargetsLookupTests(unittest.TestCase):

    def _call(self, known: dict, create_resp: _FakeResponse = None):
        from reNgine.tasks.acunetix import _create_or_reuse_acunetix_target
        with patch('reNgine.tasks.acunetix.requests.get') as mock_get, \
                patch('reNgine.tasks.acunetix.requests.post', return_value=create_resp) as mock_post:
            target_id = _create_or_reuse_acunetix_target(
                'https://acu.local', {}, False, 5, 'www.sub.example', 'https://www.sub.example',
                known_targets=known,
            )
        mock_get.assert_not_called()
        return target_id, mock_post

    def test_a_known_host_is_reused_without_a_request(self) -> None:
        target_id, mock_post = self._call({'www.sub.example': 'tgt-www'})
        self.assertEqual(target_id, 'tgt-www')
        mock_post.assert_not_called()

    def test_a_created_target_is_remembered(self) -> None:
        known: dict = {}
        target_id, mock_post = self._call(known, _FakeResponse(201, {'target_id': 'tgt-new'}))
        self.assertEqual(target_id, 'tgt-new')
        self.assertEqual(known, {'www.sub.example': 'tgt-new'})
        mock_post.assert_called_once()


class AcunetixScanFailureTests(TestCase):
    """`acunetix_scan` error handling.

    `error_message` is served to every role by the scan summary API (unlike
    `traceback`), so the reason stored there must not carry the AWVS server URL
    or credential material — security rule 8.1.
    """

    def setUp(self) -> None:
        self.domain = Domain.objects.create(name='scan.example', insert_date=timezone.now())
        engine = EngineType.objects.create(engine_name='acu-engine3', yaml_configuration='')
        self.scan = ScanHistory.objects.create(
            domain=self.domain, scan_type=engine, scan_status=1,
            start_scan_date=timezone.now(),
        )

    def _run(self, task: _FakeTask):
        from reNgine.tasks import acunetix_scan
        return acunetix_scan(task, domain_id=self.domain.id, scan_history_id=self.scan.id)

    @patch('reNgine.tasks.acunetix._create_or_reuse_acunetix_target')
    @patch('reNgine.tasks.acunetix.AcunetixAPIKey')
    def test_request_failure_does_not_expose_the_server_url(self, mock_keys, mock_create) -> None:
        mock_keys.objects.first.return_value = _creds(
            server_url='https://acu.internal.example:3443', api_key='sekret-api-key',
        )
        mock_create.side_effect = requests.exceptions.ConnectionError(
            "HTTPSConnectionPool(host='acu.internal.example', port=3443): Max retries "
            "exceeded with url: /api/v1/targets (apikey=sekret-api-key)"
        )

        task = _FakeTask(scan=self.scan)
        self.assertFalse(self._run(task))

        self.assertIn('ConnectionError', task.error)
        for leaked in (
            'acu.internal.example', '3443', 'sekret-api-key', 'HTTPSConnectionPool',
        ):
            self.assertNotIn(leaked, task.error)

    @patch('reNgine.tasks.acunetix.save_vulnerability')
    @patch('reNgine.tasks.acunetix._fetch_acunetix_vulnerabilities')
    @patch('reNgine.tasks.acunetix.requests.get')
    @patch('reNgine.tasks.acunetix._start_acunetix_scan_direct',
           return_value={'scan_id': 'scan-1'})
    @patch('reNgine.tasks.acunetix._create_or_reuse_acunetix_target', return_value='tgt-1')
    @patch('reNgine.tasks.acunetix.AcunetixAPIKey')
    def test_findings_collected_before_a_pagination_failure_are_kept(
            self, mock_keys, mock_create, mock_start, mock_get, mock_fetch, mock_save) -> None:
        mock_keys.objects.first.return_value = _creds()

        def _responses(url, **kwargs):
            if '/vulnerabilities/' in url:
                return _FakeResponse(200, {
                    'vt_name': 'Partial finding',
                    'severity': 2,
                    'references': [],
                })
            return _FakeResponse(200, {
                'current_session': {'status': 'completed', 'scan_session_id': 'sess-1'},
            })

        mock_get.side_effect = _responses
        # Page 1 of the primary URL succeeded, page 2 returned 400; neither
        # fallback URL knows this scan, so nothing replaces the partial list.
        mock_fetch.side_effect = [
            (_FakeResponse(400), [{'vuln_id': 'v-1'}]),
            (_FakeResponse(400), []),
            (_FakeResponse(404), []),
        ]

        self.assertTrue(self._run(_FakeTask(scan=self.scan)))

        self.assertEqual(mock_fetch.call_count, 3)
        self.assertEqual(
            mock_save.call_count, 1,
            'the finding read before the pagination failure must not be discarded',
        )
        self.assertEqual(mock_save.call_args.kwargs['name'], 'Partial finding')


class AcunetixSubmitTaskPlanTests(TestCase):
    """The timeline row must be planned up front, so it shows as pending."""

    def test_planned_only_when_enabled_and_http_crawl_runs(self) -> None:
        from reNgine.task_plan import build_scan_task_plan, get_task_tier

        enabled = {'vulnerability_scan': {'acunetix': {'submit_live_subdomains': True}}}
        names = [e['name'] for e in build_scan_task_plan(['http_crawl'], enabled)]
        self.assertIn('acunetix_submit', names)

        disabled = {'vulnerability_scan': {'acunetix': {'submit_live_subdomains': False}}}
        names = [e['name'] for e in build_scan_task_plan(['http_crawl'], disabled)]
        self.assertNotIn('acunetix_submit', names)

        names = [e['name'] for e in build_scan_task_plan(['port_scan'], enabled)]
        self.assertNotIn('acunetix_submit', names, 'liveness comes from http_crawl')

        self.assertEqual(get_task_tier('acunetix_submit'), 2)
