"""Regression tests for the /api/scan-summary/ hot path.

The frontend polls this endpoint every five seconds for the whole duration of a
scan, so three properties matter as much as the payload itself:

* the timeline must not ship raw tool stdout — it carries a ``has_commands``
  flag, and the command rows are fetched on demand from
  ``/api/listActivityLogs/``;
* the cost of a request must not grow with the number of ``ScanActivity`` rows;
* a GET must not write one row at a time. Closing vulnerabilities resolved by
  the latest scan is a single UPDATE, and the payload keeps the business
  meaning of the per-row loop it replaces, including its NULL-URL semantics.

All domains, hosts and users here are anonymised (RFC 2606 ranges).
"""
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.contrib.auth import get_user_model
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role

from dashboard.models import Project
from reNgine.definitions import (
    ABORTED_TASK, FAILED_TASK, INITIATED_TASK, RUNNING_TASK, SUCCESS_TASK,
)
from scanEngine.models import EngineType
from startScan.models import Command, ScanActivity, ScanHistory, Vulnerability, SecretLeak
from targetApp.models import Domain

User = get_user_model()


class ScanSummaryPayloadTestCase(TestCase):
    """Shared fixture: one project, one domain, one finished scan."""

    slug = 'summary-payload'

    def setUp(self) -> None:
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='summary-user', password='pass', email='su@test.example',
            is_staff=True, is_superuser=True,
        )
        self.client.force_authenticate(user=self.user)
        self.client.force_login(self.user)
        assign_role(self.user, 'sys_admin')

        self.project = Project.objects.create(
            name='summary-payload', slug=self.slug, insert_date=timezone.now()
        )
        self.engine = EngineType.objects.create(
            engine_name='sp-engine', yaml_configuration=''
        )
        self.domain = Domain.objects.create(
            name='sp.test.example', project=self.project, insert_date=timezone.now()
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=SUCCESS_TASK,
            start_scan_date=timezone.now(),
            tasks=['subdomain_discovery'],
        )

    # helpers -----------------------------------------------------------------

    @property
    def url(self) -> str:
        return reverse(
            'api:scan_summary_api',
            kwargs={'slug': self.project.slug, 'id': self.scan.id},
        )

    def _payload(self) -> dict:
        response = self.client.get(self.url)
        self.assertEqual(response.status_code, 200)
        return response.json()

    def _add_activity(self, **kwargs) -> ScanActivity:
        defaults = {
            'scan_of': self.scan,
            'name': 'port_scan',
            'title': 'Port Scan',
            'tier': 2,
            'status': SUCCESS_TASK,
            'time': timezone.now(),
            'time_started': timezone.now(),
        }
        defaults.update(kwargs)
        return ScanActivity.objects.create(**defaults)

    def _add_command(self, activity: ScanActivity, output: str = 'x' * 4096) -> Command:
        return Command.objects.create(
            scan_history=self.scan,
            activity=activity,
            command='nmap -sV 192.0.2.10',
            return_code=0,
            output=output,
            time=timezone.now(),
        )

    def _add_vuln(self, scan: ScanHistory, name: str, http_url, **kwargs) -> Vulnerability:
        defaults = {
            'scan_history': scan,
            'target_domain': self.domain,
            'name': name,
            'http_url': http_url,
            'severity': 2,
            'discovered_date': timezone.now(),
        }
        defaults.update(kwargs)
        return Vulnerability.objects.create(**defaults)


class TimelineCommandFlagTests(ScanSummaryPayloadTestCase):
    """The timeline says whether commands exist; it never ships their output."""

    def test_command_output_is_not_in_the_payload(self) -> None:
        activity = self._add_activity()
        self._add_command(activity, output='SECRET-TOOL-STDOUT')

        payload = self._payload()
        entry = next(e for e in payload['timeline'] if e['id'] == activity.id)

        self.assertNotIn(
            'commands', entry,
            'the timeline must not carry Command rows: Command.output is unbounded '
            'tool stdout and this endpoint is polled every 5 seconds'
        )
        self.assertNotIn('SECRET-TOOL-STDOUT', self.client.get(self.url).content.decode())

    def test_has_commands_is_true_when_the_activity_ran_commands(self) -> None:
        activity = self._add_activity()
        self._add_command(activity)

        entry = next(e for e in self._payload()['timeline'] if e['id'] == activity.id)
        self.assertIs(entry['has_commands'], True)

    def test_has_commands_is_false_when_the_activity_ran_none(self) -> None:
        activity = self._add_activity(name='sync_graph', title='Sync Graph', tier=7)

        entry = next(e for e in self._payload()['timeline'] if e['id'] == activity.id)
        self.assertIs(entry['has_commands'], False)

    def test_every_entry_carries_the_flag(self) -> None:
        with_commands = self._add_activity(target_host='a.sp.test.example')
        self._add_command(with_commands)
        self._add_command(with_commands, output='second command')
        self._add_activity(target_host='b.sp.test.example')

        timeline = self._payload()['timeline']
        self.assertEqual(len(timeline), 2)
        for entry in timeline:
            with self.subTest(entry=entry['id']):
                self.assertIn('has_commands', entry)
                self.assertIsInstance(entry['has_commands'], bool)

    def test_ghost_initiated_rows_are_still_excluded(self) -> None:
        """Filtering moved into Python; the exclusion must survive it."""
        kept = self._add_activity(status=INITIATED_TASK)
        ghost = self._add_activity(status=INITIATED_TASK, time_started=None)

        ids = {entry['id'] for entry in self._payload()['timeline']}
        self.assertIn(kept.id, ids)
        self.assertNotIn(ghost.id, ids)


class TimelineFieldRegressionTests(ScanSummaryPayloadTestCase):
    """target_host, traceback and execution_id (commit 8145b557) stay in place."""

    def test_timeline_entry_keeps_the_operator_fields(self) -> None:
        trace = 'Traceback (most recent call last):\nException: boom'
        activity = self._add_activity(
            name='wpscan_scan',
            title='WPScan',
            status=FAILED_TASK,
            tier=6,
            target_host='blog.sp.test.example',
            error_message='Task wpscan_scan failed: boom',
            traceback=trace,
            execution_id='scan-7-wpscan-1',
        )

        entry = next(e for e in self._payload()['timeline'] if e['id'] == activity.id)
        self.assertEqual(entry['status'], 'FAILED')
        self.assertEqual(entry['target_host'], 'blog.sp.test.example')
        self.assertEqual(entry['traceback'], trace)
        self.assertEqual(entry['execution_id'], 'scan-7-wpscan-1')
        self.assertEqual(entry['error_message'], 'Task wpscan_scan failed: boom')

    def test_missing_values_are_normalised_to_empty_strings(self) -> None:
        activity = self._add_activity(name='sync_graph', title='Sync Graph', tier=7)

        entry = next(e for e in self._payload()['timeline'] if e['id'] == activity.id)
        self.assertEqual(entry['target_host'], '')
        self.assertEqual(entry['traceback'], '')
        self.assertEqual(entry['execution_id'], '')

    def test_spiderfoot_detection_still_reads_the_activity_list(self) -> None:
        """is_spiderfoot_running is derived in Python now — same matching rules."""
        self.assertFalse(self._payload()['scan_info']['is_spiderfoot_running'])

        self._add_activity(
            name='spiderfoot_scan', title='Spiderfoot Scan',
            status=RUNNING_TASK, tier=7,
        )
        self.assertTrue(self._payload()['scan_info']['is_spiderfoot_running'])

    def test_title_match_is_case_insensitive(self) -> None:
        self._add_activity(
            name='osint_discovery', title='Running SpiderFoot module',
            status=RUNNING_TASK, tier=7,
        )
        self.assertTrue(self._payload()['scan_info']['is_spiderfoot_running'])

    def test_finished_spiderfoot_activity_does_not_count_as_running(self) -> None:
        self._add_activity(
            name='spiderfoot_scan', title='Spiderfoot Scan',
            status=ABORTED_TASK, tier=7,
        )
        self.assertFalse(self._payload()['scan_info']['is_spiderfoot_running'])

    def test_task_counts_and_progress_agree_with_the_activity_rows(self) -> None:
        """The prefetched list must feed get_task_counts exactly as a query did."""
        self._add_activity(name='subdomain_discovery', title='Subdomain Discovery')
        self._add_activity(name='nuclei_scan', title='Nuclei Scan', status=FAILED_TASK)
        self._add_activity(name='http_crawl', title='HTTP Crawl', status=RUNNING_TASK)

        scan_info = self._payload()['scan_info']
        self.assertEqual(scan_info['successful_task_count'], 1)
        self.assertEqual(scan_info['failed_task_count'], 1)
        self.assertEqual(scan_info['total_task_count'], 3)
        self.assertEqual(scan_info['progress'], round((2 / 3) * 100, 2))


class ScanSummaryQueryCountTests(ScanSummaryPayloadTestCase):
    """The request cost must be flat in the number of activities."""

    def _cost(self) -> int:
        with CaptureQueriesContext(connection) as captured:
            response = self.client.get(self.url)
            self.assertEqual(response.status_code, 200)
        return len(captured)

    def _add_activities(self, count: int) -> None:
        for index in range(count):
            activity = self._add_activity(target_host=f'h{index}.sp.test.example')
            self._add_command(activity)

    def test_cost_does_not_grow_with_the_activity_count(self) -> None:
        self._add_activities(3)
        self.client.get(self.url)  # warm up any per-process caches first
        three = self._cost()

        self._add_activities(27)
        thirty = self._cost()

        self.assertEqual(
            three, thirty,
            f'30 activities cost {thirty} queries against {three} for 3. The '
            'timeline has regressed into a per-activity query — most likely the '
            'Prefetch of scanactivity_set or the Count("command") annotation was '
            'dropped from ScanSummaryAPIView.get.'
        )

    def test_activities_are_loaded_once_for_all_three_consumers(self) -> None:
        """Timeline, task counts and the spiderfoot check share one query."""
        self._add_activities(5)

        with CaptureQueriesContext(connection) as captured:
            self.client.get(self.url)

        activity_queries = [
            query['sql'] for query in captured
            if 'scanactivity' in query['sql'].lower()
            and query['sql'].lstrip().upper().startswith('SELECT')
        ]
        self.assertEqual(
            len(activity_queries), 1,
            'expected a single SELECT over ScanActivity, got '
            f'{len(activity_queries)}: {activity_queries}'
        )


class ScanSummaryDoesNotWritePerRowTests(ScanSummaryPayloadTestCase):
    """A polled read endpoint must not issue one UPDATE per vulnerability."""

    def _vulnerability_updates(self) -> list:
        with CaptureQueriesContext(connection) as captured:
            response = self.client.get(self.url)
            self.assertEqual(response.status_code, 200)
        return [
            query['sql'] for query in captured
            if query['sql'].lstrip().upper().startswith('UPDATE')
            and 'vulnerability' in query['sql'].lower()
        ]

    def _stale_open_vulns(self, count: int) -> ScanHistory:
        previous = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=SUCCESS_TASK,
            start_scan_date=timezone.now(),
            tasks=['vulnerability_scan'],
        )
        for index in range(count):
            self._add_vuln(previous, f'Stale finding {index}',
                           f'https://old{index}.sp.test.example/')
        return previous

    def test_a_plain_get_issues_no_vulnerability_update(self) -> None:
        """The scan did not run vulnerability_scan, so nothing may be written."""
        self._stale_open_vulns(5)
        self.assertEqual(self._vulnerability_updates(), [])

    def test_resolution_pass_issues_one_update_regardless_of_row_count(self) -> None:
        self.scan.tasks = ['vulnerability_scan']
        self.scan.save(update_fields=['tasks'])
        self._stale_open_vulns(1)
        one_row = self._vulnerability_updates()

        self._stale_open_vulns(20)
        many_rows = self._vulnerability_updates()

        self.assertEqual(
            len(one_row), len(many_rows),
            'the number of UPDATE statements grew with the number of stale '
            'vulnerabilities — the per-row save() loop is back'
        )
        self.assertLessEqual(
            len(many_rows), 1,
            f'expected at most one bulk UPDATE, got {len(many_rows)}: {many_rows}'
        )


class ResolvedVulnerabilityClosureTests(ScanSummaryPayloadTestCase):
    """The single UPDATE must close exactly what the per-row loop closed."""

    def setUp(self) -> None:
        super().setUp()
        self.scan.tasks = ['vulnerability_scan']
        self.scan.save(update_fields=['tasks'])
        self.previous = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=SUCCESS_TASK,
            start_scan_date=timezone.now(),
            tasks=['vulnerability_scan'],
        )

    def _is_open(self, vuln: Vulnerability) -> bool:
        vuln.refresh_from_db()
        return bool(vuln.open_status)

    def test_finding_still_present_in_this_scan_stays_open(self) -> None:
        old = self._add_vuln(self.previous, 'XSS', 'https://www.sp.test.example/a')
        self._add_vuln(self.scan, 'XSS', 'https://www.sp.test.example/a')

        self._payload()
        self.assertTrue(self._is_open(old))

    def test_finding_absent_from_this_scan_is_closed(self) -> None:
        old = self._add_vuln(self.previous, 'SQLi', 'https://www.sp.test.example/b')

        self._payload()
        self.assertFalse(self._is_open(old))

    def test_same_name_on_a_different_url_does_not_keep_it_open(self) -> None:
        old = self._add_vuln(self.previous, 'XSS', 'https://www.sp.test.example/a')
        self._add_vuln(self.scan, 'XSS', 'https://www.sp.test.example/other')

        self._payload()
        self.assertFalse(self._is_open(old))

    def test_two_findings_without_a_url_match_each_other(self) -> None:
        """The Python tuple key treated NULL == NULL; plain SQL equality does not."""
        old = self._add_vuln(self.previous, 'Missing header', None)
        self._add_vuln(self.scan, 'Missing header', None)

        self._payload()
        self.assertTrue(
            self._is_open(old),
            'a finding with no URL that this scan found again was closed — the '
            'NULL branch of the resolution query is missing'
        )

    def test_finding_without_a_url_is_closed_when_this_scan_has_none_like_it(self) -> None:
        old = self._add_vuln(self.previous, 'Missing header', None)
        self._add_vuln(self.scan, 'Missing header', 'https://www.sp.test.example/c')

        self._payload()
        self.assertFalse(self._is_open(old))

    def test_suppressed_findings_are_left_alone(self) -> None:
        old = self._add_vuln(
            self.previous, 'Noisy finding', 'https://www.sp.test.example/d',
            is_suppressed=True,
        )

        self._payload()
        self.assertTrue(self._is_open(old))

    def test_already_closed_findings_are_not_reopened_or_touched(self) -> None:
        old = self._add_vuln(
            self.previous, 'Old finding', 'https://www.sp.test.example/e',
            open_status=False,
        )

        self._payload()
        self.assertFalse(self._is_open(old))

    def test_findings_of_the_current_scan_are_never_closed(self) -> None:
        current = self._add_vuln(self.scan, 'Fresh finding', 'https://www.sp.test.example/f')

        self._payload()
        self.assertTrue(self._is_open(current))

    def test_closure_is_skipped_when_the_scan_is_not_finished(self) -> None:
        self.scan.scan_status = RUNNING_TASK
        self.scan.save(update_fields=['scan_status'])
        old = self._add_vuln(self.previous, 'SQLi', 'https://www.sp.test.example/b')

        self._payload()
        self.assertTrue(self._is_open(old))


class SeverityAggregateTests(ScanSummaryPayloadTestCase):
    """The single aggregate must agree with the seven COUNTs it replaced."""

    def test_counts_match_the_rows(self) -> None:
        for severity, count in ((4, 1), (3, 2), (2, 3), (1, 4), (0, 5), (-1, 6)):
            for index in range(count):
                self._add_vuln(
                    self.scan, f'Finding {severity}-{index}',
                    f'https://www.sp.test.example/{severity}/{index}',
                    severity=severity,
                )

        payload = self._payload()
        self.assertEqual(payload['critical_count'], 1)
        self.assertEqual(payload['high_count'], 2)
        self.assertEqual(payload['medium_count'], 3)
        self.assertEqual(payload['low_count'], 4)
        self.assertEqual(payload['info_count'], 5)
        self.assertEqual(payload['unknown_count'], 6)
        self.assertEqual(payload['total_vul_ignore_info_count'], 10)
        self.assertEqual(payload['vulnerability_count'], 21)

    def test_counts_are_zero_without_vulnerabilities(self) -> None:
        payload = self._payload()
        for field in ('critical_count', 'high_count', 'medium_count',
                      'low_count', 'info_count', 'unknown_count',
                      'vulnerability_count'):
            with self.subTest(field=field):
                self.assertEqual(payload[field], 0)


class SecretLeakScanScopeTests(ScanSummaryPayloadTestCase):
    """LEAKS on scan detail must not inherit sibling-scan rows for the same domain."""

    def test_secret_leaks_are_scoped_to_the_requested_scan(self) -> None:
        sibling = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=SUCCESS_TASK,
            start_scan_date=timezone.now(),
            tasks=['osint'],
        )
        SecretLeak.objects.create(
            scan_history=sibling,
            tool_name='postleaksNg',
            secret_type='postman_leak',
            source_url='postman://sp.test.example',
            match_content='Traceback (most recent call last):',
            status='unverified',
        )
        SecretLeak.objects.create(
            scan_history=self.scan,
            tool_name='postleaksNg',
            secret_type='postman_leak',
            source_url='postman://sp.test.example',
            match_content='API_KEY=mine',
            status='unverified',
        )

        payload = self._payload()
        self.assertEqual(payload['secret_leaks_count'], 1)
        self.assertEqual(len(payload['secret_leaks']), 1)
        self.assertEqual(payload['secret_leaks'][0]['match_content'], 'API_KEY=mine')
