"""Tests for the per-activity target host shown on the scan timeline.

Covers the four pieces that make a timeline row identify the host it ran against:

* ``reNgine.temporal.activities.resolve_target_host`` — the pure resolver that
  picks a host out of a Temporal activity context.
* ``reNgine.task_plan.get_task_tier`` — tier lookup, including the runtime-only
  task names that are never part of a planned scan.
* ``reNgine.tasks.acunetix.acunetix_scan`` — early failures must report *why*
  they gave up on the task object instead of returning a bare ``False``.
* ``api.scan_summary_views.ScanSummaryAPIView`` — the timeline entries must
  carry ``target_host``, ``traceback`` and ``execution_id``.

All hosts, domains and users here are anonymised (RFC 2606 / RFC 5737 ranges).
"""
import unittest
from typing import Any, Optional
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role

from dashboard.models import Project
from reNgine.task_plan import get_task_tier
from reNgine.tasks.acunetix import _fail, acunetix_scan
from reNgine.temporal.activities import resolve_target_host
from scanEngine.models import EngineType
from startScan.models import ScanActivity, ScanHistory
from targetApp.models import Domain

User = get_user_model()


class _Named:
    """Stub standing in for a Subdomain / Domain instance (only ``.name`` is read)."""

    def __init__(self, name: Optional[str]) -> None:
        self.name = name


class _FakeTask:
    """Minimal stand-in for TemporalTaskProxy, with the attributes acunetix_scan reads."""

    def __init__(self) -> None:
        self.subdomain: Any = None
        self.subscan: Any = None
        self.target_host: str = ''
        self.error: Optional[str] = None


class ResolveTargetHostPrecedenceTests(unittest.TestCase):
    """resolve_target_host picks sources in a fixed order of specificity."""

    def test_ctx_subdomain_name_wins_over_every_other_source(self) -> None:
        host = resolve_target_host(
            {
                'subdomain_name': 'api.test.example',
                'host': 'ignored.test.example',
                'url': 'https://also-ignored.test.example/path',
            },
            subdomain=_Named('stub.test.example'),
            domain=_Named('test.example'),
        )
        self.assertEqual(host, 'api.test.example')

    def test_subdomain_object_used_when_ctx_has_no_subdomain_name(self) -> None:
        host = resolve_target_host(
            {'host': 'ignored.test.example'},
            subdomain=_Named('www.test.example'),
            domain=_Named('test.example'),
        )
        self.assertEqual(host, 'www.test.example')

    def test_ctx_host_used_when_no_subdomain_available(self) -> None:
        host = resolve_target_host(
            {'host': 'mail.test.example', 'url': 'https://ignored.test.example/'},
            domain=_Named('test.example'),
        )
        self.assertEqual(host, 'mail.test.example')

    def test_url_hostname_used_when_no_host(self) -> None:
        host = resolve_target_host(
            {'url': 'https://shop.test.example:8443/admin?a=1'},
            domain=_Named('test.example'),
        )
        # urlparse().hostname strips scheme, port, path and query.
        self.assertEqual(host, 'shop.test.example')

    def test_subdomain_http_url_used_when_url_absent(self) -> None:
        host = resolve_target_host({'subdomain_http_url': 'http://blog.test.example/'})
        self.assertEqual(host, 'blog.test.example')

    def test_url_takes_precedence_over_subdomain_http_url(self) -> None:
        host = resolve_target_host({
            'url': 'https://first.test.example/',
            'subdomain_http_url': 'https://second.test.example/',
        })
        self.assertEqual(host, 'first.test.example')

    def test_schemeless_url_falls_back_to_the_raw_value(self) -> None:
        # urlparse has no hostname for a bare authority, so the value is kept as-is.
        host = resolve_target_host({'url': 'plain.test.example'})
        self.assertEqual(host, 'plain.test.example')

    def test_domain_name_is_the_last_resort(self) -> None:
        host = resolve_target_host({}, domain=_Named('test.example'))
        self.assertEqual(host, 'test.example')

    def test_empty_context_and_no_objects_returns_empty_string(self) -> None:
        self.assertEqual(resolve_target_host({}), '')

    def test_blank_and_none_sources_are_skipped(self) -> None:
        host = resolve_target_host(
            {'subdomain_name': '   ', 'host': None, 'url': ''},
            subdomain=_Named(None),
            domain=_Named('test.example'),
        )
        self.assertEqual(host, 'test.example')

    def test_surrounding_whitespace_is_stripped(self) -> None:
        self.assertEqual(
            resolve_target_host({'subdomain_name': '  vpn.test.example  '}),
            'vpn.test.example',
        )

    def test_objects_without_a_name_attribute_do_not_raise(self) -> None:
        self.assertEqual(resolve_target_host({}, subdomain=object(), domain=object()), '')


class ResolveTargetHostPortTests(unittest.TestCase):
    """Port handling: append once, never twice, never to an empty host."""

    def test_port_is_appended_to_a_bare_host(self) -> None:
        host = resolve_target_host({'host': '192.0.2.10', 'port': 8080})
        self.assertEqual(host, '192.0.2.10:8080')

    def test_port_is_appended_to_a_subdomain_name(self) -> None:
        host = resolve_target_host({'subdomain_name': 'api.test.example', 'port': '8443'})
        self.assertEqual(host, 'api.test.example:8443')

    def test_port_is_appended_to_the_domain_fallback(self) -> None:
        host = resolve_target_host({'port': 443}, domain=_Named('test.example'))
        self.assertEqual(host, 'test.example:443')

    def test_port_is_not_appended_twice_when_host_already_has_one(self) -> None:
        host = resolve_target_host({'host': '192.0.2.10:8080', 'port': 8080})
        self.assertEqual(host, '192.0.2.10:8080')

    def test_port_is_not_appended_when_host_already_contains_a_different_port(self) -> None:
        host = resolve_target_host({'host': '192.0.2.10:9090', 'port': 8080})
        self.assertEqual(host, '192.0.2.10:9090')

    def test_url_derived_host_keeps_only_one_port(self) -> None:
        # urlparse().hostname already dropped :8443, so the ctx port is appended once.
        host = resolve_target_host({'url': 'https://shop.test.example:8443/', 'port': 8443})
        self.assertEqual(host, 'shop.test.example:8443')

    def test_port_without_a_host_returns_empty_string(self) -> None:
        self.assertEqual(resolve_target_host({'port': 8080}), '')

    def test_missing_or_blank_port_leaves_the_host_untouched(self) -> None:
        self.assertEqual(resolve_target_host({'host': '192.0.2.10'}), '192.0.2.10')
        self.assertEqual(resolve_target_host({'host': '192.0.2.10', 'port': None}), '192.0.2.10')
        self.assertEqual(resolve_target_host({'host': '192.0.2.10', 'port': ''}), '192.0.2.10')


class ResolveTargetHostTruncationTests(unittest.TestCase):
    """The result must fit ScanActivity.target_host (CharField, max_length=500)."""

    def test_overlong_host_is_truncated_to_500_characters(self) -> None:
        long_host = 'h' * 600
        host = resolve_target_host({'host': long_host})
        self.assertEqual(len(host), 500)
        self.assertEqual(host, 'h' * 500)

    def test_host_of_exactly_500_characters_is_preserved(self) -> None:
        exact_host = 'h' * 500
        self.assertEqual(resolve_target_host({'host': exact_host}), exact_host)

    def test_truncation_also_applies_after_the_port_is_appended(self) -> None:
        host = resolve_target_host({'host': 'h' * 498, 'port': 8080})
        self.assertLessEqual(len(host), 500)


class GetTaskTierTests(unittest.TestCase):
    """get_task_tier maps a task name onto its timeline tier, defaulting to 7."""

    def test_planned_tasks_keep_their_declared_tier(self) -> None:
        self.assertEqual(get_task_tier('subdomain_discovery'), 1)
        self.assertEqual(get_task_tier('http_crawl'), 2)
        self.assertEqual(get_task_tier('fetch_url'), 3)
        self.assertEqual(get_task_tier('dir_file_fuzz'), 4)
        self.assertEqual(get_task_tier('waf_detection'), 5)
        self.assertEqual(get_task_tier('nuclei_scan'), 6)
        self.assertEqual(get_task_tier('acunetix_scan'), 6)

    def test_runtime_only_tasks_are_no_longer_filed_under_tier_7(self) -> None:
        self.assertEqual(get_task_tier('search_vulns_scan'), 2)
        for name in (
            'smugglex_scan',
            'second_order_scan',
            'nuclei_dast_scan',
            'semgrep_scan',
            'wptaint_scan',
        ):
            with self.subTest(task=name):
                self.assertEqual(get_task_tier(name), 6)

    def test_post_processing_tasks_fall_through_to_tier_7(self) -> None:
        for name in ('correlate_vulnerabilities', 'sync_graph', 'scan_notification'):
            with self.subTest(task=name):
                self.assertEqual(get_task_tier(name), 7)

    def test_unknown_and_empty_names_default_to_tier_7(self) -> None:
        self.assertEqual(get_task_tier('not_a_real_task'), 7)
        self.assertEqual(get_task_tier(''), 7)


class AcunetixFailHelperTests(unittest.TestCase):
    """_fail records the reason on the task object and returns False."""

    def test_fail_returns_false_and_stores_the_message(self) -> None:
        task = _FakeTask()
        result = _fail(task, 'Acunetix API keys not fully configured in vault.')
        self.assertIs(result, False)
        self.assertEqual(task.error, 'Acunetix API keys not fully configured in vault.')

    def test_fail_logs_with_percent_style_formatting(self) -> None:
        task = _FakeTask()
        with patch('reNgine.tasks.acunetix.logger') as mock_logger:
            _fail(task, 'boom for host.test.example')
        # Security rule 2.1: externally-controlled data passed as a log argument,
        # never interpolated into the format string.
        mock_logger.error.assert_called_once_with(
            'Acunetix scan failed: %s', 'boom for host.test.example'
        )


class AcunetixScanEarlyFailureTests(unittest.TestCase):
    """Failures raised before any DB access need no database."""

    def test_invalid_subdomain_name_reports_the_reason(self) -> None:
        task = _FakeTask()
        result = acunetix_scan(task, domain_id=1, subdomain_name='not a valid host!!')
        self.assertIs(result, False)
        self.assertIsNotNone(task.error)
        self.assertIn('Invalid subdomain', task.error)
        self.assertIn('not a valid host!!', task.error)


class AcunetixScanMissingCredentialsTests(TestCase):
    """A missing/partial Acunetix credential must surface on the task, not vanish."""

    def setUp(self) -> None:
        self.project = Project.objects.create(
            name='acu-proj', slug='acu-proj', insert_date=timezone.now()
        )
        self.domain = Domain.objects.create(
            name='acu.test.example', project=self.project, insert_date=timezone.now()
        )

    def test_no_credentials_returns_false_and_sets_error(self) -> None:
        task = _FakeTask()
        with patch('reNgine.tasks.acunetix.AcunetixAPIKey') as mock_keys:
            mock_keys.objects.first.return_value = None
            result = acunetix_scan(task, domain_id=self.domain.id)

        self.assertIs(result, False)
        self.assertIsNotNone(task.error, 'acunetix_scan must report why it gave up')
        self.assertIn('Acunetix API keys', task.error)
        self.assertIn('vault', task.error)

    def test_partial_credentials_are_treated_as_missing(self) -> None:
        task = _FakeTask()
        partial = MagicMock(server_url='https://awvs.test.example', api_key='')
        with patch('reNgine.tasks.acunetix.AcunetixAPIKey') as mock_keys:
            mock_keys.objects.first.return_value = partial
            result = acunetix_scan(task, domain_id=self.domain.id)

        self.assertIs(result, False)
        self.assertIn('Acunetix API keys', task.error)

    def test_target_host_is_recorded_before_the_credential_check(self) -> None:
        task = _FakeTask()
        with patch('reNgine.tasks.acunetix.AcunetixAPIKey') as mock_keys:
            mock_keys.objects.first.return_value = None
            acunetix_scan(task, domain_id=self.domain.id)

        self.assertEqual(task.target_host, 'acu.test.example')


class ScanSummaryTimelineFieldsTests(TestCase):
    """The scan-summary timeline exposes target_host, traceback and execution_id."""

    def setUp(self) -> None:
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='timeline-host-user', password='pass', email='th@test.example',
            is_staff=True, is_superuser=True,
        )
        self.client.force_authenticate(user=self.user)
        self.client.force_login(self.user)
        assign_role(self.user, 'sys_admin')

        self.project = Project.objects.create(
            name='th-proj', slug='th-proj', insert_date=timezone.now()
        )
        engine = EngineType.objects.create(engine_name='th-engine', yaml_configuration='')
        self.domain = Domain.objects.create(
            name='th.test.example', project=self.project, insert_date=timezone.now()
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain, scan_type=engine, scan_status=2,
            start_scan_date=timezone.now(),
        )

    def _timeline(self) -> list:
        url = reverse(
            'api:scan_summary_api',
            kwargs={'slug': self.project.slug, 'id': self.scan.id},
        )
        response = self.client.get(url)
        self.assertEqual(response.status_code, 200)
        return response.json().get('timeline', [])

    def test_successful_activity_exposes_its_target_host(self) -> None:
        from reNgine.definitions import SUCCESS_TASK
        activity = ScanActivity.objects.create(
            scan_of=self.scan,
            name='acunetix_scan',
            title='Acunetix Scan',
            target_host='api.th.test.example:8443',
            tier=6,
            status=SUCCESS_TASK,
            time=timezone.now(),
            time_started=timezone.now(),
            execution_id='scan-42-acunetix-1',
        )

        entry = next(e for e in self._timeline() if e['id'] == activity.id)
        self.assertEqual(entry['target_host'], 'api.th.test.example:8443')
        self.assertEqual(entry['execution_id'], 'scan-42-acunetix-1')
        self.assertEqual(entry['traceback'], '')

    def test_failed_activity_exposes_its_traceback(self) -> None:
        from reNgine.definitions import FAILED_TASK
        trace = 'Traceback (most recent call last):\n  File "t.py", line 1\nException: boom'
        activity = ScanActivity.objects.create(
            scan_of=self.scan,
            name='wpscan_scan',
            title='WPScan',
            target_host='blog.th.test.example',
            tier=6,
            status=FAILED_TASK,
            time=timezone.now(),
            time_started=timezone.now(),
            error_message='Task wpscan_scan failed: boom',
            traceback=trace,
            execution_id='scan-42-wpscan-1',
        )

        entry = next(e for e in self._timeline() if e['id'] == activity.id)
        self.assertEqual(entry['status'], 'FAILED')
        self.assertEqual(entry['target_host'], 'blog.th.test.example')
        self.assertEqual(entry['traceback'], trace)
        self.assertEqual(entry['error_message'], 'Task wpscan_scan failed: boom')
        self.assertEqual(entry['execution_id'], 'scan-42-wpscan-1')

    def test_auditor_does_not_receive_the_traceback(self) -> None:
        """Security rule 8.1 — raw exception text stays with operator roles."""
        from reNgine.definitions import FAILED_TASK
        activity = ScanActivity.objects.create(
            scan_of=self.scan,
            name='wpscan_scan',
            title='WPScan',
            target_host='blog.th.test.example',
            tier=6,
            status=FAILED_TASK,
            time=timezone.now(),
            time_started=timezone.now(),
            error_message='Task wpscan_scan failed: boom',
            traceback='Traceback (most recent call last):\nException: boom',
        )
        auditor = User.objects.create_user(
            username='timeline-auditor', password='pass', email='ta@test.example',
        )
        assign_role(auditor, 'auditor')
        self.client.force_authenticate(user=auditor)
        self.client.force_login(auditor)

        entry = next(e for e in self._timeline() if e['id'] == activity.id)
        self.assertEqual(entry['traceback'], '')
        # The short, sanitised message stays visible to every role.
        self.assertEqual(entry['error_message'], 'Task wpscan_scan failed: boom')
        self.assertEqual(entry['target_host'], 'blog.th.test.example')

    def test_whole_scan_activity_reports_empty_strings_not_null(self) -> None:
        from reNgine.definitions import SUCCESS_TASK
        activity = ScanActivity.objects.create(
            scan_of=self.scan,
            name='sync_graph',
            title='Sync Graph',
            tier=7,
            status=SUCCESS_TASK,
            time=timezone.now(),
            time_started=timezone.now(),
        )

        entry = next(e for e in self._timeline() if e['id'] == activity.id)
        # The frontend renders these directly, so NULL must be normalised away.
        self.assertEqual(entry['target_host'], '')
        self.assertEqual(entry['traceback'], '')
        self.assertEqual(entry['execution_id'], '')

    def test_every_timeline_entry_carries_the_three_new_keys(self) -> None:
        from reNgine.definitions import SUCCESS_TASK
        for index in range(3):
            ScanActivity.objects.create(
                scan_of=self.scan,
                name='port_scan',
                title='Port Scan',
                target_host=f'host{index}.th.test.example',
                tier=2,
                status=SUCCESS_TASK,
                time=timezone.now(),
                time_started=timezone.now(),
            )

        timeline = self._timeline()
        self.assertEqual(len(timeline), 3)
        for entry in timeline:
            with self.subTest(entry=entry['id']):
                self.assertIn('target_host', entry)
                self.assertIn('traceback', entry)
                self.assertIn('execution_id', entry)
