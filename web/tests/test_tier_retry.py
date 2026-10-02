"""Tests for the tier-level scan retry endpoint (``ScanTierRetryAPIView``)."""

import os
import re
import unittest
from unittest.mock import AsyncMock, MagicMock, patch

from django.contrib.auth.models import User
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role

from reNgine.definitions import (
    ABORTED_TASK, FAILED_TASK, INITIATED_TASK, PAUSED_TASK,
    RUNNING_TASK, SUCCESS_TASK,
)
from scanEngine.models import EngineType
from startScan.models import ScanActivity, ScanHistory
from targetApp.models import Domain


def _tier_url(scan_id: int, tier: int) -> str:
    return f'/api/action/retry/tier/{scan_id}/{tier}/'


class TierRetryTestCase(TestCase):
    """Common fixture: an aborted scan owned by a penetration tester."""

    def setUp(self):
        self.user = User.objects.create_user('tierretry', password='testpass')
        assign_role(self.user, 'penetration_tester')
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        self.client.force_login(self.user)

        self.domain = Domain.objects.create(name='tier-retry.example.com')
        self.engine = EngineType.objects.create(
            engine_name='test-engine-tier-retry',
            yaml_configuration='subdomain_discovery: {}\n',
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=ABORTED_TASK,
            start_scan_date=timezone.now(),
            results_dir='/tmp/tier-retry-test',
        )

    def _activity(self, name, tier, task_status, **extra):
        return ScanActivity.objects.create(
            scan_of=self.scan,
            name=name,
            title=name,
            tier=tier,
            status=task_status,
            time=timezone.now(),
            time_started=timezone.now(),
            **extra,
        )

    def _mock_temporal(self):
        """Patch the Temporal client and return the ``start_workflow`` mock."""
        start_workflow = AsyncMock(return_value=MagicMock(id='wf'))
        client = MagicMock()
        client.start_workflow = start_workflow
        patcher = patch(
            'reNgine.temporal_client.TemporalClientProvider.get_client',
            new_callable=AsyncMock,
            return_value=client,
        )
        patcher.start()
        self.addCleanup(patcher.stop)
        return start_workflow


class TestTierRetryOnlyFailedRows(TierRetryTestCase):

    def test_only_failed_rows_in_the_tier_are_retried(self):
        start_workflow = self._mock_temporal()

        failed = self._activity('waf_detection', 5, FAILED_TASK)
        succeeded = self._activity('secret_scanning', 5, SUCCESS_TASK)
        pending = self._activity('vigolium_analysis', 5, INITIATED_TASK)
        # A failed row in a different tier must not be touched either.
        other_tier = self._activity('port_scan', 2, FAILED_TASK)

        response = self.client.post(_tier_url(self.scan.id, 5), format='json')

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body['status'])
        self.assertFalse(body['no_op'])
        self.assertEqual(body['queued_count'], 1)
        self.assertEqual(body['skipped_count'], 0)
        self.assertEqual(
            [entry['name'] for entry in body['queued']], ['waf_detection']
        )
        self.assertEqual(body['queued'][0]['activity_id'], failed.id)

        self.assertEqual(start_workflow.await_count, 1)

        failed.refresh_from_db()
        self.assertEqual(failed.status, INITIATED_TASK)
        # Kept, not cleared: the timeline hides INITIATED rows without a start
        # time, so clearing it would remove the row the operator just retried.
        self.assertIsNotNone(failed.time_started)

        for untouched, expected in (
            (succeeded, SUCCESS_TASK),
            (pending, INITIATED_TASK),
            (other_tier, FAILED_TASK),
        ):
            untouched.refresh_from_db()
            self.assertEqual(untouched.status, expected)

        self.scan.refresh_from_db()
        self.assertEqual(self.scan.scan_status, RUNNING_TASK)

    def test_original_scan_status_is_passed_to_the_workflow(self):
        start_workflow = self._mock_temporal()
        ScanHistory.objects.filter(pk=self.scan.pk).update(scan_status=SUCCESS_TASK)

        self._activity('waf_detection', 5, FAILED_TASK)
        self.client.post(_tier_url(self.scan.id, 5), format='json')

        ctx, task_name = start_workflow.await_args.kwargs['args']
        self.assertEqual(task_name, 'waf_detection')
        self.assertEqual(ctx['original_scan_status'], SUCCESS_TASK)
        self.assertEqual(ctx['scan_history_id'], self.scan.id)
        self.assertEqual(ctx['tasks'], ['waf_detection'])

    def test_running_scan_cannot_be_retried(self):
        start_workflow = self._mock_temporal()
        ScanHistory.objects.filter(pk=self.scan.pk).update(scan_status=RUNNING_TASK)
        self._activity('waf_detection', 5, FAILED_TASK)

        response = self.client.post(_tier_url(self.scan.id, 5), format='json')

        self.assertEqual(response.status_code, 400)
        self.assertEqual(start_workflow.await_count, 0)

    def test_paused_scan_cannot_be_retried(self):
        start_workflow = self._mock_temporal()
        ScanHistory.objects.filter(pk=self.scan.pk).update(scan_status=PAUSED_TASK)
        self._activity('waf_detection', 5, FAILED_TASK)

        response = self.client.post(_tier_url(self.scan.id, 5), format='json')

        self.assertEqual(response.status_code, 400)
        self.assertEqual(start_workflow.await_count, 0)


class TestTierRetryNoOp(TierRetryTestCase):

    def test_tier_with_nothing_failed_is_a_no_op(self):
        start_workflow = self._mock_temporal()
        self._activity('waf_detection', 5, SUCCESS_TASK)
        self._activity('secret_scanning', 5, INITIATED_TASK)

        response = self.client.post(_tier_url(self.scan.id, 5), format='json')

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertTrue(body['status'])
        self.assertTrue(body['no_op'])
        self.assertEqual(body['queued_count'], 0)
        self.assertEqual(body['skipped_count'], 0)
        self.assertIn('No failed tasks in tier 5', body['message'])

        self.assertEqual(start_workflow.await_count, 0)
        self.scan.refresh_from_db()
        self.assertEqual(self.scan.scan_status, ABORTED_TASK)

    def test_unknown_scan_returns_404(self):
        self._mock_temporal()
        response = self.client.post(_tier_url(self.scan.id + 9999, 5), format='json')
        self.assertEqual(response.status_code, 404)

    def test_out_of_range_tier_is_rejected(self):
        self._mock_temporal()
        response = self.client.post(_tier_url(self.scan.id, 42), format='json')
        self.assertEqual(response.status_code, 400)


class TestTierRetrySkipsUndispatchableTasks(TierRetryTestCase):

    def test_undispatchable_task_is_skipped_and_reported(self):
        start_workflow = self._mock_temporal()

        # smugglex_scan is a tier-6 runtime task SingleTaskRetryWorkflow has no
        # branch for — it would raise a non-retryable ApplicationError.
        undispatchable = self._activity('smugglex_scan', 6, FAILED_TASK)
        dispatchable = self._activity('waf_bypass', 6, FAILED_TASK)

        response = self.client.post(_tier_url(self.scan.id, 6), format='json')

        self.assertEqual(response.status_code, 200)
        body = response.json()
        self.assertEqual(body['queued_count'], 1)
        self.assertEqual(body['skipped_count'], 1)
        self.assertEqual(body['queued'][0]['activity_id'], dispatchable.id)

        skipped = body['skipped'][0]
        self.assertEqual(skipped['activity_id'], undispatchable.id)
        self.assertEqual(skipped['name'], 'smugglex_scan')
        self.assertEqual(skipped['reason'], 'unsupported_task')
        self.assertIn('smugglex_scan', skipped['message'])

        self.assertEqual(start_workflow.await_count, 1)

        undispatchable.refresh_from_db()
        self.assertEqual(
            undispatchable.status, FAILED_TASK,
            'A skipped row must stay FAILED so the timeline keeps telling the truth',
        )

    def test_nuclei_and_acunetix_rows_are_retried_through_their_steps(self):
        start_workflow = self._mock_temporal()
        nuclei = self._activity('nuclei_scan', 6, FAILED_TASK)
        acunetix = self._activity('acunetix_scan', 6, FAILED_TASK)

        response = self.client.post(_tier_url(self.scan.id, 6), format='json')

        body = response.json()
        self.assertEqual(body['queued_count'], 2)
        self.assertEqual(body['skipped_count'], 0)
        dispatched = {
            call.kwargs['args'][0]['activity_id']: call.kwargs['args'][1]
            for call in start_workflow.await_args_list
        }
        self.assertEqual(dispatched, {nuclei.id: 'vulnerability_scan', acunetix.id: 'run_acunetix'})

    def test_tier_of_only_undispatchable_tasks_is_a_reported_no_op(self):
        start_workflow = self._mock_temporal()
        self._activity('smugglex_scan', 6, FAILED_TASK)

        response = self.client.post(_tier_url(self.scan.id, 6), format='json')

        body = response.json()
        self.assertTrue(body['no_op'])
        self.assertEqual(body['queued_count'], 0)
        self.assertEqual(body['skipped_count'], 1)
        self.assertEqual(start_workflow.await_count, 0)
        self.scan.refresh_from_db()
        self.assertEqual(self.scan.scan_status, ABORTED_TASK)

    def test_subscan_rows_are_skipped(self):
        from startScan.models import SubScan, Subdomain

        start_workflow = self._mock_temporal()
        subdomain = Subdomain.objects.create(
            name='sub.tier-retry.example.com',
            target_domain=self.domain,
            scan_history=self.scan,
        )
        subscan = SubScan.objects.create(
            scan_history=self.scan,
            subdomain=subdomain,
            start_scan_date=timezone.now(),
            status=FAILED_TASK,
            type='port_scan',
        )
        row = self._activity('port_scan', 2, FAILED_TASK, subscan=subscan)

        response = self.client.post(_tier_url(self.scan.id, 2), format='json')

        body = response.json()
        self.assertEqual(body['queued_count'], 0)
        self.assertEqual(body['skipped'][0]['reason'], 'subscan_unsupported')
        self.assertEqual(start_workflow.await_count, 0)
        row.refresh_from_db()
        self.assertEqual(row.status, FAILED_TASK)


class TestTierRetryIdempotency(TierRetryTestCase):

    def test_second_immediate_call_does_not_double_start(self):
        start_workflow = self._mock_temporal()
        self._activity('waf_detection', 5, FAILED_TASK)

        first = self.client.post(_tier_url(self.scan.id, 5), format='json').json()
        self.assertEqual(first['queued_count'], 1)

        second = self.client.post(_tier_url(self.scan.id, 5), format='json').json()

        self.assertTrue(second['no_op'])
        self.assertEqual(second['queued_count'], 0)
        self.assertEqual(
            start_workflow.await_count, 1,
            'A second click must not start a second workflow for the same row',
        )

    def test_workflow_id_is_deterministic(self):
        start_workflow = self._mock_temporal()
        activity = self._activity('waf_detection', 5, FAILED_TASK)

        response = self.client.post(_tier_url(self.scan.id, 5), format='json')

        expected = f'tier-retry-{self.scan.id}-t5-a{activity.id}'
        self.assertEqual(start_workflow.await_args.kwargs['id'], expected)
        self.assertEqual(response.json()['queued'][0]['workflow_id'], expected)

    def test_row_is_restored_when_the_workflow_cannot_be_started(self):
        start_workflow = self._mock_temporal()
        start_workflow.side_effect = RuntimeError('temporal unreachable')
        activity = self._activity(
            'waf_detection', 5, FAILED_TASK, error_message='original boom'
        )

        response = self.client.post(_tier_url(self.scan.id, 5), format='json')

        body = response.json()
        self.assertFalse(body['status'])
        self.assertEqual(body['queued_count'], 0)
        self.assertEqual(body['skipped'][0]['reason'], 'start_failed')
        self.assertNotIn('temporal unreachable', body['skipped'][0]['message'])

        activity.refresh_from_db()
        self.assertEqual(activity.status, FAILED_TASK)
        self.assertEqual(activity.error_message, 'original boom')
        self.assertIsNotNone(activity.time_started)
        self.scan.refresh_from_db()
        self.assertEqual(self.scan.scan_status, ABORTED_TASK)


class TestTierRetryPermissions(TierRetryTestCase):

    def test_anonymous_user_is_rejected(self):
        start_workflow = self._mock_temporal()
        self._activity('waf_detection', 5, FAILED_TASK)

        response = APIClient().post(_tier_url(self.scan.id, 5), format='json')

        self.assertIn(response.status_code, (401, 403, 302))
        self.assertEqual(start_workflow.await_count, 0)

    def test_role_without_scan_permission_is_rejected(self):
        start_workflow = self._mock_temporal()
        self._activity('waf_detection', 5, FAILED_TASK)

        auditor = User.objects.create_user('tierretry-auditor', password='testpass')
        assign_role(auditor, 'auditor')
        client = APIClient()
        client.force_authenticate(user=auditor)

        response = client.post(_tier_url(self.scan.id, 5), format='json')

        # The app redirects a signed-in user who lacks the role rather than
        # answering 403 — see test_identity_infra and test_certificate_intel.
        # What matters here is that nothing was dispatched.
        self.assertIn(response.status_code, (302, 403))
        self.assertEqual(start_workflow.await_count, 0)

    def test_view_declares_the_same_guard_rails_as_the_single_task_view(self):
        from api.views.scan import ScanActivityRetryAPIView, ScanTierRetryAPIView

        self.assertEqual(
            ScanTierRetryAPIView.permission_classes,
            ScanActivityRetryAPIView.permission_classes,
        )
        self.assertEqual(
            ScanTierRetryAPIView.permission_required,
            ScanActivityRetryAPIView.permission_required,
        )


WORKFLOWS_FILE = os.path.join(
    os.path.dirname(__file__), '..', 'reNgine', 'temporal', 'workflows', 'jobs.py'
)


class TestRetryableTaskNamesStayInSync(unittest.TestCase):
    """The allowlist mirrors SingleTaskRetryWorkflow's dispatch chain; if a
    branch is added or removed there, this test points at the drift."""

    def test_allowlist_matches_workflow_dispatch_branches(self):
        from reNgine.task_plan import RETRYABLE_TASK_NAMES

        with open(WORKFLOWS_FILE, encoding='utf-8-sig') as handle:
            source = handle.read()

        start = source.index('class SingleTaskRetryWorkflow')
        end = source.index('Unrecognised task_name for retry', start)
        block = source[start:end]

        # Two branch shapes dispatch a task: an equality test, and a membership
        # test listing the aliases a task is also known by.
        dispatched = set(re.findall(r'task_name == "([^"]+)"', block))
        for group in re.findall(r'task_name in \(([^)]*)\)', block):
            dispatched.update(
                name.strip().strip('\'"')
                for name in group.split(',')
                if name.strip()
            )

        self.assertTrue(dispatched, 'Failed to parse the dispatch chain')
        self.assertEqual(
            set(RETRYABLE_TASK_NAMES), dispatched,
            'RETRYABLE_TASK_NAMES drifted from SingleTaskRetryWorkflow',
        )
