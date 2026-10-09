import os

import django
from django.test import TestCase
from unittest.mock import AsyncMock, MagicMock, patch

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'reNgine.settings')
django.setup()

import yaml
from django.utils import timezone

from reNgine.definitions import FAILED_TASK, RUNNING_TASK
from scanEngine.models import EngineType
from startScan.models import ScanHistory, TemporalWorkflowExecution
from targetApp.models import Domain


class TestResumeScanRecoveryBudget(TestCase):
    """Auto-recovery budget and workflow-id uniqueness for resume_scan_temporal.

    `recover_stuck_scans` caps automatic recovery with `recovery_count < 3`, so
    an automatic resume must spend one unit of that budget while a manual resume
    from the UI must reset it.
    """

    def setUp(self):
        """Create an anonymised domain, engine and a stuck RUNNING scan."""
        # recover_stuck_scans sweeps every RUNNING/FAILED scan — make sure this
        # test class only ever sees its own.
        ScanHistory.objects.filter(scan_status__in=[RUNNING_TASK, FAILED_TASK]).delete()

        self.domain = Domain.objects.create(name='recovery-test.invalid')
        self.engine = EngineType.objects.create(
            engine_name='Recovery Budget Test Engine',
            yaml_configuration=yaml.dump({'subdomain_discovery': {}}),
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            start_scan_date=timezone.now(),
            scan_status=RUNNING_TASK,
            recovery_count=0,
            tasks=['subdomain_discovery'],
            workflow_ids=['scan-0-deadbeef'],
        )

    def _dead_workflow_client(self):
        """Temporal client mock where every workflow lookup reports NOT_FOUND."""
        from temporalio.service import RPCError, RPCStatusCode

        def get_workflow_handle(workflow_id):
            handle = MagicMock()

            async def describe():
                raise RPCError('Workflow not found', RPCStatusCode.NOT_FOUND, 'details')

            handle.describe = describe
            handle.cancel = AsyncMock()
            return handle

        client = MagicMock()
        client.get_workflow_handle.side_effect = get_workflow_handle
        client.start_workflow = AsyncMock()
        return client

    def _started_workflow_ids(self, client):
        """Workflow ids passed to client.start_workflow, in call order."""
        return [call.kwargs['id'] for call in client.start_workflow.call_args_list]

    @patch('reNgine.utils.scan_cancellation.set_scan_stop_kill_switch')
    @patch('reNgine.temporal_client.TemporalClientProvider.get_client', new_callable=AsyncMock)
    def test_automatic_resume_increments_recovery_count(self, mock_get_client, mock_kill_switch):
        """An automatic resume spends one unit of the auto-recovery budget."""
        from reNgine.tasks.scan_init import resume_scan_temporal

        mock_get_client.return_value = self._dead_workflow_client()

        resume_scan_temporal(self.scan.id, auto=True)

        self.scan.refresh_from_db()
        self.assertEqual(self.scan.recovery_count, 1)
        self.assertEqual(self.scan.scan_status, RUNNING_TASK)

    @patch('reNgine.utils.scan_cancellation.set_scan_stop_kill_switch')
    @patch('reNgine.temporal_client.TemporalClientProvider.get_client', new_callable=AsyncMock)
    def test_manual_resume_does_not_consume_recovery_budget(self, mock_get_client, mock_kill_switch):
        """A user-initiated resume resets the budget instead of spending it."""
        from reNgine.tasks.scan_init import resume_scan_temporal

        mock_get_client.return_value = self._dead_workflow_client()
        self.scan.recovery_count = 2
        self.scan.save(update_fields=['recovery_count'])

        resume_scan_temporal(self.scan.id)

        self.scan.refresh_from_db()
        self.assertEqual(self.scan.recovery_count, 0)

    @patch('reNgine.utils.scan_cancellation.set_scan_stop_kill_switch')
    @patch('reNgine.temporal_client.TemporalClientProvider.get_client', new_callable=AsyncMock)
    def test_manual_resume_clears_stop_scan_date(self, mock_get_client, mock_kill_switch):
        """recover_stuck_scans relies on stop_scan_date being cleared on resume."""
        from reNgine.tasks.scan_init import resume_scan_temporal

        mock_get_client.return_value = self._dead_workflow_client()
        self.scan.stop_scan_date = timezone.now()
        self.scan.save(update_fields=['stop_scan_date'])

        resume_scan_temporal(self.scan.id)

        self.scan.refresh_from_db()
        self.assertIsNone(self.scan.stop_scan_date)

    @patch('reNgine.utils.scan_cancellation.set_scan_stop_kill_switch')
    @patch('reNgine.temporal_client.TemporalClientProvider.get_client', new_callable=AsyncMock)
    def test_resume_attempts_use_distinct_workflow_ids(self, mock_get_client, mock_kill_switch):
        """Each resume gets its own master-scan-<id>-run-<n> workflow id."""
        from reNgine.tasks.scan_init import resume_scan_temporal

        client = self._dead_workflow_client()
        mock_get_client.return_value = client

        resume_scan_temporal(self.scan.id, auto=True)
        resume_scan_temporal(self.scan.id, auto=True)

        started_ids = self._started_workflow_ids(client)
        self.assertEqual(
            started_ids,
            [
                f'master-scan-{self.scan.id}-run-0',
                f'master-scan-{self.scan.id}-run-1',
            ],
        )
        self.assertEqual(len(set(started_ids)), 2)
        self.assertEqual(
            TemporalWorkflowExecution.objects.filter(scan_history=self.scan).count(),
            2,
        )

    @patch('reNgine.utils.scan_cancellation.set_scan_stop_kill_switch')
    @patch('reNgine.temporal_client.TemporalClientProvider.get_client', new_callable=AsyncMock)
    def test_recover_stuck_scans_stops_after_three_attempts(self, mock_get_client, mock_kill_switch):
        """The recovery_count < 3 cap bounds a scan that keeps dying."""
        from reNgine.tasks.scan_init import recover_stuck_scans

        client = self._dead_workflow_client()
        mock_get_client.return_value = client

        for _ in range(4):
            recover_stuck_scans()

        self.scan.refresh_from_db()
        self.assertEqual(self.scan.recovery_count, 3)
        self.assertEqual(client.start_workflow.await_count, 3)
        self.assertEqual(
            self._started_workflow_ids(client),
            [
                f'master-scan-{self.scan.id}-run-0',
                f'master-scan-{self.scan.id}-run-1',
                f'master-scan-{self.scan.id}-run-2',
            ],
        )

    @patch('reNgine.utils.scan_cancellation.set_scan_stop_kill_switch')
    @patch('reNgine.temporal_client.TemporalClientProvider.get_client', new_callable=AsyncMock)
    def test_manual_resume_restores_the_automatic_budget(self, mock_get_client, mock_kill_switch):
        """After the cap is reached, a manual resume makes the scan recoverable again."""
        from reNgine.tasks.scan_init import recover_stuck_scans, resume_scan_temporal

        client = self._dead_workflow_client()
        mock_get_client.return_value = client

        for _ in range(4):
            recover_stuck_scans()
        self.scan.refresh_from_db()
        self.assertEqual(self.scan.recovery_count, 3)

        resume_scan_temporal(self.scan.id)

        self.scan.refresh_from_db()
        self.assertEqual(self.scan.recovery_count, 0)

        recover_stuck_scans()

        self.scan.refresh_from_db()
        self.assertEqual(self.scan.recovery_count, 1)
        self.assertEqual(len(set(self._started_workflow_ids(client))), 5)
