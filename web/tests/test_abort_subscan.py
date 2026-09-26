"""Unit tests for Temporal-aware subscan abort."""
from unittest.mock import MagicMock, patch

from django.test import SimpleTestCase

from reNgine.definitions import (
    ABORTED_TASK,
    INITIATED_TASK,
    RUNNING_TASK,
    SUCCESS_TASK,
)
from reNgine.utils.scan_cancellation import abort_subscan


class AbortSubscanTests(SimpleTestCase):
    def _subscan(self, *, parent_status=SUCCESS_TASK, workflow_ids=None):
        parent = MagicMock()
        parent.scan_status = parent_status
        subscan = MagicMock()
        subscan.id = 42
        subscan.scan_history_id = 7
        subscan.scan_history = parent
        subscan.workflow_ids = workflow_ids if workflow_ids is not None else ['subscan-wf-42']
        return subscan

    @patch('reNgine.tasks.create_scan_activity')
    @patch('reNgine.utils.scan_cancellation.TemporalClientProvider.cancel_workflow')
    @patch('reNgine.utils.scan_cancellation.set_scan_stop_kill_switch')
    def test_arms_kill_switch_when_parent_not_live(
        self, mock_kill, mock_cancel, mock_activity
    ):
        subscan = self._subscan(parent_status=SUCCESS_TASK)

        result = abort_subscan(subscan)

        self.assertTrue(result['status'])
        mock_kill.assert_called_once_with(7, enabled=True)
        mock_cancel.assert_called_once_with('subscan-wf-42')
        self.assertEqual(subscan.status, ABORTED_TASK)
        subscan.save.assert_called_once()
        mock_activity.assert_called_once()

    @patch('reNgine.tasks.create_scan_activity')
    @patch('reNgine.utils.scan_cancellation.TemporalClientProvider.cancel_workflow')
    @patch('reNgine.utils.scan_cancellation.set_scan_stop_kill_switch')
    def test_skips_kill_switch_when_parent_master_is_running(
        self, mock_kill, mock_cancel, mock_activity
    ):
        subscan = self._subscan(parent_status=RUNNING_TASK)

        result = abort_subscan(subscan)

        self.assertTrue(result['status'])
        mock_kill.assert_not_called()
        mock_cancel.assert_called_once_with('subscan-wf-42')
        self.assertEqual(subscan.status, ABORTED_TASK)

    @patch('reNgine.tasks.create_scan_activity')
    @patch('reNgine.utils.scan_cancellation.TemporalClientProvider.cancel_workflow')
    @patch('reNgine.utils.scan_cancellation.set_scan_stop_kill_switch')
    def test_skips_kill_switch_when_parent_is_initiated(
        self, mock_kill, mock_cancel, mock_activity
    ):
        subscan = self._subscan(parent_status=INITIATED_TASK)

        result = abort_subscan(subscan)

        self.assertTrue(result['status'])
        mock_kill.assert_not_called()

    @patch('reNgine.tasks.create_scan_activity')
    @patch('reNgine.utils.scan_cancellation.TemporalClientProvider.cancel_workflow')
    @patch('reNgine.utils.scan_cancellation.set_scan_stop_kill_switch')
    def test_still_aborts_when_workflow_ids_empty(
        self, mock_kill, mock_cancel, mock_activity
    ):
        subscan = self._subscan(parent_status=SUCCESS_TASK, workflow_ids=[])

        result = abort_subscan(subscan)

        self.assertTrue(result['status'])
        mock_cancel.assert_not_called()
        self.assertEqual(subscan.status, ABORTED_TASK)
