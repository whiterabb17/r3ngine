"""One failing scan tool no longer fails the whole MasterScanWorkflow.

A fuzzer that hit its time limit twice used to end the workflow, so Tiers 5-7
were marked FAILED without having run. Tool activities are now awaited through
_isolated_tool, which logs the failure and lets the scan continue.
"""
import ast
import asyncio
import inspect
from unittest import TestCase
from unittest.mock import MagicMock, patch

from temporalio.exceptions import ActivityError

from reNgine.temporal.workflows import _common, master_scan
from reNgine.temporal.workflows._common import _isolated_tool


def _activity_error() -> ActivityError:
    return ActivityError(
        'Activity task timed out', scheduled_event_id=1, started_event_id=2, identity='worker',
        activity_type='RunDirFileFuzzActivity', activity_id='1', retry_state=None,
    )


class IsolatedToolTests(TestCase):

    def _await(self, coro):
        with patch.object(_common.workflow, 'logger'), \
                patch.object(_common.workflow, 'info', return_value=MagicMock(workflow_id='master-scan-6-run-0')):
            return asyncio.run(coro)

    def test_a_failed_tool_is_logged_and_the_scan_goes_on(self) -> None:
        async def failing():
            raise _activity_error()

        self.assertIsNone(self._await(_isolated_tool('RunDirFileFuzzActivity', failing())))

    def test_the_result_of_a_tool_that_ran_is_passed_through(self) -> None:
        async def ok():
            return {'found': 3}

        self.assertEqual(self._await(_isolated_tool('RunPortScanActivity', ok())), {'found': 3})

    def test_a_user_abort_still_stops_the_scan(self) -> None:
        async def cancelled():
            raise asyncio.CancelledError()

        with self.assertRaises(asyncio.CancelledError):
            self._await(_isolated_tool('RunPortScanActivity', cancelled()))


class MasterScanUsesIsolatedToolTests(TestCase):
    """Every long tool in Tiers 1-6 of MasterScanWorkflow.run goes through _isolated_tool."""

    TOOLS = {
        'RunSubdomainDiscoveryActivity', 'RunHTTPCrawlActivity', 'RunPortScanActivity',
        'RunVigoliumDiscoveryActivity', 'RunFetchURLActivity', 'RunWebAPIDiscoveryActivity',
        'RunDirFileFuzzActivity', 'RunSecretScanningActivity', 'RunVigoliumAnalysisActivity',
        'RunWAFBypassActivity',
    }

    def test_no_tool_activity_is_awaited_bare(self) -> None:
        tree = ast.parse(inspect.getsource(master_scan.MasterScanWorkflow.run).replace('\n    ', '\n')[4:])
        bare, wrapped = set(), set()
        for node in ast.walk(tree):
            if isinstance(node, ast.Call) and getattr(node.func, 'id', None) == '_isolated_tool':
                wrapped.add(node.args[0].value)
            if isinstance(node, ast.Await) and isinstance(node.value, ast.Call):
                call = node.value
                if getattr(call.func, 'attr', None) == 'execute_activity' and call.args and isinstance(call.args[0], ast.Constant):
                    bare.add(call.args[0].value)

        self.assertEqual(self.TOOLS - wrapped, set(), 'tools not wrapped')
        self.assertEqual(self.TOOLS & bare, set(), 'tools awaited without _isolated_tool')
