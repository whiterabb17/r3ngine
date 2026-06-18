import os
import django
from django.test import TestCase
from unittest.mock import patch, MagicMock, AsyncMock

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'reNgine.settings')
django.setup()

from startScan.models import ScanHistory, EngineType, SubScan, Subdomain
from targetApp.models import Domain
from django.utils import timezone
import yaml

class TestTemporalOrchestration(TestCase):
    """Integration and unit tests for the Temporal workflow initiation handlers."""

    def setUp(self):
        """Set up test targets, scan engines, and scan history records in the DB."""
        self.domain, _ = Domain.objects.get_or_create(name='temporal-test.local')
        self.engine = EngineType.objects.create(
            engine_name='Temporal Test Engine',
            yaml_configuration=yaml.dump({
                'enable_http_crawl': True,
                'subdomain_discovery': {},
                'port_scan': {},
                'fetch_url': {},
                'web_api_discovery': {
                    'uses_tools': ['kiterunner'],
                    'kr_wordlist': 'routes-small.kite'
                }
            })
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            start_scan_date=timezone.now(),
            tasks=[]
        )

    def tearDown(self):
        """Clean up all created database models."""
        from startScan.models import ScanActivity, Subdomain, SubScan
        ScanActivity.objects.filter(scan_of=self.scan).delete()
        SubScan.objects.filter(scan_history=self.scan).delete()
        Subdomain.objects.filter(scan_history=self.scan).delete()
        self.scan.delete()
        self.engine.delete()
        self.domain.delete()

    @patch('reNgine.temporal_client.TemporalClientProvider.get_client', new_callable=AsyncMock)
    @patch('reNgine.tasks.save_endpoint')
    @patch('reNgine.tasks.send_scan_notif')
    def test_initiate_scan_temporal(self, mock_send_notif, mock_save_endpoint, mock_get_client):
        """Test that initiate_scan_temporal correctly sets up scan history and starts the MasterScanWorkflow."""
        from reNgine.tasks import initiate_scan_temporal

        # Mock Temporal Client and Workflow Handle
        mock_handle = MagicMock()
        mock_handle.id = "mock-scan-workflow-id"
        mock_client = AsyncMock()
        mock_client.start_workflow.return_value = mock_handle
        mock_get_client.return_value = mock_client

        # Mock Endpoint save
        mock_endpoint = MagicMock(is_alive=True)
        mock_endpoint.http_url = "http://temporal-test.local"
        mock_endpoint.http_status = 200
        mock_endpoint.response_time = 0.5
        mock_endpoint.page_title = "Temporal Test"
        mock_endpoint.content_type = "text/html"
        mock_endpoint.content_length = 1234
        mock_endpoint.techs.all.return_value = []
        mock_save_endpoint.return_value = (mock_endpoint, True)

        # Trigger temporal scan initiation
        result = initiate_scan_temporal(
            scan_history_id=self.scan.id,
            domain_id=self.domain.id,
            engine_id=self.engine.id
        )

        # Verify function output
        self.assertTrue(result['success'])
        self.assertEqual(result['workflow_id'], 'mock-scan-workflow-id')

        # Verify start_workflow was called with correct parameters
        mock_client.start_workflow.assert_called_once()
        args, kwargs = mock_client.start_workflow.call_args
        self.assertEqual(args[0], "MasterScanWorkflow")
        self.assertEqual(kwargs['task_queue'], "python-orchestrator-queue")
        
        # Verify the context dictionary
        temporal_ctx = args[1]
        self.assertEqual(temporal_ctx['scan_history_id'], self.scan.id)
        self.assertEqual(temporal_ctx['domain_id'], self.domain.id)
        self.assertEqual(temporal_ctx['engine_id'], self.engine.id)

    @patch('reNgine.temporal_client.TemporalClientProvider.get_client', new_callable=AsyncMock)
    @patch('reNgine.tasks.save_endpoint')
    @patch('reNgine.tasks.send_scan_notif')
    def test_initiate_subscan_temporal(self, mock_send_notif, mock_save_endpoint, mock_get_client):
        """Test that initiate_subscan_temporal sets up subscan record and triggers SubScanWorkflow on Temporal."""
        from reNgine.tasks import initiate_subscan_temporal

        # Setup subdomain
        subdomain = Subdomain.objects.create(
            name='sub.temporal-test.local',
            target_domain=self.domain,
            scan_history=self.scan
        )

        # Mock Temporal Client and Workflow Handle
        mock_handle = MagicMock()
        mock_handle.id = "mock-subscan-workflow-id"
        mock_client = AsyncMock()
        mock_client.start_workflow.return_value = mock_handle
        mock_get_client.return_value = mock_client

        # Mock Endpoint save
        mock_endpoint = MagicMock(is_alive=True)
        mock_endpoint.http_url = "http://sub.temporal-test.local"
        mock_endpoint.http_status = 200
        mock_endpoint.response_time = 0.5
        mock_endpoint.page_title = "Temporal Subscan Test"
        mock_endpoint.content_type = "text/html"
        mock_endpoint.content_length = 5678
        mock_endpoint.techs.all.return_value = []
        mock_save_endpoint.return_value = (mock_endpoint, True)

        # Trigger subscan initiation
        result = initiate_subscan_temporal(
            scan_history_id=self.scan.id,
            subdomain_id=subdomain.id,
            engine_id=self.engine.id,
            scan_type='port_scan'
        )

        # Verify function output
        self.assertTrue(result['success'])
        self.assertEqual(result['workflow_id'], 'mock-subscan-workflow-id')

        # Verify start_workflow parameters
        mock_client.start_workflow.assert_called_once()
        args, kwargs = mock_client.start_workflow.call_args
        self.assertEqual(args[0], "SubScanWorkflow")
        self.assertEqual(kwargs['task_queue'], "python-orchestrator-queue")
        
        # Verify arguments passed to SubScanWorkflow
        workflow_args = kwargs['args']
        temporal_ctx, scan_types = workflow_args
        self.assertEqual(scan_types, ['port_scan'])

        # Verify SubScan DB entry has correct status and workflow ID stored in workflow_ids
        subscan = SubScan.objects.filter(subdomain=subdomain).first()
        self.assertIsNotNone(subscan)
        self.assertEqual(temporal_ctx['subscan_id'], subscan.id)
        self.assertEqual(temporal_ctx['subdomain_id'], subdomain.id)
        self.assertEqual(subscan.workflow_ids, ['mock-subscan-workflow-id'])

    @patch('reNgine.temporal_client.TemporalClientProvider.get_client', new_callable=AsyncMock)
    @patch('reNgine.tasks.save_endpoint')
    @patch('reNgine.tasks.send_scan_notif')
    def test_initiate_multiple_subscans_temporal(self, mock_send_notif, mock_save_endpoint, mock_get_client):
        """Test that initiating subscans with multiple tasks creates multiple SubScan records

        but starts only a single SubScanWorkflow, correctly associating the workflow ID
        across all of them and passing the complete task list to Temporal.
        """
        from reNgine.tasks import initiate_subscan_temporal

        # Setup subdomain
        subdomain = Subdomain.objects.create(
            name='multi.temporal-test.local',
            target_domain=self.domain,
            scan_history=self.scan
        )

        # Mock Temporal Client and Workflow Handle
        mock_handle = MagicMock()
        mock_handle.id = "mock-multi-subscan-workflow-id"
        mock_client = AsyncMock()
        mock_client.start_workflow.return_value = mock_handle
        mock_get_client.return_value = mock_client

        # Mock Endpoint save
        mock_endpoint = MagicMock(is_alive=True)
        mock_endpoint.http_url = "http://multi.temporal-test.local"
        mock_endpoint.http_status = 200
        mock_endpoint.response_time = 0.4
        mock_endpoint.page_title = "Temporal Multi Subscan Test"
        mock_endpoint.content_type = "text/html"
        mock_endpoint.content_length = 9999
        mock_endpoint.techs.all.return_value = []
        mock_save_endpoint.return_value = (mock_endpoint, True)

        # Target multiple tasks
        tasks = ['port_scan', 'fetch_url', 'vulnerability_scan']

        # Trigger subscan initiation
        result = initiate_subscan_temporal(
            scan_history_id=self.scan.id,
            subdomain_id=subdomain.id,
            engine_id=self.engine.id,
            scan_type=tasks
        )

        # Verify output success status and workflow ID
        self.assertTrue(result['success'])
        self.assertEqual(result['workflow_id'], 'mock-multi-subscan-workflow-id')

        # Verify start_workflow was called exactly once
        mock_client.start_workflow.assert_called_once()
        args, kwargs = mock_client.start_workflow.call_args
        self.assertEqual(args[0], "SubScanWorkflow")
        
        # Verify arguments passed to SubScanWorkflow
        workflow_args = kwargs['args']
        self.assertEqual(len(workflow_args), 2)
        temporal_ctx, scan_type = workflow_args
        self.assertEqual(scan_type, tasks)

        # Verify multiple SubScan DB entries are created
        subscans = SubScan.objects.filter(subdomain=subdomain)
        self.assertEqual(subscans.count(), 3)

        # Verify all subscans have same workflow ID stored
        for subscan in subscans:
            self.assertEqual(subscan.workflow_ids, ['mock-multi-subscan-workflow-id'])

    @patch('reNgine.temporal_client.TemporalClientProvider.get_client', new_callable=AsyncMock)
    @patch('reNgine.tasks.save_endpoint')
    @patch('reNgine.tasks.send_scan_notif')
    def test_initiate_subscan_temporal_skips_duplicate_active_type(self, mock_send_notif, mock_save_endpoint, mock_get_client):
        """Duplicate subscan launches for the same subdomain/type should reuse the active run."""
        from reNgine.tasks import initiate_subscan_temporal
        from reNgine.definitions import RUNNING_TASK

        subdomain = Subdomain.objects.create(
            name='dedupe.temporal-test.local',
            target_domain=self.domain,
            scan_history=self.scan
        )

        existing_subscan = SubScan.objects.create(
            start_scan_date=timezone.now(),
            workflow_ids=['existing-workflow-id'],
            scan_history=self.scan,
            subdomain=subdomain,
            type='run_acunetix',
            status=RUNNING_TASK,
            engine=self.engine
        )

        result = initiate_subscan_temporal(
            scan_history_id=self.scan.id,
            subdomain_id=subdomain.id,
            engine_id=self.engine.id,
            scan_type='run_acunetix'
        )

        self.assertTrue(result['success'])
        self.assertTrue(result['skipped'])
        self.assertEqual(result['workflow_id'], 'existing-workflow-id')
        self.assertEqual(result['skipped_scan_types'], ['run_acunetix'])
        self.assertEqual(SubScan.objects.filter(subdomain=subdomain, type='run_acunetix').count(), 1)
        self.assertEqual(SubScan.objects.get(id=existing_subscan.id).workflow_ids, ['existing-workflow-id'])
        mock_get_client.assert_not_called()
        mock_save_endpoint.assert_not_called()
        mock_send_notif.assert_not_called()

    @patch('reNgine.tasks.resume_scan_temporal')
    @patch('reNgine.temporal_client.TemporalClientProvider.get_client', new_callable=AsyncMock)
    def test_recover_stuck_scans_restarts_running_and_failed(self, mock_get_client, mock_resume_scan):
        """Verify recover_stuck_scans recovers both RUNNING_TASK and FAILED_TASK scans with dead workflows, but not ABORTED ones."""
        from reNgine.tasks import recover_stuck_scans
        from reNgine.definitions import FAILED_TASK, RUNNING_TASK, ABORTED_TASK
        from temporalio.service import RPCError, RPCStatusCode
        from django.utils import timezone

        # Clear RUNNING/FAILED scans created by setUp to isolate this test
        ScanHistory.objects.filter(scan_status__in=[RUNNING_TASK, FAILED_TASK]).delete()

        # Create test scans under different states
        scan_running_stuck = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            start_scan_date=timezone.now(),
            scan_status=RUNNING_TASK,
            recovery_count=0,
            workflow_ids=["stuck-workflow-1"]
        )
        scan_running_active = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            start_scan_date=timezone.now(),
            scan_status=RUNNING_TASK,
            recovery_count=0,
            workflow_ids=["active-workflow-2"]
        )
        scan_failed = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            start_scan_date=timezone.now(),
            scan_status=FAILED_TASK,
            recovery_count=0,
            workflow_ids=["failed-workflow"]
        )
        scan_aborted = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            start_scan_date=timezone.now(),
            scan_status=ABORTED_TASK,
            recovery_count=0,
            workflow_ids=["aborted-workflow"]
        )
        scan_stopped = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            start_scan_date=timezone.now(),
            scan_status=RUNNING_TASK,
            recovery_count=0,
            stop_scan_date=timezone.now(),
            workflow_ids=["stopped-workflow"]
        )

        # Mock Temporal client to return NOT_FOUND (inactive/dead) for all except the active one
        mock_client = MagicMock()
        
        def mock_get_handle(workflow_id):
            h = MagicMock()
            async def mock_describe():
                if "active" in workflow_id:
                    mock_desc = MagicMock()
                    from temporalio.client import WorkflowExecutionStatus
                    mock_desc.status = WorkflowExecutionStatus.RUNNING
                    return mock_desc
                else:
                    raise RPCError("Workflow not found", RPCStatusCode.NOT_FOUND, "details")
            h.describe = mock_describe
            return h

        mock_client.get_workflow_handle.side_effect = mock_get_handle
        mock_get_client.return_value = mock_client

        # Execute recovery
        recover_stuck_scans()

        # Assert both the stuck running scan and the failed scan are resumed (dead workflows)
        self.assertEqual(mock_resume_scan.call_count, 2)
        mock_resume_scan.assert_any_call(scan_running_stuck.id)
        mock_resume_scan.assert_any_call(scan_failed.id)

        # Clean up database records
        scan_running_stuck.delete()
        scan_running_active.delete()
        scan_failed.delete()
        scan_aborted.delete()
        scan_stopped.delete()


class TestWorkflowStructuralInvariants(TestCase):
    """AST-level checks that enforce structural guarantees introduced by:

    1. Tier 6 sequential-nuclei fix (FIXES.md Fix 2): NucleiPlannerWorkflow
       must not be inside asyncio.gather with other T6 activities.
    2. MasterScanWorkflow finally-block alignment: Tier 7 activities must live
       inside the finally block, guarded by 'if success:'.

    These tests fail fast if a code change accidentally reverts the fixes.
    No Temporal server or Django ORM is required — they inspect source only.
    """

    _SOURCE_PATH = "reNgine/temporal_workflows.py"

    @classmethod
    def _source(cls):
        with open(cls._SOURCE_PATH) as f:
            return f.read()

    def test_masterscan_vulnerability_scan_not_in_assessment_futures(self):
        """NucleiPlannerWorkflow must NOT be appended to assessment_futures.

        Placing the child workflow handle inside assessment_futures means it
        would be gathered concurrently with waf_bypass.
        If those activities fail, asyncio.gather cannot cancel the Temporal
        child workflow, causing it to run unmanaged (orphaned).
        """
        import ast
        source = self._source()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == "MasterScanWorkflow":
                for item in ast.walk(node):
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == "run":
                        method_src = ast.get_source_segment(source, item) or ""
                        self.assertNotIn(
                            "assessment_futures.append",
                            method_src,
                            "vulnerability_scan (NucleiPlannerWorkflow) must not be "
                            "inside assessment_futures — it must be awaited sequentially "
                            "before the concurrent gather of other T6 activities."
                        )
                        return
        self.fail("MasterScanWorkflow.run() not found in temporal_workflows.py")

    def test_subscan_nuclei_future_variable_present(self):
        """SubScanWorkflow tier loop must declare 'nuclei_future' to separate
        vulnerability_scan from the concurrent tier_futures gather."""
        self.assertIn(
            "nuclei_future",
            self._source(),
            "SubScanWorkflow Tier 6 fix must introduce 'nuclei_future' variable "
            "to hold the vulnerability_scan coroutine separately from tier_futures."
        )

    def test_subscan_nuclei_awaited_before_tier_futures_gather(self):
        """'await nuclei_future' must appear before 'await asyncio.gather(*tier_futures)'.

        This ordering guarantees NucleiPlannerWorkflow completes before any
        concurrent T6 activity can raise — preventing the orphaned-child scenario.
        """
        source = self._source()
        nuclei_idx = source.find("await nuclei_future")
        gather_idx = source.find("await asyncio.gather(*tier_futures)")
        self.assertGreater(nuclei_idx, 0,
                           "'await nuclei_future' not found in temporal_workflows.py")
        self.assertGreater(gather_idx, 0,
                           "'await asyncio.gather(*tier_futures)' not found")
        self.assertLess(
            nuclei_idx, gather_idx,
            "'await nuclei_future' must appear before 'await asyncio.gather(*tier_futures)' "
            "in the SubScanWorkflow tier loop."
        )

    def test_masterscan_has_success_flag(self):
        """MasterScanWorkflow.run() must declare 'success' and set it True/False."""
        import ast
        source = self._source()
        tree = ast.parse(source)
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == "MasterScanWorkflow":
                for item in ast.walk(node):
                    if isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)) and item.name == "run":
                        method_src = ast.get_source_segment(source, item) or ""
                        self.assertIn("success = True", method_src,
                                      "MasterScanWorkflow.run() must set 'success = True'")
                        self.assertIn("success = False", method_src,
                                      "MasterScanWorkflow.run() must initialise 'success = False'")
                        return
        self.fail("MasterScanWorkflow.run() not found in temporal_workflows.py")

    def test_masterscan_correlate_activity_in_finally_block(self):
        """CorrelateVulnerabilitiesActivity must appear inside a finally: block
        in MasterScanWorkflow.run(), not inline in the try: body."""
        import ast
        source = self._source()
        tree = ast.parse(source)

        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == "MasterScanWorkflow":
                for item in ast.walk(node):
                    if not isinstance(item, (ast.FunctionDef, ast.AsyncFunctionDef)):
                        continue
                    if item.name != "run":
                        continue
                    for try_node in ast.walk(item):
                        if not isinstance(try_node, ast.Try):
                            continue
                        finally_src = "".join(
                            ast.get_source_segment(source, stmt) or ""
                            for stmt in try_node.finalbody
                        )
                        if "CorrelateVulnerabilitiesActivity" in finally_src:
                            return  # Correct — found in finally block
                    self.fail(
                        "CorrelateVulnerabilitiesActivity must be inside a 'finally:' block "
                        "in MasterScanWorkflow.run(), not inline in the try: body. "
                        "It must be guarded by 'if success:' so it only runs on clean completion."
                    )
        self.fail("MasterScanWorkflow.run() not found in temporal_workflows.py")

    def test_masterscan_nuclei_failure_does_not_raise(self):
        """NucleiPlannerWorkflow failure must be caught so Tier 7 still runs.

        Reads temporal_workflows.py source and asserts the execute_child_workflow
        call for NucleiPlannerWorkflow is wrapped in a try-except block,
        confirming Tier 7 correlation/risk/Neo4j activities are not gated on it.
        """
        import ast

        src_path = os.path.join(
            os.path.dirname(__file__), '..', 'reNgine', 'temporal_workflows.py'
        )
        with open(src_path) as f:
            source = f.read()

        tree = ast.parse(source)

        # Find the MasterScanWorkflow.run method
        run_method = None
        for node in ast.walk(tree):
            if isinstance(node, ast.ClassDef) and node.name == 'MasterScanWorkflow':
                for item in node.body:
                    if isinstance(item, (ast.AsyncFunctionDef, ast.FunctionDef)) and item.name == 'run':
                        run_method = item
                        break
                break

        self.assertIsNotNone(run_method, "MasterScanWorkflow.run not found")

        # Find execute_child_workflow("NucleiPlannerWorkflow") call node
        nuclei_call_node = None
        for node in ast.walk(run_method):
            if isinstance(node, ast.Expr) and isinstance(node.value, (ast.Await, ast.Call)):
                call = node.value.value if isinstance(node.value, ast.Await) else node.value
                if isinstance(call, ast.Call):
                    func = call.func
                    func_name = (
                        func.attr if isinstance(func, ast.Attribute) else
                        func.id if isinstance(func, ast.Name) else ''
                    )
                    if func_name == 'execute_child_workflow':
                        if call.args and isinstance(call.args[0], ast.Constant):
                            if call.args[0].value == 'NucleiPlannerWorkflow':
                                nuclei_call_node = node
                                break

        self.assertIsNotNone(
            nuclei_call_node,
            "execute_child_workflow('NucleiPlannerWorkflow') call not found in MasterScanWorkflow.run",
        )

        # The call must be inside a Try block (i.e. wrapped in try-except)
        def _is_inside_try(target_node, search_root):
            """Return True if target_node is a direct statement inside a Try body."""
            for node in ast.walk(search_root):
                if isinstance(node, ast.Try):
                    if target_node in node.body:
                        return True
            return False

        self.assertTrue(
            _is_inside_try(nuclei_call_node, run_method),
            "execute_child_workflow('NucleiPlannerWorkflow') must be wrapped in a try-except "
            "so that nuclei failures do not kill Tier 7 (correlation, risk scoring, Neo4j).",
        )
