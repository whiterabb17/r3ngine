from django.test import TestCase
from django.urls import reverse
from unittest.mock import patch, MagicMock, AsyncMock
from startScan.models import ScanHistory, ScanActivity
from reNgine.definitions import FAILED_TASK, RUNNING_TASK, INITIATED_TASK, SUCCESS_TASK, ABORTED_TASK


def _make_scan(status=FAILED_TASK):
    from django.utils import timezone
    from targetApp.models import Domain
    domain = Domain.objects.create(name="example.test")
    from scanEngine.models import EngineType
    engine = EngineType.objects.create(
        engine_name="Test Engine",
        yaml_configuration="subdomain_discovery:\n  uses_tools: []\n",
    )
    return ScanHistory.objects.create(
        domain=domain,
        scan_type=engine,
        scan_status=status,
        results_dir="/tmp/test",
        start_scan_date=timezone.now(),
    )


def _make_activity(scan, name="param_discovery", status=FAILED_TASK):
    import uuid
    return ScanActivity.objects.create(
        scan_of=scan,
        task_uid=uuid.uuid4(),
        name=name,
        title="Param Discovery",
        tier=3,
        status=status,
        time_started="2026-06-21T10:00:00Z",
        time="2026-06-21T10:00:00Z",
    )


class RetryTaskViewTests(TestCase):
    def setUp(self):
        from django.contrib.auth.models import User
        self.user = User.objects.create_superuser("admin", "a@b.com", "password")
        self.client.force_login(self.user)

    @patch("api.views.scan.run_and_close")
    def test_retry_failed_activity_resets_to_initiated(self, mock_run):
        mock_run.return_value = None
        scan = _make_scan(status=FAILED_TASK)
        act = _make_activity(scan, status=FAILED_TASK)
        url = reverse("api:retry_task", kwargs={"pk": act.pk})
        resp = self.client.post(url, content_type="application/json")
        self.assertEqual(resp.status_code, 200)
        act.refresh_from_db()
        self.assertEqual(act.status, INITIATED_TASK)
        # Keep time_started so the timeline does not hide this as a ghost row.
        self.assertIsNotNone(act.time_started)

    @patch("api.views.scan.run_and_close")
    def test_retry_flips_scan_to_running(self, mock_run):
        mock_run.return_value = None
        scan = _make_scan(status=FAILED_TASK)
        act = _make_activity(scan, status=FAILED_TASK)
        url = reverse("api:retry_task", kwargs={"pk": act.pk})
        self.client.post(url, content_type="application/json")
        scan.refresh_from_db()
        self.assertEqual(scan.scan_status, RUNNING_TASK)

    def test_retry_returns_400_when_scan_running(self):
        scan = _make_scan(status=RUNNING_TASK)
        act = _make_activity(scan, status=FAILED_TASK)
        url = reverse("api:retry_task", kwargs={"pk": act.pk})
        resp = self.client.post(url, content_type="application/json")
        self.assertEqual(resp.status_code, 400)

    def test_retry_returns_400_for_non_failed_activity(self):
        scan = _make_scan(status=FAILED_TASK)
        act = _make_activity(scan, status=SUCCESS_TASK)
        url = reverse("api:retry_task", kwargs={"pk": act.pk})
        resp = self.client.post(url, content_type="application/json")
        self.assertEqual(resp.status_code, 400)

    def test_retry_returns_404_for_missing_activity(self):
        url = reverse("api:retry_task", kwargs={"pk": 99999})
        resp = self.client.post(url, content_type="application/json")
        self.assertEqual(resp.status_code, 404)

    @patch("api.views.scan.run_and_close")
    def test_retry_returns_400_when_scan_paused(self, mock_run):
        from reNgine.definitions import PAUSED_TASK
        scan = _make_scan(status=PAUSED_TASK)
        act = _make_activity(scan, status=FAILED_TASK)
        url = reverse("api:retry_task", kwargs={"pk": act.pk})
        resp = self.client.post(url, content_type="application/json")
        self.assertEqual(resp.status_code, 400)

    @patch("api.views.scan.run_and_close")
    def test_retry_subscan_activity_carries_subscan_context(self, mock_run):
        """Subscan-linked activities are retryable like parent-scan rows."""
        from django.utils import timezone
        from startScan.models import SubScan, Subdomain
        scan = _make_scan(status=FAILED_TASK)
        subdomain = Subdomain.objects.create(
            scan_history=scan, target_domain=scan.domain, name="app.example.test",
        )
        subscan = SubScan.objects.create(
            scan_history=scan, subdomain=subdomain, status=FAILED_TASK,
            start_scan_date=timezone.now(),
        )
        act = _make_activity(scan, status=FAILED_TASK)
        ScanActivity.objects.filter(pk=act.pk).update(subscan=subscan)

        with patch("reNgine.temporal_client.TemporalClientProvider.get_client",
                   new_callable=AsyncMock) as mock_get_client:
            url = reverse("api:retry_task", kwargs={"pk": act.pk})
            resp = self.client.post(url, content_type="application/json")
            self.assertEqual(resp.status_code, 200)
            # Drive the coroutine handed to run_and_close to inspect the ctx.
            import asyncio
            asyncio.run(mock_run.call_args[0][1])
        ctx = mock_get_client.return_value.start_workflow.call_args.kwargs["args"][0]
        self.assertEqual(ctx["subscan_id"], subscan.id)
        self.assertEqual(ctx["subdomain_id"], subdomain.id)

    @patch("api.views.scan.run_and_close")
    def test_retry_success_activity_on_completed_scan_returns_200(self, mock_run):
        """Guard must accept any activity status when the parent scan is SUCCESS."""
        mock_run.return_value = None
        scan = _make_scan(status=SUCCESS_TASK)
        act = _make_activity(scan, status=SUCCESS_TASK)
        url = reverse("api:retry_task", kwargs={"pk": act.pk})
        resp = self.client.post(url, content_type="application/json")
        self.assertEqual(resp.status_code, 200)
        act.refresh_from_db()
        self.assertEqual(act.status, INITIATED_TASK)

    def test_retry_success_activity_on_running_scan_still_returns_400(self):
        """RUNNING scan must still block retry even if the activity is in any state."""
        scan = _make_scan(status=RUNNING_TASK)
        act = _make_activity(scan, status=SUCCESS_TASK)
        url = reverse("api:retry_task", kwargs={"pk": act.pk})
        resp = self.client.post(url, content_type="application/json")
        self.assertEqual(resp.status_code, 400)

    @patch("api.views.scan.run_and_close")
    def test_retry_ctx_includes_original_scan_status(self, mock_run):
        """original_scan_status captured before scan flips to RUNNING must equal SUCCESS_TASK."""
        from unittest.mock import AsyncMock
        import asyncio

        mock_client = MagicMock()
        mock_client.start_workflow = AsyncMock()

        scan = _make_scan(status=SUCCESS_TASK)
        act = _make_activity(scan, status=SUCCESS_TASK)
        url = reverse("api:retry_task", kwargs={"pk": act.pk})

        with patch(
            "reNgine.temporal_client.TemporalClientProvider.get_client",
            new=AsyncMock(return_value=mock_client),
        ):
            mock_run.side_effect = lambda _loop, coro: asyncio.run(coro)
            resp = self.client.post(url, content_type="application/json")

        self.assertEqual(resp.status_code, 200)
        _, call_kwargs = mock_client.start_workflow.call_args
        ctx_arg = call_kwargs["args"][0]
        self.assertEqual(ctx_arg.get("original_scan_status"), SUCCESS_TASK)

    @patch("api.views.scan.run_and_close")
    @patch("reNgine.utils.scan_cancellation.set_scan_stop_kill_switch")
    def test_retry_aborted_activity_clears_kill_switch(self, mock_kill, mock_run):
        """Abort leaves Redis scan_stop_{id}; retry must clear it or Go kills the run."""
        mock_run.return_value = None
        scan = _make_scan(status=ABORTED_TASK)
        act = _make_activity(scan, status=ABORTED_TASK)
        url = reverse("api:retry_task", kwargs={"pk": act.pk})
        resp = self.client.post(url, content_type="application/json")
        self.assertEqual(resp.status_code, 200)
        act.refresh_from_db()
        self.assertEqual(act.status, INITIATED_TASK)
        scan.refresh_from_db()
        self.assertEqual(scan.scan_status, RUNNING_TASK)
        mock_kill.assert_called_with(scan.id, enabled=False)

    @patch("api.views.scan.run_and_close")
    def test_retry_aborted_activity_on_aborted_scan_returns_200(self, mock_run):
        mock_run.return_value = None
        scan = _make_scan(status=ABORTED_TASK)
        act = _make_activity(scan, status=ABORTED_TASK)
        url = reverse("api:retry_task", kwargs={"pk": act.pk})
        resp = self.client.post(url, content_type="application/json")
        self.assertEqual(resp.status_code, 200)


class RetryFailedTasksTemporalTests(TestCase):
    @patch("reNgine.temporal_client.TemporalClientProvider.get_client", new_callable=AsyncMock)
    def test_orm_updates_happen_before_async_start(self, mock_get_client):
        """Django ORM inside asyncio.run() raises SynchronousOnlyOperation."""
        from reNgine.tasks.scan_init import retry_failed_tasks_temporal

        mock_client = MagicMock()
        mock_client.start_workflow = AsyncMock()
        mock_get_client.return_value = mock_client

        scan = _make_scan(status=FAILED_TASK)
        act = _make_activity(scan, name="generate_impact_assessment", status=FAILED_TASK)

        started = retry_failed_tasks_temporal(scan, auto=False)

        self.assertEqual(started, ["generate_impact_assessment"])
        act.refresh_from_db()
        self.assertEqual(act.status, INITIATED_TASK)
        self.assertIsNotNone(act.time_started)
        mock_client.start_workflow.assert_awaited()
        _, kwargs = mock_client.start_workflow.call_args
        self.assertEqual(kwargs["args"][1], "generate_impact_assessment")
        self.assertEqual(kwargs["args"][0]["scan_history_id"], scan.id)

    def _retry(self, *row_names):
        from reNgine.tasks.scan_init import retry_failed_tasks_temporal

        scan = _make_scan(status=FAILED_TASK)
        rows = [_make_activity(scan, name=name, status=FAILED_TASK) for name in row_names]
        client = MagicMock()
        client.start_workflow = AsyncMock()
        with patch("reNgine.temporal_client.TemporalClientProvider.get_client",
                   new_callable=AsyncMock, return_value=client):
            started = retry_failed_tasks_temporal(scan, auto=True)
        scan.refresh_from_db()
        return scan, rows, started, client.start_workflow

    def test_a_nuclei_row_is_retried_through_the_vulnerability_scan_step(self):
        """Recovery sent the row name, which SingleTaskRetryWorkflow rejects at once."""
        _, (row,), started, start = self._retry("nuclei_scan")

        self.assertEqual(started, ["vulnerability_scan"])
        ctx, task_name = start.call_args.kwargs["args"]
        self.assertEqual(task_name, "vulnerability_scan")
        self.assertEqual(ctx["tasks"], ["vulnerability_scan"])
        self.assertEqual(ctx["activity_id"], row.id, "the row is closed even if the retry fails early")
        row.refresh_from_db()
        self.assertEqual(row.status, INITIATED_TASK)

    def test_rows_of_one_step_start_a_single_retry(self):
        _, _, started, start = self._retry("nuclei_scan", "vulnerability_scan")

        self.assertEqual(started, ["vulnerability_scan"])
        self.assertEqual(start.await_count, 1)

    def test_a_row_that_cannot_be_retried_leaves_the_scan_alone(self):
        scan, (row,), started, start = self._retry("crlfuzz_scan")

        self.assertEqual(started, [])
        start.assert_not_awaited()
        self.assertEqual(scan.scan_status, FAILED_TASK, "nothing runs, so the scan must not show RUNNING")
        row.refresh_from_db()
        self.assertEqual(row.status, FAILED_TASK)


from reNgine.temporal_activities import get_scan_final_status_activity, initialize_scan_tasks_activity


class GetScanFinalStatusTests(TestCase):
    def test_returns_failed_when_task_did_not_succeed(self):
        scan = _make_scan()
        result = get_scan_final_status_activity(scan.id, False)
        self.assertEqual(result, FAILED_TASK)

    def test_returns_success_when_no_true_failures(self):
        scan = _make_scan()
        _make_activity(scan, name="http_crawl", status=SUCCESS_TASK)
        result = get_scan_final_status_activity(scan.id, True)
        self.assertEqual(result, SUCCESS_TASK)

    def test_returns_failed_when_other_tasks_still_failed(self):
        scan = _make_scan()
        import uuid
        ScanActivity.objects.create(
            scan_of=scan,
            task_uid=uuid.uuid4(),
            name="other_task",
            title="Other",
            tier=2,
            status=FAILED_TASK,
            time_started="2026-06-21T09:00:00Z",
            time="2026-06-21T09:00:00Z",
        )
        result = get_scan_final_status_activity(scan.id, True)
        self.assertEqual(result, FAILED_TASK)

    def test_returns_failed_when_sibling_tasks_remain_aborted(self):
        """A successful single retry must not erase an aborted scan's unfinished work."""
        scan = _make_scan(status=ABORTED_TASK)
        _make_activity(scan, name="http_crawl", status=SUCCESS_TASK)
        _make_activity(scan, name="port_scan", status=ABORTED_TASK)
        result = get_scan_final_status_activity(scan.id, True)
        self.assertEqual(result, FAILED_TASK)

    def test_keeps_running_when_sibling_retry_still_pending(self):
        scan = _make_scan()
        _make_activity(scan, name="generate_impact_assessment", status=SUCCESS_TASK)
        _make_activity(scan, name="sync_graph", status=INITIATED_TASK)
        result = get_scan_final_status_activity(
            scan.id, True, ["generate_impact_assessment", "sync_graph"]
        )
        self.assertEqual(result, RUNNING_TASK)

    def test_a_planned_row_that_never_started_does_not_hold_the_scan_running(self):
        import uuid
        scan = _make_scan()
        _make_activity(scan, name="generate_impact_assessment", status=SUCCESS_TASK)
        ScanActivity.objects.create(
            scan_of=scan, task_uid=uuid.uuid4(), name="sync_graph", title="Graph Sync",
            tier=7, status=INITIATED_TASK, time="2026-06-21T10:00:00Z", time_started=None,
        )
        result = get_scan_final_status_activity(
            scan.id, True, ["generate_impact_assessment", "sync_graph"]
        )
        self.assertEqual(result, SUCCESS_TASK)

    def test_failed_retry_marks_visible_initiated_row_failed(self):
        scan = _make_scan()
        act = _make_activity(scan, name="generate_impact_assessment", status=INITIATED_TASK)
        result = get_scan_final_status_activity(
            scan.id, False, [], "generate_impact_assessment"
        )
        self.assertEqual(result, FAILED_TASK)
        act.refresh_from_db()
        self.assertEqual(act.status, FAILED_TASK)

    def test_failed_retry_leaves_ghost_initiated_alone(self):
        import uuid
        scan = _make_scan()
        ghost = ScanActivity.objects.create(
            scan_of=scan,
            task_uid=uuid.uuid4(),
            name="generate_impact_assessment",
            title="AI Impact Assessment",
            tier=7,
            status=INITIATED_TASK,
            time="2026-06-21T10:00:00Z",
            time_started=None,
        )
        result = get_scan_final_status_activity(
            scan.id, False, [], "generate_impact_assessment"
        )
        self.assertEqual(result, FAILED_TASK)
        ghost.refresh_from_db()
        self.assertEqual(ghost.status, INITIATED_TASK)


class SingleTaskRetryWorkflowSourceTests(TestCase):
    def test_catches_application_error_and_retries_impact_assessment(self):
        from pathlib import Path
        source = (
            Path(__file__).resolve().parent.parent
            / "reNgine"
            / "temporal"
            / "workflows"
            / "jobs.py"
        ).read_text(encoding="utf-8")
        self.assertIn('task_name == "generate_impact_assessment"', source)
        self.assertIn(
            "except (ActivityError, ChildWorkflowError, ApplicationError)",
            source,
        )
        retry_run = source.split("class SingleTaskRetryWorkflow", 1)[1]
        activity_pos = retry_run.find('"GetScanFinalStatusActivity"')
        success_override_pos = retry_run.find("final_status = SUCCESS_TASK")
        self.assertGreater(activity_pos, 0)
        self.assertGreater(success_override_pos, activity_pos)


class TierStalenessTests(TestCase):
    def test_existing_row_tier_is_updated(self):
        scan = _make_scan()
        # Simulate a row that was created when web_api_discovery was in tier 5
        import uuid
        old_row = ScanActivity.objects.create(
            scan_of=scan,
            task_uid=uuid.uuid4(),
            name="web_api_discovery",
            title="Web API Discovery",
            tier=5,
            status=INITIATED_TASK,
            time="2026-06-21T10:00:00Z",
        )
        # Call activity with a plan that puts web_api_discovery in tier 3
        ctx = {
            "scan_history_id": scan.id,
            "tasks": ["web_api_discovery"],
            "yaml_configuration": {},
        }
        with patch(
            "reNgine.task_plan.build_scan_task_plan",
            return_value=[{"name": "web_api_discovery", "title": "Web API Discovery", "tier": 3}],
        ):
            initialize_scan_tasks_activity(ctx)

        old_row.refresh_from_db()
        self.assertEqual(old_row.tier, 3)


class RetryTaskDispatchNameTests(TestCase):
    """Rows named after their activity are retried as the step that runs them."""

    def setUp(self):
        from django.contrib.auth.models import User
        self.client.force_login(User.objects.create_superuser("dispatch", "d@test.example", "password"))

    def _retry(self, name):
        scan = _make_scan(status=SUCCESS_TASK)
        act = _make_activity(scan, name=name, status=FAILED_TASK)
        temporal = MagicMock()
        temporal.start_workflow = AsyncMock()
        with patch("reNgine.temporal_client.TemporalClientProvider.get_client", new=AsyncMock(return_value=temporal)):
            resp = self.client.post(reverse("api:retry_task", kwargs={"pk": act.pk}), content_type="application/json")
        return resp, temporal.start_workflow, scan, act

    def test_a_nuclei_row_is_retried_through_the_vulnerability_scan_step(self):
        resp, start, _scan, _act = self._retry("nuclei_scan")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(start.call_args.kwargs["args"][1], "vulnerability_scan")
        self.assertTrue(start.call_args.kwargs["id"].startswith("retry-vulnerability_scan-"))

    def test_the_acunetix_row_is_retried_through_run_acunetix(self):
        resp, start, _scan, _act = self._retry("acunetix_scan")
        self.assertEqual(resp.status_code, 200)
        self.assertEqual(start.call_args.kwargs["args"][1], "run_acunetix")

    def test_a_row_the_workflow_cannot_retry_is_refused_without_changes(self):
        resp, start, scan, act = self._retry("crlfuzz_scan")
        self.assertEqual(resp.status_code, 400)
        self.assertFalse(resp.json()["status"])
        start.assert_not_called()
        act.refresh_from_db()
        scan.refresh_from_db()
        self.assertEqual(act.status, FAILED_TASK)
        self.assertEqual(scan.scan_status, SUCCESS_TASK)

    def test_dispatch_names_always_name_a_step_the_workflow_handles(self):
        from reNgine.task_plan import RETRY_TASK_ALIASES, RETRYABLE_TASK_NAMES, retry_dispatch_name
        for row, step in RETRY_TASK_ALIASES.items():
            self.assertIn(step, RETRYABLE_TASK_NAMES)
            self.assertEqual(retry_dispatch_name(row), step)
            self.assertEqual(retry_dispatch_name(f"single_tool_{row}"), step)
        self.assertIsNone(retry_dispatch_name("crlfuzz_scan"))
