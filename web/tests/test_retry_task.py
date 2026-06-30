from django.test import TestCase
from django.urls import reverse
from unittest.mock import patch, MagicMock
from startScan.models import ScanHistory, ScanActivity
from reNgine.definitions import FAILED_TASK, RUNNING_TASK, INITIATED_TASK, SUCCESS_TASK


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

    @patch("api.views.run_and_close")
    def test_retry_failed_activity_resets_to_initiated(self, mock_run):
        mock_run.return_value = None
        scan = _make_scan(status=FAILED_TASK)
        act = _make_activity(scan, status=FAILED_TASK)
        url = reverse("api:retry_task", kwargs={"pk": act.pk})
        resp = self.client.post(url, content_type="application/json")
        self.assertEqual(resp.status_code, 200)
        act.refresh_from_db()
        self.assertEqual(act.status, INITIATED_TASK)
        self.assertIsNone(act.time_started)

    @patch("api.views.run_and_close")
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

    @patch("api.views.run_and_close")
    def test_retry_returns_400_when_scan_paused(self, mock_run):
        from reNgine.definitions import PAUSED_TASK
        scan = _make_scan(status=PAUSED_TASK)
        act = _make_activity(scan, status=FAILED_TASK)
        url = reverse("api:retry_task", kwargs={"pk": act.pk})
        resp = self.client.post(url, content_type="application/json")
        self.assertEqual(resp.status_code, 400)

    def test_retry_returns_400_for_subscan_activity(self):
        scan = _make_scan(status=FAILED_TASK)
        act = _make_activity(scan, status=FAILED_TASK)
        # Patch objects.get so the returned instance reports a non-null subscan_id
        original_get = ScanActivity.objects.get

        def patched_get(**kwargs):
            obj = original_get(**kwargs)
            obj.subscan_id = 42  # non-null simulates a subscan-linked activity
            return obj

        url = reverse("api:retry_task", kwargs={"pk": act.pk})
        with patch.object(ScanActivity.objects, 'get', side_effect=patched_get):
            resp = self.client.post(url, content_type="application/json")
        self.assertEqual(resp.status_code, 400)


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
