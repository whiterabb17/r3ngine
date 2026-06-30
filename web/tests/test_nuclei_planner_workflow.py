"""
Tests for NucleiPlannerWorkflow — sequential severity scanning and tag batching.

Uses WorkflowEnvironment (time-skipping) from temporalio.testing to execute
the workflow against mocked activities and verify:

  1. GatherNucleiTagsActivity is called once before the severity loop.
  2. Each severity × tag-batch combination triggers its own RunNucleiActivity call.
  3. Calls are sequential and in the correct (severity, batch) order.
  4. NUCLEI_DEFAULT_SEVERITIES applies when no severity list is configured.
  5. No tags → single pass per severity with tag_batch=None (no -tags flag).
  6. run_nuclei=False suppresses all RunNucleiActivity calls.
  7. MarkVulnerabilityScanCompleteActivity fires exactly once on every run.
"""

import asyncio
import os
import unittest
from typing import Any, Dict, List, Optional
from unittest import IsolatedAsyncioTestCase

import django

os.environ.setdefault("DJANGO_SETTINGS_MODULE", "reNgine.settings")
django.setup()

from temporalio import activity
from temporalio.testing import WorkflowEnvironment
from temporalio.worker import Worker

from reNgine.temporal_workflows import NucleiPlannerWorkflow
from reNgine.definitions import NUCLEI_DEFAULT_SEVERITIES


# ---------------------------------------------------------------------------
# Mock activities — registered under their production names so the workflow
# can dispatch by name without touching real infrastructure.
# ---------------------------------------------------------------------------

@activity.defn(name="CheckScanAliveActivity")
async def _mock_check_scan_alive(scan_id: int, subscan_id: int = None) -> bool:
    """Lifecycle guard mock — always reports scan alive."""
    return True


@activity.defn(name="CreateProxyListActivity")
async def _mock_create_proxy_list(ctx: Dict[str, Any]) -> str:
    return "/tmp/mock_proxies.txt"

@activity.defn(name="CleanupProxyListActivity")
async def _mock_cleanup_proxy_list(file_path: str) -> bool:
    return True

@activity.defn(name="GatherNucleiTagsActivity")
async def _mock_gather_tags(ctx: Dict[str, Any]) -> Dict[str, Any]:
    """Default mock: no tech detected → empty batches (no -tags flag)."""
    return {'tags': [], 'batches': []}


@activity.defn(name="RunCRLFuzzActivity")
async def _mock_crlfuzz(ctx: Dict[str, Any]) -> Dict:
    return {}


@activity.defn(name="RunDalfoxActivity")
async def _mock_dalfox(ctx: Dict[str, Any]) -> Dict:
    return {}


@activity.defn(name="RunS3ScannerActivity")
async def _mock_s3scanner(ctx: Dict[str, Any]) -> Dict:
    return {}


@activity.defn(name="RunAcunetixActivity")
async def _mock_acunetix(ctx: Dict[str, Any]) -> Dict:
    return {}


@activity.defn(name="RunCpanelScanActivity")
async def _mock_cpanel(ctx: Dict[str, Any]) -> Dict:
    return {}


@activity.defn(name="RunWpscanActivity")
async def _mock_wpscan(ctx: Dict[str, Any]) -> Dict:
    return {}


@activity.defn(name="RunReact2ShellActivity")
async def _mock_react2shell(ctx: Dict[str, Any]) -> Dict:
    return {}


@activity.defn(name="RunSemgrepActivity")
async def _mock_semgrep(ctx: Dict[str, Any]) -> Dict:
    return {}


@activity.defn(name="RunVigoliumScanActivity")
async def _mock_vigolium(ctx: Dict[str, Any]) -> Dict:
    return {}


@activity.defn(name="MarkVulnerabilityScanCompleteActivity")
async def _mock_mark_complete(ctx: Dict[str, Any]) -> Dict:
    return {}


@activity.defn(name="RunWPTaintScanActivity")
async def _mock_wptaint_scan(ctx: Dict[str, Any]) -> Dict:
    return {}


_NOOP_SUPPORT_ACTIVITIES = [
    _mock_check_scan_alive,
    _mock_create_proxy_list,
    _mock_cleanup_proxy_list,
    _mock_gather_tags,
    _mock_crlfuzz,
    _mock_dalfox,
    _mock_s3scanner,
    _mock_acunetix,
    _mock_cpanel,
    _mock_wpscan,
    _mock_react2shell,
    _mock_semgrep,
    _mock_vigolium,
    _mock_wptaint_scan,
    _mock_mark_complete,
]


def _ctx(severities=None, run_nuclei: bool = True) -> Dict[str, Any]:
    """Minimal scan context for NucleiPlannerWorkflow tests.

    All optional scanners (crlfuzz, dalfox, s3scanner, etc.) are disabled so
    only RunNucleiActivity / GatherNucleiTagsActivity calls appear in logs.
    """
    nuclei_cfg: Dict[str, Any] = {}
    if severities is not None:
        nuclei_cfg["severity"] = severities

    return {
        "scan_history_id": 1,
        "yaml_configuration": {
            "vulnerability_scan": {
                "run_nuclei": run_nuclei,
                "nuclei": nuclei_cfg,
                "run_crlfuzz": False,
                "run_dalfox": False,
                "run_s3scanner": False,
                "run_acunetix": False,
                "cpanel_scanner": {"run_cpanel2shell": False},
                "run_wpscan": False,
                "run_wptaint_scan": False,
                "react_scanner": {"run_react2shell": False},
                "run_vigolium": False,
            },
            "leaks_and_secrets": {"run_semgrep": False},
        },
    }


class TestNucleiPlannerWorkflowSequential(IsolatedAsyncioTestCase):
    """Verify per-severity sequential execution in NucleiPlannerWorkflow."""

    async def _run_workflow(self, ctx, nuclei_activity, wf_id, extra_activities=None):
        """Spin up a time-skipping WorkflowEnvironment and execute the workflow."""
        support = list(_NOOP_SUPPORT_ACTIVITIES)
        # Replace _mock_gather_tags if caller provides a custom one via extra_activities
        if extra_activities:
            support_names = {a.__name__ for a in support}
            for ea in extra_activities:
                if ea.__name__ in support_names:
                    support = [a for a in support if a.__name__ != ea.__name__]
            support = extra_activities + support

        async with await WorkflowEnvironment.start_time_skipping() as env:
            async with Worker(
                env.client,
                task_queue="python-orchestrator-queue",
                workflows=[NucleiPlannerWorkflow],
                activities=[nuclei_activity, *support],
            ):
                return await env.client.execute_workflow(
                    NucleiPlannerWorkflow.run,
                    ctx,
                    id=wf_id,
                    task_queue="python-orchestrator-queue",
                )

    async def test_each_severity_gets_own_activity_call_in_order(self):
        """With no tags, RunNucleiActivity is called once per severity in order."""
        call_log: List[str] = []

        @activity.defn(name="RunNucleiActivity")
        async def track_nuclei(ctx: Dict[str, Any], severity: str, tag_batch: Optional[List[str]] = None) -> Dict:
            call_log.append(severity)
            return {}

        result = await self._run_workflow(
            _ctx(severities=["critical", "high", "medium"]),
            track_nuclei,
            "test-nuclei-ordered",
        )

        self.assertEqual(result, {"status": "SUCCESS"})
        self.assertEqual(
            call_log,
            ["critical", "high", "medium"],
            msg=f"Expected severities in order ['critical','high','medium']; got {call_log}",
        )

    async def test_default_severities_applied_when_none_configured(self):
        """NUCLEI_DEFAULT_SEVERITIES is used when no severity list is in yaml config."""
        call_log: List[str] = []

        @activity.defn(name="RunNucleiActivity")
        async def track_nuclei(ctx: Dict[str, Any], severity: str, tag_batch: Optional[List[str]] = None) -> Dict:
            call_log.append(severity)
            return {}

        result = await self._run_workflow(
            _ctx(severities=None),
            track_nuclei,
            "test-nuclei-defaults",
        )

        self.assertEqual(result, {"status": "SUCCESS"})
        self.assertEqual(
            call_log,
            list(NUCLEI_DEFAULT_SEVERITIES),
            msg=f"Expected default severities {list(NUCLEI_DEFAULT_SEVERITIES)}; got {call_log}",
        )

    async def test_run_nuclei_false_skips_all_nuclei_activity_calls(self):
        """RunNucleiActivity must not fire when run_nuclei=False in yaml config."""
        call_log: List[str] = []

        @activity.defn(name="RunNucleiActivity")
        async def track_nuclei(ctx: Dict[str, Any], severity: str, tag_batch: Optional[List[str]] = None) -> Dict:
            call_log.append(severity)
            return {}

        result = await self._run_workflow(
            _ctx(severities=["critical", "high"], run_nuclei=False),
            track_nuclei,
            "test-nuclei-disabled",
        )

        self.assertEqual(result, {"status": "SUCCESS"})
        self.assertEqual(
            call_log,
            [],
            msg=f"RunNucleiActivity must not be called when run_nuclei=False; got {call_log}",
        )

    async def test_single_severity_produces_single_call(self):
        """Configuring one severity results in exactly one RunNucleiActivity call."""
        call_log: List[str] = []

        @activity.defn(name="RunNucleiActivity")
        async def track_nuclei(ctx: Dict[str, Any], severity: str, tag_batch: Optional[List[str]] = None) -> Dict:
            call_log.append(severity)
            return {}

        result = await self._run_workflow(
            _ctx(severities=["critical"]),
            track_nuclei,
            "test-nuclei-single",
        )

        self.assertEqual(result, {"status": "SUCCESS"})
        self.assertEqual(call_log, ["critical"])

    async def test_mark_complete_activity_always_fires(self):
        """MarkVulnerabilityScanCompleteActivity must be called exactly once."""
        mark_count: List[int] = []

        @activity.defn(name="RunNucleiActivity")
        async def noop_nuclei(ctx: Dict[str, Any], severity: str, tag_batch: Optional[List[str]] = None) -> Dict:
            return {}

        @activity.defn(name="MarkVulnerabilityScanCompleteActivity")
        async def track_mark(ctx: Dict[str, Any]) -> Dict:
            mark_count.append(1)
            return {}

        support = [a for a in _NOOP_SUPPORT_ACTIVITIES if a is not _mock_mark_complete]

        async with await WorkflowEnvironment.start_time_skipping() as env:
            async with Worker(
                env.client,
                task_queue="python-orchestrator-queue",
                workflows=[NucleiPlannerWorkflow],
                activities=[noop_nuclei, track_mark, *support],
            ):
                await env.client.execute_workflow(
                    NucleiPlannerWorkflow.run,
                    _ctx(severities=["high"]),
                    id="test-nuclei-mark-complete",
                    task_queue="python-orchestrator-queue",
                )

        self.assertEqual(
            sum(mark_count),
            1,
            msg=f"MarkVulnerabilityScanCompleteActivity must be called exactly once; called {sum(mark_count)} time(s)",
        )


class TestNucleiPlannerTagBatching(IsolatedAsyncioTestCase):
    """Verify NucleiPlannerWorkflow passes activity-provided batches through to RunNucleiActivity.

    Batching logic moved to GatherNucleiTagsActivity in v3.7.0. The workflow
    consumes pre-built batches; it does not split tags itself.
    """

    async def _run_with_batches(self, severities, batches, wf_id):
        """Run the workflow with controlled pre-built batches and collect (severity, batch) pairs."""
        call_log: List[tuple] = []

        @activity.defn(name="GatherNucleiTagsActivity")
        async def mock_gather(ctx: Dict[str, Any]) -> Dict[str, Any]:
            return {'tags': [t for batch in batches for t in batch], 'batches': batches}

        @activity.defn(name="RunNucleiActivity")
        async def track_nuclei(ctx: Dict[str, Any], severity: str, tag_batch: Optional[List[str]] = None) -> Dict:
            call_log.append((severity, tag_batch))
            return {}

        support = [a for a in _NOOP_SUPPORT_ACTIVITIES
                   if a.__name__ not in ("_mock_gather_tags",)]

        async with await WorkflowEnvironment.start_time_skipping() as env:
            async with Worker(
                env.client,
                task_queue="python-orchestrator-queue",
                workflows=[NucleiPlannerWorkflow],
                activities=[mock_gather, track_nuclei, *support],
            ):
                await env.client.execute_workflow(
                    NucleiPlannerWorkflow.run,
                    _ctx(severities=severities),
                    id=wf_id,
                    task_queue="python-orchestrator-queue",
                )

        return call_log

    async def test_no_batches_produces_one_unfiltered_call_per_severity(self):
        """Empty batches from activity → one RunNucleiActivity call per severity with tag_batch=None."""
        call_log = await self._run_with_batches(
            severities=["critical", "high"],
            batches=[],
            wf_id="test-no-batches",
        )
        self.assertEqual(call_log, [("critical", None), ("high", None)])

    async def test_single_batch_fires_once_per_severity(self):
        """One batch → one RunNucleiActivity call per severity with that batch."""
        batch = ["wordpress", "wp-plugin", "wp-theme"]
        call_log = await self._run_with_batches(
            severities=["critical", "high"],
            batches=[batch],
            wf_id="test-single-batch",
        )
        self.assertEqual(call_log, [
            ("critical", batch),
            ("high", batch),
        ])

    async def test_two_batches_fire_in_order_per_severity(self):
        """Two batches → two calls per severity, severity-first ordering preserved."""
        batch_a = ["wordpress"]
        batch_b = ["wp-plugin", "wp-theme"]
        call_log = await self._run_with_batches(
            severities=["critical", "high"],
            batches=[batch_a, batch_b],
            wf_id="test-two-batches",
        )
        expected = [
            ("critical", batch_a),
            ("critical", batch_b),
            ("high",     batch_a),
            ("high",     batch_b),
        ]
        self.assertEqual(call_log, expected)

    async def test_workflow_does_not_split_batches(self):
        """Workflow passes batches through as-is; it does not sub-split large batches."""
        large_batch = ["wordpress", "wp-plugin", "wp-theme", "wp", "joomla", "drupal", "apache"]
        call_log = await self._run_with_batches(
            severities=["critical"],
            batches=[large_batch],
            wf_id="test-passthrough",
        )
        self.assertEqual(call_log, [("critical", large_batch)])

    async def test_gather_tags_called_once_before_severity_loop(self):
        """GatherNucleiTagsActivity fires exactly once regardless of severity/batch count."""
        gather_count: List[int] = []

        @activity.defn(name="GatherNucleiTagsActivity")
        async def counting_gather(ctx: Dict[str, Any]) -> Dict[str, Any]:
            gather_count.append(1)
            return {'tags': ['wordpress', 'apache'], 'batches': [['wordpress'], ['apache']]}

        @activity.defn(name="RunNucleiActivity")
        async def noop_nuclei(ctx: Dict[str, Any], severity: str, tag_batch: Optional[List[str]] = None) -> Dict:
            return {}

        support = [a for a in _NOOP_SUPPORT_ACTIVITIES
                   if a.__name__ not in ("_mock_gather_tags",)]

        async with await WorkflowEnvironment.start_time_skipping() as env:
            async with Worker(
                env.client,
                task_queue="python-orchestrator-queue",
                workflows=[NucleiPlannerWorkflow],
                activities=[counting_gather, noop_nuclei, *support],
            ):
                await env.client.execute_workflow(
                    NucleiPlannerWorkflow.run,
                    _ctx(severities=["critical", "high", "medium"]),
                    id="test-gather-once",
                    task_queue="python-orchestrator-queue",
                )

        self.assertEqual(
            sum(gather_count),
            1,
            msg=f"GatherNucleiTagsActivity must fire exactly once; fired {sum(gather_count)} time(s)",
        )
