"""Verify AssessmentWorkflow calls the new stages in the correct order.

We inspect the workflow module rather than running a full Temporal
worker — the goal here is to prove the workflow file sequences activities
correctly. A full-worker integration test lives in the Temporal
integration suite (out of scope for this plan).
"""
import inspect
from django.test import TestCase


class TestAssessmentWorkflowNewStages(TestCase):
    def test_run_method_calls_correlation_and_graph_sync_in_order(self):
        from reNgine.temporal.workflows.assessment_workflow import AssessmentWorkflow
        src = inspect.getsource(AssessmentWorkflow.run)

        # Correlation must appear after Analysis and before Validation
        idx_analysis = src.find("Phase 3: Analysis")
        idx_correlation = src.find("run_asset_correlation_activity")
        idx_validation = src.find("Phase 4: Validation")
        idx_graph_sync = src.find("sync_assessment_graph_activity")
        idx_reporting = src.find("Phase 5: Reporting")

        self.assertGreater(idx_correlation, 0, "correlation activity call missing")
        self.assertGreater(idx_graph_sync, 0, "graph sync activity call missing")

        self.assertGreater(idx_correlation, idx_analysis, "correlation must be after Analysis")
        self.assertLess(idx_correlation, idx_validation, "correlation must be before Validation")
        self.assertGreater(idx_graph_sync, idx_validation, "graph sync must be after Validation")
        self.assertLess(idx_graph_sync, idx_reporting, "graph sync must be before Reporting")
