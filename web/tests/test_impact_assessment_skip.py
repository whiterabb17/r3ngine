"""A disabled LLM must skip the impact assessment, not fail the scan.

`_run_task` raises when a task function returns False, which fails the Temporal
activity, burns its retry budget and marks the whole scan FAILED. Skipping a
feature that is switched off has to be indistinguishable from doing nothing.
"""
from unittest.mock import MagicMock, patch

from django.test import TestCase


class _FakeTask:
    """Minimal stand-in for the task proxy passed as `self`."""

    def __init__(self) -> None:
        self.subscan = None
        self.error = None
        self._is_temporal_proxy = True


class GenerateImpactAssessmentSkipTests(TestCase):

    def _call(self, **kwargs) -> object:
        from reNgine.tasks import generate_impact_assessment
        task = _FakeTask()
        result = generate_impact_assessment(task, **kwargs)
        return task, result

    @patch('reNgine.llm.llm_env_enabled', return_value=False)
    def test_disabled_llm_returns_none_not_false(self, _mock_enabled: MagicMock) -> None:
        task, result = self._call(scan_history_id=1)
        self.assertIsNone(
            result,
            'LLM_ENABLED unset is a skip: returning False fails the activity and the scan',
        )
        self.assertIsNone(task.error)

    @patch('reNgine.llm.llm_env_enabled', return_value=True)
    def test_missing_identifiers_fail_with_a_reason(self, _mock_enabled: MagicMock) -> None:
        task, result = self._call()
        self.assertFalse(result)
        self.assertIn('scan_history_id', task.error or '')
