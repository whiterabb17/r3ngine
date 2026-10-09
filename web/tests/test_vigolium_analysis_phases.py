"""Tier 5 vigolium analysis must not redo what the earlier pass already did.

`discovery` over the subdomain roots is exactly the pass `vigolium_discovery`
runs in Tier 2, and `external-harvest` is skipped by vigolium itself under
`--stateless`, which every r3ngine invocation uses.

The drop is driven by evidence that the earlier pass really produced output for
this scan — its JSONL file — not by the engine config flag, which only says the
pass was requested.
"""
import json
import os
import tempfile
from unittest import TestCase

from reNgine.tasks.vigolium import (
    _analysis_phases,
    _discovery_output_file,
    _discovery_produced_results,
)


class AnalysisPhaseSelectionTests(TestCase):

    def test_discovery_is_dropped_when_tier2_ran_it(self) -> None:
        self.assertEqual(
            _analysis_phases(skip_spidering=False, discovery_already_ran=True),
            'spidering,known-issue-scan,dynamic-assessment',
        )

    def test_discovery_is_kept_when_tier2_is_disabled(self) -> None:
        """A scan configured without the Tier 2 pass must lose no coverage."""
        self.assertEqual(
            _analysis_phases(skip_spidering=False, discovery_already_ran=False),
            'spidering,discovery,known-issue-scan,dynamic-assessment',
        )

    def test_skip_spidering_removes_only_the_browser_crawl(self) -> None:
        self.assertEqual(
            _analysis_phases(skip_spidering=True, discovery_already_ran=True),
            'known-issue-scan,dynamic-assessment',
        )
        self.assertEqual(
            _analysis_phases(skip_spidering=True, discovery_already_ran=False),
            'discovery,known-issue-scan,dynamic-assessment',
        )

    def test_external_harvest_is_never_requested(self) -> None:
        """It is a no-op under --stateless — see the helper's docstring."""
        for skip in (True, False):
            for ran in (True, False):
                self.assertNotIn(
                    'external-harvest',
                    _analysis_phases(skip_spidering=skip, discovery_already_ran=ran),
                )

    def test_assessment_phases_always_run(self) -> None:
        for skip in (True, False):
            for ran in (True, False):
                phases = _analysis_phases(skip_spidering=skip, discovery_already_ran=ran)
                self.assertIn('known-issue-scan', phases)
                self.assertIn('dynamic-assessment', phases)


class DiscoveryEvidenceTests(TestCase):
    """`discovery_already_ran` comes from the earlier pass's output, not the config."""

    def setUp(self) -> None:
        self._tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self._tmp.cleanup)
        self.results_dir = self._tmp.name

    def _write_output(self, *records: dict) -> str:
        output_file = _discovery_output_file(self.results_dir)
        os.makedirs(os.path.dirname(output_file), exist_ok=True)
        with open(output_file, 'w') as f:
            for record in records:
                f.write(json.dumps(record) + '\n')
        return output_file

    def test_output_path_is_where_the_discovery_task_writes(self) -> None:
        self.assertEqual(
            _discovery_output_file('/scan_results/7'),
            '/scan_results/7/vigolium/discovery/discovery.jsonl',
        )

    def test_no_output_file_means_discovery_did_not_run(self) -> None:
        """Disabled, crashed, or returned early with no targets — all look like this."""
        self.assertFalse(_discovery_produced_results(self.results_dir))

    def test_empty_output_file_means_discovery_produced_nothing(self) -> None:
        self._write_output()
        self.assertFalse(_discovery_produced_results(self.results_dir))

    def test_output_without_records_means_discovery_produced_nothing(self) -> None:
        """A progress/log-only file is not evidence of coverage."""
        self._write_output({'type': 'progress', 'data': {'phase': 'discovery'}})
        self.assertFalse(_discovery_produced_results(self.results_dir))

    def test_http_records_are_evidence_discovery_ran(self) -> None:
        self._write_output(
            {'type': 'http_record', 'data': {'url': 'https://host.example.test/a', 'status_code': 200}},
        )
        self.assertTrue(_discovery_produced_results(self.results_dir))

    def test_scan_summary_alone_is_evidence_discovery_ran(self) -> None:
        """Probed the same roots and found nothing — Tier 5 would find nothing either."""
        self._write_output({'type': 'scan', 'data': {'total_requests': 12}})
        self.assertTrue(_discovery_produced_results(self.results_dir))

    def test_malformed_lines_do_not_mask_real_records(self) -> None:
        self._write_output()
        output_file = _discovery_output_file(self.results_dir)
        with open(output_file, 'w') as f:
            f.write('not json at all\n')
            f.write(json.dumps({'type': 'finding', 'data': {'module_name': 'x'}}) + '\n')
        self.assertTrue(_discovery_produced_results(self.results_dir))

    def test_enabled_but_empty_pass_keeps_discovery_in_the_phase_list(self) -> None:
        """The regression the config flag caused: enabled, produced nothing, coverage lost."""
        self.assertEqual(
            _analysis_phases(
                skip_spidering=False,
                discovery_already_ran=_discovery_produced_results(self.results_dir),
            ),
            'spidering,discovery,known-issue-scan,dynamic-assessment',
        )

    def test_real_output_drops_discovery_from_the_phase_list(self) -> None:
        self._write_output(
            {'type': 'http_record', 'data': {'url': 'https://host.example.test/a', 'status_code': 200}},
        )
        self.assertEqual(
            _analysis_phases(
                skip_spidering=False,
                discovery_already_ran=_discovery_produced_results(self.results_dir),
            ),
            'spidering,known-issue-scan,dynamic-assessment',
        )
