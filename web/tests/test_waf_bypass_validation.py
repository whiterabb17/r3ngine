"""WAF bypass findings must be differentially validated before persist.

A single non-403 response used to create WafBypassFinding rows even when the
baseline (same payload, no bypass header) was never blocked. That produced
false positives on hosts that simply do not WAF the probe.
"""
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import MagicMock, patch

from reNgine.utils.waf import (
	WafBypassOrchestrator,
	_probe_result_from_response,
	_response_looks_allowed,
	_response_looks_blocked,
)


def _resp(status_code, text=''):
	return SimpleNamespace(status_code=status_code, text=text)


class TestBlockedHeuristics(TestCase):

	def test_block_statuses(self):
		self.assertTrue(_response_looks_blocked(403, ''))
		self.assertTrue(_response_looks_blocked(429, ''))
		self.assertFalse(_response_looks_blocked(200, 'ok'))
		# Auth / origin errors alone are not treated as WAF blocks.
		self.assertFalse(_response_looks_blocked(401, ''))
		self.assertFalse(_response_looks_blocked(503, ''))
		self.assertTrue(_response_looks_blocked(503, 'Access Denied by WAF'))

	def test_soft_block_body(self):
		self.assertTrue(_response_looks_blocked(200, 'Access Denied by CloudFlare'))
		self.assertFalse(_response_looks_blocked(200, 'welcome home'))
		# Vendor name alone on a normal page must not count as blocked.
		self.assertFalse(_response_looks_blocked(200, 'cdn powered by cloudflare scripts'))

	def test_allowed_excludes_server_errors(self):
		self.assertTrue(_response_looks_allowed(200, 'ok'))
		self.assertFalse(_response_looks_allowed(502, 'bad gateway'))
		self.assertFalse(_response_looks_allowed(500, 'error'))
		self.assertFalse(_response_looks_allowed(200, 'Access Denied'))


class TestProbeResult(TestCase):

	def test_from_response(self):
		result = _probe_result_from_response(_resp(403, 'forbidden'))
		self.assertTrue(result.blocked)
		self.assertEqual(result.status_code, 403)


class TestHeaderBypassValidation(TestCase):

	def setUp(self):
		self.subdomain = SimpleNamespace(
			name='waf.example.com',
			scan_history=SimpleNamespace(id=1),
		)
		self.orchestrator = WafBypassOrchestrator(self.subdomain)

	@patch('reNgine.utils.waf.WafBypassFinding.objects.create')
	@patch('reNgine.utils.waf.WafBypassOrchestrator._record_command')
	@patch('reNgine.utils.waf.requests.get')
	@patch('startScan.models.ScanActivity.objects.filter')
	def test_persists_only_when_differential_validates(
		self, mock_filter, mock_get, _mock_cmd, mock_create,
	):
		mock_filter.return_value.last.return_value = None
		# baseline blocked, then for first header: candidate allowed,
		# then validation rounds: baseline blocked / candidate allowed x2.
		# Remaining headers: candidate blocked (403) so skipped quickly.
		sequence = [
			_resp(403, 'blocked'),  # initial baseline
			_resp(200, 'ok'),       # X-Forwarded-For candidate (potential)
			_resp(403, 'blocked'),  # validate round1 baseline
			_resp(200, 'ok'),       # validate round1 candidate
			_resp(403, 'blocked'),  # validate round2 baseline
			_resp(200, 'ok'),       # validate round2 candidate
		]
		# 8 remaining headers each need one candidate probe → all blocked
		sequence.extend([_resp(403, 'blocked')] * 8)
		mock_get.side_effect = sequence
		mock_create.return_value = MagicMock()

		findings = self.orchestrator._test_headers()

		self.assertEqual(len(findings), 1)
		mock_create.assert_called_once()
		kwargs = mock_create.call_args.kwargs
		self.assertTrue(kwargs['is_successful'])
		self.assertIn('Validated differential', kwargs['payload_evidence'])
		self.assertIn('X-Forwarded-For', kwargs['technique'])

	@patch('reNgine.utils.waf.WafBypassFinding.objects.create')
	@patch('reNgine.utils.waf.requests.get')
	@patch('startScan.models.ScanActivity.objects.filter')
	def test_skips_when_baseline_not_blocked(self, mock_filter, mock_get, mock_create):
		mock_filter.return_value.last.return_value = None
		mock_get.return_value = _resp(200, 'always open')

		findings = self.orchestrator._test_headers()

		self.assertEqual(findings, [])
		mock_create.assert_not_called()
		# Only the baseline probe
		self.assertEqual(mock_get.call_count, 1)

	@patch('reNgine.utils.waf.WafBypassFinding.objects.create')
	@patch('reNgine.utils.waf.WafBypassOrchestrator._record_command')
	@patch('reNgine.utils.waf.requests.get')
	@patch('startScan.models.ScanActivity.objects.filter')
	def test_discards_potential_that_fails_confirmation(
		self, mock_filter, mock_get, mock_cmd, mock_create,
	):
		mock_filter.return_value.last.return_value = None
		sequence = [
			_resp(403, 'blocked'),  # baseline
			_resp(200, 'ok'),       # potential candidate
			_resp(200, 'open'),     # validation baseline no longer blocked
			_resp(200, 'ok'),       # validation candidate (unused path after reject)
		]
		sequence.extend([_resp(403, 'blocked')] * 8)
		mock_get.side_effect = sequence

		findings = self.orchestrator._test_headers()

		self.assertEqual(findings, [])
		mock_create.assert_not_called()
		mock_cmd.assert_not_called()

	@patch('reNgine.utils.waf.WafBypassFinding.objects.create')
	@patch('reNgine.utils.waf.WafBypassOrchestrator._record_command')
	@patch('reNgine.utils.waf.requests.get')
	@patch('startScan.models.ScanActivity.objects.filter')
	def test_persists_soft_block_same_status_differential(
		self, mock_filter, mock_get, mock_cmd, mock_create,
	):
		"""Challenge-page baseline and clean candidate can both be HTTP 200."""
		mock_filter.return_value.last.return_value = None
		challenge = 'Attention Required! | Cloudflare Access Denied'
		sequence = [
			_resp(200, challenge),  # baseline soft-blocked
			_resp(200, 'ok'),       # potential
			_resp(200, challenge),  # validate r1 baseline
			_resp(200, 'ok'),       # validate r1 candidate
			_resp(200, challenge),  # validate r2 baseline
			_resp(200, 'ok'),       # validate r2 candidate
		]
		sequence.extend([_resp(200, challenge)] * 8)
		mock_get.side_effect = sequence
		mock_create.return_value = MagicMock()

		findings = self.orchestrator._test_headers()

		self.assertEqual(len(findings), 1)
		mock_create.assert_called_once()
		mock_cmd.assert_called_once()
		self.assertIn('X-Forwarded-For', mock_create.call_args.kwargs['technique'])

	@patch('reNgine.utils.waf.WafBypassFinding.objects.create')
	@patch('reNgine.utils.waf.WafBypassOrchestrator._record_command')
	@patch('reNgine.utils.waf.requests.get')
	@patch('startScan.models.ScanActivity.objects.filter')
	def test_ignores_server_error_candidates(
		self, mock_filter, mock_get, mock_cmd, mock_create,
	):
		mock_filter.return_value.last.return_value = None
		# Baseline blocked; every header candidate returns 502 — inconclusive.
		sequence = [_resp(403, 'blocked')] + [_resp(502, 'bad gateway')] * 9
		mock_get.side_effect = sequence

		findings = self.orchestrator._test_headers()

		self.assertEqual(findings, [])
		mock_create.assert_not_called()
		mock_cmd.assert_not_called()
