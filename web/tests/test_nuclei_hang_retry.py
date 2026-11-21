"""Tests for nuclei hang/timeout watchdog markers and tag-batch retry."""
import os
import tempfile
from unittest.mock import MagicMock, patch

from django.test import TestCase
from django.utils import timezone

from reNgine.definitions import (
	NUCLEI_HANG_KILL_MARKER,
	NUCLEI_HANG_MAX_ATTEMPTS,
	NUCLEI_STALL_TIMEOUT_SECONDS,
	NUCLEI_TIMEOUT_KILL_MARKER,
)
from reNgine.tasks.vuln import (
	_nuclei_line_is_hang_kill,
	_nuclei_line_is_timeout_kill,
)
from reNgine.utils.task import _go_executor_workflow_input
from scanEngine.models import EngineType
from startScan.models import Domain, ScanHistory


class TestNucleiHangHelpers(TestCase):
	def test_detects_hang_marker(self):
		self.assertTrue(_nuclei_line_is_hang_kill(NUCLEI_HANG_KILL_MARKER))
		self.assertTrue(_nuclei_line_is_hang_kill(f'prefix {NUCLEI_HANG_KILL_MARKER}'))

	def test_detects_timeout_marker(self):
		self.assertTrue(_nuclei_line_is_timeout_kill(NUCLEI_TIMEOUT_KILL_MARKER))

	def test_ignores_unrelated_lines(self):
		self.assertFalse(_nuclei_line_is_hang_kill('[INF] Templates loaded'))
		self.assertFalse(_nuclei_line_is_hang_kill({'template-id': 'x'}))
		self.assertFalse(_nuclei_line_is_timeout_kill(NUCLEI_HANG_KILL_MARKER))
		self.assertFalse(_nuclei_line_is_hang_kill(NUCLEI_TIMEOUT_KILL_MARKER))

	def test_go_executor_payload_sets_stall_for_nuclei(self):
		payload = _go_executor_workflow_input(
			'nuclei -j -tags xss',
			scan_history_id=11,
			command_rec_id=99,
			cwd='/tmp',
			timeout=43200,
			tool='nuclei',
		)
		self.assertEqual(payload['stall_timeout_seconds'], NUCLEI_STALL_TIMEOUT_SECONDS)
		self.assertEqual(payload['timeout_seconds'], 43200)
		self.assertEqual(payload['scan_id'], 11)

	def test_go_executor_payload_omits_stall_for_other_tools(self):
		payload = _go_executor_workflow_input(
			'httpx -l urls.txt',
			timeout=100,
			tool='httpx',
		)
		self.assertNotIn('stall_timeout_seconds', payload)
		self.assertEqual(payload['timeout_seconds'], 100)


class TestNucleiHangRetry(TestCase):
	def setUp(self):
		self.domain = Domain.objects.create(name='example.com')
		self.engine = EngineType.objects.create(
			engine_name='Test Engine Hang',
			yaml_configuration={},
		)
		self.scan = ScanHistory.objects.create(
			domain=self.domain,
			scan_type=self.engine,
			scan_status=1,
			start_scan_date=timezone.now(),
		)
		self.results_dir = tempfile.mkdtemp()
		self.output_path = os.path.join(self.results_dir, 'nuclei.json')

	def _self_proxy(self):
		proxy = MagicMock()
		proxy.yaml_configuration = {
			'vulnerability_scan': {
				'intensity': 'aggressive',
				'nuclei': {'auto_update_templates': False},
			}
		}
		proxy.results_dir = self.results_dir
		proxy.output_path = self.output_path
		proxy.scan_id = self.scan.id
		proxy.scan = self.scan
		proxy.domain = self.domain
		proxy.subscan = None
		proxy.history_file = None
		proxy.activity_id = None
		proxy.activity = None
		proxy.notify = MagicMock()
		return proxy

	def _run(self, mock_stream):
		from reNgine.tasks import nuclei_scan

		nuclei_scan(
			self._self_proxy(),
			urls=['http://example.com'],
			ctx={'scan_history_id': self.scan.id},
			tags_override=['php', 'recaptcha'],
		)
		return mock_stream.call_count

	@patch('reNgine.tasks.vuln.OpenAiAPIKey.objects')
	@patch('reNgine.tasks.vuln.run_command')
	@patch('reNgine.tasks.vuln.stream_command')
	@patch('scanEngine.models.Notification.objects')
	def test_retries_hang_then_soft_skips(
		self, mock_notif, mock_stream, _mock_run, mock_openai
	):
		mock_notif.first.return_value = None
		mock_openai.all.return_value.first.return_value = None
		mock_stream.side_effect = [
			iter([NUCLEI_HANG_KILL_MARKER]),
			iter([NUCLEI_HANG_KILL_MARKER]),
		]

		calls = self._run(mock_stream)
		self.assertEqual(calls, NUCLEI_HANG_MAX_ATTEMPTS)
		self.assertTrue(os.path.exists(self.output_path))
		with open(self.output_path) as f:
			self.assertEqual(f.read().strip(), '[]')

	@patch('reNgine.tasks.vuln.OpenAiAPIKey.objects')
	@patch('reNgine.tasks.vuln.run_command')
	@patch('reNgine.tasks.vuln.stream_command')
	@patch('scanEngine.models.Notification.objects')
	def test_stops_after_hang_then_success(
		self, mock_notif, mock_stream, _mock_run, mock_openai
	):
		mock_notif.first.return_value = None
		mock_openai.all.return_value.first.return_value = None
		mock_stream.side_effect = [
			iter([NUCLEI_HANG_KILL_MARKER]),
			iter([]),
		]

		calls = self._run(mock_stream)
		self.assertEqual(calls, 2)

	@patch('reNgine.tasks.vuln.OpenAiAPIKey.objects')
	@patch('reNgine.tasks.vuln.run_command')
	@patch('reNgine.tasks.vuln.stream_command')
	@patch('scanEngine.models.Notification.objects')
	def test_timeout_kill_does_not_retry(
		self, mock_notif, mock_stream, _mock_run, mock_openai
	):
		mock_notif.first.return_value = None
		mock_openai.all.return_value.first.return_value = None
		mock_stream.side_effect = [
			iter([NUCLEI_TIMEOUT_KILL_MARKER]),
			iter([NUCLEI_TIMEOUT_KILL_MARKER]),
		]

		calls = self._run(mock_stream)
		self.assertEqual(calls, 1)
		with open(self.output_path) as f:
			self.assertEqual(f.read().strip(), '[]')
