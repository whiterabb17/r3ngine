"""Betterleaks secret_scanning: structured JSON persist + help/noise rejection."""
import json
import os
import tempfile
from unittest.mock import MagicMock, patch

from django.test import TestCase
from django.utils import timezone

from startScan.models import Domain, ScanHistory, SecretLeak
from scanEngine.models import EngineType


HELP_STDOUT = (
	'Betterleaks scans code, past or present, for secrets\n'
	'--hmac-key=KEY HMAC fingerprint key; overrides\n'
	'BETTERLEAKS_FINGERPRINT_HMAC_KEY.\n'
	'--redact Redact secrets in findings, including report\n'
	'url Download and scan one HTTP(S) URL for secrets.\n'
	'git Scan Git repositories for secrets.\n'
	'github Scan GitHub repositories and resources for secrets.\n'
	'gitlab Scan GitLab projects and resources for secrets.\n'
	'for secrets.\n'
	's3 Scan an S3 or S3-compatible bucket for secrets.\n'
	'stdin Detect secrets from stdin.\n'
	'or HMAC-SHA-256 with a key).\n'
	'validate Validate a known secret without running detection.\n'
)


class BetterleaksSecretScanTests(TestCase):
	def setUp(self):
		domain = Domain.objects.create(name='betterleaks-test.local')
		engine = EngineType.objects.create(
			engine_name='BetterleaksTest',
			yaml_configuration='secret_scanning: {}',
		)
		self.scan = ScanHistory.objects.create(
			domain=domain,
			scan_type=engine,
			scan_status=0,
			start_scan_date=timezone.now(),
		)

	def test_help_stdout_without_report_persists_nothing(self):
		from reNgine.tasks.osint.secret_leaks import run_betterleaks_scan

		with tempfile.TemporaryDirectory() as temp_dir:
			mock_proc = MagicMock()
			mock_proc.communicate.return_value = (HELP_STDOUT, '')
			mock_proc.returncode = 2
			with patch('reNgine.tasks.osint.secret_leaks.subprocess.Popen', return_value=mock_proc):
				saved = run_betterleaks_scan(self.scan, temp_dir)

		self.assertEqual(saved, 0)
		self.assertEqual(
			SecretLeak.objects.filter(scan_history=self.scan, tool_name='betterleaks').count(),
			0,
		)

	def test_valid_json_findings_are_persisted(self):
		from reNgine.tasks.osint.secret_leaks import run_betterleaks_scan

		report = {
			'schema_version': '1',
			'findings': [
				{
					'rule_id': 'aws-access-key',
					'description': 'AWS Access Key',
					'match': {'value': 'AKIAIOSFODNN7EXAMPLE'},
					'location': {'path': '/tmp/secrets_temp/config.env'},
				},
				{
					'rule_id': 'generic-api-key',
					'match': {'value': 'sk-live-abcdef123456'},
					'location': {'path': '/tmp/secrets_temp/app.js'},
				},
			],
			'scan': {'state': 'complete', 'num_findings': 2},
		}

		with tempfile.TemporaryDirectory() as temp_dir:
			report_path = os.path.join(temp_dir, 'betterleaks_report.json')
			with open(report_path, 'w', encoding='utf-8') as f:
				json.dump(report, f)

			mock_proc = MagicMock()
			mock_proc.communicate.return_value = ('', '')
			mock_proc.returncode = 0
			with patch('reNgine.tasks.osint.secret_leaks.subprocess.Popen', return_value=mock_proc):
				saved = run_betterleaks_scan(self.scan, temp_dir)

		self.assertEqual(saved, 2)
		leaks = SecretLeak.objects.filter(scan_history=self.scan, tool_name='betterleaks')
		self.assertEqual(leaks.count(), 2)
		contents = set(leaks.values_list('match_content', flat=True))
		self.assertEqual(contents, {'AKIAIOSFODNN7EXAMPLE', 'sk-live-abcdef123456'})
		types = set(leaks.values_list('secret_type', flat=True))
		self.assertEqual(types, {'aws-access-key', 'generic-api-key'})

	def test_help_shaped_match_values_are_skipped(self):
		from reNgine.tasks.osint.secret_leaks import persist_betterleaks_report

		report = {
			'findings': [
				{
					'rule_id': 'noise',
					'match': {'value': 'Betterleaks scans code, past or present, for secrets'},
					'location': {'path': 'help'},
				},
				{
					'rule_id': 'github-pat',
					'match': {'value': 'ghp_realTokenValue1234567890'},
					'location': {'path': 'src/config.js'},
				},
			]
		}
		saved = persist_betterleaks_report(self.scan, report)
		self.assertEqual(saved, 1)
		leaks = SecretLeak.objects.filter(scan_history=self.scan, tool_name='betterleaks')
		self.assertEqual(leaks.count(), 1)
		self.assertEqual(leaks.first().match_content, 'ghp_realTokenValue1234567890')

	def test_legitimate_betterleaks_env_secret_is_persisted(self):
		"""Regression: env-style secrets must not be dropped by help-noise markers."""
		from reNgine.tasks.osint.secret_leaks import persist_betterleaks_report

		secret_line = 'BETTERLEAKS_FINGERPRINT_HMAC_KEY=super-secret-hmac-value'
		report = {
			'findings': [
				{
					'rule_id': 'generic-api-key',
					'match': {
						'value': 'super-secret-hmac-value',
						'full': secret_line,
					},
					'location': {'path': 'deploy/.env'},
				},
			]
		}
		# Prefer match.value (real secret); also ensure full-line fallback survives.
		saved = persist_betterleaks_report(self.scan, report)
		self.assertEqual(saved, 1)
		self.assertEqual(
			SecretLeak.objects.filter(scan_history=self.scan, tool_name='betterleaks').count(),
			1,
		)

		SecretLeak.objects.filter(scan_history=self.scan, tool_name='betterleaks').delete()
		report_full_only = {
			'findings': [
				{
					'rule_id': 'generic-api-key',
					'match': {'full': secret_line},
					'location': {'path': 'deploy/.env'},
				},
			]
		}
		saved_full = persist_betterleaks_report(self.scan, report_full_only)
		self.assertEqual(saved_full, 1)
		leak = SecretLeak.objects.get(scan_history=self.scan, tool_name='betterleaks')
		self.assertEqual(leak.match_content, secret_line)

	def test_invalid_json_report_persists_nothing(self):
		from reNgine.tasks.osint.secret_leaks import run_betterleaks_scan

		with tempfile.TemporaryDirectory() as temp_dir:
			report_path = os.path.join(temp_dir, 'betterleaks_report.json')
			with open(report_path, 'w', encoding='utf-8') as f:
				f.write('not-json{')

			mock_proc = MagicMock()
			mock_proc.communicate.return_value = ('', '')
			mock_proc.returncode = 0
			with patch('reNgine.tasks.osint.secret_leaks.subprocess.Popen', return_value=mock_proc):
				saved = run_betterleaks_scan(self.scan, temp_dir)

		self.assertEqual(saved, 0)
		self.assertEqual(
			SecretLeak.objects.filter(scan_history=self.scan, tool_name='betterleaks').count(),
			0,
		)
