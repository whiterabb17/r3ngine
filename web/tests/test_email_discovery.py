"""Tests for email discovery orchestrator, tools, and model changes."""
import uuid
import json
from unittest.mock import patch, MagicMock, call
from django.test import TestCase
from startScan.models import Email, ScanHistory
from reNgine.utils.task import save_email


class TestEmailSourceField(TestCase):
    def test_email_created_with_default_source(self):
        email = Email.objects.create(address='test@example.com')
        self.assertEqual(email.source, Email.SOURCE_HUNTER)

    def test_email_created_with_manual_source(self):
        email = Email.objects.create(address='manual@example.com', source=Email.SOURCE_MANUAL)
        self.assertEqual(email.source, Email.SOURCE_MANUAL)

    def test_source_choices_defined(self):
        choices = dict(Email.SOURCE_CHOICES)
        self.assertIn(Email.SOURCE_MANUAL, choices)
        self.assertIn(Email.SOURCE_HUNTER, choices)
        self.assertIn(Email.SOURCE_HARVESTER, choices)
        self.assertIn(Email.SOURCE_PHONEBOOK, choices)
        self.assertIn(Email.SOURCE_PATTERN, choices)
        self.assertIn(Email.SOURCE_CRAWLED, choices)


class TestSaveEmailSource(TestCase):
    def test_save_email_default_source_is_hunter(self):
        email, created = save_email('default@example.com')
        self.assertTrue(created)
        self.assertEqual(email.source, Email.SOURCE_HUNTER)

    def test_save_email_manual_source(self):
        email, created = save_email('manual@example.com', source=Email.SOURCE_MANUAL)
        self.assertTrue(created)
        self.assertEqual(email.source, Email.SOURCE_MANUAL)

    def test_save_email_dedup_preserves_existing_source(self):
        # First call creates with manual source
        save_email('dup@example.com', source=Email.SOURCE_MANUAL)
        # Second call with different source — get_or_create means source won't change
        email, created = save_email('dup@example.com', source=Email.SOURCE_HUNTER)
        self.assertFalse(created)
        self.assertEqual(email.source, Email.SOURCE_MANUAL)


# ── Orchestrator tests (Task 3) ───────────────────────────────────────────────

class TestEmailDiscoveryOrchestrator(TestCase):
    def setUp(self):
        self.scan_id = 42
        self.job_id = str(uuid.uuid4())
        self.domain = 'example.com'

    @patch('reNgine.tasks.email_discovery.run_hunter_discovery', return_value=3)
    @patch('reNgine.tasks.email_discovery.run_harvester_discovery', return_value=2)
    @patch('reNgine.tasks.email_discovery.run_phonebook_discovery', return_value=1)
    @patch('reNgine.tasks.email_discovery.run_pattern_inference', return_value=0)
    @patch('reNgine.tasks.email_discovery.run_crawled_extraction', return_value=1)
    @patch('reNgine.tasks.email_discovery._push_to_stream')
    @patch('reNgine.tasks.email_discovery._check_stop_signal', return_value=False)
    @patch('reNgine.tasks.email_discovery._clear_active')
    def test_orchestrator_calls_all_tools(
        self, mock_clear, mock_stop, mock_push, mock_crawled,
        mock_pattern, mock_phonebook, mock_harvester, mock_hunter
    ):
        from reNgine.tasks.email_discovery import run_email_discovery
        run_email_discovery(self.scan_id, self.domain, self.job_id)

        mock_hunter.assert_called_once_with(self.scan_id, self.domain)
        mock_harvester.assert_called_once_with(self.scan_id, self.domain)
        mock_phonebook.assert_called_once_with(self.scan_id, self.domain)
        mock_pattern.assert_called_once_with(self.scan_id, self.domain)
        mock_crawled.assert_called_once_with(self.scan_id, self.domain)
        mock_clear.assert_called_once_with(self.scan_id)

    @patch('reNgine.tasks.email_discovery.run_hunter_discovery', return_value=5)
    @patch('reNgine.tasks.email_discovery.run_harvester_discovery', side_effect=Exception('timeout'))
    @patch('reNgine.tasks.email_discovery.run_phonebook_discovery', return_value=0)
    @patch('reNgine.tasks.email_discovery.run_pattern_inference', return_value=0)
    @patch('reNgine.tasks.email_discovery.run_crawled_extraction', return_value=1)
    @patch('reNgine.tasks.email_discovery._push_to_stream')
    @patch('reNgine.tasks.email_discovery._check_stop_signal', return_value=False)
    @patch('reNgine.tasks.email_discovery._clear_active')
    def test_tool_error_does_not_stop_discovery(
        self, mock_clear, mock_stop, mock_push, mock_crawled,
        mock_pattern, mock_phonebook, mock_harvester, mock_hunter
    ):
        from reNgine.tasks.email_discovery import run_email_discovery
        run_email_discovery(self.scan_id, self.domain, self.job_id)
        # phonebook, pattern, crawled still called despite harvester error
        mock_phonebook.assert_called_once()
        mock_pattern.assert_called_once()
        mock_crawled.assert_called_once()

    @patch('reNgine.tasks.email_discovery.run_hunter_discovery', return_value=5)
    @patch('reNgine.tasks.email_discovery.run_harvester_discovery', return_value=2)
    @patch('reNgine.tasks.email_discovery.run_phonebook_discovery', return_value=0)
    @patch('reNgine.tasks.email_discovery.run_pattern_inference', return_value=0)
    @patch('reNgine.tasks.email_discovery.run_crawled_extraction', return_value=0)
    @patch('reNgine.tasks.email_discovery._push_to_stream')
    @patch('reNgine.tasks.email_discovery._check_stop_signal', side_effect=[False, True, False, False, False])
    @patch('reNgine.tasks.email_discovery._clear_active')
    def test_stop_signal_halts_between_tools(
        self, mock_clear, mock_stop, mock_push, mock_crawled,
        mock_pattern, mock_phonebook, mock_harvester, mock_hunter
    ):
        from reNgine.tasks.email_discovery import run_email_discovery
        run_email_discovery(self.scan_id, self.domain, self.job_id)
        # stop checked before each tool; after hunter (False) and before harvester (True) → stops
        mock_hunter.assert_called_once()
        mock_harvester.assert_not_called()


# ── Hunter.io tests (Task 4) ──────────────────────────────────────────────────

class TestHunterDiscovery(TestCase):
    @patch('reNgine.tasks.email_discovery.run_hunter_lookup')
    @patch('reNgine.tasks.email_discovery.HunterIOAPIKey')
    @patch('reNgine.tasks.email_discovery.ScanHistory')
    def test_hunter_discovery_returns_email_count(self, mock_sh, mock_key, mock_run):
        mock_key.objects.filter.return_value.first.return_value = MagicMock(key='testkey')
        mock_run.return_value = {'emails': 7, 'employees': 2, 'skipped': False}
        mock_sh.objects.get.return_value = MagicMock(id=1)
        from reNgine.tasks.email_discovery import run_hunter_discovery
        count = run_hunter_discovery(1, 'example.com')
        self.assertEqual(count, 7)

    @patch('reNgine.tasks.email_discovery.HunterIOAPIKey')
    def test_hunter_discovery_no_api_key_returns_zero(self, mock_key):
        mock_key.objects.filter.return_value.first.return_value = None
        from reNgine.tasks.email_discovery import run_hunter_discovery
        count = run_hunter_discovery(1, 'example.com')
        self.assertEqual(count, 0)


class TestHarvesterDiscovery(TestCase):
    @patch('reNgine.tasks.email_discovery.subprocess.run')
    @patch('reNgine.tasks.email_discovery.save_email')
    @patch('reNgine.tasks.email_discovery.ScanHistory')
    @patch('builtins.open', new_callable=MagicMock)
    @patch('os.path.isfile', return_value=True)
    @patch('json.load', return_value={'emails': ['a@example.com', 'b@example.com'], 'linkedin_people': []})
    def test_harvester_returns_email_count(
        self, mock_json, mock_isfile, mock_open, mock_sh, mock_save, mock_proc
    ):
        mock_proc.return_value = MagicMock(returncode=0)
        mock_save.return_value = (MagicMock(), True)
        from reNgine.tasks.email_discovery import run_harvester_discovery
        count = run_harvester_discovery(1, 'example.com')
        self.assertEqual(count, 2)

    @patch('reNgine.tasks.email_discovery.subprocess.run')
    @patch('os.path.isfile', return_value=False)
    def test_harvester_no_output_file_returns_zero(self, mock_isfile, mock_proc):
        mock_proc.return_value = MagicMock(returncode=1)
        from reNgine.tasks.email_discovery import run_harvester_discovery
        count = run_harvester_discovery(1, 'example.com')
        self.assertEqual(count, 0)


# ── phonebook.cz tests (Task 5) ───────────────────────────────────────────────

class TestPhonebookDiscovery(TestCase):
    @patch('reNgine.tasks.email_discovery.requests.get')
    @patch('reNgine.tasks.email_discovery.save_email')
    @patch('reNgine.tasks.email_discovery.ScanHistory')
    def test_phonebook_extracts_emails(self, mock_sh, mock_save, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            text='<a href="mailto:found@example.com">found@example.com</a> also info@example.com'
        )
        mock_save.return_value = (MagicMock(), True)
        from reNgine.tasks.email_discovery import run_phonebook_discovery
        count = run_phonebook_discovery(1, 'example.com')
        self.assertGreater(count, 0)

    @patch('reNgine.tasks.email_discovery.requests.get')
    @patch('reNgine.tasks.email_discovery.ScanHistory')
    def test_phonebook_non_200_raises(self, mock_sh, mock_get):
        mock_get.return_value = MagicMock(status_code=429, text='')
        from reNgine.tasks.email_discovery import run_phonebook_discovery
        with self.assertRaises(RuntimeError):
            run_phonebook_discovery(1, 'example.com')


class TestCrawledExtraction(TestCase):
    @patch('reNgine.tasks.email_discovery.Screenshot')
    @patch('reNgine.tasks.email_discovery.save_email')
    @patch('reNgine.tasks.email_discovery.ScanHistory')
    @patch('builtins.open', new_callable=MagicMock)
    def test_crawled_extracts_emails_from_html_files(self, mock_open, mock_sh, mock_save, mock_screenshot):
        mock_screenshot.objects.filter.return_value.exclude.return_value.exclude.return_value.values_list.return_value = [
            '/tmp/scan_42/html/sub.example.com.html',
        ]
        mock_open.return_value.__enter__.return_value.read.return_value = (
            '<html><body>Contact: admin@example.com and support@example.com</body></html>'
        )
        mock_save.return_value = (MagicMock(), True)
        from reNgine.tasks.email_discovery import run_crawled_extraction
        count = run_crawled_extraction(1, 'example.com')
        self.assertEqual(count, 2)

    @patch('reNgine.tasks.email_discovery.Screenshot')
    @patch('reNgine.tasks.email_discovery.ScanHistory')
    def test_crawled_no_html_files_returns_zero(self, mock_sh, mock_screenshot):
        mock_screenshot.objects.filter.return_value.exclude.return_value.exclude.return_value.values_list.return_value = []
        from reNgine.tasks.email_discovery import run_crawled_extraction
        count = run_crawled_extraction(1, 'example.com')
        self.assertEqual(count, 0)


# ── Pattern inference tests (Task 6) ─────────────────────────────────────────

class TestPatternInference(TestCase):
    @patch('reNgine.tasks.email_discovery._smtp_verify_email')
    @patch('reNgine.tasks.email_discovery.save_email')
    @patch('reNgine.tasks.email_discovery.Employee')
    @patch('reNgine.tasks.email_discovery.ScanHistory')
    def test_generates_patterns_for_employees(self, mock_sh, mock_emp, mock_save, mock_verify):
        emp = MagicMock()
        emp.name = 'John Smith'
        mock_emp.objects.filter.return_value.exclude.return_value = [emp]
        mock_verify.return_value = True
        mock_save.return_value = (MagicMock(), True)
        from reNgine.tasks.email_discovery import run_pattern_inference
        count = run_pattern_inference(1, 'example.com')
        # 6 patterns * 1 employee = 6 candidates, all verified as True
        self.assertEqual(count, 6)

    @patch('reNgine.tasks.email_discovery._smtp_verify_email', return_value=False)
    @patch('reNgine.tasks.email_discovery.Employee')
    @patch('reNgine.tasks.email_discovery.ScanHistory')
    def test_unverified_patterns_not_saved(self, mock_sh, mock_emp, mock_verify):
        emp = MagicMock()
        emp.name = 'Jane Doe'
        mock_emp.objects.filter.return_value.exclude.return_value = [emp]
        from reNgine.tasks.email_discovery import run_pattern_inference
        count = run_pattern_inference(1, 'example.com')
        self.assertEqual(count, 0)

    @patch('reNgine.tasks.email_discovery.Employee')
    @patch('reNgine.tasks.email_discovery.ScanHistory')
    def test_single_name_employees_skipped(self, mock_sh, mock_emp):
        emp = MagicMock()
        emp.name = 'Madonna'
        mock_emp.objects.filter.return_value.exclude.return_value = [emp]
        from reNgine.tasks.email_discovery import run_pattern_inference
        count = run_pattern_inference(1, 'example.com')
        self.assertEqual(count, 0)
