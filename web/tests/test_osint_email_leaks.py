from unittest.mock import patch, MagicMock
from django.test import TestCase
from django.utils import timezone
from startScan.models import ScanHistory, Domain
from scanEngine.models import EngineType


class TestEmailLeaks(TestCase):
    def setUp(self):
        domain = Domain.objects.create(name='example-test.local')
        engine = EngineType.objects.create(engine_name='Test', yaml_configuration='osint: {}')
        self.scan = ScanHistory.objects.create(
            domain=domain,
            scan_type=engine,
            scan_status=0,
            start_scan_date=timezone.now(),
        )

    @patch('reNgine.osint.email_leaks.run_command')
    def test_run_emailfinder_saves_emails(self, mock_run):
        from reNgine.osint.email_leaks import run_emailfinder

        mock_run.return_value = (
            0,
            'test@example-test.local\ninfo@example-test.local\n',
        )

        class FakeSelf:
            scan = self.scan

        run_emailfinder(FakeSelf(), 'example-test.local', self.scan, '/tmp/test_results')
        self.assertEqual(self.scan.emails.count(), 2)

    @patch('reNgine.osint.email_leaks.run_command')
    def test_run_emailfinder_invalid_emails_skipped(self, mock_run):
        from reNgine.osint.email_leaks import run_emailfinder

        mock_run.return_value = (0, 'notanemail\ntest@example-test.local\n')

        class FakeSelf:
            scan = self.scan

        run_emailfinder(FakeSelf(), 'example-test.local', self.scan, '/tmp/test_results')
        self.assertEqual(self.scan.emails.count(), 1)

    @patch('reNgine.osint.email_leaks.run_command')
    def test_run_leaksearch_skips_without_key(self, mock_run):
        from reNgine.osint.email_leaks import run_leaksearch

        class FakeSelf:
            scan = self.scan

        # No LeakSearchAPIKey in DB — should skip without calling run_command
        run_leaksearch(FakeSelf(), 'example-test.local', self.scan, '/tmp/test_results')
        mock_run.assert_not_called()

    @patch('reNgine.osint.email_leaks.run_command')
    def test_run_leaksearch_uses_key(self, mock_run):
        from dashboard.models import LeakSearchAPIKey
        from reNgine.osint.email_leaks import run_leaksearch

        LeakSearchAPIKey.objects.create(key='test_api_key_12345')
        mock_run.return_value = (0, '')

        class FakeSelf:
            scan = self.scan

        run_leaksearch(FakeSelf(), 'example-test.local', self.scan, '/tmp/test_results')
        mock_run.assert_called_once()
        call_args = mock_run.call_args[0][0]
        self.assertIn('example-test.local', ' '.join(call_args))
