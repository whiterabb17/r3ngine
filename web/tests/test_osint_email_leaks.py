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

    # ------------------------------------------------------------------
    # emailfinder config flag (Finding 1 fix)
    # ------------------------------------------------------------------

    @patch('reNgine.tasks.osint.run_emailfinder')
    def test_emailfinder_suppressed_when_config_false(self, mock_ef):
        """osint_discovery must NOT call run_emailfinder when emailfinder: false."""
        from reNgine.tasks.osint import osint_discovery

        class FakeSelf:
            scan = self.scan
            notify = lambda self, **kw: None  # noqa: E731

        config = {
            'discover': ['emails'],
            'emailfinder': False,
        }
        osint_discovery(
            FakeSelf(),
            config=config,
            host='example-test.local',
            scan_history_id=self.scan.id,
            activity_id=None,
            results_dir='/tmp',
        )
        mock_ef.assert_not_called()

    @patch('reNgine.tasks.osint.run_emailfinder')
    def test_emailfinder_called_when_config_true(self, mock_ef):
        """osint_discovery calls run_emailfinder when emailfinder: true and emails in discover."""
        from reNgine.tasks.osint import osint_discovery

        class FakeSelf:
            scan = self.scan
            notify = lambda self, **kw: None  # noqa: E731

        config = {
            'discover': ['emails'],
            'emailfinder': True,
        }
        osint_discovery(
            FakeSelf(),
            config=config,
            host='example-test.local',
            scan_history_id=self.scan.id,
            activity_id=None,
            results_dir='/tmp',
        )
        mock_ef.assert_called_once()

    @patch('reNgine.tasks.osint.run_emailfinder')
    def test_emailfinder_called_when_config_key_absent(self, mock_ef):
        """emailfinder defaults to enabled when key is absent from config."""
        from reNgine.tasks.osint import osint_discovery

        class FakeSelf:
            scan = self.scan
            notify = lambda self, **kw: None  # noqa: E731

        config = {
            'discover': ['emails'],
            # 'emailfinder' key intentionally absent — should default to True
        }
        osint_discovery(
            FakeSelf(),
            config=config,
            host='example-test.local',
            scan_history_id=self.scan.id,
            activity_id=None,
            results_dir='/tmp',
        )
        mock_ef.assert_called_once()

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
