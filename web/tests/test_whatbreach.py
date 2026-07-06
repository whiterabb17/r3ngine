import os
from unittest.mock import patch, MagicMock
from django.test import TestCase
from django.utils import timezone
from startScan.models import EmailBreach, ScanHistory, Email
from targetApp.models import Domain
from scanEngine.models import EngineType
from dashboard.models import HunterIOAPIKey


SAMPLE_OUTPUT = b"""
[ i ] starting search on a total of 2 email(s)
[ i ] starting search on single email address: alice@corp.com
[ i ] searching breached accounts on HIBP related to: alice@corp.com
[ i ] found a total of 2 database breach(es) pertaining to: alice@corp.com
---------------------------------------------------------------------------
Breach/Paste:        | Database/Paste Link:
LinkedIn             | https://www.dehashed.com/search?query=LinkedIn
Dropbox              | https://www.dehashed.com/search?query=Dropbox
---------------------------------------------------------------------------
[ i ] starting search on single email address: bob@corp.com
[ ! ] email bob@corp.com was not found in any breach
"""

HUNTER_OUTPUT = b"""
[ i ] starting search on hunter.io using alice@corp.com
[ i ] discovered a total of 3 email(s)
[ i ] discovered associated email address(es):
\t-> alice@corp.com
\t-> newperson@corp.com
"""


class TestRunWhatbreach(TestCase):
    def setUp(self):
        self.domain = Domain.objects.create(name='corp.com')
        engine = EngineType.objects.create(engine_name='test', yaml_configuration='{}')
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=engine,
            scan_status=0,
            start_scan_date=timezone.now(),
        )
        alice = Email.objects.create(address='alice@corp.com')
        bob = Email.objects.create(address='bob@corp.com')
        self.scan.emails.add(alice, bob)
        HunterIOAPIKey.objects.create(key='test-hunter-key')

    @patch('reNgine.osint.whatbreach._RESULTS_BASE', '/tmp')
    @patch('reNgine.osint.whatbreach.subprocess.Popen')
    @patch('reNgine.osint.whatbreach._ensure_whatbreach_hunter_key')
    def test_creates_email_breach_rows(self, mock_ensure_key, mock_popen):
        proc = MagicMock()
        proc.stdout = SAMPLE_OUTPUT.splitlines(keepends=True)
        proc.wait.return_value = 0
        mock_popen.return_value.__enter__ = MagicMock(return_value=proc)
        mock_popen.return_value.__exit__ = MagicMock(return_value=False)

        from reNgine.osint.whatbreach import run_whatbreach
        task_self = MagicMock()
        task_self.scan = self.scan
        count = run_whatbreach(task_self, 'corp.com', self.scan, '/tmp', download_databases=False)

        self.assertEqual(count, 2)
        breaches = EmailBreach.objects.filter(scan_history=self.scan, source='whatbreach')
        self.assertEqual(breaches.count(), 2)
        names = list(breaches.values_list('breach_name', flat=True))
        self.assertIn('LinkedIn', names)
        self.assertIn('Dropbox', names)

    @patch('reNgine.osint.whatbreach.subprocess.Popen')
    @patch('reNgine.osint.whatbreach._ensure_whatbreach_hunter_key')
    def test_skips_when_no_emails(self, mock_ensure_key, mock_popen):
        self.scan.emails.clear()
        from reNgine.osint.whatbreach import run_whatbreach
        task_self = MagicMock()
        task_self.scan = self.scan
        count = run_whatbreach(task_self, 'corp.com', self.scan, '/tmp')
        self.assertEqual(count, 0)
        mock_popen.assert_not_called()

    @patch('reNgine.osint.whatbreach.subprocess.Popen')
    @patch('reNgine.osint.whatbreach._ensure_whatbreach_hunter_key')
    def test_skips_when_no_hunter_key(self, mock_ensure_key, mock_popen):
        HunterIOAPIKey.objects.all().delete()
        from reNgine.osint.whatbreach import run_whatbreach
        task_self = MagicMock()
        task_self.scan = self.scan
        count = run_whatbreach(task_self, 'corp.com', self.scan, '/tmp')
        self.assertEqual(count, 0)
        mock_popen.assert_not_called()

    def test_ensure_hunter_key_no_duplicate(self):
        """Key written twice should not appear twice in the file."""
        import tempfile
        from reNgine.osint.whatbreach import _ensure_whatbreach_hunter_key
        with tempfile.TemporaryDirectory() as tmpdir:
            with patch('reNgine.osint.whatbreach._TOKENS_PATH', tmpdir):
                token_file = os.path.join(tmpdir, 'hunter.io')
                _ensure_whatbreach_hunter_key('my-key-123')
                _ensure_whatbreach_hunter_key('my-key-123')
                content = open(token_file).read()
                self.assertEqual(content.count('my-key-123'), 1)

    @patch('reNgine.osint.whatbreach._RESULTS_BASE', '/tmp')
    @patch('reNgine.osint.whatbreach.subprocess.Popen')
    @patch('reNgine.osint.whatbreach._ensure_whatbreach_hunter_key')
    def test_pipes_stdin_when_download_enabled(self, mock_ensure_key, mock_popen):
        proc = MagicMock()
        proc.stdout = []
        proc.wait.return_value = 0
        mock_popen.return_value.__enter__ = MagicMock(return_value=proc)
        mock_popen.return_value.__exit__ = MagicMock(return_value=False)

        from reNgine.osint.whatbreach import run_whatbreach
        task_self = MagicMock()
        task_self.scan = self.scan
        run_whatbreach(task_self, 'corp.com', self.scan, '/tmp', download_databases=True)

        # Verify -d flag was appended to command
        call_args = mock_popen.call_args[0][0]
        self.assertIn('-d', call_args)

        # Verify y\n bytes were written to stdin
        proc.stdin.write.assert_called_once_with(b'y\n' * 50)
