import csv
import os
import tempfile
from unittest.mock import patch, MagicMock
from django.test import TestCase
from django.utils import timezone
from startScan.models import ScanHistory, Email, CredResult, DnsRecord, Subdomain
from targetApp.models import Domain
from scanEngine.models import EngineType


class TestIsMicrosoftEmailProvider(TestCase):
    def setUp(self):
        self.domain = Domain.objects.create(name='corp.com')
        engine = EngineType.objects.create(engine_name='test', yaml_configuration='{}')
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=engine,
            scan_status=0,
            start_scan_date=timezone.now(),
            results_dir='/tmp/test',
        )

    def test_detects_microsoft_mx(self):
        DnsRecord.objects.create(
            scan_history=self.scan,
            target_domain=self.domain,
            record_type='MX',
            value='corp-com.mail.protection.outlook.com',
        )
        from reNgine.osint.credspy import is_microsoft_email_provider
        self.assertTrue(is_microsoft_email_provider(self.scan.id))

    def test_detects_autodiscover_subdomain(self):
        Subdomain.objects.create(
            scan_history=self.scan,
            name='autodiscover.corp.com',
        )
        from reNgine.osint.credspy import is_microsoft_email_provider
        self.assertTrue(is_microsoft_email_provider(self.scan.id))

    def test_returns_false_for_google_mx(self):
        DnsRecord.objects.create(
            scan_history=self.scan,
            target_domain=self.domain,
            record_type='MX',
            value='aspmx.l.google.com',
        )
        from reNgine.osint.credspy import is_microsoft_email_provider
        self.assertFalse(is_microsoft_email_provider(self.scan.id))


CSV_OUTPUT = """Email,Exists,PreferredType,HasPassword,RemoteNGC,HasFido,HasCertAuth,DomainType
alice@corp.com,True,Password,True,False,False,False,Managed
bob@corp.com,False,,,,,,
"""


class TestRunCredspy(TestCase):
    def setUp(self):
        self.domain = Domain.objects.create(name='corp.com')
        engine = EngineType.objects.create(engine_name='test', yaml_configuration='{}')
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=engine,
            scan_status=0,
            start_scan_date=timezone.now(),
            results_dir='/tmp/test',
        )
        alice = Email.objects.create(address='alice@corp.com')
        bob = Email.objects.create(address='bob@corp.com')
        self.scan.emails.add(alice, bob)
        DnsRecord.objects.create(
            scan_history=self.scan,
            target_domain=self.domain,
            record_type='MX',
            value='corp-com.mail.protection.outlook.com',
        )

    @patch('reNgine.osint.credspy.get_random_proxy', return_value='socks5://proxy:1080')
    @patch('reNgine.osint.credspy.subprocess.run')
    def test_creates_cred_result_rows(self, mock_run, mock_proxy):
        mock_run.return_value.returncode = 0

        with tempfile.TemporaryDirectory() as tmpdir:
            csv_path = os.path.join(tmpdir, 'credspy_output.csv')
            with open(csv_path, 'w') as fh:
                fh.write(CSV_OUTPUT)

            with patch('reNgine.osint.credspy._get_csv_path', return_value=csv_path):
                from reNgine.osint.credspy import run_credspy
                task_self = MagicMock()
                task_self.scan = self.scan
                count = run_credspy(task_self, 'corp.com', self.scan, tmpdir)

        self.assertEqual(count, 2)
        results = CredResult.objects.filter(scan_history=self.scan, tool_name='credspy')
        self.assertEqual(results.count(), 2)
        alice = results.get(email_address='alice@corp.com')
        self.assertTrue(alice.account_exists)
        self.assertTrue(alice.has_password)
        self.assertEqual(alice.domain_type, 'Managed')
        # Verify --proxy flag was passed
        call_cmd = mock_run.call_args[0][0]
        self.assertIn('--proxy', call_cmd)
        self.assertIn('socks5://proxy:1080', call_cmd)

    @patch('reNgine.osint.credspy.get_random_proxy', return_value='')
    @patch('reNgine.osint.credspy.subprocess.run')
    def test_skips_when_no_proxy(self, mock_run, mock_proxy):
        from reNgine.osint.credspy import run_credspy
        task_self = MagicMock()
        task_self.scan = self.scan
        count = run_credspy(task_self, 'corp.com', self.scan, '/tmp')
        self.assertEqual(count, 0)
        mock_run.assert_not_called()

    @patch('reNgine.osint.credspy.get_random_proxy', return_value='socks5://proxy:1080')
    @patch('reNgine.osint.credspy.subprocess.run')
    def test_skips_when_no_microsoft_detected(self, mock_run, mock_proxy):
        DnsRecord.objects.filter(scan_history=self.scan).delete()
        from reNgine.osint.credspy import run_credspy
        task_self = MagicMock()
        task_self.scan = self.scan
        count = run_credspy(task_self, 'corp.com', self.scan, '/tmp')
        self.assertEqual(count, 0)
        mock_run.assert_not_called()
