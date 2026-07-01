import json
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone
from startScan.models import ScanHistory
from scanEngine.models import EngineType
from targetApp.models import Domain


class TestCloudRecon(TestCase):
    def setUp(self):
        domain = Domain.objects.create(name='example-test.local')
        engine = EngineType.objects.create(engine_name='Test', yaml_configuration='osint: {}')
        self.scan = ScanHistory.objects.create(
            domain=domain,
            scan_type=engine,
            scan_status=0,
            start_scan_date=timezone.now(),
            tasks=[],
        )

    @patch('reNgine.osint.cloud_recon.run_command')
    def test_run_msftrecon_saves_subdomains(self, mock_run):
        from reNgine.osint.cloud_recon import run_msftrecon

        # msftrecon JSON output uses 'domains' key (from --json flag)
        mock_output = json.dumps({
            'domains': ['mail.example-test.local', 'login.example-test.local'],
        })
        mock_run.return_value = (0, mock_output)

        class FakeSelf:
            scan = self.scan

        run_msftrecon(FakeSelf(), 'example-test.local', self.scan, '/tmp/test_results')

        from startScan.models import Subdomain
        names = list(
            Subdomain.objects.filter(scan_history=self.scan).values_list('name', flat=True)
        )
        self.assertIn('mail.example-test.local', names)
        self.assertIn('login.example-test.local', names)

    @patch('reNgine.osint.cloud_recon.run_command')
    def test_run_msftrecon_handles_empty_output(self, mock_run):
        from reNgine.osint.cloud_recon import run_msftrecon

        mock_run.return_value = (0, '')

        class FakeSelf:
            scan = self.scan

        # Should not raise
        run_msftrecon(FakeSelf(), 'example-test.local', self.scan, '/tmp/test_results')

    @patch('reNgine.osint.cloud_recon.run_command')
    def test_run_msftrecon_handles_invalid_json(self, mock_run):
        from reNgine.osint.cloud_recon import run_msftrecon

        mock_run.return_value = (0, 'not json output')

        class FakeSelf:
            scan = self.scan

        # Should not raise
        run_msftrecon(FakeSelf(), 'example-test.local', self.scan, '/tmp/test_results')

    @patch('reNgine.osint.cloud_recon.run_command')
    def test_run_msftrecon_nonzero_exit_still_saves(self, mock_run):
        """Non-zero exit code with valid JSON should still save domains."""
        from reNgine.osint.cloud_recon import run_msftrecon

        mock_output = json.dumps({'domains': ['autodiscover.example-test.local']})
        mock_run.return_value = (1, mock_output)

        class FakeSelf:
            scan = self.scan

        run_msftrecon(FakeSelf(), 'example-test.local', self.scan, '/tmp/test_results')

        from startScan.models import Subdomain
        names = list(
            Subdomain.objects.filter(scan_history=self.scan).values_list('name', flat=True)
        )
        self.assertIn('autodiscover.example-test.local', names)
