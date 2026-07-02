"""Tests for web/reNgine/osint/api_leaks.py.

run_command returns a 2-tuple: (return_code: int, output: str)
"""
from unittest.mock import patch, MagicMock

from django.test import TestCase
from django.utils import timezone

from startScan.models import ScanHistory, Domain, Subdomain, SecretLeak
from scanEngine.models import EngineType


class FakeSelf:
    """Minimal self-like object expected by the api_leaks functions."""
    pass


class TestAPILeaks(TestCase):
    def setUp(self):
        domain = Domain.objects.create(name='example-test.local')
        engine = EngineType.objects.create(
            engine_name='Test',
            yaml_configuration='osint: {}',
        )
        self.scan = ScanHistory.objects.create(
            domain=domain,
            scan_type=engine,
            scan_status=0,
            start_scan_date=timezone.now(),
        )
        self.subdomain = Subdomain.objects.create(
            name='api.example-test.local',
            scan_history=self.scan,
            http_status=200,
            http_url='http://api.example-test.local',
        )

    # ------------------------------------------------------------------
    # porch-pirate
    # ------------------------------------------------------------------

    @patch('reNgine.osint.api_leaks.run_command')
    @patch('reNgine.osint.api_leaks._get_proxy', return_value=None)
    def test_porch_pirate_saves_leaks(self, mock_proxy, mock_run):
        from reNgine.osint.api_leaks import run_porch_pirate

        # 2-tuple: (return_code, output)
        mock_run.return_value = (0, 'SECRET_KEY=abc123\nAPI_TOKEN=xyz789\n')

        run_porch_pirate(FakeSelf(), 'example-test.local', self.scan, '/tmp')

        leaks = SecretLeak.objects.filter(scan_history=self.scan, tool_name='porch-pirate')
        self.assertGreater(leaks.count(), 0)

    @patch('reNgine.osint.api_leaks.run_command')
    @patch('reNgine.osint.api_leaks._get_proxy', return_value=None)
    def test_porch_pirate_no_leaks_on_empty_output(self, mock_proxy, mock_run):
        from reNgine.osint.api_leaks import run_porch_pirate

        mock_run.return_value = (0, '')

        run_porch_pirate(FakeSelf(), 'example-test.local', self.scan, '/tmp')

        leaks = SecretLeak.objects.filter(scan_history=self.scan, tool_name='porch-pirate')
        self.assertEqual(leaks.count(), 0)

    @patch('reNgine.osint.api_leaks.run_command')
    @patch('reNgine.osint.api_leaks._get_proxy', return_value=None)
    def test_porch_pirate_skips_lines_without_separator(self, mock_proxy, mock_run):
        from reNgine.osint.api_leaks import run_porch_pirate

        # Lines without '=' or ':' should not be saved
        mock_run.return_value = (0, 'plainlinewithoutkey\nanothernomatch\n')

        run_porch_pirate(FakeSelf(), 'example-test.local', self.scan, '/tmp')

        leaks = SecretLeak.objects.filter(scan_history=self.scan, tool_name='porch-pirate')
        self.assertEqual(leaks.count(), 0)

    # ------------------------------------------------------------------
    # postleaksNg
    # ------------------------------------------------------------------

    @patch('reNgine.osint.api_leaks.run_command')
    @patch('reNgine.osint.api_leaks._get_proxy', return_value=None)
    def test_postleaks_saves_leaks(self, mock_proxy, mock_run):
        from reNgine.osint.api_leaks import run_postleaks

        mock_run.return_value = (0, 'API_KEY=test_key\nDB_PASSWORD=secret\n')

        run_postleaks(FakeSelf(), 'example-test.local', self.scan, '/tmp')

        leaks = SecretLeak.objects.filter(scan_history=self.scan, tool_name='postleaksNg')
        self.assertGreater(leaks.count(), 0)

    @patch('reNgine.osint.api_leaks.run_command')
    @patch('reNgine.osint.api_leaks._get_proxy', return_value=None)
    def test_postleaks_no_leaks_on_empty_output(self, mock_proxy, mock_run):
        from reNgine.osint.api_leaks import run_postleaks

        mock_run.return_value = (0, '')

        run_postleaks(FakeSelf(), 'example-test.local', self.scan, '/tmp')

        leaks = SecretLeak.objects.filter(scan_history=self.scan, tool_name='postleaksNg')
        self.assertEqual(leaks.count(), 0)

    # ------------------------------------------------------------------
    # SwaggerSpy internet mode
    # ------------------------------------------------------------------

    @patch('reNgine.osint.api_leaks.run_command')
    @patch('reNgine.osint.api_leaks._get_proxy', return_value=None)
    def test_swaggerspy_internet_saves_dorks(self, mock_proxy, mock_run):
        from reNgine.osint.api_leaks import run_swaggerspy_internet

        # 2-tuple: (return_code, output) — output contains discovered URLs
        mock_run.return_value = (
            0,
            'https://api.example-test.local/swagger.json\nhttps://other.com/api-docs\n',
        )

        run_swaggerspy_internet(FakeSelf(), 'example-test.local', self.scan, '/tmp')

        self.assertGreater(self.scan.dorks.count(), 0)

    @patch('reNgine.osint.api_leaks.run_command')
    @patch('reNgine.osint.api_leaks._get_proxy', return_value=None)
    def test_swaggerspy_internet_no_dorks_on_empty_output(self, mock_proxy, mock_run):
        from reNgine.osint.api_leaks import run_swaggerspy_internet

        mock_run.return_value = (0, '')

        run_swaggerspy_internet(FakeSelf(), 'example-test.local', self.scan, '/tmp')

        self.assertEqual(self.scan.dorks.count(), 0)

    @patch('reNgine.osint.api_leaks.run_command')
    @patch('reNgine.osint.api_leaks._get_proxy', return_value=None)
    def test_swaggerspy_internet_ignores_non_url_lines(self, mock_proxy, mock_run):
        from reNgine.osint.api_leaks import run_swaggerspy_internet

        # Lines that don't start with 'http' should be ignored
        mock_run.return_value = (0, '[*] Searching...\nno url here\nftp://bad.example.com\n')

        run_swaggerspy_internet(FakeSelf(), 'example-test.local', self.scan, '/tmp')

        self.assertEqual(self.scan.dorks.count(), 0)

    # ------------------------------------------------------------------
    # SwaggerSpy path mode
    # ------------------------------------------------------------------

    @patch('reNgine.osint.api_leaks.requests')
    @patch('reNgine.osint.api_leaks._get_proxy', return_value=None)
    def test_swaggerspy_path_mode_probes_live_subdomains(self, mock_proxy, mock_requests):
        from reNgine.osint.api_leaks import run_swaggerspy_path_mode

        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.text = '{"swagger": "2.0", "info": {"title": "Test API"}}'
        mock_requests.get.return_value = mock_response

        run_swaggerspy_path_mode(FakeSelf(), 'example-test.local', self.scan, '/tmp')

        # At least one path probe should have matched the swagger keyword
        self.assertGreater(self.scan.dorks.count(), 0)

    @patch('reNgine.osint.api_leaks.requests')
    @patch('reNgine.osint.api_leaks._get_proxy', return_value=None)
    def test_swaggerspy_path_mode_skips_non_200(self, mock_proxy, mock_requests):
        from reNgine.osint.api_leaks import run_swaggerspy_path_mode

        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.text = 'Not Found'
        mock_requests.get.return_value = mock_response

        run_swaggerspy_path_mode(FakeSelf(), 'example-test.local', self.scan, '/tmp')

        self.assertEqual(self.scan.dorks.count(), 0)

    @patch('reNgine.osint.api_leaks.requests')
    @patch('reNgine.osint.api_leaks._get_proxy', return_value=None)
    def test_swaggerspy_path_mode_handles_request_exceptions(self, mock_proxy, mock_requests):
        from reNgine.osint.api_leaks import run_swaggerspy_path_mode

        mock_requests.get.side_effect = Exception('Connection refused')

        # Should not raise — exceptions are swallowed per path
        run_swaggerspy_path_mode(FakeSelf(), 'example-test.local', self.scan, '/tmp')

        self.assertEqual(self.scan.dorks.count(), 0)

    @patch('reNgine.osint.api_leaks.requests')
    @patch('reNgine.osint.api_leaks._get_proxy', return_value=None)
    def test_swaggerspy_path_mode_no_live_subdomains(self, mock_proxy, mock_requests):
        from reNgine.osint.api_leaks import run_swaggerspy_path_mode

        # Create a scan with no live subdomains
        domain2 = Domain.objects.create(name='empty-test.local')
        engine2 = EngineType.objects.create(
            engine_name='EmptyTest',
            yaml_configuration='osint: {}',
        )
        scan2 = ScanHistory.objects.create(
            domain=domain2,
            scan_type=engine2,
            scan_status=0,
            start_scan_date=timezone.now(),
        )

        run_swaggerspy_path_mode(FakeSelf(), 'empty-test.local', scan2, '/tmp')

        # No subdomains → no requests made → no dorks
        mock_requests.get.assert_not_called()
        self.assertEqual(scan2.dorks.count(), 0)
