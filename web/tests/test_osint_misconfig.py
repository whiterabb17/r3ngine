"""Tests for web/reNgine/osint/misconfig.py.

run_command returns a 2-tuple: (return_code: int, output: str)
"""
import json
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from startScan.models import ScanHistory, Domain
from scanEngine.models import EngineType


class FakeSelf:
    """Minimal self-like object expected by run_misconfig_mapper."""
    pass


class TestMisconfigMapper(TestCase):
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

    # ------------------------------------------------------------------
    # JSON array output (standard format)
    # ------------------------------------------------------------------

    @patch('reNgine.osint.misconfig.run_command')
    def test_run_misconfig_mapper_saves_dorks(self, mock_run):
        """A JSON array finding with a URL is persisted as a Dork."""
        from reNgine.osint.misconfig import run_misconfig_mapper

        mock_output = json.dumps([
            {'service': 'Bucket', 'url': 'https://s3.amazonaws.com/example-test', 'vulnerable': True},
        ])
        mock_run.return_value = (0, mock_output)

        run_misconfig_mapper(FakeSelf(), 'example-test.local', self.scan, '/tmp')

        self.assertGreater(self.scan.dorks.count(), 0)

    @patch('reNgine.osint.misconfig.run_command')
    def test_run_misconfig_mapper_handles_empty_array(self, mock_run):
        """An empty JSON array produces no Dork records."""
        from reNgine.osint.misconfig import run_misconfig_mapper

        mock_run.return_value = (0, '[]')

        run_misconfig_mapper(FakeSelf(), 'example-test.local', self.scan, '/tmp')

        self.assertEqual(self.scan.dorks.count(), 0)

    @patch('reNgine.osint.misconfig.run_command')
    def test_run_misconfig_mapper_handles_empty_output(self, mock_run):
        """Completely empty output produces no Dork records and does not raise."""
        from reNgine.osint.misconfig import run_misconfig_mapper

        mock_run.return_value = (0, '')

        run_misconfig_mapper(FakeSelf(), 'example-test.local', self.scan, '/tmp')

        self.assertEqual(self.scan.dorks.count(), 0)

    @patch('reNgine.osint.misconfig.run_command')
    def test_run_misconfig_mapper_multiple_findings(self, mock_run):
        """Multiple findings in the JSON array each produce a Dork."""
        from reNgine.osint.misconfig import run_misconfig_mapper

        mock_output = json.dumps([
            {'service': 'S3', 'url': 'https://s3.amazonaws.com/example-test-1', 'vulnerable': True},
            {'service': 'Azure', 'url': 'https://example-test.blob.core.windows.net', 'vulnerable': True},
        ])
        mock_run.return_value = (0, mock_output)

        run_misconfig_mapper(FakeSelf(), 'example-test.local', self.scan, '/tmp')

        self.assertEqual(self.scan.dorks.count(), 2)

    @patch('reNgine.osint.misconfig.run_command')
    def test_run_misconfig_mapper_skips_findings_without_url(self, mock_run):
        """Findings without a 'url' key are skipped and not persisted."""
        from reNgine.osint.misconfig import run_misconfig_mapper

        mock_output = json.dumps([
            {'service': 'S3', 'vulnerable': True},  # no url
        ])
        mock_run.return_value = (0, mock_output)

        run_misconfig_mapper(FakeSelf(), 'example-test.local', self.scan, '/tmp')

        self.assertEqual(self.scan.dorks.count(), 0)

    @patch('reNgine.osint.misconfig.run_command')
    def test_run_misconfig_mapper_dork_type_includes_service(self, mock_run):
        """The Dork type field includes the service name from the finding."""
        from reNgine.osint.misconfig import run_misconfig_mapper
        from startScan.models import Dork

        mock_output = json.dumps([
            {'service': 'GitHub', 'url': 'https://github.com/example-test', 'vulnerable': False},
        ])
        mock_run.return_value = (0, mock_output)

        run_misconfig_mapper(FakeSelf(), 'example-test.local', self.scan, '/tmp')

        dork = Dork.objects.filter(type='misconfig_GitHub').first()
        self.assertIsNotNone(dork)

    # ------------------------------------------------------------------
    # JSONL output (one JSON object per line)
    # ------------------------------------------------------------------

    @patch('reNgine.osint.misconfig.run_command')
    def test_run_misconfig_mapper_parses_jsonl(self, mock_run):
        """JSONL output (one JSON object per line) is parsed correctly."""
        from reNgine.osint.misconfig import run_misconfig_mapper

        jsonl_output = (
            '{"service": "Heroku", "url": "https://example-test.herokuapp.com", "vulnerable": true}\n'
            '{"service": "Netlify", "url": "https://example-test.netlify.app", "vulnerable": false}\n'
        )
        mock_run.return_value = (0, jsonl_output)

        run_misconfig_mapper(FakeSelf(), 'example-test.local', self.scan, '/tmp')

        self.assertEqual(self.scan.dorks.count(), 2)

    # ------------------------------------------------------------------
    # Non-JSON / error output
    # ------------------------------------------------------------------

    @patch('reNgine.osint.misconfig.run_command')
    def test_run_misconfig_mapper_handles_non_json_output(self, mock_run):
        """Non-JSON output is tolerated and produces no Dork records."""
        from reNgine.osint.misconfig import run_misconfig_mapper

        mock_run.return_value = (1, 'Error: target unreachable\n')

        # Should not raise
        run_misconfig_mapper(FakeSelf(), 'example-test.local', self.scan, '/tmp')

        self.assertEqual(self.scan.dorks.count(), 0)

    @patch('reNgine.osint.misconfig.run_command')
    def test_run_misconfig_mapper_deduplicates_dorks(self, mock_run):
        """get_or_create ensures duplicate URLs produce only one Dork record."""
        from reNgine.osint.misconfig import run_misconfig_mapper

        url = 'https://s3.amazonaws.com/example-test-dup'
        mock_output = json.dumps([
            {'service': 'S3', 'url': url, 'vulnerable': True},
            {'service': 'S3', 'url': url, 'vulnerable': True},
        ])
        mock_run.return_value = (0, mock_output)

        run_misconfig_mapper(FakeSelf(), 'example-test.local', self.scan, '/tmp')

        from startScan.models import Dork
        self.assertEqual(Dork.objects.filter(type='misconfig_S3', url=url).count(), 1)
