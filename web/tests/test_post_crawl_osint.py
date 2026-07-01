"""Tests for Task 9: post-crawl OSINT (exifray metadata + SwaggerSpy path probe)."""
import json
import tempfile
from unittest.mock import patch, MagicMock
from django.test import TestCase
from django.utils import timezone
from startScan.models import ScanHistory, Domain, EndPoint, Subdomain
from scanEngine.models import EngineType


class TestPostCrawlOsint(TestCase):
    def setUp(self):
        domain = Domain.objects.create(name='example-test.local')
        engine = EngineType.objects.create(engine_name='Test', yaml_configuration='osint: {}')
        self.scan = ScanHistory.objects.create(
            domain=domain,
            scan_type=engine,
            scan_status=0,
            start_scan_date=timezone.now(),
        )
        subdomain = Subdomain.objects.create(name='example-test.local', scan_history=self.scan)
        # A PDF endpoint that exifray should discover
        EndPoint.objects.create(
            scan_history=self.scan,
            subdomain=subdomain,
            http_url='https://example-test.local/doc/report.pdf',
            http_status=200,
        )

    @patch('reNgine.osint.post_crawl_metadata.subprocess.run')
    def test_exifray_runs_and_parses_output(self, mock_subproc):
        from reNgine.osint.post_crawl_metadata import run_post_crawl_exifray
        from startScan.models import MetaFinderDocument

        def fake_run(cmd, **kwargs):
            output_file = cmd[cmd.index('-o') + 1]
            with open(output_file, 'w') as f:
                json.dump([
                    {
                        'url': 'https://example-test.local/doc.pdf',
                        'author': 'Test User',
                        'title': 'Test Doc',
                    },
                ], f)
            return MagicMock(returncode=0, stderr=b'')

        mock_subproc.side_effect = fake_run

        class FakeSelf:
            scan = self.scan

        with tempfile.TemporaryDirectory() as tmpdir:
            run_post_crawl_exifray(FakeSelf(), 'example-test.local', {}, tmpdir)

        self.assertEqual(
            MetaFinderDocument.objects.filter(scan_history=self.scan).count(), 1
        )
        doc = MetaFinderDocument.objects.get(scan_history=self.scan)
        self.assertEqual(doc.url, 'https://example-test.local/doc.pdf')
        self.assertEqual(doc.author, 'Test User')

    @patch('reNgine.osint.post_crawl_metadata.subprocess.run')
    def test_exifray_handles_subprocess_failure(self, mock_subproc):
        from reNgine.osint.post_crawl_metadata import run_post_crawl_exifray

        mock_subproc.side_effect = Exception('exifray not found')

        class FakeSelf:
            scan = self.scan

        with tempfile.TemporaryDirectory() as tmpdir:
            # Should not raise
            run_post_crawl_exifray(FakeSelf(), 'example-test.local', {}, tmpdir)

    @patch('reNgine.osint.post_crawl_metadata.subprocess.run')
    def test_exifray_handles_missing_output_file(self, mock_subproc):
        from reNgine.osint.post_crawl_metadata import run_post_crawl_exifray

        mock_subproc.return_value = MagicMock(returncode=0, stderr=b'')

        class FakeSelf:
            scan = self.scan

        with tempfile.TemporaryDirectory() as tmpdir:
            # No output file written — should log and return cleanly
            run_post_crawl_exifray(FakeSelf(), 'example-test.local', {}, tmpdir)

    @patch('reNgine.osint.post_crawl_metadata.subprocess.run')
    def test_exifray_handles_malformed_json(self, mock_subproc):
        from reNgine.osint.post_crawl_metadata import run_post_crawl_exifray

        def fake_run(cmd, **kwargs):
            output_file = cmd[cmd.index('-o') + 1]
            with open(output_file, 'w') as f:
                f.write('not valid json')
            return MagicMock(returncode=0, stderr=b'')

        mock_subproc.side_effect = fake_run

        class FakeSelf:
            scan = self.scan

        with tempfile.TemporaryDirectory() as tmpdir:
            # Should not raise on malformed JSON
            run_post_crawl_exifray(FakeSelf(), 'example-test.local', {}, tmpdir)

    @patch('reNgine.osint.post_crawl_metadata.subprocess.run')
    def test_exifray_accepts_dict_wrapper_output(self, mock_subproc):
        """exifray may return {'documents': [...]} as well as a plain list."""
        from reNgine.osint.post_crawl_metadata import run_post_crawl_exifray
        from startScan.models import MetaFinderDocument

        def fake_run(cmd, **kwargs):
            output_file = cmd[cmd.index('-o') + 1]
            with open(output_file, 'w') as f:
                json.dump({'documents': [
                    {'url': 'https://example-test.local/report.docx', 'author': 'Alice'},
                ]}, f)
            return MagicMock(returncode=0, stderr=b'')

        mock_subproc.side_effect = fake_run

        class FakeSelf:
            scan = self.scan

        with tempfile.TemporaryDirectory() as tmpdir:
            run_post_crawl_exifray(FakeSelf(), 'example-test.local', {}, tmpdir)

        self.assertEqual(
            MetaFinderDocument.objects.filter(scan_history=self.scan).count(), 1
        )

    @patch('reNgine.tasks.osint.run_post_crawl_exifray')
    @patch('reNgine.tasks.osint.run_swaggerspy_path_mode')
    def test_post_crawl_osint_calls_configured_tools(self, mock_swagger, mock_exifray):
        from reNgine.tasks.osint import post_crawl_osint

        class FakeSelf:
            scan = self.scan
            scan_id = self.scan.id
            results_dir = '/tmp'
            domain = self.scan.domain
            yaml_configuration = {
                'post_crawl_osint': {'metagoofil': True, 'swaggerspy': True}
            }

        post_crawl_osint(FakeSelf())
        mock_exifray.assert_called_once()
        mock_swagger.assert_called_once()

    @patch('reNgine.tasks.osint.run_post_crawl_exifray')
    @patch('reNgine.tasks.osint.run_swaggerspy_path_mode')
    def test_post_crawl_osint_respects_config_flags(self, mock_swagger, mock_exifray):
        from reNgine.tasks.osint import post_crawl_osint

        class FakeSelf:
            scan = self.scan
            scan_id = self.scan.id
            results_dir = '/tmp'
            domain = self.scan.domain
            yaml_configuration = {
                'post_crawl_osint': {'metagoofil': False, 'swaggerspy': False}
            }

        post_crawl_osint(FakeSelf())
        mock_exifray.assert_not_called()
        mock_swagger.assert_not_called()

    @patch('reNgine.tasks.osint.run_post_crawl_exifray')
    @patch('reNgine.tasks.osint.run_swaggerspy_path_mode')
    def test_post_crawl_osint_skips_when_no_config(self, mock_swagger, mock_exifray):
        from reNgine.tasks.osint import post_crawl_osint

        class FakeSelf:
            scan = self.scan
            scan_id = self.scan.id
            results_dir = '/tmp'
            domain = self.scan.domain
            yaml_configuration = {}

        result = post_crawl_osint(FakeSelf())
        self.assertTrue(result)
        mock_exifray.assert_not_called()
        mock_swagger.assert_not_called()
