"""Tests for extended dorking engines: dorks_hunter and xnldorker.

run_command returns a 2-tuple: (return_code: int, output: str)

Run inside Docker:
    docker exec r3ngine-web-1 bash -c \
        "cd /usr/src/app && python3 manage.py test tests.test_osint_dorking_extended --keepdb --verbosity=2"
"""
from unittest.mock import patch, mock_open

from django.test import TestCase
from django.utils import timezone

from startScan.models import ScanHistory, Domain
from scanEngine.models import EngineType


class TestDorkingExtended(TestCase):
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

    @patch('builtins.open', new_callable=mock_open, read_data='')
    @patch('reNgine.tasks.osint.run_command')
    def test_dorking_calls_dorks_hunter_when_in_engines(self, mock_run, mock_file):
        from reNgine.tasks.osint import dorking

        mock_run.return_value = (0, '')
        config = {
            'dork_engines': ['dorks_hunter'],
        }
        dorking(
            config=config,
            host='example-test.local',
            scan_history_id=self.scan.id,
            results_dir='/tmp',
        )
        calls_str = str(mock_run.call_args_list)
        self.assertIn('dorks_hunter', calls_str)

    @patch('reNgine.tasks.osint.run_command')
    def test_dorking_calls_xnldorker_when_in_engines(self, mock_run):
        from reNgine.tasks.osint import dorking

        mock_run.return_value = (0, 'https://example-test.local/admin\n')
        config = {
            'dork_engines': ['xnldorker'],
        }
        dorking(
            config=config,
            host='example-test.local',
            scan_history_id=self.scan.id,
            results_dir='/tmp',
        )
        calls_str = str(mock_run.call_args_list)
        self.assertIn('xnldorker', calls_str)

    @patch('builtins.open', new_callable=mock_open, read_data='')
    @patch('reNgine.tasks.osint.run_command')
    def test_dorking_both_engines_run_additively(self, mock_run, mock_file):
        from reNgine.tasks.osint import dorking

        mock_run.return_value = (0, '')
        config = {'dork_engines': ['dorks_hunter', 'xnldorker']}
        dorking(
            config=config,
            host='example-test.local',
            scan_history_id=self.scan.id,
            results_dir='/tmp',
        )
        calls_str = str(mock_run.call_args_list)
        self.assertIn('dorks_hunter', calls_str)
        self.assertIn('xnldorker', calls_str)

    @patch('builtins.open', new_callable=mock_open, read_data='https://example-test.local/login\nhttps://example-test.local/admin\n')
    @patch('reNgine.tasks.osint.run_command')
    def test_dorks_hunter_urls_saved_to_dorks(self, mock_run, mock_file):
        from reNgine.tasks.osint import dorking
        from startScan.models import Dork

        mock_run.return_value = (0, '')
        config = {'dork_engines': ['dorks_hunter']}
        result = dorking(
            config=config,
            host='example-test.local',
            scan_history_id=self.scan.id,
            results_dir='/tmp',
        )
        saved_dork_urls = list(Dork.objects.filter(type='dorks_hunter').values_list('url', flat=True))
        self.assertIn('https://example-test.local/login', saved_dork_urls)
        self.assertIn('https://example-test.local/admin', saved_dork_urls)

    @patch('reNgine.tasks.osint.run_command')
    def test_xnldorker_urls_saved_to_dorks(self, mock_run):
        from reNgine.tasks.osint import dorking
        from startScan.models import Dork

        mock_run.return_value = (0, 'https://example-test.local/secret\nhttps://example-test.local/api\n')
        config = {'dork_engines': ['xnldorker']}
        result = dorking(
            config=config,
            host='example-test.local',
            scan_history_id=self.scan.id,
            results_dir='/tmp',
        )
        saved_dork_urls = list(Dork.objects.filter(type='xnldorker').values_list('url', flat=True))
        self.assertIn('https://example-test.local/secret', saved_dork_urls)
        self.assertIn('https://example-test.local/api', saved_dork_urls)

    @patch('reNgine.tasks.osint.run_command')
    def test_no_extended_engines_when_config_empty(self, mock_run):
        from reNgine.tasks.osint import dorking

        mock_run.return_value = (0, '')
        config = {}
        dorking(
            config=config,
            host='example-test.local',
            scan_history_id=self.scan.id,
            results_dir='/tmp',
        )
        calls_str = str(mock_run.call_args_list)
        self.assertNotIn('dorks_hunter', calls_str)
        self.assertNotIn('xnldorker', calls_str)
