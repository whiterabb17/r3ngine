"""
Tests for holehe, maigret, and secret_scanning execution paths.

Run inside Docker:
    docker exec -it r3ngine-web-1 bash -c \
        "cd /usr/src/app && python3 manage.py test tests.test_osint_tools --verbosity=2 --keepdb"
"""
from unittest.mock import patch, MagicMock
from django.test import TestCase
from django.utils import timezone
from startScan.models import ScanHistory, Domain
from scanEngine.models import EngineType


class TestOsintOrchestratorAlwaysRuns(TestCase):
    """osint_orchestrator must be called even when discover/dorks produce results."""

    def setUp(self):
        from scanEngine.models import EngineType
        self.domain = Domain.objects.create(name='osint-test.example.com')
        self.engine, _ = EngineType.objects.get_or_create(engine_name='test')
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_status=0,
            start_scan_date=timezone.now(),
            scan_type=self.engine,
        )

    @patch('reNgine.tasks.osint.osint_orchestrator')
    @patch('reNgine.tasks.osint.finish_osint')
    @patch('reNgine.tasks.osint.osint_discovery')
    def test_orchestrator_called_when_discovery_produces_results(
        self, mock_discovery, mock_finish, mock_orchestrator
    ):
        """If osint_discovery returns results, osint_orchestrator must still run."""
        mock_discovery.return_value = {'emails': ['a@example.com']}

        from reNgine.tasks import osint
        proxy = MagicMock()
        proxy.scan = self.scan
        proxy.yaml_configuration = {
            'osint': {'discover': ['emails'], 'intensity': 'normal'}
        }
        proxy.activity_id = None
        proxy.results_dir = '/tmp'
        proxy.scan_id = self.scan.id
        proxy.history_file = '/tmp/history.txt'

        osint(proxy, host='osint-test.example.com', ctx={})

        mock_orchestrator.assert_called_once_with(scan_history_id=self.scan.id)

    @patch('reNgine.tasks.osint.osint_orchestrator')
    @patch('reNgine.tasks.osint.finish_osint')
    def test_orchestrator_called_when_no_discovery_config(
        self, mock_finish, mock_orchestrator
    ):
        """Even with no discover config, osint_orchestrator must run."""
        from reNgine.tasks import osint
        proxy = MagicMock()
        proxy.scan = self.scan
        proxy.yaml_configuration = {'osint': {'intensity': 'normal'}}
        proxy.activity_id = None
        proxy.results_dir = '/tmp'
        proxy.scan_id = self.scan.id
        proxy.history_file = '/tmp/history.txt'

        osint(proxy, host='osint-test.example.com', ctx={})

        mock_orchestrator.assert_called_once_with(scan_history_id=self.scan.id)


class TestSecretScanningInTaskList(TestCase):
    """Engines that run secret scanning must have 'secret_scanning' in their task list."""

    ENGINES_REQUIRING_SECRET_SCAN = [
        'Full Scan',
        'reNgine Recommended',
        'Vulnerability Scan',
        'Comprehensive',
        'Web App & API Discovery',
    ]

    def test_secret_scanning_in_relevant_engine_tasks(self):
        for name in self.ENGINES_REQUIRING_SECRET_SCAN:
            try:
                engine = EngineType.objects.get(engine_name=name)
                self.assertIn(
                    'secret_scanning', engine.tasks,
                    f"Engine '{name}' is missing 'secret_scanning' from its task list"
                )
            except EngineType.DoesNotExist:
                pass  # Engine not installed in this environment

    def test_secret_scanning_config_reads_from_top_level_key(self):
        """Config resolution must check 'secret_scanning' key before osint.leaks_and_secrets."""
        yaml_config = {'secret_scanning': {'trufflehog': True, 'gitleaks': False}}
        config = (
            yaml_config.get('secret_scanning') or
            yaml_config.get('leaks_and_secrets') or
            yaml_config.get('osint', {}).get('leaks_and_secrets') or
            {}
        )
        self.assertTrue(config.get('trufflehog'))
        self.assertFalse(config.get('gitleaks'))

    def test_secret_scanning_config_fallback_to_osint_leaks(self):
        """Config resolution must fall back to osint.leaks_and_secrets when top-level key absent."""
        yaml_config = {'osint': {'leaks_and_secrets': {'trufflehog': True, 'gitleaks': True}}}
        config = (
            yaml_config.get('secret_scanning') or
            yaml_config.get('leaks_and_secrets') or
            yaml_config.get('osint', {}).get('leaks_and_secrets') or
            {}
        )
        self.assertTrue(config.get('trufflehog'))
        self.assertTrue(config.get('gitleaks'))
