import json
from unittest.mock import patch, MagicMock
from django.test import TestCase
from django.utils import timezone
from startScan.models import ScanHistory
from targetApp.models import Domain
from scanEngine.models import EngineType


class TestGitHubAnalysis(TestCase):
    def setUp(self):
        domain = Domain.objects.create(name='acme-test.local')
        engine = EngineType.objects.create(engine_name='Test', yaml_configuration='osint: {}')
        self.scan = ScanHistory.objects.create(
            domain=domain,
            scan_type=engine,
            scan_status=0,
            start_scan_date=timezone.now(),
            tasks=[],
        )

    def test_derive_github_orgs_strips_tld(self):
        from reNgine.osint.github_analysis import _derive_github_orgs
        with patch('reNgine.osint.github_analysis.requests.get') as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 200
            mock_get.return_value = mock_resp
            orgs = _derive_github_orgs('acme.com', token=None)
        self.assertIn('acme', orgs)

    def test_derive_github_orgs_returns_empty_when_all_404(self):
        from reNgine.osint.github_analysis import _derive_github_orgs
        with patch('reNgine.osint.github_analysis.requests.get') as mock_get:
            mock_resp = MagicMock()
            mock_resp.status_code = 404
            mock_get.return_value = mock_resp
            orgs = _derive_github_orgs('example-test.local', token=None)
        self.assertEqual(orgs, [])

    @patch('reNgine.osint.github_analysis.subprocess.run')
    @patch('reNgine.osint.github_analysis._derive_github_orgs')
    def test_run_github_analysis_no_key_runs_enumerepo_rate_limited(
        self, mock_derive, mock_subproc
    ):
        from reNgine.osint.github_analysis import run_github_analysis
        mock_derive.return_value = ['acme']
        mock_subproc.return_value = MagicMock(
            returncode=0,
            stdout=b'acme/repo1\nacme/repo2\n',
        )
        config = {'github_analysis': {'uses_tools': ['enumerepo']}}

        class FakeSelf:
            scan = self.scan

        run_github_analysis(FakeSelf(), 'acme-test.local', self.scan, '/tmp', config)
        mock_subproc.assert_called()

    def test_gato_skipped_without_key(self):
        from reNgine.osint.github_analysis import _run_gato
        with patch('reNgine.osint.github_analysis.subprocess.run') as mock_sub:
            _run_gato(['acme'], token=None, results_dir='/tmp')
            mock_sub.assert_not_called()

    @patch('reNgine.osint.github_analysis.subprocess.run')
    @patch('reNgine.osint.github_analysis._derive_github_orgs')
    def test_run_github_analysis_skips_when_no_orgs(self, mock_derive, mock_subproc):
        """When org derivation returns nothing, analysis exits early without subprocess."""
        from reNgine.osint.github_analysis import run_github_analysis
        mock_derive.return_value = []

        class FakeSelf:
            scan = self.scan

        run_github_analysis(FakeSelf(), 'unknown-test.local', self.scan, '/tmp', {
            'github_analysis': {'uses_tools': ['enumerepo']},
        })
        mock_subproc.assert_not_called()

    @patch('reNgine.osint.github_analysis.subprocess.run')
    @patch('reNgine.osint.github_analysis._derive_github_orgs')
    def test_run_github_analysis_empty_config_skips(self, mock_derive, mock_subproc):
        """Empty github_analysis config exits before any subprocess call."""
        from reNgine.osint.github_analysis import run_github_analysis

        class FakeSelf:
            scan = self.scan

        run_github_analysis(FakeSelf(), 'acme-test.local', self.scan, '/tmp', {})
        mock_derive.assert_not_called()
        mock_subproc.assert_not_called()

    @patch('reNgine.osint.github_analysis.save_secret_leak')
    @patch('reNgine.osint.github_analysis.subprocess.run')
    def test_run_noseyparker_parses_json(self, mock_subproc, mock_save):
        """_run_noseyparker calls save_secret_leak for each finding in report.

        Mock data uses the noseyparker v0.24.0 JSON schema: a list of finding
        objects, each with 'rule_name' and 'matches' (not a dict with 'findings').
        Each match has 'snippet.matching' and 'provenance' list.
        """
        from reNgine.osint.github_analysis import _run_noseyparker
        # noseyparker v0.24.0: top-level list, not a dict with a 'findings' key
        scan_json = json.dumps([
            {
                'rule_name': 'AWS API Credentials',
                'matches': [
                    {
                        'snippet': {
                            'before': 'AWS_ACCESS_KEY_ID=',
                            'matching': 'AKIAIOSFODNN7EXAMPLE',
                            'after': '\n',
                        },
                        'provenance': [
                            {'kind': 'git_repo', 'repo_path': '/tmp/acme_repo1'},
                        ],
                    }
                ],
            }
        ]).encode()
        # First call (scan) returns 0; second call (report) returns JSON
        mock_subproc.side_effect = [
            MagicMock(returncode=0, stdout=b'', stderr=b''),
            MagicMock(returncode=0, stdout=scan_json, stderr=b''),
        ]
        _run_noseyparker(['acme/repo1'], self.scan, '/tmp')
        mock_save.assert_called_once()
        call_kwargs = mock_save.call_args[1]
        self.assertEqual(call_kwargs['tool_name'], 'noseyparker')
        self.assertEqual(call_kwargs['secret_type'], 'AWS API Credentials')
        self.assertEqual(call_kwargs['source_url'], '/tmp/acme_repo1')

    @patch('reNgine.osint.github_analysis.subprocess.run')
    def test_gato_runs_with_token(self, mock_subproc):
        """_run_gato calls subprocess.run when a token is provided."""
        from reNgine.osint.github_analysis import _run_gato
        mock_subproc.return_value = MagicMock(returncode=0)
        _run_gato(['acme'], token='ghp_testtoken12345', results_dir='/tmp')
        mock_subproc.assert_called_once()
        cmd = mock_subproc.call_args[0][0]
        self.assertIn('--target', cmd)
        self.assertIn('acme', cmd)
