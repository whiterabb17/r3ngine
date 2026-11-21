"""Tests for php2shell / node2shell Tier 6 scanners.

Gating mirrors react2shell (technology fingerprint). Parsers consume the
Assetnote JSON envelope ({results: [...]}) and persist only vulnerable=true.
"""

import os
import shutil
import tempfile
from unittest.mock import MagicMock, patch

from django.test import TestCase
from django.utils import timezone

from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain, Technology, Vulnerability
from targetApp.models import Domain


def _make_proxy(scan, subdomain=None, yaml_config=None):
    proxy = MagicMock()
    proxy.scan = scan
    proxy.scan_id = scan.id
    proxy.domain = scan.domain
    proxy.subdomain = subdomain
    proxy.subscan = None
    proxy.yaml_configuration = yaml_config or {
        'vulnerability_scan': {
            'php_scanner': {'run_php2shell': True},
            'node_scanner': {'run_node2shell': True},
        }
    }
    proxy.results_dir = scan.results_dir
    proxy.activity_id = None
    return proxy


class TestPhpNode2ShellGating(TestCase):
    def setUp(self):
        self.domain = Domain.objects.create(name='shell-gate.example.com')
        self.engine = EngineType.objects.create(engine_name='Shell Gate Test Engine')
        results_dir = tempfile.mkdtemp(prefix='rengine_test_2shell_')
        self.addCleanup(shutil.rmtree, results_dir, ignore_errors=True)
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_status=1,
            start_scan_date=timezone.now(),
            scan_type=self.engine,
            results_dir=results_dir,
        )

    def _make_subdomain(self, name):
        return Subdomain.objects.create(
            name=name,
            scan_history=self.scan,
            target_domain=self.domain,
        )

    def _add_tech(self, subdomain, tech_name):
        tech, _ = Technology.objects.get_or_create(name=tech_name)
        subdomain.technologies.add(tech)
        subdomain.save()

    @patch('reNgine.tasks.run_command', return_value=(0, ''))
    def test_php_skips_when_no_php_tech(self, mock_run):
        self._make_subdomain('app.shell-gate.example.com')
        proxy = _make_proxy(self.scan)
        from reNgine.tasks.vulnerability import php2shell_scan
        result = php2shell_scan(proxy)
        self.assertIsNone(result)
        mock_run.assert_not_called()

    @patch('reNgine.tasks.run_command', return_value=(0, ''))
    def test_php_skips_when_disabled(self, mock_run):
        sub = self._make_subdomain('app.shell-gate.example.com')
        self._add_tech(sub, 'PHP')
        proxy = _make_proxy(self.scan, yaml_config={
            'vulnerability_scan': {'php_scanner': {'run_php2shell': False}},
        })
        from reNgine.tasks.vulnerability import php2shell_scan
        result = php2shell_scan(proxy)
        self.assertIsNone(result)
        mock_run.assert_not_called()

    @patch('reNgine.tasks.vulnerability.parse_php2shell_results')
    @patch('reNgine.tasks.run_command', return_value=(0, ''))
    def test_php_runs_when_php_tech(self, mock_run, mock_parse):
        sub = self._make_subdomain('app.shell-gate.example.com')
        self._add_tech(sub, 'PHP')
        proxy = _make_proxy(self.scan)
        from reNgine.tasks.vulnerability import php2shell_scan
        result = php2shell_scan(proxy)
        self.assertEqual(result, 'php2shell scan completed')
        mock_run.assert_called_once()
        self.assertIn('php2shell-scanner/scanner.py', mock_run.call_args[0][0])
        mock_parse.assert_called_once()

    @patch('reNgine.tasks.run_command', return_value=(0, ''))
    def test_node_skips_when_no_node_tech(self, mock_run):
        self._make_subdomain('api.shell-gate.example.com')
        proxy = _make_proxy(self.scan)
        from reNgine.tasks.vulnerability import node2shell_scan
        result = node2shell_scan(proxy)
        self.assertIsNone(result)
        mock_run.assert_not_called()

    @patch('reNgine.tasks.vulnerability.parse_node2shell_results')
    @patch('reNgine.tasks.run_command', return_value=(0, ''))
    def test_node_runs_when_express_tech(self, mock_run, mock_parse):
        sub = self._make_subdomain('api.shell-gate.example.com')
        self._add_tech(sub, 'Express')
        proxy = _make_proxy(self.scan)
        from reNgine.tasks.vulnerability import node2shell_scan
        result = node2shell_scan(proxy)
        self.assertEqual(result, 'node2shell scan completed')
        mock_run.assert_called_once()
        self.assertIn('node2shell-scanner/scanner.py', mock_run.call_args[0][0])
        mock_parse.assert_called_once()

    @patch('reNgine.tasks.run_command', return_value=(0, ''))
    def test_node_skips_expressionengine_false_positive(self, mock_run):
        """ExpressionEngine must not match the Express gate."""
        sub = self._make_subdomain('cms.shell-gate.example.com')
        self._add_tech(sub, 'ExpressionEngine')
        proxy = _make_proxy(self.scan)
        from reNgine.tasks.vulnerability import node2shell_scan
        result = node2shell_scan(proxy)
        self.assertIsNone(result)
        mock_run.assert_not_called()

    @patch('reNgine.tasks.run_command', return_value=(0, ''))
    def test_php_subscan_non_php_skipped(self, mock_run):
        sub = self._make_subdomain('app.shell-gate.example.com')
        proxy = _make_proxy(self.scan, subdomain=sub)
        from reNgine.tasks.vulnerability import php2shell_scan
        result = php2shell_scan(proxy)
        self.assertIsNone(result)
        mock_run.assert_not_called()


class TestPhpNode2ShellParsers(TestCase):
    def setUp(self):
        self.domain = Domain.objects.create(name='shell-parse.example.com')
        self.engine = EngineType.objects.create(engine_name='Shell Parse Engine')
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_status=1,
            start_scan_date=timezone.now(),
            scan_type=self.engine,
        )
        self.subdomain = Subdomain.objects.create(
            name='app.shell-parse.example.com',
            scan_history=self.scan,
            target_domain=self.domain,
        )
        self.task = MagicMock()
        self.task.domain = self.domain
        self.task.scan = self.scan

    def _sample_path(self, name):
        here = os.path.dirname(__file__)
        path = os.path.join(here, 'sample_data', name)
        if os.path.exists(path):
            return path
        return os.path.join('web', 'tests', 'sample_data', name)

    def test_parse_php2shell_persists_only_vulnerable(self):
        from reNgine.tasks.vulnerability import parse_php2shell_results
        parse_php2shell_results(self.task, self._sample_path('php2shell_sample.json'), self.subdomain)
        vulns = Vulnerability.objects.filter(scan_history=self.scan, source='PHP2Shell')
        self.assertEqual(vulns.count(), 1)
        vuln = vulns.first()
        self.assertEqual(vuln.severity, 4)
        self.assertIn('CVE-2026-109618', vuln.name)
        self.assertIn('Empty HTTP 500', vuln.description)
        self.assertEqual(vuln.http_url, 'https://php.example.com/index.php')

    def test_parse_node2shell_persists_only_vulnerable(self):
        from reNgine.tasks.vulnerability import parse_node2shell_results
        parse_node2shell_results(self.task, self._sample_path('node2shell_sample.json'), self.subdomain)
        vulns = Vulnerability.objects.filter(scan_history=self.scan, source='Node2Shell')
        self.assertEqual(vulns.count(), 1)
        vuln = vulns.first()
        self.assertEqual(vuln.severity, 4)
        self.assertIn('CVE-2026-111497', vuln.name)
        self.assertIn('Brotli', vuln.description)
