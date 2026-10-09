import os
import signal
import threading
import django
import json
import yaml
from django.test import TestCase, tag
from unittest.mock import patch, MagicMock

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'reNgine.settings')
django.setup()

from startScan.models import ScanHistory, EngineType, Subdomain, Vulnerability
from targetApp.models import Domain
from django.utils import timezone

class TestSubscanSeverityStability(TestCase):
    """
    Test suite to verify stabilizing changes made to:
    1. save_vulnerability centralized severity string conversion.
    2. parse_react2shell_results severity integer normalization.
    """

    def setUp(self):
        self.domain, _ = Domain.objects.get_or_create(name='stability.test.local')
        self.engine = EngineType.objects.create(
            engine_name='Subscan Stability Test Engine',
            yaml_configuration=yaml.dump({
                'subdomain_discovery': {},
                'port_scan': {},
                'vulnerability_scan': {
                    'enabled': True,
                    'run_apme': False
                },
                'fetch_url': {},
                'dir_file_fuzz': {}
            })
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            start_scan_date=timezone.now(),
            results_dir='/tmp/stability_tests',
            tasks=[]
        )
        self.subdomain = Subdomain.objects.create(
            name='target.stability.test.local',
            target_domain=self.domain,
            scan_history=self.scan,
            http_url='http://target.stability.test.local'
        )

    def tearDown(self):
        Vulnerability.objects.filter(scan_history=self.scan).delete()
        Subdomain.objects.filter(scan_history=self.scan).delete()
        self.scan.delete()
        self.engine.delete()
        self.domain.delete()

    def test_save_vulnerability_severity_guard(self):
        """
        Verify that save_vulnerability converts string severities to correct integers,
        preventing ValueError database layer crashes during save operations.
        """
        from reNgine.common_func import save_vulnerability
        
        # Test distinct string/integer severity inputs and verify mapped integer outcomes
        test_cases = [
            ('info', 0),
            ('INFO', 0),
            ('low', 1),
            ('Low', 1),
            ('medium', 2),
            ('Medium', 2),
            ('high', 3),
            ('High', 3),
            ('critical', 4),
            ('CRITICAL', 4),
            ('unknown_or_invalid_string', 2),  # Should default to Medium (2)
            (3, 3),                            # Integer should pass through unchanged
            (1, 1)                             # Integer should pass through unchanged
        ]
        
        for input_severity, expected_int in test_cases:
            vuln_name = f"Test Severity Normalization - {input_severity}"
            
            save_vulnerability(
                target_domain=self.domain,
                scan_history=self.scan,
                http_url='http://target.stability.test.local',
                subdomain=self.subdomain,
                name=vuln_name,
                severity=input_severity,
                description=f"Testing severity conversion for {input_severity}",
                remediation="None",
                type="Test"
            )
            
            # Fetch from DB and verify correctness
            vuln = Vulnerability.objects.get(scan_history=self.scan, name=vuln_name)
            self.assertEqual(vuln.severity, expected_int)

    @patch('reNgine.tasks.vulnerability.logger')
    def test_parse_react2shell_results_severity(self, mock_logger):
        """
        Verify that parse_react2shell_results successfully parses severity strings and
        correctly invokes save_vulnerability with corresponding integer values.
        """
        from reNgine.tasks.vulnerability import parse_react2shell_results
        
        mock_task = MagicMock()
        mock_task.domain = self.domain
        mock_task.scan = self.scan
        
        # Define mock findings payload
        findings = [
            {
                'vulnerability': 'React Component Source Leak A',
                'severity': 'high',
                'details': 'Found source map leak A',
                'remediation': 'Fix build settings A'
            },
            {
                'vulnerability': 'React Component Source Leak B',
                'severity': 'CRITICAL',
                'details': 'Found source map leak B',
                'remediation': 'Fix build settings B'
            },
            {
                'vulnerability': 'React Component Source Leak C',
                'severity': 'info',
                'details': 'Found source map leak C',
                'remediation': 'Fix build settings C'
            }
        ]
        
        # Write to temporary file
        temp_file = '/tmp/react2shell_test_findings.json'
        os.makedirs(os.path.dirname(temp_file), exist_ok=True)
        with open(temp_file, 'w') as f:
            json.dump(findings, f)
            
        try:
            parse_react2shell_results(mock_task, temp_file, self.subdomain)
            
            # Fetch saved vulnerabilities and assert fields
            vuln_a = Vulnerability.objects.get(scan_history=self.scan, name='React Component Source Leak A')
            self.assertEqual(vuln_a.severity, 3)
            self.assertEqual(vuln_a.description, 'Found source map leak A')
            
            vuln_b = Vulnerability.objects.get(scan_history=self.scan, name='React Component Source Leak B')
            self.assertEqual(vuln_b.severity, 4)
            self.assertEqual(vuln_b.description, 'Found source map leak B')
            
            vuln_c = Vulnerability.objects.get(scan_history=self.scan, name='React Component Source Leak C')
            self.assertEqual(vuln_c.severity, 0)
            self.assertEqual(vuln_c.description, 'Found source map leak C')
            
        finally:
            if os.path.exists(temp_file):
                os.remove(temp_file)

    @patch('reNgine.utils.task.Command')
    @patch('reNgine.utils.task.SOCConfiguration')
    def test_stream_command_watchdog_kills_hung_process(self, mock_soc_config, mock_command_model):
        """The watchdog kills a process that outlives the timeout (fake process and clock).

        The real-subprocess version below is tagged integration: it waits out
        the watchdog's 2 s poll interval in wall time.
        """
        from reNgine.utils.task import stream_command

        mock_soc_config.objects.get_or_create.return_value = (
            MagicMock(enable_live_log_streaming=False), False,
        )
        mock_cmd_obj = MagicMock()
        mock_command_model.objects.create.return_value = mock_cmd_obj

        killed = threading.Event()

        class _HungStdout:
            def readline(self):
                # Blocks like a pipe from a silent process until the kill;
                # the bound only keeps a broken watchdog from hanging the suite.
                was_killed = killed.wait(timeout=10)
                return '' if was_killed else 'still running'

            def close(self):
                pass

        class _HungProcess:
            pid = 4242
            returncode = None
            stdout = _HungStdout()

            def poll(self):
                return self.returncode

            def wait(self, timeout=None):
                return self.returncode

        process = _HungProcess()

        def fake_killpg(pgid, sig):
            process.returncode = -sig
            killed.set()

        clock = [1000.0]

        def fake_sleep(seconds):
            clock[0] += seconds

        with patch('reNgine.utils.task.subprocess.Popen', return_value=process), \
                patch('reNgine.utils.task.os.getpgid', side_effect=lambda pid: pid), \
                patch('reNgine.utils.task.os.killpg', side_effect=fake_killpg) as mock_killpg, \
                patch('time.monotonic', side_effect=lambda: clock[0]), \
                patch('time.sleep', side_effect=fake_sleep) as mock_sleep:
            lines = list(stream_command(
                'sleep 10', timeout=1, shell=False, route_to_executor=False,
            ))

        self.assertEqual(lines, [])
        self.assertTrue(killed.is_set())
        mock_killpg.assert_called_once_with(4242, signal.SIGKILL)
        mock_sleep.assert_called_with(2)
        self.assertEqual(process.returncode, -signal.SIGKILL)
        mock_cmd_obj.save.assert_called()

    @tag('integration')
    @patch('reNgine.utils.task.Command')
    @patch('reNgine.utils.task.SOCConfiguration')
    def test_stream_command_watchdog_timeout(self, mock_soc_config, mock_command_model):
        """
        Verify that stream_command properly enforces a watchdog timeout,
        killing hung subprocesses using the background watchdog thread.
        """
        from reNgine.utils.task import stream_command
        import time

        # Mock SOCConfiguration
        mock_soc = MagicMock()
        mock_soc.enable_live_log_streaming = False
        mock_soc_config.objects.get_or_create.return_value = (mock_soc, False)

        # Mock Command database object
        mock_cmd_obj = MagicMock()
        mock_command_model.objects.create.return_value = mock_cmd_obj

        # Execute a command that would sleep indefinitely, but with a very small timeout (1s)
        start_time = time.time()
        lines = list(stream_command("sleep 10", timeout=1, shell=False))
        duration = time.time() - start_time

        # The command should have been killed by the watchdog after 1 second
        self.assertLess(duration, 4.0) # Allow slight buffer for thread scheduling
        # Also confirm the Command database object was updated with a return code indicating termination/killed status
        mock_cmd_obj.save.assert_called()

    def test_save_vulnerability_rejects_null_agent_enrichment(self):
        """Explicit agent_enrichment=None must not hit the NOT NULL jsonb column."""
        from reNgine.common_func import save_vulnerability
        from startScan.models import Vulnerability

        vuln, created = save_vulnerability(
            target_domain=self.domain,
            scan_history=self.scan,
            subdomain=self.subdomain,
            http_url='http://target.stability.test.local/enrichment-null',
            name='Agent Enrichment Null Guard',
            severity=0,
            description='probe',
            type='test',
            agent_enrichment=None,
        )
        self.assertTrue(created)
        self.assertEqual(vuln.agent_enrichment, {})
        stored = Vulnerability.objects.get(pk=vuln.pk)
        self.assertEqual(stored.agent_enrichment, {})

    def test_save_vulnerability_deduplication(self):
        """
        Verify that save_vulnerability correctly deduplicates findings based on core identity
        (name, scan_history, subdomain, http_url) and updates volatile fields in-place.
        """
        from reNgine.common_func import save_vulnerability

        vuln_name = "Centralized Deduplication Test Vuln"
        http_url = "http://target.stability.test.local/vuln"

        # 1. Save first instance
        vuln1, created1 = save_vulnerability(
            target_domain=self.domain,
            scan_history=self.scan,
            subdomain=self.subdomain,
            http_url=http_url,
            name=vuln_name,
            severity=3,
            description="Initial description",
            curl_command="curl -X GET http://target.stability.test.local/vuln"
        )
        self.assertTrue(created1)
        self.assertEqual(vuln1.description, "Initial description")

        # 2. Save duplicate instance (same identity, different volatile fields)
        vuln2, created2 = save_vulnerability(
            target_domain=self.domain,
            scan_history=self.scan,
            subdomain=self.subdomain,
            http_url=http_url,
            name=vuln_name,
            severity=3,
            description="Updated description showing deduplication works",
            curl_command="curl -X POST http://target.stability.test.local/vuln"
        )
        self.assertFalse(created2)
        self.assertEqual(vuln1.id, vuln2.id)

        # 3. Assert DB only has 1 record for this scan, and it has the updated description
        db_vulns = Vulnerability.objects.filter(scan_history=self.scan, name=vuln_name)
        self.assertEqual(db_vulns.count(), 1)
        self.assertEqual(db_vulns.first().description, "Updated description showing deduplication works")

        # 4. Save vulnerability for a different URL - should create a new record
        vuln3, created3 = save_vulnerability(
            target_domain=self.domain,
            scan_history=self.scan,
            subdomain=self.subdomain,
            http_url="http://target.stability.test.local/other-vuln",
            name=vuln_name,
            severity=3,
            description="Different url description",
            curl_command="curl -X GET http://target.stability.test.local/other-vuln"
        )
        self.assertTrue(created3)
        self.assertNotEqual(vuln1.id, vuln3.id)
        self.assertEqual(Vulnerability.objects.filter(scan_history=self.scan, name=vuln_name).count(), 2)

