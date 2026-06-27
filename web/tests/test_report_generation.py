import os
from unittest.mock import patch, MagicMock
from django.test import TestCase, TransactionTestCase
from django.utils import timezone

from reNgine.report_tasks import generate_report_task
from startScan.models import Domain, ScanHistory, ScanReport, StressTestResult, SecretLeak
from scanEngine.models import EngineType, VulnerabilityReportSetting, OpSec, Proxy

class ReportGenerationTest(TransactionTestCase):
    """
    Test suite to verify that PDF report generation for stress testing runs successfully,
    correctly aggregates telemetry data, and passes all required metrics to WeasyPrint
    without raising NameError or other template compilation crashes.
    """

    def setUp(self):
        """
        Set up the test fixtures, including domain, scan history, engine type,
        reports settings, and sample stress results.
        """
        # Create dependencies
        self.domain = Domain.objects.create(name="defijn.io")
        self.engine = EngineType.objects.create(engine_name="Test Engine")
        
        # Ensure OpSec and Proxy records exist to prevent DB errors
        OpSec.objects.get_or_create(id=1)
        Proxy.objects.get_or_create(id=1)

        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_status=2,
            start_scan_date=timezone.now(),
            scan_type=self.engine
        )

        # Create StressTestResult objects associated with the scan
        StressTestResult.objects.create(
            scan_history=self.scan,
            tool_used="k6",
            total_requests=1000,
            successful_requests=950,
            failed_requests=50,
            avg_latency_ms=12.5,
            p95_latency_ms=25.0,
            p99_latency_ms=35.0,
            max_requests_per_second=100.0
        )
        
        StressTestResult.objects.create(
            scan_history=self.scan,
            tool_used="wrk",
            total_requests=2000,
            successful_requests=1980,
            failed_requests=20,
            avg_latency_ms=15.0,
            p95_latency_ms=30.0,
            p99_latency_ms=45.0,
            max_requests_per_second=200.0
        )

        # Create VulnerabilityReportSetting
        VulnerabilityReportSetting.objects.create(
            company_name="Test Corp",
            company_address="123 Test St",
            company_email="admin@test.com",
            company_website="https://test.com",
            show_rengine_banner=True,
            show_footer=True,
            footer_text="Test Footer",
            show_executive_summary=True,
            executive_summary_description="Summary for {company_name} scan on {target_name}. P95 Latency: {stress_avg_p95}"
        )

    @patch('reNgine.report_tasks.HTML')
    @patch('reNgine.charts.generate_subdomain_chart_by_http_status')
    @patch('reNgine.charts.generate_stress_latency_chart')
    @patch('reNgine.charts.generate_stress_success_rate_chart')
    def test_stress_modern_report_generation(self, mock_success_chart, mock_latency_chart, mock_subdomain_chart, mock_html):
        """
        Verify that the 'stress_modern' template compiles correctly and is successfully
        written to a PDF via WeasyPrint.
        """
        mock_subdomain_chart.return_value = 'mocked_chart_base64'
        mock_latency_chart.return_value = 'mocked_chart_base64'
        mock_success_chart.return_value = 'mocked_chart_base64'

        # Mock WeasyPrint write_pdf return value
        mock_html_instance = MagicMock()
        mock_html_instance.write_pdf.return_value = b"%PDF-1.4 Mock Content"
        mock_html.return_value = mock_html_instance

        # Create ScanReport for stress_modern
        report = ScanReport.objects.create(
            scan_history=self.scan,
            report_type="stress_test",
            report_template="stress_modern",
            params={'ignore_info_vuln': False, 'include_attack_surface_map': False},
            status=0
        )

        # Trigger Celery report generation task synchronously
        generate_report_task(report.id)

        # Reload report from DB
        report.refresh_from_db()

        # Assertions
        self.assertEqual(report.status, 2) # Success status
        self.assertIsNone(report.error_message)
        self.assertTrue(report.report_file.name.endswith(".pdf"))
        self.assertTrue(report.report_file.size > 0)
        
        # Verify rendered HTML contains aggregated metrics
        mock_html.assert_called_once()
        rendered_html = mock_html.call_args[1]['string']
        
        # Total requests: 1000 + 2000 = 3000
        self.assertIn("3000", rendered_html)
        
        # Avg P95: (25.0 + 30.0) / 2 = 27.5
        # The templates format this using floatformat filter
        self.assertIn("27.5", rendered_html)
        
        # Verify individual results are rendered
        self.assertIn("wrk", rendered_html)
        self.assertIn("k6", rendered_html)
        self.assertIn("15.0ms", rendered_html)
        self.assertIn("12.5ms", rendered_html)

    @patch('reNgine.report_tasks.HTML')
    @patch('reNgine.charts.generate_subdomain_chart_by_http_status')
    @patch('reNgine.charts.generate_stress_latency_chart')
    @patch('reNgine.charts.generate_stress_success_rate_chart')
    def test_stress_cyber_pro_report_generation(self, mock_success_chart, mock_latency_chart, mock_subdomain_chart, mock_html):
        """
        Verify that the 'stress_cyber_pro' template compiles correctly and is successfully
        written to a PDF via WeasyPrint.
        """
        mock_subdomain_chart.return_value = 'mocked_chart_base64'
        mock_latency_chart.return_value = 'mocked_chart_base64'
        mock_success_chart.return_value = 'mocked_chart_base64'

        # Mock WeasyPrint write_pdf return value
        mock_html_instance = MagicMock()
        mock_html_instance.write_pdf.return_value = b"%PDF-1.4 Mock Content"
        mock_html.return_value = mock_html_instance

        # Create ScanReport for stress_cyber_pro
        report = ScanReport.objects.create(
            scan_history=self.scan,
            report_type="stress_test",
            report_template="stress_cyber_pro",
            params={'ignore_info_vuln': False, 'include_attack_surface_map': False},
            status=0
        )

        # Trigger Celery report generation task synchronously
        generate_report_task(report.id)

        # Reload report from DB
        report.refresh_from_db()

        # Assertions
        self.assertEqual(report.status, 2) # Success status
        self.assertIsNone(report.error_message)
        self.assertTrue(report.report_file.name.endswith(".pdf"))
        self.assertTrue(report.report_file.size > 0)
        
        # Verify WeasyPrint was called
        mock_html.assert_called_once()
        rendered_html = mock_html.call_args[1]['string']
        
        # Total requests: 1000 + 2000 = 3000
        self.assertIn("3000", rendered_html)
        
        # Avg P95: (25.0 + 30.0) / 2 = 27.5
        self.assertIn("27.5", rendered_html)

        # Verify individual results are rendered
        self.assertIn("wrk", rendered_html)
        self.assertIn("k6", rendered_html)
        self.assertIn("45.0ms", rendered_html) # P99 for wrk
        self.assertIn("35.0ms", rendered_html) # P99 for k6

    @patch('reNgine.report_tasks.HTML')
    @patch('reNgine.charts.generate_subdomain_chart_by_http_status')
    @patch('reNgine.charts.generate_stress_latency_chart')
    @patch('reNgine.charts.generate_stress_success_rate_chart')
    def test_report_generation_with_comments(self, mock_success_chart, mock_latency_chart, mock_subdomain_chart, mock_html):
        """
        Verify that `{comments}` is correctly replaced when comments are provided,
        and replaced with an empty string when not provided.
        """
        mock_subdomain_chart.return_value = 'mocked_chart_base64'
        mock_latency_chart.return_value = 'mocked_chart_base64'
        mock_success_chart.return_value = 'mocked_chart_base64'

        mock_html_instance = MagicMock()
        mock_html_instance.write_pdf.return_value = b"%PDF-1.4 Mock Content"
        mock_html.return_value = mock_html_instance

        # 1. Update report settings to include {comments}
        setting = VulnerabilityReportSetting.objects.first()
        setting.executive_summary_description = "Assessment comments: {comments}"
        setting.save()

        # 2. Generate with comments
        report_with = ScanReport.objects.create(
            scan_history=self.scan,
            report_type="vulnerability",
            report_template="modern",
            params={
                'ignore_info_vuln': False,
                'include_attack_surface_map': False,
                'comments': 'These are custom comments.'
            },
            status=0
        )
        generate_report_task(report_with.id)
        
        # Verify rendered HTML contains custom comments
        rendered_html_with = mock_html.call_args[1]['string']
        self.assertIn("Assessment comments: These are custom comments.", rendered_html_with)

        # Reset mock
        mock_html.reset_mock()

        # 3. Generate without comments
        report_without = ScanReport.objects.create(
            scan_history=self.scan,
            report_type="vulnerability",
            report_template="modern",
            params={
                'ignore_info_vuln': False,
                'include_attack_surface_map': False
            },
            status=0
        )
        generate_report_task(report_without.id)
        
        # Verify rendered HTML replaces {comments} with empty string
        rendered_html_without = mock_html.call_args[1]['string']
        self.assertIn("Assessment comments: ", rendered_html_without)
        self.assertNotIn("{comments}", rendered_html_without)


class VulnersReportGroupingTest(TestCase):
    def setUp(self):
        from scanEngine.models import EngineType
        from startScan.models import Domain, ScanHistory, Vulnerability
        engine = EngineType.objects.create(engine_name='Test Engine', yaml_configuration='')
        domain = Domain.objects.create(name='report-test.com')
        scan = ScanHistory.objects.create(
            domain=domain,
            scan_type=engine,
            scan_status=2,
            start_scan_date='2026-01-01T00:00:00Z'
        )
        # Create vulners vulns with same group_key
        for hash_id, cvss in [('HASH-A', 9.8), ('CVE-2026-1234', 7.5), ('HASH-B', 9.8)]:
            Vulnerability.objects.create(
                scan_history=scan,
                target_domain=domain,
                name=f'Exim smtpd 4.99.2 ({hash_id})',
                severity=4 if cvss >= 9 else 3,
                source='VULNERS',
                group_key='Exim smtpd 4.99.2',
                cvss_score=cvss,
                http_url='mail.report-test.com:465'
            )
        # Create non-vulners vuln
        Vulnerability.objects.create(
            scan_history=scan,
            target_domain=domain,
            name='SQL Injection',
            severity=4,
            source='nuclei',
            cvss_score=9.0,
            http_url='http://report-test.com/login'
        )
        self.scan = scan

    def test_build_vuln_context_separates_vulners(self):
        """build_vuln_context must separate vulners from other vulns and group by group_key."""
        from reNgine.report_tasks import build_vuln_context
        ctx = build_vuln_context(self.scan, ignore_info=False)

        # Non-vulners in all_vulnerabilities
        all_names = [v.name for v in ctx['all_vulnerabilities']]
        self.assertIn('SQL Injection', all_names)
        self.assertNotIn('Exim smtpd 4.99.2 (HASH-A)', all_names)

        # Vulners in grouped_vulners_findings
        self.assertEqual(len(ctx['grouped_vulners_findings']), 1)
        group = ctx['grouped_vulners_findings'][0]
        self.assertEqual(group['group_key'], 'Exim smtpd 4.99.2')
        self.assertEqual(group['count'], 3)
        self.assertEqual(group['max_severity'], 4)

    def test_build_vuln_context_total_count(self):
        """all_vulnerabilities_count must be total (vulners + non-vulners)."""
        from reNgine.report_tasks import build_vuln_context
        ctx = build_vuln_context(self.scan, ignore_info=False)
        self.assertEqual(ctx['all_vulnerabilities_count'], 4)  # 3 vulners + 1 nuclei


class SecretLeaksReportContextTest(TransactionTestCase):
    """Verify secret_leaks context vars are injected (or suppressed) correctly."""

    def setUp(self):
        from scanEngine.models import EngineType, OpSec, Proxy
        OpSec.objects.get_or_create(id=1)
        Proxy.objects.get_or_create(id=1)
        from targetApp.models import Domain as TargetDomain
        from dashboard.models import Project
        self.project = Project.objects.create(
            name='leak-rpt-proj',
            slug='leak-rpt-proj',
            insert_date=timezone.now(),
        )
        self.domain = TargetDomain.objects.create(
            name='leaktest.example.com', project=self.project, insert_date=timezone.now()
        )
        self.engine = EngineType.objects.create(engine_name='Leak Test Engine')
        self.scan = ScanHistory.objects.create(
            domain=self.domain, scan_status=2,
            start_scan_date=timezone.now(), scan_type=self.engine,
        )
        SecretLeak.objects.create(
            scan_history=self.scan,
            tool_name='Semgrep',
            secret_type='AWS Access Key',
            source_url='https://leaktest.example.com/app.js',
            match_content='AWS_ACCESS_KEY_ID=AKIA...',
        )

    @patch('reNgine.report_tasks.HTML')
    @patch('reNgine.report_tasks.CSS')
    def _run_report(self, params, mock_css, mock_html):
        mock_html.return_value.write_pdf.return_value = b'%PDF'
        report_obj = ScanReport.objects.create(
            scan_history=self.scan,
            report_type='full',
            report_template='modern',
            params=params,
        )
        generate_report_task(report_obj.id)
        report_obj.refresh_from_db()
        return report_obj

    def test_secret_leaks_included_by_default(self):
        report = self._run_report({'include_secret_findings': True})
        self.assertEqual(report.status, 2)

    def test_secret_leaks_excluded_when_flag_false(self):
        report = self._run_report({'include_secret_findings': False})
        self.assertEqual(report.status, 2)
