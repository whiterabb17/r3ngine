"""
Integration tests for Phase 2 - Enhanced Stress Report Generation.
Tests report builder, chart generation, and full PDF report pipeline.
"""
import os
import base64
import json
from datetime import timedelta
from unittest.mock import patch
from django.test import TestCase, Client
from django.utils import timezone
from django.contrib.auth.models import User
from startScan.models import (
    ScanHistory, Domain, StressTestResult, StressTelemetryPoint,
    StressToolConfiguration, EndPoint, ScanReport
)
from scanEngine.models import EngineType
from reNgine.stress.report_builder import StressReportBuilder
from reNgine.charts import (
    generate_stress_latency_distribution_chart,
    generate_stress_response_code_chart,
    generate_stress_error_breakdown_chart,
    generate_stress_endpoint_heatmap
)
from tests.chart_stubs import MINIMAL_PNG, patch_chart_render, rendered_figure


class StressReportBuilderTestCase(TestCase):
    """Test the StressReportBuilder class."""

    def setUp(self):
        """Create test data."""
        self.user = User.objects.create_user(username='testuser', password='pass123')

        self.domain = Domain.objects.create(
            name='example.com',
            description='Test domain'
        )

        self.engine = EngineType.objects.create(engine_name='quick_scan')
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            start_scan_date=timezone.now(),
            scan_status=2,
            initiated_by=self.user
        )

        self.stress_result = StressTestResult.objects.create(
            scan_history=self.scan,
            target_domain=self.domain,
            tool_used='k6',
            concurrency_used=50,
            duration='30s',
            total_requests=10000,
            successful_requests=9800,
            failed_requests=200,
            avg_latency_ms=150.5,
            p50_latency_ms=100.0,
            p75_latency_ms=120.0,
            p90_latency_ms=180.0,
            p95_latency_ms=250.0,
            p99_latency_ms=500.0,
            p999_latency_ms=750.0,
            max_requests_per_second=500.0,
            peak_throughput_rps=450.0,
            start_time=timezone.now(),
            end_time=timezone.now() + timedelta(seconds=30),
            endpoints_tested=['http://example.com/', 'http://example.com/api'],
            response_code_distribution={
                '200': 8000,
                '301': 500,
                '404': 1000,
                '500': 200,
            },
            error_breakdown={
                'timeout': 100,
                'connection_refused': 50,
                'tls_error': 30,
            },
            max_concurrent_connections=50,
            test_status='success',
            findings='Latency variance detected. P99 is 3.3x higher than average.',
            anomalies_detected=['high_p99_latency', 'elevated_error_rate'],
            recommendations='Implement caching. Optimize database queries. Scale application servers.',
            is_kill_switch_triggered=False
        )

        self.tool_config = StressToolConfiguration.objects.create(
            stress_result=self.stress_result,
            tool_configs={
                'vus': 50,
                'duration': '30s',
                'rps': None,
                'timeout': '30s'
            }
        )

        # Create telemetry points
        for i in range(10):
            StressTelemetryPoint.objects.create(
                stress_result=self.stress_result,
                tool='k6',
                timestamp=timezone.now() + timedelta(seconds=i*3),
                latency_ms=150.0 + (i * 10),
                throughput=450.0 - (i * 5),
                error_rate=0.02,
                request_count=1000 + (i * 100),
                error_count=20 + (i * 2),
                tool_specific_metrics={
                    'rps': 450.0 - (i * 5),
                    'error_count': 20 + (i * 2),
                }
            )

    def test_stress_report_builder_initialization(self):
        """Test that builder initializes with stress result."""
        builder = StressReportBuilder(self.stress_result)
        self.assertIsNotNone(builder)
        self.assertEqual(builder.stress_result, self.stress_result)

    def test_build_test_metadata(self):
        """Test building test metadata section."""
        builder = StressReportBuilder(self.stress_result)
        metadata = builder._build_test_metadata()

        self.assertEqual(metadata['tool_used'], 'k6')
        self.assertEqual(metadata['tool_display_name'], 'K6')
        self.assertEqual(metadata['concurrency_level'], 50)
        self.assertEqual(metadata['endpoints_tested_count'], 2)
        self.assertEqual(metadata['duration'], '30s')

    def test_build_performance_summary(self):
        """Test building performance summary KPI cards."""
        builder = StressReportBuilder(self.stress_result)
        summary = builder._build_performance_summary()

        self.assertEqual(summary['total_requests'], 10000)
        self.assertEqual(summary['successful_requests'], 9800)
        self.assertEqual(summary['failed_requests'], 200)
        self.assertAlmostEqual(summary['success_rate_percent'], 98.0)
        self.assertAlmostEqual(summary['error_rate_percent'], 2.0)
        self.assertEqual(summary['avg_latency_ms'], 150.5)

    def test_build_tool_specific_section(self):
        """Test building tool-specific section."""
        builder = StressReportBuilder(self.stress_result)
        tool_section = builder._build_tool_specific_section('k6', [])

        self.assertEqual(tool_section['tool'], 'k6')
        self.assertIn('k6_specific', tool_section)
        self.assertIn('status_code_distribution', tool_section['k6_specific'])
        self.assertIn('error_breakdown', tool_section['k6_specific'])

    def test_build_endpoint_analysis(self):
        """Test building endpoint analysis section."""
        builder = StressReportBuilder(self.stress_result)
        endpoint_analysis = builder._build_endpoint_analysis()

        self.assertEqual(endpoint_analysis['endpoint_count'], 2)
        self.assertEqual(len(endpoint_analysis['endpoints']), 2)

    def test_build_findings_and_recommendations(self):
        """Test building findings and recommendations section."""
        builder = StressReportBuilder(self.stress_result)
        findings = builder._build_findings_recommendations()

        self.assertIn('findings', findings)
        self.assertIn('anomalies', findings)
        self.assertIn('recommendations', findings)
        self.assertEqual(len(findings['findings_list']), 1)
        self.assertEqual(len(findings['anomalies']), 2)

    def test_build_timeline_data(self):
        """Test building timeline/time-series data."""
        builder = StressReportBuilder(self.stress_result)
        timeline = builder._build_timeline_data()

        self.assertIn('latency_over_time', timeline)
        self.assertIn('throughput_over_time', timeline)
        self.assertIn('error_rate_over_time', timeline)
        self.assertGreater(len(timeline['latency_over_time']), 0)

    def test_build_full_context(self):
        """Test building complete report context."""
        builder = StressReportBuilder(self.stress_result)
        context = builder.build()

        required_keys = [
            'test_metadata', 'performance_summary', 'tool_sections',
            'endpoint_analysis', 'findings_and_recommendations', 'timeline_data'
        ]
        for key in required_keys:
            self.assertIn(key, context)


class StressChartGenerationTestCase(TestCase):
    """Test chart generation functions."""

    def setUp(self):
        """Create test data."""
        self.domain = Domain.objects.create(name='example.com')
        self.engine = EngineType.objects.create(engine_name='quick_scan')
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            start_scan_date=timezone.now()
        )

        self.stress_result = StressTestResult.objects.create(
            scan_history=self.scan,
            target_domain=self.domain,
            tool_used='k6',
            concurrency_used=50,
            duration='30s',
            total_requests=10000,
            successful_requests=9800,
            failed_requests=200,
            avg_latency_ms=150.0,
            p50_latency_ms=100.0,
            p75_latency_ms=120.0,
            p90_latency_ms=180.0,
            p95_latency_ms=250.0,
            p99_latency_ms=500.0,
            p999_latency_ms=750.0,
            max_requests_per_second=500.0,
            peak_throughput_rps=450.0,
            endpoints_tested=['http://example.com/'],
            response_code_distribution={
                '200': 8000,
                '301': 500,
                '404': 1000,
                '500': 200,
            },
            error_breakdown={
                'timeout': 100,
                'connection_refused': 50,
            },
            test_status='success'
        )

    def assertIsStubPng(self, chart_base64):
        """The helper returns the renderer's PNG bytes, base64-encoded for the template."""
        self.assertIsInstance(chart_base64, str)
        self.assertTrue(chart_base64.startswith('iVBOR'))  # PNG magic number in base64
        self.assertEqual(base64.b64decode(chart_base64), MINIMAL_PNG)

    @patch_chart_render()
    def test_latency_distribution_chart_generation(self, mock_to_image):
        """Latency distribution: one bar per percentile, rendered as PNG."""
        chart_base64 = generate_stress_latency_distribution_chart(self.stress_result)

        self.assertIsStubPng(chart_base64)
        mock_to_image.assert_called_once()
        self.assertEqual(mock_to_image.call_args.kwargs, {'format': 'png'})
        fig = rendered_figure(mock_to_image)
        self.assertEqual(len(fig.data), 1)
        bar = fig.data[0]
        self.assertEqual(bar.type, 'bar')
        self.assertEqual(list(bar.x), ['P50', 'P75', 'P90', 'P95', 'P99', 'P999', 'Avg'])
        self.assertEqual(list(bar.y), [100.0, 120.0, 180.0, 250.0, 500.0, 750.0, 150.0])
        self.assertEqual(fig.layout.title.text, 'Latency Distribution (ms)')

    @patch_chart_render()
    def test_response_code_chart_generation(self, mock_to_image):
        """Response codes: pie sorted by count, with count and share in the labels."""
        chart_base64 = generate_stress_response_code_chart(self.stress_result.response_code_distribution)

        self.assertIsStubPng(chart_base64)
        fig = rendered_figure(mock_to_image)
        pie = fig.data[0]
        self.assertEqual(pie.type, 'pie')
        self.assertEqual(list(pie.labels), ['200', '404', '301', '500'])
        self.assertEqual(list(pie.values), [8000, 1000, 500, 200])
        self.assertEqual(pie.text[0], '200<br>8000<br>(82.5%)')
        self.assertEqual(fig.layout.title.text, 'Response Code Distribution')

    @patch_chart_render()
    def test_error_breakdown_chart_generation(self, mock_to_image):
        """Error breakdown: one bar per error type, coloured by type."""
        chart_base64 = generate_stress_error_breakdown_chart(self.stress_result.error_breakdown)

        self.assertIsStubPng(chart_base64)
        bar = rendered_figure(mock_to_image).data[0]
        self.assertEqual(list(bar.x), ['timeout', 'connection_refused'])
        self.assertEqual(list(bar.y), [100, 50])
        self.assertEqual(list(bar.marker.color), ['#FF4D6A', '#FF9F43'])

    @patch_chart_render()
    def test_endpoint_heatmap_generation(self, mock_to_image):
        """Endpoint heatmap: one row per endpoint, columns are status classes."""
        chart_base64 = generate_stress_endpoint_heatmap(
            self.stress_result.endpoints_tested,
            self.stress_result.response_code_distribution
        )

        self.assertIsStubPng(chart_base64)
        heatmap = rendered_figure(mock_to_image).data[0]
        self.assertEqual(heatmap.type, 'heatmap')
        self.assertEqual(list(heatmap.y), ['http://example.com/'])
        self.assertEqual(
            list(heatmap.x),
            ['2xx Success', '3xx Redirect', '4xx Client Error', '5xx Server Error'],
        )
        self.assertEqual([list(row) for row in heatmap.z], [[8000, 500, 1000, 200]])

    @patch_chart_render()
    def test_chart_with_empty_data(self, mock_to_image):
        """Test chart generation with empty data returns None gracefully."""
        result = generate_stress_response_code_chart({})
        self.assertIsNone(result)

        result = generate_stress_error_breakdown_chart({})
        self.assertIsNone(result)

        result = generate_stress_endpoint_heatmap([], {})
        self.assertIsNone(result)
        mock_to_image.assert_not_called()


class StressReportGenerationAPITestCase(TestCase):
    """Test the stress report generation API endpoint."""

    def setUp(self):
        """Create test data and client."""
        self.client = Client()
        self.user = User.objects.create_user(username='testuser', password='pass123')
        self.domain = Domain.objects.create(name='example.com')
        self.engine = EngineType.objects.create(engine_name='quick_scan')
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            start_scan_date=timezone.now(),
            initiated_by=self.user
        )

        self.stress_result = StressTestResult.objects.create(
            scan_history=self.scan,
            target_domain=self.domain,
            tool_used='k6',
            concurrency_used=50,
            duration='30s',
            total_requests=10000,
            successful_requests=9800,
            failed_requests=200,
            avg_latency_ms=150.0,
            p50_latency_ms=100.0,
            p75_latency_ms=120.0,
            p90_latency_ms=180.0,
            p95_latency_ms=250.0,
            p99_latency_ms=500.0,
            p999_latency_ms=750.0,
            max_requests_per_second=500.0,
            endpoints_tested=['http://example.com/'],
            response_code_distribution={'200': 8000, '404': 1000},
            error_breakdown={},
            test_status='success'
        )

    @patch('reNgine.stress.views.threading.Thread')
    def test_stress_report_api_initiation(self, mock_thread):
        """Test that report generation API initiates correctly."""
        from reNgine.tasks.report import generate_report_task

        self.client.force_login(self.user)

        response = self.client.post(
            f'/api/stress/{self.scan.id}/report/',
            data={
                'report_template': 'stress_modern',
                'include_endpoints': True,
                'include_timeline': True
            },
            content_type='application/json'
        )

        self.assertEqual(response.status_code, 201)
        data = json.loads(response.content)
        self.assertTrue(data['status'])
        self.assertIn('report_id', data)
        # Rendering (PDF + kaleido charts) runs in the background thread; the
        # API only has to hand it the new report.
        mock_thread.assert_called_once_with(
            target=generate_report_task, args=(data['report_id'],), daemon=True,
        )
        mock_thread.return_value.start.assert_called_once_with()

    def test_stress_report_api_status_check(self):
        """Test that report status can be checked."""
        self.client.force_login(self.user)

        # Create a report
        report = ScanReport.objects.create(
            scan_history=self.scan,
            report_type='stress_test',
            report_template='stress_modern',
            status=-1
        )

        # Check status
        response = self.client.get(
            f'/api/stress/{self.scan.id}/report/',
            {'report_id': report.id}
        )

        self.assertEqual(response.status_code, 200)
        data = json.loads(response.content)
        self.assertEqual(data['status'], -1)


class StressReportTemplateTestCase(TestCase):
    """Test that stress report templates render without errors."""

    def test_stress_modern_template_context(self):
        """Test that stress_modern template has required context."""
        from django.template import Template, Context

        domain = Domain.objects.create(name='example.com')
        engine = EngineType.objects.create(engine_name='quick_scan')
        scan = ScanHistory.objects.create(
            domain=domain,
            scan_type=engine,
            start_scan_date=timezone.now()
        )

        stress_result = StressTestResult.objects.create(
            scan_history=scan,
            target_domain=domain,
            tool_used='k6',
            concurrency_used=50,
            total_requests=10000,
            successful_requests=9800,
            failed_requests=200,
            avg_latency_ms=150.0,
            p95_latency_ms=250.0,
            p99_latency_ms=500.0,
            max_requests_per_second=500.0,
            test_status='success'
        )

        builder = StressReportBuilder(stress_result)
        context = builder.build()

        # Verify all required context keys for template
        self.assertIn('test_metadata', context)
        self.assertIn('performance_summary', context)
        self.assertIn('tool_sections', context)

    def test_stress_cyber_pro_template_context(self):
        """Test that stress_cyber_pro template has required context."""
        domain = Domain.objects.create(name='example.com')
        engine = EngineType.objects.create(engine_name='quick_scan')
        scan = ScanHistory.objects.create(
            domain=domain,
            scan_type=engine,
            start_scan_date=timezone.now()
        )

        stress_result = StressTestResult.objects.create(
            scan_history=scan,
            target_domain=domain,
            tool_used='wrk',
            concurrency_used=100,
            total_requests=50000,
            successful_requests=49000,
            failed_requests=1000,
            avg_latency_ms=200.0,
            p95_latency_ms=350.0,
            p99_latency_ms=600.0,
            max_requests_per_second=1000.0,
            test_status='success'
        )

        builder = StressReportBuilder(stress_result)
        context = builder.build()

        # Verify template context
        self.assertIn('test_metadata', context)
        self.assertIsInstance(context['performance_summary'], dict)
