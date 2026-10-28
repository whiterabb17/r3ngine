"""Tests for Lighthouse performance benchmarking parser and report context."""

from django.test import TestCase, TransactionTestCase
from django.utils import timezone
from unittest.mock import patch

from reNgine.report_performance import build_performance_context
from reNgine.tasks.performance_benchmark import parse_lighthouse_json
from reNgine.tasks.report import generate_report_task
from startScan.models import (
    EndPoint,
    PerformanceBenchmark,
    ScanHistory,
    ScanReport,
    Subdomain,
)


SAMPLE_LIGHTHOUSE = {
    'fetchTime': '2026-10-28T12:00:00.000Z',
    'finalUrl': 'https://example.com/',
    'categories': {
        'performance': {'score': 0.87, 'title': 'Performance'},
        'accessibility': {'score': 0.92, 'title': 'Accessibility'},
        'best-practices': {'score': 0.75, 'title': 'Best Practices'},
        'seo': {'score': 0.81, 'title': 'SEO'},
    },
    'audits': {
        'first-contentful-paint': {'numericValue': 1200.5, 'displayValue': '1.2 s', 'score': 0.9},
        'largest-contentful-paint': {'numericValue': 2400.0, 'displayValue': '2.4 s', 'score': 0.8},
        'total-blocking-time': {'numericValue': 150.0, 'displayValue': '150 ms', 'score': 0.85},
        'cumulative-layout-shift': {'numericValue': 0.05, 'displayValue': '0.05', 'score': 0.95},
        'speed-index': {'numericValue': 3000.0, 'displayValue': '3.0 s', 'score': 0.8},
        'interactive': {'numericValue': 3500.0, 'displayValue': '3.5 s', 'score': 0.75},
        'server-response-time': {'numericValue': 180.0, 'displayValue': '180 ms', 'score': 0.9},
    },
}


class ParseLighthouseJsonTest(TestCase):
    def test_parses_scores_and_metrics(self):
        parsed = parse_lighthouse_json(SAMPLE_LIGHTHOUSE)
        self.assertEqual(parsed['performance_score'], 87.0)
        self.assertEqual(parsed['accessibility_score'], 92.0)
        self.assertEqual(parsed['best_practices_score'], 75.0)
        self.assertEqual(parsed['seo_score'], 81.0)
        self.assertEqual(parsed['fcp_ms'], 1200.5)
        self.assertEqual(parsed['lcp_ms'], 2400.0)
        self.assertEqual(parsed['tbt_ms'], 150.0)
        self.assertEqual(parsed['cls'], 0.05)
        self.assertEqual(parsed['speed_index_ms'], 3000.0)
        self.assertEqual(parsed['tti_ms'], 3500.0)
        self.assertEqual(parsed['ttfb_ms'], 180.0)
        self.assertIsNone(parsed['error'])
        self.assertIn('categories', parsed['raw_json'])
        self.assertIn('audits', parsed['raw_json'])

    def test_invalid_payload(self):
        parsed = parse_lighthouse_json(None)
        self.assertEqual(parsed['raw_json'], {})
        self.assertIn('Invalid', parsed['error'])


class PerformanceReportContextTest(TransactionTestCase):
    def setUp(self):
        from scanEngine.models import EngineType, OpSec, Proxy
        from targetApp.models import Domain as TargetDomain
        from dashboard.models import Project
        from tests.chart_stubs import patch_chart_render

        patcher = patch_chart_render()
        patcher.start()
        self.addCleanup(patcher.stop)

        OpSec.objects.get_or_create(id=1)
        Proxy.objects.get_or_create(id=1)
        self.project = Project.objects.create(
            name='perf-rpt-proj',
            slug='perf-rpt-proj',
            insert_date=timezone.now(),
        )
        self.domain = TargetDomain.objects.create(
            name='perf.example.com', project=self.project, insert_date=timezone.now()
        )
        self.engine = EngineType.objects.create(engine_name='Perf Engine')
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_status=2,
            start_scan_date=timezone.now(),
            scan_type=self.engine,
        )
        self.sub = Subdomain.objects.create(
            name='perf.example.com',
            scan_history=self.scan,
            target_domain=self.domain,
            http_url='https://perf.example.com/',
            http_status=200,
            response_time=0.25,
        )
        self.endpoint = EndPoint.objects.create(
            scan_history=self.scan,
            target_domain=self.domain,
            subdomain=self.sub,
            http_url='https://perf.example.com/',
            http_status=200,
            response_time=0.4,
            is_default=True,
        )
        parsed = parse_lighthouse_json(SAMPLE_LIGHTHOUSE)
        PerformanceBenchmark.objects.create(
            scan_history=self.scan,
            subdomain=self.sub,
            endpoint=self.endpoint,
            http_url=self.endpoint.http_url,
            **{k: parsed[k] for k in (
                'performance_score', 'accessibility_score', 'best_practices_score',
                'seo_score', 'fcp_ms', 'lcp_ms', 'tbt_ms', 'cls',
                'speed_index_ms', 'tti_ms', 'ttfb_ms', 'raw_json', 'error',
            )},
        )

    def test_build_performance_context(self):
        ctx = build_performance_context(self.scan)
        self.assertTrue(ctx['has_benchmarks'])
        self.assertEqual(ctx['success_count'], 1)
        self.assertEqual(ctx['avg_performance_score'], 87.0)
        self.assertEqual(ctx['avg_lcp_ms'], 2400.0)
        self.assertEqual(ctx['probe_latency']['count'], 1)
        self.assertAlmostEqual(ctx['probe_latency']['avg_ms'], 400.0)
        self.assertEqual(len(ctx['rows']), 1)

    @patch('reNgine.tasks.report.HTML')
    @patch('reNgine.tasks.report.CSS')
    def test_report_includes_performance_section_when_flag_set(self, mock_css, mock_html):
        mock_html.return_value.write_pdf.return_value = b'%PDF'
        report = ScanReport.objects.create(
            scan_history=self.scan,
            report_type='full',
            report_template='modern',
            params={'include_performance_benchmarking': True},
        )
        generate_report_task(report.id)
        report.refresh_from_db()
        self.assertEqual(report.status, 2)
        rendered = mock_html.call_args[1]['string']
        self.assertIn('Performance Benchmarking', rendered)
        self.assertIn('Lighthouse Results', rendered)

    @patch('reNgine.tasks.report.HTML')
    @patch('reNgine.tasks.report.CSS')
    def test_report_omits_performance_section_when_flag_unset(self, mock_css, mock_html):
        mock_html.return_value.write_pdf.return_value = b'%PDF'
        report = ScanReport.objects.create(
            scan_history=self.scan,
            report_type='full',
            report_template='modern',
            params={},
        )
        generate_report_task(report.id)
        report.refresh_from_db()
        self.assertEqual(report.status, 2)
        rendered = mock_html.call_args[1]['string']
        self.assertNotIn('Performance Benchmarking', rendered)
