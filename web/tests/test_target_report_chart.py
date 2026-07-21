import base64
from django.test import TestCase
from unittest.mock import patch
from datetime import datetime
from reNgine.charts import generate_severity_trend_chart, generate_findings_timeline_chart


class SeverityTrendChartTest(TestCase):
    def setUp(self):
        self.trend_data = [
            {'scan_id': 1, 'date': datetime(2026, 6, 1), 'critical': 2, 'high': 3, 'medium': 5, 'low': 1, 'info': 0},
            {'scan_id': 2, 'date': datetime(2026, 6, 15), 'critical': 1, 'high': 2, 'medium': 4, 'low': 2, 'info': 1},
        ]

    @patch('reNgine.charts.to_image')
    def test_returns_base64_string(self, mock_to_image):
        mock_to_image.return_value = b'fake-png-bytes'
        result = generate_severity_trend_chart(self.trend_data)
        self.assertIsInstance(result, str)
        self.assertEqual(base64.b64decode(result), b'fake-png-bytes')

    def test_empty_data_returns_empty_string(self):
        result = generate_severity_trend_chart([])
        self.assertEqual(result, '')

    @patch('reNgine.charts.to_image')
    def test_single_scan_renders(self, mock_to_image):
        mock_to_image.return_value = b'fake-png-bytes'
        result = generate_severity_trend_chart([self.trend_data[0]])
        self.assertIsInstance(result, str)
        mock_to_image.assert_called_once()


class FindingsTimelineChartTest(TestCase):
    def setUp(self):
        self.timeline_data = [
            {'date': datetime(2026, 6, 1), 'new_findings': 5, 'resolved': 0, 'open_total': 5},
            {'date': datetime(2026, 6, 15), 'new_findings': 2, 'resolved': 3, 'open_total': 4},
            {'date': datetime(2026, 7, 1), 'new_findings': 1, 'resolved': 2, 'open_total': 3},
        ]

    @patch('reNgine.charts.to_image')
    def test_returns_base64_string(self, mock_to_image):
        mock_to_image.return_value = b'fake-png-bytes'
        result = generate_findings_timeline_chart(self.timeline_data)
        self.assertIsInstance(result, str)
        self.assertEqual(base64.b64decode(result), b'fake-png-bytes')

    def test_empty_data_returns_empty_string(self):
        result = generate_findings_timeline_chart([])
        self.assertEqual(result, '')

    def test_single_entry_returns_empty_string(self):
        result = generate_findings_timeline_chart([self.timeline_data[0]])
        self.assertEqual(result, '')

    @patch('reNgine.charts.to_image')
    def test_has_three_traces(self, mock_to_image):
        mock_to_image.return_value = b'fake-png-bytes'
        generate_findings_timeline_chart(self.timeline_data)
        called_fig = mock_to_image.call_args[0][0]
        self.assertEqual(len(called_fig.data), 3)
