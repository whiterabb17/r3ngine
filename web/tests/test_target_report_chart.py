import base64
from django.test import TestCase
from datetime import datetime
from reNgine.charts import generate_severity_trend_chart, generate_findings_timeline_chart
from tests.chart_stubs import MINIMAL_PNG, patch_chart_render, rendered_figure


class SeverityTrendChartTest(TestCase):
    def setUp(self):
        self.trend_data = [
            {'scan_id': 1, 'date': datetime(2026, 6, 1), 'critical': 2, 'high': 3, 'medium': 5, 'low': 1, 'info': 0},
            {'scan_id': 2, 'date': datetime(2026, 6, 15), 'critical': 1, 'high': 2, 'medium': 4, 'low': 2, 'info': 1},
        ]

    @patch_chart_render()
    def test_returns_base64_string(self, mock_to_image):
        result = generate_severity_trend_chart(self.trend_data)
        self.assertIsInstance(result, str)
        self.assertEqual(base64.b64decode(result), MINIMAL_PNG)
        self.assertEqual(mock_to_image.call_args.kwargs, {'format': 'png'})

    @patch_chart_render()
    def test_figure_groups_severities_per_scan(self, mock_to_image):
        generate_severity_trend_chart(self.trend_data)
        fig = rendered_figure(mock_to_image)
        self.assertEqual(fig.layout.barmode, 'group')
        self.assertEqual(
            [trace.name for trace in fig.data],
            ['Critical', 'High', 'Medium', 'Low', 'Info'],
        )
        for trace in fig.data:
            self.assertEqual(list(trace.x), ['2026-06-01', '2026-06-15'])
        self.assertEqual(list(fig.data[0].y), [2, 1])
        self.assertEqual(list(fig.data[4].y), [0, 1])

    @patch_chart_render()
    def test_empty_data_returns_empty_string(self, mock_to_image):
        result = generate_severity_trend_chart([])
        self.assertEqual(result, '')
        mock_to_image.assert_not_called()

    @patch_chart_render()
    def test_single_scan_renders(self, mock_to_image):
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

    @patch_chart_render()
    def test_returns_base64_string(self, mock_to_image):
        result = generate_findings_timeline_chart(self.timeline_data)
        self.assertIsInstance(result, str)
        self.assertEqual(base64.b64decode(result), MINIMAL_PNG)

    @patch_chart_render()
    def test_empty_data_returns_empty_string(self, mock_to_image):
        result = generate_findings_timeline_chart([])
        self.assertEqual(result, '')
        mock_to_image.assert_not_called()

    @patch_chart_render()
    def test_single_entry_returns_empty_string(self, mock_to_image):
        result = generate_findings_timeline_chart([self.timeline_data[0]])
        self.assertEqual(result, '')
        mock_to_image.assert_not_called()

    @patch_chart_render()
    def test_has_three_traces(self, mock_to_image):
        generate_findings_timeline_chart(self.timeline_data)
        fig = rendered_figure(mock_to_image)
        self.assertEqual(len(fig.data), 3)
        self.assertEqual(
            [trace.name for trace in fig.data],
            ['New Findings', 'Resolved', 'Open (Total)'],
        )
        self.assertEqual(list(fig.data[0].x), ['2026-06-01', '2026-06-15', '2026-07-01'])
        self.assertEqual(list(fig.data[1].y), [0, 3, 2])
        self.assertEqual(list(fig.data[2].y), [5, 4, 3])
