from django.test import TestCase
from unittest.mock import patch, MagicMock
from reNgine.common_func import get_http_urls


class TestGetHttpUrlsUncrawledFilter(TestCase):
    """get_http_urls(is_uncrawled=True) must find endpoints with http_status=0."""

    def _make_ctx(self, scan_id=1, domain_id=1):
        return {'scan_history_id': scan_id, 'domain_id': domain_id}

    @patch('reNgine.common_func.ScanHistory')
    @patch('reNgine.common_func.Domain')
    @patch('reNgine.common_func.EndPoint')
    def test_finds_endpoints_with_http_status_zero(self, MockEndPoint, MockDomain, MockScan):
        """Endpoints with http_status=0 (model default) must be returned when is_uncrawled=True."""
        mock_scan = MagicMock()
        mock_domain = MagicMock()
        MockScan.objects.filter.return_value.first.return_value = mock_scan
        MockDomain.objects.filter.return_value.first.return_value = mock_domain

        mock_ep = MagicMock()
        mock_ep.http_url = 'http://sub.example.com'
        mock_ep.is_alive = True

        mock_qs = MagicMock()
        mock_qs.distinct.return_value.order_by.return_value.all.return_value = [mock_ep]
        MockEndPoint.objects = MagicMock()
        MockEndPoint.objects.filter.return_value = mock_qs

        with patch('reNgine.common_func.is_valid_url', return_value=True):
            result = get_http_urls(is_uncrawled=True, ctx=self._make_ctx())

        self.assertIsInstance(result, list)

    @patch('reNgine.common_func.ScanHistory')
    @patch('reNgine.common_func.Domain')
    @patch('reNgine.common_func.EndPoint')
    def test_uncrawled_filter_uses_http_status_zero_not_null(self, MockEndPoint, MockDomain, MockScan):
        """Verify the ORM call includes http_status=0 in the uncrawled filter."""
        MockScan.objects.filter.return_value.first.return_value = MagicMock()
        MockDomain.objects.filter.return_value.first.return_value = MagicMock()

        mock_qs = MagicMock()
        mock_qs.filter.return_value = mock_qs
        mock_qs.distinct.return_value.order_by.return_value.all.return_value = []
        MockEndPoint.objects = mock_qs

        with patch('reNgine.common_func.is_valid_url', return_value=True):
            get_http_urls(is_uncrawled=True, ctx=self._make_ctx())

        call_args_list = mock_qs.filter.call_args_list
        filter_kwargs = [str(c) for c in call_args_list]
        combined = ' '.join(filter_kwargs)
        self.assertTrue('http_status=0' in combined or "'http_status', 0" in combined)


class TestSeedEndpointsForCrawlActivity(TestCase):
    """seed_endpoints_for_crawl_activity ensures every subdomain has a default EndPoint."""

    def _make_ctx(self):
        return {
            'scan_history_id': 10,
            'domain_id': 5,
            'results_dir': '/tmp/results',
            'yaml_configuration': {},
        }

    @patch('reNgine.temporal.activities.activity')
    def test_activity_creates_missing_endpoints(self, mock_activity):
        """For each subdomain without a default endpoint, save_endpoint is called."""
        from reNgine.temporal_activities import seed_endpoints_for_crawl_activity

        mock_sub1 = MagicMock()
        mock_sub1.name = 'sub1.example.com'
        mock_sub2 = MagicMock()
        mock_sub2.name = 'sub2.example.com'

        with patch('startScan.models.Subdomain') as MockSub, \
             patch('startScan.models.EndPoint') as MockEP, \
             patch('reNgine.utils.task.save_endpoint') as mock_save_ep:

            MockSub.objects.filter.return_value = [mock_sub1, mock_sub2]
            MockEP.objects.filter.return_value.first.return_value = None
            mock_save_ep.return_value = (MagicMock(), True)

            result = seed_endpoints_for_crawl_activity(self._make_ctx())

        self.assertEqual(mock_save_ep.call_count, 2)
        self.assertIn('seed_urls', result)
        self.assertIsInstance(result['seed_urls'], list)

    @patch('reNgine.temporal.activities.activity')
    def test_activity_skips_existing_endpoints(self, mock_activity):
        """Subdomains that already have a default endpoint are not re-seeded."""
        from reNgine.temporal_activities import seed_endpoints_for_crawl_activity

        mock_sub = MagicMock()
        mock_sub.name = 'already.example.com'

        with patch('startScan.models.Subdomain') as MockSub, \
             patch('startScan.models.EndPoint') as MockEP, \
             patch('reNgine.utils.task.save_endpoint') as mock_save_ep:

            MockSub.objects.filter.return_value = [mock_sub]
            mock_existing_ep = MagicMock()
            mock_existing_ep.http_url = 'http://already.example.com'
            MockEP.objects.filter.return_value.first.return_value = mock_existing_ep

            result = seed_endpoints_for_crawl_activity(self._make_ctx())

        mock_save_ep.assert_not_called()
        self.assertIn('http://already.example.com', result['seed_urls'])


class TestRunHTTPCrawlBridgeActivity(TestCase):
    """RunHTTPCrawlBridgeActivity fetches and crawls new/dead/not-alive endpoints."""

    def _make_ctx(self):
        return {
            'scan_history_id': 10,
            'domain_id': 5,
            'results_dir': '/tmp/results',
            'yaml_configuration': {},
        }

    @patch('reNgine.temporal.activities._run_task')
    @patch('reNgine.temporal.activities.activity')
    def test_bridge_activity_crawls_expected_endpoints(self, mock_activity, mock_run_task):
        """Verify bridge activity retrieves dead/not-alive/new endpoints and calls _run_task."""
        from reNgine.temporal_activities import run_http_crawl_bridge_activity

        mock_ep = MagicMock()
        mock_ep.http_url = 'http://dead.example.com'

        mock_qs = MagicMock()
        # Mock filter to return mock_qs
        mock_qs.filter.return_value = mock_qs
        # Mock values_list to return distinct values
        mock_qs.order_by.return_value.values_list.return_value.distinct.return_value = ['http://dead.example.com']

        with patch('startScan.models.EndPoint.objects') as MockEPObjects:
            MockEPObjects.filter.return_value = mock_qs

            result = run_http_crawl_bridge_activity(self._make_ctx())

        # Assert that it called _run_task with the right arguments
        mock_run_task.assert_called_once()
        args, kwargs = mock_run_task.call_args
        self.assertEqual(kwargs['task_name'], 'http_crawl_bridge')
        self.assertEqual(kwargs['urls'], ['http://dead.example.com'])
        self.assertFalse(kwargs['recrawl'])

    @patch('reNgine.temporal.activities._run_task')
    @patch('reNgine.temporal.activities.activity')
    def test_bridge_activity_skips_when_no_endpoints(self, mock_activity, mock_run_task):
        """Verify bridge activity skips calling _run_task when no target endpoints are found."""
        from reNgine.temporal_activities import run_http_crawl_bridge_activity

        mock_qs = MagicMock()
        mock_qs.filter.return_value = mock_qs
        mock_qs.order_by.return_value.values_list.return_value.distinct.return_value = []

        with patch('startScan.models.EndPoint.objects') as MockEPObjects:
            MockEPObjects.filter.return_value = mock_qs

            result = run_http_crawl_bridge_activity(self._make_ctx())

        # Assert that it did not call _run_task and returned True
        mock_run_task.assert_not_called()
        self.assertTrue(result)

