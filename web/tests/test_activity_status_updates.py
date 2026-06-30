"""Tests that activity wrappers correctly update ScanActivity status via _run_task."""
from unittest.mock import patch, MagicMock
from django.test import TestCase


def _make_ctx(scan_id=99):
    return {
        'scan_history_id': scan_id,
        'domain_id': 1,
        'engine_id': 1,
        'domain_name': 'example.com',
        'results_dir': '/tmp/test_results',
    }


class TestRunParamDiscoveryActivityStatus(TestCase):

    def _call(self, ctx, url_to_derive=None, task_raises=None):
        """Call run_param_discovery_activity with mocked internals."""
        from reNgine.temporal_activities import run_param_discovery_activity

        mock_endpoint_qs = MagicMock()
        mock_endpoint_qs.values_list.return_value.first.return_value = url_to_derive

        with patch('temporalio.activity.logger'), \
             patch('temporalio.activity.info', return_value=MagicMock(activity_id='act-1')), \
             patch('startScan.models.EndPoint.objects') as mock_ep, \
             patch('targetApp.models.Domain.objects') as mock_dom, \
             patch('reNgine.temporal.activities._run_task') as mock_run_task, \
             patch('reNgine.temporal.activities.TemporalTaskProxy') as mock_proxy_cls:

            mock_ep.filter.return_value = mock_endpoint_qs
            mock_dom.filter.return_value.first.return_value = None

            mock_proxy = MagicMock()
            mock_proxy_cls.return_value = mock_proxy

            if task_raises:
                mock_run_task.side_effect = task_raises
            else:
                mock_run_task.return_value = True

            run_param_discovery_activity(ctx)

        return mock_proxy, mock_run_task

    def test_calls_run_task_when_urls_available(self):
        """When URLs are found, _run_task must be called (not param_discovery directly)."""
        ctx = _make_ctx()
        _, mock_run_task = self._call(ctx, url_to_derive='https://example.com/')
        mock_run_task.assert_called_once()
        _, kwargs = mock_run_task.call_args
        self.assertEqual(kwargs.get('task_name'), 'param_discovery')

    def test_run_task_receives_derived_urls(self):
        """The derived URLs must be forwarded to _run_task as the 'urls' kwarg."""
        ctx = _make_ctx()
        _, mock_run_task = self._call(ctx, url_to_derive='https://example.com/')
        _, kwargs = mock_run_task.call_args
        self.assertIn('urls', kwargs)
        self.assertEqual(kwargs['urls'], ['https://example.com/'])

    def test_marks_success_on_skip_no_urls(self):
        """When no URLs can be derived, ScanActivity must be marked SUCCESS (not left RUNNING)."""
        ctx = _make_ctx()
        mock_proxy, mock_run_task = self._call(ctx, url_to_derive=None)
        mock_run_task.assert_not_called()
        mock_proxy.update_scan_activity.assert_called_once()
        from reNgine.definitions import SUCCESS_TASK
        mock_proxy.update_scan_activity.assert_called_with(SUCCESS_TASK)

    def test_does_not_call_param_discovery_directly(self):
        """param_discovery must not be called directly — only via _run_task."""
        import inspect
        from reNgine.temporal_activities import run_param_discovery_activity
        source = inspect.getsource(run_param_discovery_activity)
        self.assertNotIn(
            'param_discovery(',
            source,
            "run_param_discovery_activity must not call param_discovery() directly; use _run_task",
        )


class TestRunSearchVulnsActivityStatus(TestCase):

    def test_delegates_to_run_task(self):
        """run_search_vulns_activity must delegate to _run_task, not call search_vulns_scan directly."""
        from reNgine.temporal_activities import run_search_vulns_activity
        ctx = {
            **_make_ctx(),
            'service': 'http',
            'version': '2.4.1',
            'host': '192.0.2.1',
            'port': 80,
            'subdomain_id': 5,
        }

        with patch('temporalio.activity.logger'), \
             patch('temporalio.activity.info', return_value=MagicMock(activity_id='act-2')), \
             patch('reNgine.temporal.activities._run_task') as mock_run_task:

            mock_run_task.return_value = True
            run_search_vulns_activity(ctx)

        mock_run_task.assert_called_once()
        _, kwargs = mock_run_task.call_args
        self.assertEqual(kwargs.get('task_name'), 'search_vulns_scan')

    def test_does_not_call_search_vulns_scan_directly(self):
        """search_vulns_scan must not be called directly — only via _run_task."""
        import inspect
        from reNgine.temporal_activities import run_search_vulns_activity
        source = inspect.getsource(run_search_vulns_activity)
        self.assertNotIn(
            'search_vulns_scan(',
            source,
            "run_search_vulns_activity must not call search_vulns_scan() directly; use _run_task",
        )

    def test_run_task_receives_service_params(self):
        """_run_task must receive service, host, port, version in kwargs."""
        from reNgine.temporal_activities import run_search_vulns_activity
        ctx = {
            **_make_ctx(),
            'service': 'ssh',
            'version': '7.4',
            'host': '10.0.0.1',
            'port': 22,
            'subdomain_id': 3,
        }

        with patch('temporalio.activity.logger'), \
             patch('temporalio.activity.info', return_value=MagicMock(activity_id='act-3')), \
             patch('reNgine.temporal.activities._run_task') as mock_run_task:

            mock_run_task.return_value = True
            run_search_vulns_activity(ctx)

        _, kwargs = mock_run_task.call_args
        self.assertEqual(kwargs.get('service'), 'ssh')
        self.assertEqual(kwargs.get('host'), '10.0.0.1')
        self.assertEqual(kwargs.get('port'), 22)
        self.assertEqual(kwargs.get('version'), '7.4')
