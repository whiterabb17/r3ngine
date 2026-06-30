"""Integration tests verifying cpde_tasks.param_discovery wires all sources."""
from unittest.mock import patch, MagicMock
from django.test import TestCase


class TestParamDiscoveryWiresUrlCollector(TestCase):

    def test_collect_all_called_with_results_dir(self):
        """param_discovery must call url_param_collector.collect_all(results_dir)."""
        from reNgine.tasks.cpde import param_discovery

        ctx = {
            'scan_history_id': 99,
            'results_dir': '/tmp/test_results',
            'domain_id': 1,
            'proxy': None,
        }

        with patch('reNgine.cpde.js_collector.get_js_urls_from_results_dir', return_value=[]), \
             patch('reNgine.cpde.js_collector.download_js_files', return_value=[]), \
             patch('reNgine.cpde.ast_analyzer.extract_from_js_files', return_value=[]), \
             patch('reNgine.tasks.cpde.has_openapi_spec', return_value=False), \
             patch('reNgine.cpde.url_param_collector.collect_all') as mock_collect, \
             patch('reNgine.cpde.correlation_engine.correlate', return_value=[]), \
             patch('reNgine.tasks.cpde.activity_heartbeat_safe'), \
             patch('startScan.models.Domain.objects') as mock_dom, \
             patch('reNgine.tasks.cpde.save_endpoint', return_value=(MagicMock(), True)), \
             patch('reNgine.utils.graph.get_neo4j_driver', return_value=None):

            mock_dom.filter.return_value.first.return_value = None
            mock_collect.return_value = [
                {'name': 'tool_param', 'location': 'query_string', 'data_type': None,
                 'source_url': 'https://example.com/?tool_param=1', 'confidence': 65,
                 'context': 'arjun:GET', 'is_auth_related': False}
            ]

            param_discovery(MagicMock(), urls=['https://example.com/'], ctx=ctx)

        mock_collect.assert_called_once_with('/tmp/test_results')

    def test_tool_findings_passed_to_correlate(self):
        """Tool findings from collect_all must be combined with ast+openapi before correlate()."""
        from reNgine.tasks.cpde import param_discovery
        ctx = {
            'scan_history_id': 99,
            'results_dir': '/tmp/test_results',
            'domain_id': 1,
            'proxy': None,
        }

        tool_finding = {
            'name': 'arjun_param', 'location': 'query_string', 'data_type': None,
            'source_url': 'https://example.com/?arjun_param=val', 'confidence': 75,
            'context': 'arjun:GET', 'is_auth_related': False,
        }

        with patch('reNgine.cpde.js_collector.get_js_urls_from_results_dir', return_value=[]), \
             patch('reNgine.cpde.js_collector.download_js_files', return_value=[]), \
             patch('reNgine.cpde.ast_analyzer.extract_from_js_files', return_value=[]), \
             patch('reNgine.tasks.cpde.has_openapi_spec', return_value=False), \
             patch('reNgine.cpde.url_param_collector.collect_all', return_value=[tool_finding]), \
             patch('reNgine.cpde.correlation_engine.correlate') as mock_correlate, \
             patch('reNgine.tasks.cpde.activity_heartbeat_safe'), \
             patch('startScan.models.Domain.objects') as mock_dom, \
             patch('reNgine.tasks.cpde.save_endpoint', return_value=(MagicMock(), True)), \
             patch('reNgine.utils.graph.get_neo4j_driver', return_value=None):

            mock_dom.filter.return_value.first.return_value = None
            mock_correlate.return_value = []

            param_discovery(MagicMock(), urls=['https://example.com/'], ctx=ctx)

        # correlate() must have been called with a list that contains tool_finding
        assert mock_correlate.called
        positional_args = mock_correlate.call_args[0]
        combined_findings = positional_args[0]
        self.assertIn(tool_finding, combined_findings)

    def test_source_code_imports_url_param_collector(self):
        """cpde_tasks.py must import url_param_collector."""
        import inspect
        import reNgine.tasks.cpde as mod
        source = inspect.getsource(mod)
        self.assertIn('url_param_collector', source)
