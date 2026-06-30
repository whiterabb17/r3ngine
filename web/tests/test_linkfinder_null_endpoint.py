"""Regression test for null endpoint_id in save_parameter.

save_endpoint() returns (None, False) for off-domain URLs (e.g. CDN links
discovered by LinkFinder). save_parameter must not be called with endpoint=None
because the Parameter model has a NOT NULL FK on endpoint_id.

This test patches save_endpoint to return None and verifies save_parameter
is never called — guarding the fix added to tasks.py:web_api_discovery.
"""
from unittest.mock import patch, MagicMock, call
from django.test import TestCase


class TestLinkFinderNullEndpointGuard(TestCase):
    """save_parameter must never be called when save_endpoint returns None."""

    @patch('reNgine.tasks.save_parameter')
    @patch('reNgine.tasks.save_endpoint', return_value=(None, False))
    @patch('reNgine.tasks.run_command')
    @patch('builtins.open', create=True)
    @patch('os.path.exists', return_value=True)
    @patch('reNgine.tasks.urlparse')
    def test_save_parameter_not_called_when_endpoint_is_none(
        self, mock_urlparse, mock_exists, mock_open, mock_run_cmd,
        mock_save_ep, mock_save_param,
    ):
        """When save_endpoint returns None for an off-domain URL with '?',
        save_parameter must NOT be called."""
        from reNgine.tasks import web_api_discovery
        from io import StringIO

        # Return a URL with '?' so the parameter branch is triggered
        mock_urlparse.return_value = MagicMock(scheme='https', netloc='example.com')
        lf_line = 'https://cdn.react.dev/errors/?code=418\n'
        mock_open.return_value.__enter__ = lambda s: StringIO(lf_line)
        mock_open.return_value.__exit__ = MagicMock(return_value=False)

        proxy = MagicMock()
        proxy.yaml_configuration = {
            'web_api_discovery': {'uses_tools': ['linkfinder']},
        }
        proxy.results_dir = '/tmp/web_api_test'
        proxy.scan_id = 1
        proxy.scan = MagicMock()
        proxy.scan.domain.name = 'example.com'
        proxy.history_file = None
        proxy.activity_id = None
        proxy.activity = None

        ctx = {'scan_history_id': 1, 'domain_name': 'example.com'}

        try:
            web_api_discovery(proxy, urls=['https://example.com'], ctx=ctx)
        except Exception:
            pass

        # The key assertion: save_parameter must never be called with endpoint=None
        for c in mock_save_param.call_args_list:
            endpoint_arg = c[0][0] if c[0] else c[1].get('endpoint')
            self.assertIsNotNone(
                endpoint_arg,
                "save_parameter called with endpoint=None — would cause NOT NULL violation",
            )
