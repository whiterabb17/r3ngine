"""Tests for the processed_* subdomain guards of InQL, jwt_tool and graphql-cop.

web_api_discovery iterates over every discovered URL, so a subdomain with N
URLs used to invoke these three tools N times. Each tool now owns a
``processed_<tool>_subdomains`` set, mirroring the Arjun / ParamSpider /
LinkFinder call sites, so it runs at most once per subdomain per activity
attempt.

All subprocess, network and DB access is mocked.
"""
import inspect
import shutil
import tempfile
from contextlib import ExitStack
from unittest.mock import MagicMock, patch

from django.test import TestCase


def _make_proxy(tools):
    """Build a TemporalTaskProxy stand-in for web_api_discovery."""
    proxy = MagicMock()
    proxy.results_dir = tempfile.mkdtemp(prefix='web_api_discovery_')
    proxy.scan_id = 1
    proxy.activity_id = 'act-1'
    proxy.scan = MagicMock()
    proxy.scan.id = 1
    proxy.domain = MagicMock()
    proxy.yaml_configuration = {'web_api_discovery': {'uses_tools': list(tools)}}
    return proxy


def _run_discovery(tools, urls, graphql_gate=True, jwt_gate=True):
    """Run web_api_discovery with every side effect mocked out.

    Returns (run_command_mock, run_jwt_scan_mock, run_graphql_cop_mock).
    """
    from reNgine.tasks.crawl import web_api_discovery

    proxy = _make_proxy(tools)
    ctx = {'scan_history_id': 1, 'api_discovery_tools': list(tools)}

    with ExitStack() as stack:
        p = stack.enter_context
        # Patched where the names are looked up: crawl.py imports these via
        # `from reNgine.common_func import *`.
        p(patch('reNgine.tasks.crawl.api_discovery.get_http_urls', return_value=[]))
        p(patch('reNgine.tasks.crawl.api_discovery.get_random_proxy', return_value=None))
        p(patch('reNgine.tasks.crawl.api_discovery.has_graphql_endpoint', return_value=graphql_gate))
        p(patch('reNgine.tasks.crawl.api_discovery.has_jwt_tokens', return_value=jwt_gate))
        p(patch('reNgine.tasks.crawl.api_discovery.Neo4jManager'))
        subdomain_filter = p(patch('reNgine.tasks.crawl.api_discovery.Subdomain.objects.filter'))
        subdomain_filter.return_value.first.return_value = MagicMock()
        run_command = p(patch('reNgine.tasks.crawl.api_discovery.run_command', return_value=(0, '')))
        # jwt_tool and graphql-cop are imported inside the loop body from
        # reNgine.tasks.api, so that module is where the name is looked up.
        run_jwt_scan = p(patch('reNgine.tasks.api.run_jwt_scan'))
        run_graphql_cop = p(patch('reNgine.tasks.api.run_graphql_cop'))
        p(patch('reNgine.tasks.auth_discovery.extract_auth_candidates'))

        try:
            web_api_discovery(proxy, urls=list(urls), ctx=ctx)
        finally:
            shutil.rmtree(proxy.results_dir, ignore_errors=True)

    return run_command, run_jwt_scan, run_graphql_cop


def _inql_commands(run_command):
    """Extract the inql command lines issued through run_command."""
    commands = []
    for call in run_command.call_args_list:
        cmd = call[0][0] if call[0] else call[1].get('cmd', '')
        if isinstance(cmd, str) and cmd.startswith('inql '):
            commands.append(cmd)
    return commands


class TestInqlProcessedSubdomainGuard(TestCase):

    def test_inql_skips_subdomain_already_processed(self):
        """Several URLs on one subdomain must produce a single inql invocation."""
        run_command, _, _ = _run_discovery(
            ['inql'],
            [
                'https://api.example.com/v1',
                'https://api.example.com/v2',
                'https://api.example.com/graphql',
            ],
        )
        self.assertEqual(len(_inql_commands(run_command)), 1)

    def test_inql_runs_once_per_new_subdomain(self):
        """A new subdomain is processed and then added to the guard set."""
        run_command, _, _ = _run_discovery(
            ['inql'],
            [
                'https://api.example.com/v1',
                'https://api.example.com/v2',
                'https://shop.example.com/v1',
                'https://shop.example.com/v2',
            ],
        )
        commands = _inql_commands(run_command)
        self.assertEqual(len(commands), 2)
        self.assertTrue(any('api.example.com' in cmd for cmd in commands))
        self.assertTrue(any('shop.example.com' in cmd for cmd in commands))

    def test_inql_not_run_without_targets(self):
        """The guard must not break the empty-input path."""
        run_command, _, _ = _run_discovery(['inql'], [])
        self.assertEqual(_inql_commands(run_command), [])


class TestJwtToolProcessedSubdomainGuard(TestCase):

    def test_jwt_tool_skips_subdomain_already_processed(self):
        """Several URLs on one subdomain must produce a single jwt_tool run."""
        _, run_jwt_scan, _ = _run_discovery(
            ['jwt_tool'],
            [
                'https://api.example.com/login',
                'https://api.example.com/refresh',
                'https://api.example.com/profile',
            ],
        )
        self.assertEqual(run_jwt_scan.call_count, 1)

    def test_jwt_tool_runs_once_per_new_subdomain(self):
        """A new subdomain is processed and then added to the guard set."""
        _, run_jwt_scan, _ = _run_discovery(
            ['jwt_tool'],
            [
                'https://api.example.com/login',
                'https://api.example.com/refresh',
                'https://auth.example.com/login',
                'https://auth.example.com/refresh',
            ],
        )
        self.assertEqual(run_jwt_scan.call_count, 2)

    def test_jwt_tool_not_run_without_targets(self):
        """The guard must not break the empty-input path."""
        _, run_jwt_scan, _ = _run_discovery(['jwt_tool'], [])
        run_jwt_scan.assert_not_called()


class TestGraphqlCopProcessedSubdomainGuard(TestCase):

    def test_graphql_cop_skips_subdomain_already_processed(self):
        """Several URLs on one subdomain must produce a single graphql-cop run."""
        _, _, run_graphql_cop = _run_discovery(
            ['graphql-cop'],
            [
                'https://api.example.com/graphql',
                'https://api.example.com/v1',
                'https://api.example.com/v2',
            ],
        )
        self.assertEqual(run_graphql_cop.call_count, 1)

    def test_graphql_cop_runs_once_per_new_subdomain(self):
        """A new subdomain is processed and then added to the guard set."""
        _, _, run_graphql_cop = _run_discovery(
            ['graphql-cop'],
            [
                'https://api.example.com/graphql',
                'https://api.example.com/v1',
                'https://gql.example.com/graphql',
                'https://gql.example.com/v1',
            ],
        )
        self.assertEqual(run_graphql_cop.call_count, 2)

    def test_graphql_cop_not_run_without_targets(self):
        """The guard must not break the empty-input path."""
        _, _, run_graphql_cop = _run_discovery(['graphql-cop'], [])
        run_graphql_cop.assert_not_called()


class TestProcessedGuardSetsInitialisation(TestCase):
    """The guard sets must live outside the per-URL loop to have any effect."""

    def _source(self):
        from reNgine.tasks.crawl import web_api_discovery
        return inspect.getsource(web_api_discovery)

    def _assert_initialised_before_loop(self, set_name):
        source = self._source()
        set_pos = source.find(f'{set_name} = set()')
        loop_pos = source.find('for url, subdomain_name, subdomain in url_subdomain_map')
        self.assertNotEqual(set_pos, -1, f'{set_name} not initialised in web_api_discovery')
        self.assertGreater(
            loop_pos, set_pos,
            f'{set_name} must be defined before the per-URL for loop',
        )

    def test_processed_inql_subdomains_initialised_before_loop(self):
        self._assert_initialised_before_loop('processed_inql_subdomains')

    def test_processed_jwt_subdomains_initialised_before_loop(self):
        self._assert_initialised_before_loop('processed_jwt_subdomains')

    def test_processed_graphql_cop_subdomains_initialised_before_loop(self):
        self._assert_initialised_before_loop('processed_graphql_cop_subdomains')
