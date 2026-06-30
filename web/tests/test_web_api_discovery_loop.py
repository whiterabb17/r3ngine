"""Tests for web_api_discovery loop gate-caching and LinkFinder deduplication."""
import inspect
from unittest.mock import patch, MagicMock
from django.test import TestCase


class TestGraphQLGateCaching(TestCase):

    def test_graphql_gate_cache_dict_present_before_loop(self):
        """_graphql_gate_cache must be initialised before the for loop in web_api_discovery."""
        import reNgine.tasks as tasks_mod
        source = inspect.getsource(tasks_mod.web_api_discovery)
        cache_pos = source.find('_graphql_gate_cache')
        loop_pos = source.find('for url, subdomain_name, subdomain in url_subdomain_map')
        self.assertNotEqual(cache_pos, -1, "_graphql_gate_cache not found in web_api_discovery")
        self.assertGreater(
            loop_pos, cache_pos,
            "_graphql_gate_cache must be defined before the per-URL for loop",
        )

    def test_has_graphql_endpoint_not_called_directly_in_inql_block(self):
        """InQL block must not call has_graphql_endpoint() directly — must go via _graphql_gate_cache."""
        import reNgine.tasks as tasks_mod
        source = inspect.getsource(tasks_mod.web_api_discovery)
        inql_start = source.find('# InQL')
        graphql_cop_start = source.find('# graphql-cop')
        self.assertGreater(inql_start, 0, "InQL comment block not found")
        inql_region = source[inql_start:graphql_cop_start]
        # The cache lookup must appear before any direct call
        cache_lookup = inql_region.find('_graphql_gate_cache')
        direct_call = inql_region.find('has_graphql_endpoint(')
        self.assertNotEqual(cache_lookup, -1, "InQL block must reference _graphql_gate_cache")
        # If has_graphql_endpoint is called directly it must only be inside the cache-miss branch
        if direct_call != -1:
            # The direct call must be after the cache lookup (inside the miss branch)
            self.assertGreater(
                direct_call, cache_lookup,
                "InQL block calls has_graphql_endpoint before checking _graphql_gate_cache",
            )

    def test_graphql_cop_block_uses_gate_cache(self):
        """graphql-cop block must reference _graphql_gate_cache."""
        import reNgine.tasks as tasks_mod
        source = inspect.getsource(tasks_mod.web_api_discovery)
        cop_start = source.find('# graphql-cop')
        self.assertGreater(cop_start, 0, "graphql-cop comment block not found")
        jwt_start = source.find('# jwt_tool')
        # graphql-cop comes after jwt_tool in the loop; find the jwt block first
        # to bound the cop region correctly
        semgrep_start = source.find('# Semgrep - Post-discovery')
        cop_region = source[cop_start:semgrep_start]
        self.assertIn('_graphql_gate_cache', cop_region,
                      "graphql-cop block must use _graphql_gate_cache")

    def test_inql_and_graphql_cop_share_same_cache_name(self):
        """Both InQL and graphql-cop must reference the same _graphql_gate_cache dict."""
        import reNgine.tasks as tasks_mod
        source = inspect.getsource(tasks_mod.web_api_discovery)
        # Count occurrences of _graphql_gate_cache — must appear in both blocks
        count = source.count('_graphql_gate_cache')
        self.assertGreaterEqual(count, 4,
            f"_graphql_gate_cache appears only {count} times; expected at least 4 "
            "(init + miss-branch write + InQL lookup + graphql-cop lookup)")


class TestJWTGateCaching(TestCase):

    def test_jwt_gate_cache_dict_present_before_loop(self):
        """_jwt_gate_cache must be initialised before the for loop in web_api_discovery."""
        import reNgine.tasks as tasks_mod
        source = inspect.getsource(tasks_mod.web_api_discovery)
        cache_pos = source.find('_jwt_gate_cache')
        loop_pos = source.find('for url, subdomain_name, subdomain in url_subdomain_map')
        self.assertNotEqual(cache_pos, -1, "_jwt_gate_cache not found in web_api_discovery")
        self.assertGreater(
            loop_pos, cache_pos,
            "_jwt_gate_cache must be defined before the per-URL for loop",
        )

    def test_jwt_tool_block_uses_gate_cache(self):
        """The jwt_tool block must reference _jwt_gate_cache instead of calling has_jwt_tokens directly."""
        import reNgine.tasks as tasks_mod
        source = inspect.getsource(tasks_mod.web_api_discovery)
        jwt_start = source.find('# jwt_tool')
        self.assertGreater(jwt_start, 0, "jwt_tool comment block not found")
        graphql_cop_start = source.find('# graphql-cop')
        jwt_region = source[jwt_start:graphql_cop_start]
        self.assertIn('_jwt_gate_cache', jwt_region,
                      "jwt_tool block must use _jwt_gate_cache")

    def test_has_jwt_tokens_not_called_directly_without_cache_guard(self):
        """has_jwt_tokens must only appear inside the _jwt_gate_cache miss branch."""
        import reNgine.tasks as tasks_mod
        source = inspect.getsource(tasks_mod.web_api_discovery)
        jwt_start = source.find('# jwt_tool')
        graphql_cop_start = source.find('# graphql-cop')
        jwt_region = source[jwt_start:graphql_cop_start]
        cache_lookup = jwt_region.find('_jwt_gate_cache')
        direct_call = jwt_region.find('has_jwt_tokens(')
        self.assertNotEqual(cache_lookup, -1, "jwt_tool block must reference _jwt_gate_cache")
        if direct_call != -1:
            self.assertGreater(
                direct_call, cache_lookup,
                "jwt_tool block calls has_jwt_tokens before checking _jwt_gate_cache",
            )


class TestLinkFinderDeduplication(TestCase):

    def test_processed_linkfinder_subdomains_set_present_before_loop(self):
        """processed_linkfinder_subdomains must be initialised before the for loop."""
        import reNgine.tasks as tasks_mod
        source = inspect.getsource(tasks_mod.web_api_discovery)
        set_pos = source.find('processed_linkfinder_subdomains')
        loop_pos = source.find('for url, subdomain_name, subdomain in url_subdomain_map')
        self.assertNotEqual(set_pos, -1, "processed_linkfinder_subdomains not found in web_api_discovery")
        self.assertGreater(
            loop_pos, set_pos,
            "processed_linkfinder_subdomains must be defined before the per-URL for loop",
        )

    def test_linkfinder_block_checks_processed_set(self):
        """LinkFinder block must guard on processed_linkfinder_subdomains before running."""
        import reNgine.tasks as tasks_mod
        source = inspect.getsource(tasks_mod.web_api_discovery)
        lf_start = source.find('# LinkFinder')
        self.assertGreater(lf_start, 0, "LinkFinder comment block not found")
        inql_start = source.find('# InQL')
        lf_region = source[lf_start:inql_start]
        self.assertIn('processed_linkfinder_subdomains', lf_region,
                      "LinkFinder block must check processed_linkfinder_subdomains")

    def test_linkfinder_uses_exists_not_getsize_as_primary_guard(self):
        """LinkFinder Temporal retry guard must use os.path.exists, not os.path.getsize > 0."""
        import reNgine.tasks as tasks_mod
        source = inspect.getsource(tasks_mod.web_api_discovery)
        lf_start = source.find('# LinkFinder')
        inql_start = source.find('# InQL')
        lf_region = source[lf_start:inql_start]
        # The run/skip decision inside the LinkFinder block must not use getsize as the
        # primary guard (which was the bug — empty file caused re-run).
        # After the fix, processed_linkfinder_subdomains is the primary dedup guard;
        # os.path.exists is the Temporal retry guard; getsize is not used for run/skip.
        run_cmd_pos = lf_region.find('run_command')
        getsize_before_run = lf_region.rfind('getsize', 0, run_cmd_pos)
        self.assertEqual(
            getsize_before_run, -1,
            "os.path.getsize must not guard whether LinkFinder runs (causes re-run on empty output). "
            "Use processed_linkfinder_subdomains + os.path.exists instead.",
        )
