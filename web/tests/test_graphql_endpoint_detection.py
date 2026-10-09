"""A URL that mentions graphql is not a GraphQL endpoint.

A front end that ships its dependency tree serves every file of the graphql
package under a path containing "/graphql". Matching that substring both
switched the GraphQL tooling on for the host and handed graphql-cop the .js
files as targets, which it then reported as "does not seem to be running
GraphQL" — once per file, every scan.
"""
import os

import django
from django.test import TestCase
from django.utils import timezone
from unittest import TestCase as PlainTestCase
from unittest.mock import patch

os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'reNgine.settings')
django.setup()

from reNgine.common_func import has_graphql_endpoint, is_graphql_endpoint_url
from scanEngine.models import EngineType
from startScan.models import EndPoint, ScanHistory
from targetApp.models import Domain


class TestIsGraphqlEndpointUrl(PlainTestCase):
    """Pure URL classification — no database, no network."""

    def test_bare_endpoint(self):
        self.assertTrue(is_graphql_endpoint_url('https://host.example.test/graphql'))

    def test_trailing_slash(self):
        self.assertTrue(is_graphql_endpoint_url('https://host.example.test/graphql/'))

    def test_nested_under_api(self):
        self.assertTrue(is_graphql_endpoint_url('https://host.example.test/api/graphql'))

    def test_graphiql_console(self):
        self.assertTrue(is_graphql_endpoint_url('https://host.example.test/graphiql'))

    def test_query_string_is_still_an_endpoint(self):
        self.assertTrue(
            is_graphql_endpoint_url('https://host.example.test/graphql?query=%7B__schema%7D')
        )

    def test_case_is_ignored(self):
        self.assertTrue(is_graphql_endpoint_url('https://host.example.test/GraphQL'))

    def test_shipped_dependency_file_is_not_an_endpoint(self):
        """The case seen in production."""
        self.assertFalse(
            is_graphql_endpoint_url(
                'https://host.example.test/node_modules/graphql/error/syntaxError.js'
            )
        )

    def test_bundled_script_is_not_an_endpoint(self):
        self.assertFalse(
            is_graphql_endpoint_url('https://host.example.test/static/js/graphql.min.js')
        )

    def test_documentation_page_is_not_an_endpoint(self):
        self.assertFalse(
            is_graphql_endpoint_url('https://host.example.test/docs/graphql/getting-started')
        )

    def test_hyphenated_sibling_path_is_not_an_endpoint(self):
        self.assertFalse(
            is_graphql_endpoint_url('https://host.example.test/graphql-playground/assets/app.js')
        )

    def test_empty_url(self):
        self.assertFalse(is_graphql_endpoint_url(''))


class TestHasGraphqlEndpointDbEvidence(TestCase):
    """The gate's zero-cost database check must apply the same rule."""

    def setUp(self):
        self.domain = Domain.objects.create(name='graphql-gate.example.test')
        self.engine = EngineType.objects.create(
            engine_name='graphql-gate-test-engine',
            yaml_configuration='subdomain_discovery: {}\n',
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            start_scan_date=timezone.now(),
        )

    def _endpoint(self, url):
        return EndPoint.objects.create(
            scan_history=self.scan,
            target_domain=self.domain,
            http_url=url,
        )

    @patch('reNgine.common_func.probe_gates.requests.head')
    def test_dependency_file_does_not_count_as_evidence(self, mock_head):
        """Without the fix this returned True from the database, never probing."""
        import requests as _requests

        self._endpoint(
            'https://host.example.test/node_modules/graphql/error/syntaxError.js'
        )
        # has_graphql_endpoint only swallows RequestException; a bare Exception
        # would escape and look like a regression of the DB filter.
        mock_head.side_effect = _requests.ConnectionError(
            'probe should decide, not the .js file'
        )

        self.assertFalse(
            has_graphql_endpoint(self.scan.id, 'https://host.example.test/')
        )

    @patch('reNgine.common_func.probe_gates.requests.head')
    def test_real_endpoint_counts_as_evidence_without_probing(self, mock_head):
        self._endpoint('https://host.example.test/api/graphql')

        self.assertTrue(
            has_graphql_endpoint(self.scan.id, 'https://host.example.test/')
        )
        mock_head.assert_not_called()
