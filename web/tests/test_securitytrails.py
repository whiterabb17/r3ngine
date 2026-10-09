"""SecurityTrails subdomain source: API client, vault storage and discovery step."""
import os
import tempfile
from unittest import mock

import requests
from django.contrib.auth import get_user_model
from django.test import TestCase
from rolepermissions.roles import assign_role

from dashboard.models import SecurityTrailsAPIKey
from reNgine.common_func import get_securitytrails_key
from reNgine.osint.securitytrails import (
    SecurityTrailsError,
    fetch_securitytrails_subdomains,
)
from reNgine.tasks.subdomain import _collect_securitytrails_subdomains

_GET = 'reNgine.osint.securitytrails.requests.get'


def _response(status_code=200, payload=None):
    response = mock.Mock(status_code=status_code, ok=200 <= status_code < 300)
    response.json.return_value = payload if payload is not None else {}
    return response


class FetchSecurityTrailsSubdomainsTest(TestCase):

    @mock.patch(_GET)
    def test_labels_become_sorted_unique_fqdns(self, get):
        get.return_value = _response(payload={
            'subdomains': ['www', 'API', 'www', ' mail. ', '', 42],
            'meta': {'limit_reached': False},
        })

        result = fetch_securitytrails_subdomains('example.com', 'st-key')

        self.assertEqual(result, ['api.example.com', 'mail.example.com', 'www.example.com'])
        url = get.call_args.args[0]
        self.assertEqual(url, 'https://api.securitytrails.com/v1/domain/example.com/subdomains')
        self.assertEqual(get.call_args.kwargs['headers']['APIKEY'], 'st-key')

    @mock.patch(_GET)
    def test_truncated_result_is_logged_and_returned(self, get):
        get.return_value = _response(payload={'subdomains': ['a'], 'meta': {'limit_reached': True}})

        with self.assertLogs('reNgine.osint.securitytrails', level='WARNING') as logs:
            result = fetch_securitytrails_subdomains('example.com', 'st-key')

        self.assertEqual(result, ['a.example.com'])
        self.assertIn('truncated', logs.output[0])

    @mock.patch(_GET)
    def test_http_errors_raise_a_safe_message(self, get):
        cases = {
            401: 'rejected the API key',
            403: 'rejected the API key',
            429: 'quota or rate limit exceeded',
            500: 'HTTP 500',
        }
        for status_code, message in cases.items():
            with self.subTest(status_code=status_code):
                get.return_value = _response(status_code=status_code)
                with self.assertRaisesRegex(SecurityTrailsError, message):
                    fetch_securitytrails_subdomains('example.com', 'st-key')

    @mock.patch(_GET, side_effect=requests.ConnectionError('boom st-key'))
    def test_network_error_does_not_leak_details(self, _get):
        with self.assertRaises(SecurityTrailsError) as ctx:
            fetch_securitytrails_subdomains('example.com', 'st-key')
        self.assertEqual(str(ctx.exception), 'SecurityTrails request failed: ConnectionError')

    @mock.patch(_GET)
    def test_rejects_missing_key_and_non_domain_without_a_request(self, get):
        with self.assertRaises(SecurityTrailsError):
            fetch_securitytrails_subdomains('example.com', '')
        with self.assertRaises(SecurityTrailsError):
            fetch_securitytrails_subdomains('example.com/../../account', 'st-key')
        get.assert_not_called()


class CollectSecurityTrailsSubdomainsTest(TestCase):

    def setUp(self):
        tmp = tempfile.TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        self.results_file = os.path.join(tmp.name, 'subdomains_securitytrails.txt')

    @mock.patch(_GET)
    def test_without_a_vault_key_no_query_is_spent(self, get):
        self.assertEqual(_collect_securitytrails_subdomains('example.com', self.results_file), 0)
        get.assert_not_called()
        self.assertFalse(os.path.exists(self.results_file))

    @mock.patch(_GET)
    def test_writes_one_subdomain_per_line(self, get):
        SecurityTrailsAPIKey.objects.create(key='st-key')
        get.return_value = _response(payload={'subdomains': ['www', 'api']})

        count = _collect_securitytrails_subdomains('example.com', self.results_file)

        self.assertEqual(count, 2)
        with open(self.results_file) as f:
            self.assertEqual(f.read(), 'api.example.com\nwww.example.com\n')

    @mock.patch(_GET)
    def test_api_failure_is_logged_and_skipped(self, get):
        SecurityTrailsAPIKey.objects.create(key='st-key')
        get.return_value = _response(status_code=429)

        self.assertEqual(_collect_securitytrails_subdomains('example.com', self.results_file), 0)
        self.assertFalse(os.path.exists(self.results_file))


class SecurityTrailsVaultTest(TestCase):
    URL = '/scanEngine/default/api_vault'

    def setUp(self):
        user = get_user_model().objects.create_user(
            username='vault-admin', password='unused', is_superuser=True,
        )
        assign_role(user, 'sys_admin')
        self.client.force_login(user)

    def test_key_is_saved_returned_and_cleared(self):
        response = self.client.post(
            self.URL, {'key_securitytrails': 'st-key'}, HTTP_ACCEPT='application/json',
        )
        self.assertEqual(response.status_code, 200)
        self.assertEqual(get_securitytrails_key(), 'st-key')

        response = self.client.get(self.URL, HTTP_ACCEPT='application/json')
        self.assertEqual(response.json()['securitytrails_key'], 'st-key')

        self.client.post(self.URL, {'key_securitytrails': ''}, HTTP_ACCEPT='application/json')
        self.assertEqual(get_securitytrails_key(), '')
        self.assertEqual(SecurityTrailsAPIKey.objects.count(), 1)

    def test_other_keys_leave_it_untouched(self):
        SecurityTrailsAPIKey.objects.create(id=1, key='st-key')
        self.client.post(self.URL, {'key_chaos': 'chaos'}, HTTP_ACCEPT='application/json')
        self.assertEqual(get_securitytrails_key(), 'st-key')
