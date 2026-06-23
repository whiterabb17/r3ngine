# web/tests/test_auth_discovery_tasks.py
import requests as req
import unittest
from unittest.mock import patch, MagicMock
from django.test import TestCase
from django.utils import timezone

from startScan.models import ScanHistory, EndPoint, Subdomain, AuthCandidate
from targetApp.models import Domain
from scanEngine.models import EngineType
from reNgine.definitions import RUNNING_TASK


# ---------------------------------------------------------------------------
# HTML fixtures used across test classes
# ---------------------------------------------------------------------------

SIMPLE_LOGIN_FORM = """
<html><body>
<form action="/login" method="POST">
    <input type="text" name="username">
    <input type="password" name="password">
    <input type="hidden" name="_csrf_token" value="abc123">
    <button type="submit">Login</button>
</form>
</body></html>
"""

UNQUOTED_PASSWORD_FORM = """
<html><body>
<form action="/auth" method="post">
    <input type=text name=user>
    <input type=password name=pass>
</form>
</body></html>
"""

NO_PASSWORD_FORM = """
<html><body>
<form action="/search" method="GET">
    <input type="text" name="q">
    <button>Search</button>
</form>
</body></html>
"""

MULTIPLE_FORMS = """
<html><body>
<form action="/search" method="GET">
    <input type="text" name="q">
</form>
<form action="/wp-login.php" method="POST">
    <input type="text" name="log">
    <input type="password" name="pwd">
    <input type="hidden" name="_wpnonce" value="xyz">
</form>
</body></html>
"""

AUTOCOMPLETE_PASSWORD_FORM = """
<html><body>
<form action="/login" method="POST">
    <input type="email" name="email">
    <input type="text" name="token" autocomplete="current-password">
</form>
</body></html>
"""


class TestFetchWithProxyRetry(TestCase):
    """Tests for the _fetch_with_proxy_retry helper."""

    @patch('reNgine.auth_discovery_tasks.requests.get')
    def test_uses_first_proxy_when_it_works(self, mock_get):
        mock_get.return_value = MagicMock(status_code=200, text='<html/>')
        from reNgine.auth_discovery_tasks import _fetch_with_proxy_retry
        response, used_proxy = _fetch_with_proxy_retry(
            'http://example.com', ['http://p1:8080', 'http://p2:8080']
        )
        self.assertEqual(mock_get.call_count, 1)
        self.assertEqual(used_proxy, 'http://p1:8080')

    @patch('reNgine.auth_discovery_tasks.requests.get')
    def test_falls_back_to_second_proxy_on_first_failure(self, mock_get):
        mock_get.side_effect = [
            req.exceptions.ProxyError("p1 down"),
            MagicMock(status_code=200, text='<html/>'),
        ]
        from reNgine.auth_discovery_tasks import _fetch_with_proxy_retry
        response, used_proxy = _fetch_with_proxy_retry(
            'http://example.com', ['http://p1:8080', 'http://p2:8080']
        )
        self.assertEqual(mock_get.call_count, 2)
        self.assertEqual(used_proxy, 'http://p2:8080')

    @patch('reNgine.auth_discovery_tasks.requests.get')
    def test_falls_back_to_direct_when_all_three_proxies_fail(self, mock_get):
        mock_get.side_effect = [
            req.exceptions.ProxyError("p1"),
            req.exceptions.ProxyError("p2"),
            req.exceptions.ProxyError("p3"),
            MagicMock(status_code=200, text='<html/>'),  # 4th: direct
        ]
        from reNgine.auth_discovery_tasks import _fetch_with_proxy_retry
        response, used_proxy = _fetch_with_proxy_retry(
            'http://example.com',
            ['http://p1:8080', 'http://p2:8080', 'http://p3:8080'],
        )
        self.assertEqual(mock_get.call_count, 4)
        self.assertIsNone(used_proxy)

    @patch('reNgine.auth_discovery_tasks.requests.get')
    def test_raises_when_all_attempts_fail_including_direct(self, mock_get):
        mock_get.side_effect = req.exceptions.ConnectionError("all down")
        from reNgine.auth_discovery_tasks import _fetch_with_proxy_retry
        with self.assertRaises(req.exceptions.ConnectionError):
            _fetch_with_proxy_retry('http://example.com', ['http://p1:8080'])

    @patch('reNgine.auth_discovery_tasks.requests.get')
    def test_direct_connection_when_no_proxies_configured(self, mock_get):
        mock_get.return_value = MagicMock(status_code=200, text='<html/>')
        from reNgine.auth_discovery_tasks import _fetch_with_proxy_retry
        response, used_proxy = _fetch_with_proxy_retry('http://example.com', [])
        mock_get.assert_called_once()
        call_kwargs = mock_get.call_args
        # proxies argument should be None for direct connection
        passed_proxies = call_kwargs[1].get('proxies') if call_kwargs[1] else call_kwargs.kwargs.get('proxies')
        self.assertIsNone(passed_proxies)
        self.assertIsNone(used_proxy)

    @patch('reNgine.auth_discovery_tasks.requests.get')
    def test_only_uses_first_three_proxies_from_a_longer_list(self, mock_get):
        # proxies 1-3 fail, 4th attempt is direct (not proxy[3])
        mock_get.side_effect = [
            req.exceptions.ProxyError("p1"),
            req.exceptions.ProxyError("p2"),
            req.exceptions.ProxyError("p3"),
            MagicMock(status_code=200, text='<html/>'),
        ]
        from reNgine.auth_discovery_tasks import _fetch_with_proxy_retry
        _, used_proxy = _fetch_with_proxy_retry(
            'http://example.com',
            ['http://p1:8080', 'http://p2:8080', 'http://p3:8080', 'http://p4:8080'],
        )
        # p4 must NOT have been used — fallback goes direct
        self.assertIsNone(used_proxy)
        self.assertEqual(mock_get.call_count, 4)


class TestExtractLoginForms(TestCase):
    """Tests for the _extract_login_forms helper."""

    def _run(self, html, base='http://example.com'):
        from reNgine.auth_discovery_tasks import _extract_login_forms
        return _extract_login_forms(html, base)

    def test_extracts_simple_login_form(self):
        forms = self._run(SIMPLE_LOGIN_FORM, 'http://example.com/login')
        self.assertEqual(len(forms), 1)
        f = forms[0]
        self.assertEqual(f['action'], 'http://example.com/login')
        self.assertEqual(f['method'], 'POST')
        self.assertEqual(f['user_field'], 'username')
        self.assertEqual(f['pass_field'], 'password')
        self.assertIn('_csrf_token', f['hidden_fields'])
        self.assertEqual(f['hidden_fields']['_csrf_token'], 'abc123')

    def test_detects_unquoted_type_password(self):
        forms = self._run(UNQUOTED_PASSWORD_FORM)
        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0]['pass_field'], 'pass')
        self.assertEqual(forms[0]['user_field'], 'user')

    def test_ignores_form_without_password_field(self):
        forms = self._run(NO_PASSWORD_FORM)
        self.assertEqual(len(forms), 0)

    def test_extracts_only_login_form_from_multi_form_page(self):
        forms = self._run(MULTIPLE_FORMS, 'http://example.com')
        self.assertEqual(len(forms), 1)
        f = forms[0]
        self.assertEqual(f['action'], 'http://example.com/wp-login.php')
        self.assertEqual(f['user_field'], 'log')
        self.assertEqual(f['pass_field'], 'pwd')
        self.assertIn('_wpnonce', f['hidden_fields'])
        self.assertEqual(f['hidden_fields']['_wpnonce'], 'xyz')

    def test_resolves_relative_action_url(self):
        html = (
            '<html><body>'
            '<form action="/auth/login" method="POST">'
            '<input type="text" name="user">'
            '<input type="password" name="pass">'
            '</form></body></html>'
        )
        forms = self._run(html, 'http://example.com/login')
        self.assertEqual(forms[0]['action'], 'http://example.com/auth/login')

    def test_uses_base_url_when_action_is_empty(self):
        html = (
            '<html><body>'
            '<form method="POST">'
            '<input type="text" name="user">'
            '<input type="password" name="pass">'
            '</form></body></html>'
        )
        forms = self._run(html, 'http://example.com/login')
        self.assertEqual(forms[0]['action'], 'http://example.com/login')

    def test_returns_empty_list_for_empty_html(self):
        self.assertEqual(self._run(''), [])

    def test_detects_autocomplete_current_password(self):
        forms = self._run(AUTOCOMPLETE_PASSWORD_FORM, 'http://example.com')
        self.assertEqual(len(forms), 1)
        self.assertEqual(forms[0]['pass_field'], 'token')
        self.assertEqual(forms[0]['user_field'], 'email')

    def test_method_defaults_to_post(self):
        html = (
            '<html><body>'
            '<form action="/login">'
            '<input type="text" name="user">'
            '<input type="password" name="pass">'
            '</form></body></html>'
        )
        forms = self._run(html)
        self.assertEqual(forms[0]['method'], 'POST')

    def test_all_fields_contains_every_input_name(self):
        forms = self._run(SIMPLE_LOGIN_FORM, 'http://example.com/login')
        self.assertIn('username', forms[0]['all_fields'])
        self.assertIn('password', forms[0]['all_fields'])
        self.assertIn('_csrf_token', forms[0]['all_fields'])


class TestExtractAuthCandidates(TestCase):
    """Integration tests for extract_auth_candidates orchestrator."""

    def setUp(self):
        self.domain = Domain.objects.create(name='test.example.com')
        self.engine = EngineType.objects.create(
            engine_name='test-engine-auth',
            yaml_configuration='{}',
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=RUNNING_TASK,
            start_scan_date=timezone.now(),
        )
        self.subdomain = Subdomain.objects.create(
            scan_history=self.scan,
            name='test.example.com',
            target_domain=self.domain,
        )
        self.login_endpoint = EndPoint.objects.create(
            scan_history=self.scan,
            subdomain=self.subdomain,
            http_url='http://test.example.com/login',
            http_status=200,
        )
        self.mock_self = MagicMock()
        self.mock_self.scan = self.scan
        self.mock_self.scan_id = self.scan.id

    @patch('reNgine.auth_discovery_tasks.get_proxy_list')
    @patch('reNgine.auth_discovery_tasks.get_random_proxy')
    @patch('reNgine.auth_discovery_tasks._fetch_with_proxy_retry')
    @patch('reNgine.tasks.http_crawl')
    def test_saves_auth_candidate_when_login_form_found(
        self, mock_http_crawl, mock_fetch, mock_rp, mock_pl
    ):
        mock_pl.return_value = []
        mock_rp.return_value = ''
        mock_fetch.return_value = (MagicMock(text=SIMPLE_LOGIN_FORM, status_code=200), None)

        from reNgine.auth_discovery_tasks import extract_auth_candidates
        extract_auth_candidates(self.mock_self, ctx={})

        candidates = AuthCandidate.objects.filter(scan_history=self.scan)
        self.assertEqual(candidates.count(), 1)
        c = candidates.first()
        # form action="/login" resolved against base "http://test.example.com/login"
        self.assertEqual(c.target, 'http://test.example.com/login')
        self.assertEqual(c.protocol, 'http')
        self.assertEqual(c.port, 80)
        self.assertEqual(c.metadata['user_field'], 'username')
        self.assertEqual(c.metadata['pass_field'], 'password')
        self.assertEqual(c.metadata['method'], 'POST')
        self.assertIn('_csrf_token', c.metadata['hidden_fields'])

    @patch('reNgine.auth_discovery_tasks.get_proxy_list')
    @patch('reNgine.auth_discovery_tasks.get_random_proxy')
    @patch('reNgine.auth_discovery_tasks._fetch_with_proxy_retry')
    @patch('reNgine.tasks.http_crawl')
    def test_no_candidate_saved_when_no_login_form(
        self, mock_http_crawl, mock_fetch, mock_rp, mock_pl
    ):
        mock_pl.return_value = []
        mock_rp.return_value = ''
        mock_fetch.return_value = (
            MagicMock(text='<html><body><p>Welcome</p></body></html>', status_code=200), None
        )

        from reNgine.auth_discovery_tasks import extract_auth_candidates
        extract_auth_candidates(self.mock_self, ctx={})

        self.assertEqual(
            AuthCandidate.objects.filter(scan_history=self.scan).count(), 0
        )

    @patch('reNgine.auth_discovery_tasks.get_proxy_list')
    @patch('reNgine.auth_discovery_tasks.get_random_proxy')
    @patch('reNgine.auth_discovery_tasks._fetch_with_proxy_retry')
    @patch('reNgine.tasks.http_crawl')
    def test_skips_endpoints_already_in_candidate_list(
        self, mock_http_crawl, mock_fetch, mock_rp, mock_pl
    ):
        AuthCandidate.objects.create(
            scan_history=self.scan,
            target=self.login_endpoint.http_url,
            protocol='http',
            port=80,
        )
        mock_pl.return_value = []
        mock_rp.return_value = ''

        from reNgine.auth_discovery_tasks import extract_auth_candidates
        extract_auth_candidates(self.mock_self, ctx={})

        mock_fetch.assert_not_called()

    @patch('reNgine.auth_discovery_tasks.get_proxy_list')
    @patch('reNgine.auth_discovery_tasks.get_random_proxy')
    @patch('reNgine.auth_discovery_tasks._fetch_with_proxy_retry')
    @patch('reNgine.tasks.http_crawl')
    def test_continues_to_next_endpoint_on_fetch_error(
        self, mock_http_crawl, mock_fetch, mock_rp, mock_pl
    ):
        EndPoint.objects.create(
            scan_history=self.scan,
            subdomain=self.subdomain,
            http_url='http://test.example.com/admin',
            http_status=200,
        )
        mock_pl.return_value = []
        mock_rp.return_value = ''
        mock_fetch.side_effect = [
            req.exceptions.ConnectionError("down"),
            (MagicMock(text=SIMPLE_LOGIN_FORM, status_code=200), None),
        ]

        from reNgine.auth_discovery_tasks import extract_auth_candidates
        extract_auth_candidates(self.mock_self, ctx={})

        # The first endpoint fails; the second succeeds and produces one candidate.
        # The form action="/login" resolves to http://test.example.com/login
        # regardless of which base URL was fetched.
        candidates = AuthCandidate.objects.filter(scan_history=self.scan)
        self.assertEqual(candidates.count(), 1)
        self.assertIn('/login', candidates.first().target)

    @patch('reNgine.auth_discovery_tasks.get_proxy_list')
    @patch('reNgine.auth_discovery_tasks.get_random_proxy')
    @patch('reNgine.auth_discovery_tasks._fetch_with_proxy_retry')
    @patch('reNgine.tasks.http_crawl')
    def test_protocol_is_http_for_https_endpoints(
        self, mock_http_crawl, mock_fetch, mock_rp, mock_pl
    ):
        """HTTPS endpoints are mapped to protocol='http' (PROTOCOL_CHOICES has no 'https')."""
        EndPoint.objects.create(
            scan_history=self.scan,
            subdomain=self.subdomain,
            http_url='https://test.example.com/login',
            http_status=200,
        )
        mock_pl.return_value = []
        mock_rp.return_value = ''
        mock_fetch.return_value = (MagicMock(text=SIMPLE_LOGIN_FORM, status_code=200), None)

        # Remove the http endpoint so only the https one fires
        self.login_endpoint.delete()

        from reNgine.auth_discovery_tasks import extract_auth_candidates
        extract_auth_candidates(self.mock_self, ctx={})

        candidates = AuthCandidate.objects.filter(scan_history=self.scan)
        self.assertEqual(candidates.count(), 1)
        # protocol maps to 'http' even for https (PROTOCOL_CHOICES constraint)
        self.assertEqual(candidates.first().protocol, 'http')
        # port should default to 443 for https endpoints
        self.assertEqual(candidates.first().port, 443)

    @patch('reNgine.auth_discovery_tasks.get_proxy_list')
    @patch('reNgine.auth_discovery_tasks.get_random_proxy')
    @patch('reNgine.auth_discovery_tasks._fetch_with_proxy_retry')
    @patch('reNgine.tasks.http_crawl')
    def test_extract_auth_candidates_filters_socks_proxies(
        self, mock_http_crawl, mock_fetch, mock_rp, mock_pl
    ):
        mock_pl.return_value = []
        mock_rp.return_value = 'http://http.com'
        mock_fetch.return_value = (MagicMock(text=SIMPLE_LOGIN_FORM, status_code=200), None)

        from reNgine.auth_discovery_tasks import extract_auth_candidates
        extract_auth_candidates(self.mock_self, ctx={})

        mock_fetch.assert_called_once()
        called_proxy_list = mock_fetch.call_args[0][1]
        self.assertEqual(called_proxy_list, ['http://http.com'])
        mock_rp.assert_called_once_with(http_only=True)

    @patch('reNgine.auth_discovery_tasks.get_proxy_list')
    @patch('reNgine.auth_discovery_tasks.get_random_proxy')
    @patch('reNgine.auth_discovery_tasks._fetch_with_proxy_retry')
    @patch('reNgine.tasks.http_crawl')
    def test_extract_auth_candidates_falls_back_to_http_only_random_proxy(
        self, mock_http_crawl, mock_fetch, mock_rp, mock_pl
    ):
        mock_pl.return_value = []
        mock_rp.return_value = 'http://random-http.com'
        mock_fetch.return_value = (MagicMock(text=SIMPLE_LOGIN_FORM, status_code=200), None)

        from reNgine.auth_discovery_tasks import extract_auth_candidates
        extract_auth_candidates(self.mock_self, ctx={})

        mock_fetch.assert_called_once()
        called_proxy_list = mock_fetch.call_args[0][1]
        self.assertEqual(called_proxy_list, ['http://random-http.com'])
        mock_rp.assert_called_once_with(http_only=True)

    @patch('reNgine.auth_discovery_tasks.get_proxy_list')
    @patch('reNgine.auth_discovery_tasks.get_random_proxy')
    @patch('reNgine.auth_discovery_tasks._fetch_with_proxy_retry')
    @patch('reNgine.tasks.http_crawl')
    def test_updates_endpoint_status_and_triggers_crawl_when_status_is_0(
        self, mock_http_crawl, mock_fetch, mock_rp, mock_pl
    ):
        mock_pl.return_value = []
        mock_rp.return_value = ''
        mock_fetch.return_value = (MagicMock(text=SIMPLE_LOGIN_FORM, status_code=200), None)

        # Create an endpoint with status 0
        zero_status_ep = EndPoint.objects.create(
            scan_history=self.scan,
            subdomain=self.subdomain,
            http_url='http://test.example.com/zero-status-login',
            http_status=0,
        )

        # Delete the login endpoint so only zero_status_ep fires
        self.login_endpoint.delete()

        from reNgine.auth_discovery_tasks import extract_auth_candidates
        extract_auth_candidates(self.mock_self, ctx={})

        # Reload ep from DB and assert status updated
        zero_status_ep.refresh_from_db()
        self.assertEqual(zero_status_ep.http_status, 200)

        # Assert http_crawl was called with this URL
        mock_http_crawl.assert_called_once_with(self.mock_self, urls=['http://test.example.com/zero-status-login'], recrawl=True, ctx={})
