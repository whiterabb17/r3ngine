from django.test import TestCase
from unittest.mock import patch, MagicMock
from reNgine.common_func import (
    validate_proxies, get_random_proxy, remove_proxy_from_pool,
    get_valid_proxy_count, mark_proxy_used, is_proxy_recently_used,
)
import reNgine.common_func as _cf
from scanEngine.models import Proxy
import requests

class ProxyValidationTests(TestCase):
    def setUp(self):
        Proxy.objects.all().delete()
        # Isolate in-process caches between tests
        _cf._used_proxy_cache.clear()
        _cf._failed_proxy_cache.clear()

    @patch('reNgine.common_func.requests.Session')
    def test_validate_proxies_concurrently(self, mock_session):
        # Setup session factory
        sessions_created = []
        def session_factory():
            session = MagicMock()
            session.__enter__.return_value = session
            
            def get_side_effect(url, **kwargs):
                proxy = session.proxies.get('http', '')
                if 'work1' in proxy or 'work2' in proxy:
                    mock_response = MagicMock()
                    mock_response.status_code = 200
                    mock_response.text = '1.2.3.4'
                    mock_response.json.return_value = {"ip": "1.2.3.4", "query": "1.2.3.4"}
                    return mock_response
                else:
                    raise requests.exceptions.ProxyError("Connection Refused")
            
            session.get.side_effect = get_side_effect
            sessions_created.append(session)
            return session
        mock_session.side_effect = session_factory

        proxy_text = "work1.com:8080\ndead.com:8080\nwork2.com:1080\n"
        result = validate_proxies(proxy_text)
        self.assertIn("work1.com:8080", result)
        self.assertNotIn("dead.com:8080", result)
        self.assertIn("work2.com:1080", result)

    @patch('reNgine.common_func.requests.Session')
    def test_get_random_proxy_limit(self, mock_session):
        # Create a list of 10 dead proxies
        proxy_lines = [f"dead{i}.com:8080" for i in range(10)]
        Proxy.objects.create(
            use_proxy=True,
            proxies="\n".join(proxy_lines)
        )

        sessions_created = []
        def session_factory():
            session = MagicMock()
            session.__enter__.return_value = session
            session.get.side_effect = requests.exceptions.ProxyError("Connection Timeout")
            sessions_created.append(session)
            return session
        mock_session.side_effect = session_factory

        result = get_random_proxy()
        self.assertEqual(result, '')
        # It should try to validate all 10 proxies in parallel
        self.assertEqual(len(sessions_created), 10)

    def test_remove_proxy_from_pool_is_idempotent(self):
        proxy = Proxy.objects.create(
            use_proxy=True,
            proxies="http://alive.com:8080\ndead.com:8080\nsocks5://foo:1080"
        )

        self.assertTrue(remove_proxy_from_pool("http://dead.com:8080", proxy))
        proxy.refresh_from_db()
        self.assertEqual(proxy.proxies, "http://alive.com:8080\nsocks5://foo:1080")
        self.assertFalse(remove_proxy_from_pool("http://dead.com:8080", proxy))

    @patch('reNgine.common_func.remove_proxy_from_pool')
    @patch('reNgine.common_func.requests.Session')
    @patch('reNgine.common_func.random.shuffle', lambda proxies: None)
    def test_get_random_proxy_removes_invalid_entries(self, mock_session, mock_remove):
        # TestCase wraps in an uncommitted transaction, so worker-thread saves are
        # not visible in the main thread.  We verify the integration point (that
        # get_random_proxy calls remove_proxy_from_pool for dead entries) via a mock,
        # and rely on test_remove_proxy_from_pool_removes_non_recently_used for the
        # actual DB-removal logic.
        Proxy.objects.create(
            use_proxy=True,
            proxies="dead.com:8080\nwork.com:8080"
        )

        def session_factory():
            session = MagicMock()
            session.__enter__.return_value = session

            def get_side_effect(url, **kwargs):
                proxy_url = session.proxies.get('http', '')
                if 'work.com' in proxy_url:
                    import time
                    time.sleep(0.05)
                    mock_response = MagicMock()
                    mock_response.status_code = 200
                    mock_response.text = '1.2.3.4'
                    mock_response.json.return_value = {"ip": "1.2.3.4", "query": "1.2.3.4"}
                    return mock_response
                raise requests.exceptions.ProxyError("Connection Refused")

            session.get.side_effect = get_side_effect
            return session
        mock_session.side_effect = session_factory

        result = get_random_proxy()

        self.assertEqual(result, "http://work.com:8080")
        # Verify that the dead proxy was passed to remove_proxy_from_pool
        removed_urls = [call.args[0] for call in mock_remove.call_args_list]
        self.assertIn("http://dead.com:8080", removed_urls)

    @patch('reNgine.common_func.requests.Session')
    @patch('reNgine.common_func.random.shuffle', lambda proxies: None)
    def test_get_random_proxy_keeps_valid_entry(self, mock_session):
        proxy = Proxy.objects.create(
            use_proxy=True,
            proxies="work.com:8080"
        )

        def session_factory():
            session = MagicMock()
            session.__enter__.return_value = session
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = '1.2.3.4'
            mock_response.json.return_value = {"ip": "1.2.3.4", "query": "1.2.3.4"}
            session.get.return_value = mock_response
            return session
        mock_session.side_effect = session_factory

        result = get_random_proxy()
        proxy.refresh_from_db()

        self.assertEqual(result, "http://work.com:8080")
        self.assertEqual(proxy.proxies, "work.com:8080")

    @patch('reNgine.common_func.requests.Session')
    @patch('reNgine.common_func.random.shuffle', lambda proxies: None)
    def test_get_random_proxy_http_only_filters_socks(self, mock_session):
        proxy = Proxy.objects.create(
            use_proxy=True,
            proxies="socks5://socks-proxy.com:1080\nhttp://http-proxy.com:8080"
        )

        def session_factory():
            session = MagicMock()
            session.__enter__.return_value = session
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = '1.2.3.4'
            mock_response.json.return_value = {"ip": "1.2.3.4", "query": "1.2.3.4"}
            session.get.return_value = mock_response
            return session
        mock_session.side_effect = session_factory

        # Request HTTP proxy only
        result = get_random_proxy(http_only=True)
        self.assertEqual(result, "http://http-proxy.com:8080")

    def test_get_random_proxy_http_only_ignores_tor(self):
        Proxy.objects.create(
            use_proxy=True,
            use_tor=True
        )
        # SOCKS Tor is bypassed when http_only=True
        result = get_random_proxy(http_only=True)
        self.assertEqual(result, '')

    # ------------------------------------------------------------------
    # 24-hour retention tests
    # ------------------------------------------------------------------

    def test_mark_proxy_used_is_recently_used(self):
        mark_proxy_used('http://myproxy.com:8080')
        self.assertTrue(is_proxy_recently_used('http://myproxy.com:8080'))

    def test_unmarked_proxy_is_not_recently_used(self):
        self.assertFalse(is_proxy_recently_used('http://never-used.com:8080'))

    def test_remove_proxy_from_pool_skips_recently_used(self):
        proxy = Proxy.objects.create(
            use_proxy=True,
            proxies='http://alive.com:8080\nhttp://recent.com:9090'
        )
        mark_proxy_used('http://recent.com:9090')

        # recent.com should be protected — remove must return False and leave the list intact
        removed = remove_proxy_from_pool('http://recent.com:9090', proxy)
        self.assertFalse(removed)
        proxy.refresh_from_db()
        self.assertIn('recent.com:9090', proxy.proxies)

    def test_remove_proxy_from_pool_removes_non_recently_used(self):
        proxy = Proxy.objects.create(
            use_proxy=True,
            proxies='http://alive.com:8080\nhttp://stale.com:9090'
        )
        # stale.com was never marked as used — should be removed normally
        removed = remove_proxy_from_pool('http://stale.com:9090', proxy)
        self.assertTrue(removed)
        proxy.refresh_from_db()
        self.assertNotIn('stale.com:9090', proxy.proxies)

    @patch('reNgine.common_func.requests.Session')
    @patch('reNgine.common_func.random.shuffle', lambda proxies: None)
    def test_get_random_proxy_marks_valid_proxy_as_used(self, mock_session):
        Proxy.objects.create(
            use_proxy=True,
            proxies='http://goodproxy.com:8080'
        )

        def session_factory():
            session = MagicMock()
            session.__enter__.return_value = session
            mock_response = MagicMock()
            mock_response.status_code = 200
            mock_response.text = '5.6.7.8'
            mock_response.json.return_value = {'ip': '5.6.7.8', 'query': '5.6.7.8'}
            session.get.return_value = mock_response
            return session
        mock_session.side_effect = session_factory

        result = get_random_proxy()
        self.assertEqual(result, 'http://goodproxy.com:8080')
        self.assertTrue(is_proxy_recently_used('http://goodproxy.com:8080'))

    @patch('reNgine.common_func.requests.Session')
    @patch('reNgine.common_func.random.shuffle', lambda proxies: None)
    def test_recently_used_proxy_survives_transient_failure(self, mock_session):
        """A proxy that was used recently must not be DB-deleted on a transient failure."""
        proxy = Proxy.objects.create(
            use_proxy=True,
            proxies='http://transient.com:8080'
        )
        mark_proxy_used('http://transient.com:8080')

        # Simulate the proxy now failing validation
        def session_factory():
            session = MagicMock()
            session.__enter__.return_value = session
            session.get.side_effect = requests.exceptions.ProxyError('timeout')
            return session
        mock_session.side_effect = session_factory

        result = get_random_proxy()
        # No live proxy found for this scan — that's expected
        self.assertEqual(result, '')
        # But the proxy must still be in the DB pool
        proxy.refresh_from_db()
        self.assertIn('transient.com:8080', proxy.proxies)
