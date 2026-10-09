"""Tests for the freshness tiers in get_random_proxy().

The old code returned an unchecked proxy for the whole of Proxy.proxy_ttl_minutes
(two hours by default), so an entry that died minutes after the batch run kept
being handed to scans. These tests pin the three tiers that replaced it.
"""
from datetime import timedelta
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from reNgine import common_func
from reNgine.common_func import get_random_proxy
from scanEngine.models import Proxy

LIVE = 'http://live.com:8080'
DEAD = 'http://dead.com:8080'


class GetRandomProxyFreshnessTests(TestCase):
    def setUp(self):
        # The failure cache is module-global and would leak between tests.
        common_func._failed_proxy_cache.clear()

    def _make_pool(self, proxies, verified_minutes_ago, ttl_minutes=120):
        return Proxy.objects.create(
            use_proxy=True,
            proxies='\n'.join(proxies),
            proxies_verified_at=timezone.now() - timedelta(minutes=verified_minutes_ago),
            proxy_ttl_minutes=ttl_minutes,
        )

    @patch('reNgine.common_func.proxy_pool.PROXY_TRUST_WINDOW_SECONDS', 300)
    @patch('reNgine.common_func.proxy_pool.check_proxy_robust')
    def test_inside_trust_window_returns_without_checking(self, mock_check):
        """A list verified seconds ago is still taken on trust — that is the point."""
        self._make_pool([LIVE], verified_minutes_ago=1)

        result = get_random_proxy()

        self.assertEqual(result, LIVE)
        self.assertEqual(mock_check.call_count, 0)

    @patch('reNgine.common_func.proxy_pool.PROXY_TRUST_WINDOW_SECONDS', 300)
    @patch('reNgine.common_func.proxy_pool.check_proxy_robust')
    def test_past_trust_window_verifies_before_handing_out(self, mock_check):
        """30 minutes old is inside the TTL but must no longer be trusted blind."""
        mock_check.return_value = True
        self._make_pool([LIVE], verified_minutes_ago=30)

        result = get_random_proxy()

        self.assertEqual(result, LIVE)
        self.assertEqual(mock_check.call_count, 1)
        self.assertEqual(mock_check.call_args[0][0], LIVE)

    @patch('reNgine.common_func.proxy_pool.PROXY_TRUST_WINDOW_SECONDS', 300)
    @patch('reNgine.common_func.proxy_pool.PROXY_SAMPLE_ATTEMPTS', 3)
    @patch('reNgine.common_func.proxy_pool.check_proxy_robust')
    def test_dead_entry_inside_ttl_is_not_returned(self, mock_check):
        """The regression this fixes: a dead proxy inside the TTL used to be served."""
        mock_check.side_effect = lambda url, **kw: url == LIVE
        self._make_pool([DEAD, LIVE], verified_minutes_ago=30)

        result = get_random_proxy()

        self.assertEqual(result, LIVE)

    @patch('reNgine.common_func.proxy_pool.PROXY_TRUST_WINDOW_SECONDS', 300)
    @patch('reNgine.common_func.proxy_pool.PROXY_SAMPLE_ATTEMPTS', 1)
    @patch('reNgine.common_func.proxy_pool.check_proxy_robust')
    def test_sampling_falls_back_to_full_revalidation(self, mock_check):
        """One sampled miss must not end the search while other entries remain."""
        mock_check.side_effect = lambda url, **kw: url == LIVE
        self._make_pool([DEAD, LIVE], verified_minutes_ago=30)

        result = get_random_proxy()

        # Either the sample hit LIVE directly, or it hit DEAD and the parallel
        # re-validation below found LIVE. Both paths must end on a live proxy.
        self.assertEqual(result, LIVE)

    @patch('reNgine.common_func.proxy_pool.PROXY_TRUST_WINDOW_SECONDS', 300)
    @patch('reNgine.common_func.proxy_pool.check_proxy_robust')
    def test_past_ttl_still_revalidates(self, mock_check):
        mock_check.side_effect = lambda url, **kw: url == LIVE
        self._make_pool([LIVE], verified_minutes_ago=180, ttl_minutes=120)

        result = get_random_proxy()

        self.assertEqual(result, LIVE)
        self.assertGreaterEqual(mock_check.call_count, 1)

    @patch('reNgine.common_func.proxy_pool.PROXY_TRUST_WINDOW_SECONDS', 300)
    @patch('reNgine.common_func.proxy_pool.check_proxy_robust')
    def test_all_dead_returns_empty(self, mock_check):
        mock_check.return_value = False
        self._make_pool([DEAD], verified_minutes_ago=30)

        self.assertEqual(get_random_proxy(), '')

    @patch('reNgine.common_func.proxy_pool.PROXY_TRUST_WINDOW_SECONDS', 300)
    @patch('reNgine.common_func.proxy_pool.check_proxy_robust')
    def test_credentialed_proxy_survives_a_failed_sample(self, mock_check):
        """The sampled check must not undo the paid-proxy protection."""
        paid = 'socks5://acct7:s3cr3t@px.io:1080'
        mock_check.return_value = False
        proxy = self._make_pool([paid], verified_minutes_ago=30)

        get_random_proxy()

        proxy.refresh_from_db()
        self.assertIn(paid, proxy.proxies)

    @patch('reNgine.common_func.proxy_pool.PROXY_TRUST_WINDOW_SECONDS', 300)
    @patch('reNgine.common_func.proxy_pool.check_proxy_robust')
    def test_tor_mode_still_bypasses_everything(self, mock_check):
        Proxy.objects.create(use_proxy=True, use_tor=True, proxies=LIVE)

        self.assertEqual(get_random_proxy(), 'socks5://tor:9050')
        self.assertEqual(mock_check.call_count, 0)
