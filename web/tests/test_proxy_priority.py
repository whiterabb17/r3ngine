"""Tests for the hand-entered priority proxy pool.

These live in their own model field so that the automatic fetch, which rewrites
the scraped pool wholesale, cannot overwrite them, and so they can be tried
before anything scraped.
"""
from unittest.mock import patch

from django.test import TestCase

from reNgine import common_func
from reNgine.common_func import get_priority_proxies, get_proxy_list, get_random_proxy
from reNgine.tasks import fetch_proxies_task
from scanEngine.models import Proxy

PAID = 'socks5h://acct7:s3cr3t@px.io:1080'
FREE = 'http://free.com:8080'


class PriorityProxyTests(TestCase):
    def setUp(self):
        common_func._failed_proxy_cache.clear()

    def test_returns_manual_entries_in_order(self):
        Proxy.objects.create(
            use_proxy=True, priority_proxies=f'{PAID}\nhttp://second.io:3128'
        )
        self.assertEqual(
            get_priority_proxies(), [PAID, 'http://second.io:3128']
        )

    def test_disabled_checkbox_hides_them(self):
        Proxy.objects.create(
            use_proxy=True, priority_proxies=PAID, use_priority_proxies=False
        )
        self.assertEqual(get_priority_proxies(), [])

    def test_proxy_list_puts_them_first(self):
        Proxy.objects.create(use_proxy=True, proxies=FREE, priority_proxies=PAID)
        self.assertEqual(get_proxy_list(), [PAID, FREE])

    def test_proxy_list_deduplicates(self):
        Proxy.objects.create(use_proxy=True, proxies=FREE, priority_proxies=FREE)
        self.assertEqual(get_proxy_list(), [FREE])

    @patch('reNgine.common_func.proxy_pool.check_proxy_robust')
    def test_a_live_priority_proxy_wins_over_the_scraped_pool(self, mock_check):
        mock_check.return_value = True
        Proxy.objects.create(use_proxy=True, proxies=FREE, priority_proxies=PAID)

        self.assertEqual(get_random_proxy(), PAID)

    @patch('reNgine.common_func.proxy_pool.check_proxy_robust')
    def test_falls_back_to_scraped_pool_when_priority_is_dead(self, mock_check):
        mock_check.side_effect = lambda url, **kw: url == FREE
        Proxy.objects.create(use_proxy=True, proxies=FREE, priority_proxies=PAID)

        self.assertEqual(get_random_proxy(), FREE)

    @patch('reNgine.common_func.proxy_pool.check_proxy_robust')
    def test_dead_priority_proxy_is_never_deleted(self, mock_check):
        """The whole point of the field: the operator vouched for these."""
        mock_check.return_value = False
        proxy = Proxy.objects.create(use_proxy=True, priority_proxies=PAID)

        get_random_proxy()

        proxy.refresh_from_db()
        self.assertEqual(proxy.priority_proxies, PAID)

    @patch('reNgine.common_func.check_proxy_robust')
    @patch('reNgine.tasks.proxies.requests.get')
    def test_proxy_fetch_cannot_touch_them(self, mock_get, mock_check):
        """fetch_proxies_task rewrites the scraped field only."""
        mock_get.return_value.status_code = 200
        mock_get.return_value.text = '9.9.9.9:3128'
        mock_check.return_value = True
        proxy = Proxy.objects.create(use_proxy=True, priority_proxies=PAID)

        fetch_proxies_task(limit=1)

        proxy.refresh_from_db()
        self.assertEqual(proxy.priority_proxies, PAID)
        self.assertNotIn(PAID, proxy.proxies or '')
