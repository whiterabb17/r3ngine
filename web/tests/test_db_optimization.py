import concurrent.futures
import threading
from unittest.mock import patch, MagicMock
from django.test import TestCase, TransactionTestCase
from scanEngine.models import Proxy


class FetchProxiesThreadCapTest(TestCase):
    """Verify fetch_proxies_task never spawns more than 32 validation threads."""

    @patch('reNgine.common_func.check_proxy_robust', return_value=True)
    @patch('reNgine.job_tracker.update_job')
    @patch('reNgine.tasks.requests.get')
    def test_max_workers_capped_at_32(self, mock_get, _mock_job, _mock_check):
        # Return 200 fake proxies from the first URL, empty from the rest.
        fake_proxies = '\n'.join(
            f'192.0.2.{i % 256}:{8000 + (i // 256)}' for i in range(200)
        )
        live_response = MagicMock()
        live_response.status_code = 200
        live_response.text = fake_proxies

        empty_response = MagicMock()
        empty_response.status_code = 200
        empty_response.text = ''

        # First call returns 200 proxies; subsequent calls return empty
        mock_get.side_effect = [live_response] + [empty_response] * 100

        captured = {}
        original_tpe = concurrent.futures.ThreadPoolExecutor

        def spy_tpe(**kwargs):
            captured['max_workers'] = kwargs.get('max_workers', 0)
            return original_tpe(**kwargs)

        with patch('concurrent.futures.ThreadPoolExecutor', side_effect=spy_tpe):
            from reNgine.tasks import fetch_proxies_task
            fetch_proxies_task(limit=200, job_id=None)

        self.assertIn(
            'max_workers',
            captured,
            "ThreadPoolExecutor was never called — check that fetch_proxies_task reached the verification step",
        )
        self.assertLessEqual(
            captured['max_workers'],
            32,
            f"Expected max_workers <= 32, got {captured['max_workers']}",
        )


class RemoveProxyRaceTest(TransactionTestCase):
    """Concurrent removals must not cause lost updates.

    Uses TransactionTestCase (not TestCase) so that each removal runs in its
    own real committed transaction. TestCase wraps everything in a single
    outer transaction; select_for_update() inside a nested atomic block on a
    different thread connection would deadlock or see stale snapshots.
    """

    def setUp(self):
        self.proxy = Proxy.objects.create(
            use_proxy=True,
            proxies='http://a.example.com:8080\nhttp://b.example.com:8080\nhttp://c.example.com:8080',
        )

    def test_concurrent_removals_no_lost_update(self):
        from reNgine.common_func import remove_proxy_from_pool
        results = []
        errors = []

        def _remove(addr):
            try:
                results.append(remove_proxy_from_pool(f'http://{addr}:8080'))
            except Exception as e:
                errors.append(e)

        threads = [
            threading.Thread(target=_remove, args=(host,))
            for host in ['a.example.com', 'b.example.com', 'c.example.com']
        ]
        for t in threads:
            t.start()
        for t in threads:
            t.join()

        self.assertEqual(errors, [], msg=f"Threads raised exceptions: {errors}")
        self.proxy.refresh_from_db()
        remaining = [ln.strip() for ln in (self.proxy.proxies or '').splitlines() if ln.strip()]
        self.assertEqual(remaining, [], msg=f"Expected all proxies removed, got: {remaining}")

    def test_idempotent_removal(self):
        from reNgine.common_func import remove_proxy_from_pool
        r1 = remove_proxy_from_pool('http://a.example.com:8080', self.proxy)
        r2 = remove_proxy_from_pool('http://a.example.com:8080')
        self.assertTrue(r1)
        self.assertFalse(r2)
