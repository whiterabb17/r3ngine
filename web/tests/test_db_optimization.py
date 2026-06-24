import concurrent.futures
import threading
from unittest.mock import patch, MagicMock
from django.test import TestCase, TransactionTestCase
from django.test.utils import CaptureQueriesContext
from django.db import connection
from django.utils import timezone
from scanEngine.models import Proxy, EngineType


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


class PortScanSubdomainCacheTest(TestCase):
    """Subdomain table should be queried once per unique host, not once per port."""

    def setUp(self):
        import os
        import tempfile
        from targetApp.models import Domain
        from startScan.models import ScanHistory, Subdomain

        self.domain = Domain.objects.create(name='test-portscan.invalid')
        self.engine = EngineType.objects.create(engine_name='Test Engine Port Scan')
        self.scan = ScanHistory.objects.create(
            scan_status=0,
            domain=self.domain,
            scan_type=self.engine,
            start_scan_date=timezone.now(),
        )
        self.subdomain = Subdomain.objects.create(
            name='192.0.2.1',
            target_domain=self.domain,
            scan_history=self.scan,
        )
        # Temporary results dir so port_scan can write files
        self.results_dir = tempfile.mkdtemp()

    def tearDown(self):
        import shutil
        shutil.rmtree(self.results_dir, ignore_errors=True)

    def _build_proxy(self):
        """Build a minimal mock proxy that satisfies port_scan()'s self interface."""
        from unittest.mock import MagicMock, PropertyMock
        proxy = MagicMock()
        proxy.scan = self.scan
        proxy.domain = self.domain
        proxy.subscan = None
        proxy.scan_id = self.scan.id
        proxy.subscan_id = None
        proxy.activity_id = None
        proxy.results_dir = self.results_dir
        proxy.history_file = f'{self.results_dir}/commands.txt'
        proxy.output_path = f'{self.results_dir}/port_scan.txt'
        proxy.yaml_configuration = {}
        # MagicMock.notify() will silently absorb calls
        return proxy

    def test_subdomain_queried_once_per_host(self):
        """10 ports on the same host → at most 1 Subdomain SELECT after caching is applied."""
        import json
        from unittest.mock import patch, MagicMock
        from django.test.utils import CaptureQueriesContext
        from django.db import connection
        from reNgine.tasks import port_scan

        parse_lines = [
            json.dumps({'host': '192.0.2.1', 'ip': '192.0.2.1', 'port': 8000 + i})
            for i in range(10)
        ]
        parse_only = '\n'.join(parse_lines)

        proxy = self._build_proxy()

        mock_ip = MagicMock()
        mock_ip.ports = MagicMock()
        mock_port = MagicMock()
        mock_port.is_uncommon = False

        with patch('reNgine.tasks.save_ip_address', return_value=(mock_ip, True)), \
             patch('reNgine.tasks.save_endpoint', return_value=(None, False)), \
             patch('reNgine.tasks.update_or_create_port', return_value=(mock_port, False)), \
             patch('reNgine.tasks.get_port_service_description', return_value={}), \
             patch('reNgine.tasks.save_auth_candidate', return_value=None):

            with CaptureQueriesContext(connection) as ctx:
                port_scan(proxy, hosts=['192.0.2.1'], ctx={
                    'scan_history_id': self.scan.id,
                    'domain_id': self.domain.id,
                }, parse_only=parse_only)

        subdomain_selects = [
            q for q in ctx.captured_queries
            if 'subdomain' in q['sql'].lower()
            and q['sql'].strip().upper().startswith('SELECT')
        ]
        self.assertLessEqual(
            len(subdomain_selects),
            1,
            msg=(
                f"Expected at most 1 Subdomain SELECT for 10 ports on the same host, "
                f"got {len(subdomain_selects)}. Queries: "
                + str([q['sql'] for q in subdomain_selects])
            ),
        )


class SaveEndpointCacheTest(TestCase):
    """ScanHistory and Domain should be fetched at most once across repeated save_endpoint() calls."""

    def setUp(self):
        from targetApp.models import Domain
        from startScan.models import ScanHistory
        from scanEngine.models import EngineType
        engine = EngineType.objects.create(engine_name='Test Engine Endpoint Cache')
        self.domain = Domain.objects.create(name='endpoint-cache-test.invalid')
        self.scan = ScanHistory.objects.create(
            scan_status=0,
            domain=self.domain,
            scan_type=engine,
            start_scan_date=timezone.now(),
        )

    def test_scan_and_domain_fetched_once(self):
        from reNgine.utils.task import save_endpoint
        ctx = {'scan_history_id': self.scan.id, 'domain_id': self.domain.id}

        with CaptureQueriesContext(connection) as captured:
            for port in [8080, 8443, 3000]:
                save_endpoint(f'http://192.0.2.1:{port}', ctx=ctx)

        scan_selects = [
            q for q in captured.captured_queries
            if 'scanhistory' in q['sql'].lower()
            and q['sql'].strip().upper().startswith('SELECT')
        ]
        domain_selects = [
            q for q in captured.captured_queries
            if 'domain' in q['sql'].lower()
            and q['sql'].strip().upper().startswith('SELECT')
            and 'endpoint' not in q['sql'].lower()
        ]
        self.assertLessEqual(len(scan_selects), 1, "ScanHistory queried more than once")
        self.assertLessEqual(len(domain_selects), 1, "Domain queried more than once")

    def test_scan_fetched_once_for_matching_urls(self):
        """URLs whose host matches the domain name reach the else-branch where
        _scan_obj is fetched and cached.  Three calls with the same ctx must
        produce at most one SELECT against scanhistory.
        """
        from reNgine.utils.task import save_endpoint

        # Use the domain name as the URL host so the guard at
        #   ``if domain and domain.name not in http_url``
        # is satisfied and execution falls through to the else-branch where
        # ScanHistory is fetched (and then cached in ctx['_scan_obj']).
        domain_host = self.domain.name  # 'endpoint-cache-test.invalid'
        ctx = {'scan_history_id': self.scan.id, 'domain_id': self.domain.id}

        with CaptureQueriesContext(connection) as captured:
            for port in [9080, 9443, 9000]:
                save_endpoint(f'http://{domain_host}:{port}/', ctx=ctx)

        scan_selects = [
            q for q in captured.captured_queries
            if 'scanhistory' in q['sql'].lower()
            and q['sql'].strip().upper().startswith('SELECT')
        ]
        self.assertLessEqual(
            len(scan_selects),
            1,
            msg=(
                f"Expected at most 1 ScanHistory SELECT across 3 matching-URL calls, "
                f"got {len(scan_selects)}. Queries: "
                + str([q['sql'] for q in scan_selects])
            ),
        )


class SaveVulnerabilityQueryCountTest(TestCase):
    """Saving a vuln with tags/CVEs/CWEs should not UPDATE the vuln row per M2M entry."""

    def setUp(self):
        from targetApp.models import Domain
        from startScan.models import ScanHistory
        self.domain = Domain.objects.create(name='vuln-test.invalid')
        self.engine = EngineType.objects.create(engine_name='Test Engine Vuln')
        self.scan = ScanHistory.objects.create(
            scan_status=0,
            domain=self.domain,
            scan_type=self.engine,
            start_scan_date=timezone.now(),
        )

    def test_no_update_per_m2m_entry(self):
        from reNgine.common_func import save_vulnerability

        with CaptureQueriesContext(connection) as ctx:
            save_vulnerability(
                name='Test XSS',
                severity=2,
                scan_history=self.scan,
                target_domain=self.domain,
                tags=['xss', 'sqli', 'csrf'],
                cve_ids=['CVE-2021-1234', 'CVE-2022-5678'],
                cwe_ids=['CWE-79', 'CWE-89'],
                references=['https://nvd.nist.gov/vuln/detail/CVE-2021-1234'],
            )

        update_queries = [
            q for q in ctx.captured_queries
            if q['sql'].strip().upper().startswith('UPDATE')
            and 'vulnerability' in q['sql'].lower()
        ]
        # At most 2 UPDATEs: one for the initial upsert, one for discovered_date/status.
        # Before fix: 8 UPDATEs (one per tag + CVE + CWE + reference).
        self.assertLessEqual(len(update_queries), 2,
            msg=f"Too many UPDATEs: {[q['sql'] for q in update_queries]}")


class OpSecManagerSingletonTest(TestCase):
    """get_opsec_manager() should query the DB only once regardless of call count."""

    def setUp(self):
        # Reset singleton and TTL timestamp between tests
        import reNgine.utils.opsec as opsec_mod
        opsec_mod._opsec_manager_instance = None
        opsec_mod._opsec_manager_fetched_at = 0.0

    def tearDown(self):
        import reNgine.utils.opsec as opsec_mod
        opsec_mod._opsec_manager_instance = None
        opsec_mod._opsec_manager_fetched_at = 0.0

    def test_db_queried_only_once_across_multiple_calls(self):
        from reNgine.utils.opsec import get_opsec_manager

        with CaptureQueriesContext(connection) as ctx:
            get_opsec_manager()
            get_opsec_manager()
            get_opsec_manager()

        db_queries = ctx.captured_queries
        # 2 queries on first call (OpSec + Proxy); 0 on subsequent calls
        self.assertLessEqual(len(db_queries), 2,
            msg=f"Expected ≤2 queries, got {len(db_queries)}: {[q['sql'] for q in db_queries]}")

    def test_refresh_re_queries_db(self):
        from reNgine.utils.opsec import get_opsec_manager

        get_opsec_manager()  # warms cache
        with CaptureQueriesContext(connection) as ctx:
            get_opsec_manager(refresh=True)  # must re-query

        self.assertGreaterEqual(len(ctx.captured_queries), 2)

    def test_ttl_expiry_triggers_re_fetch(self):
        """After TTL elapses, the next call should re-query the DB."""
        import reNgine.utils.opsec as opsec_mod
        from reNgine.utils.opsec import get_opsec_manager
        from unittest.mock import patch

        get_opsec_manager()  # warm the cache
        first_instance = opsec_mod._opsec_manager_instance

        # Simulate TTL expiry by backdating the fetch timestamp
        opsec_mod._opsec_manager_fetched_at -= opsec_mod._OPSEC_MANAGER_TTL + 1.0

        with CaptureQueriesContext(connection) as ctx:
            second = get_opsec_manager()

        self.assertGreaterEqual(
            len(ctx.captured_queries), 2,
            "Expected DB re-query after TTL expiry"
        )
        self.assertIsNot(second, first_instance, "Expected a new OpSecManager instance after TTL")
