from django.test import TestCase
from django.utils import timezone
from unittest.mock import patch, MagicMock
import unittest
from startScan.models import ScanHistory
from targetApp.models import Domain
from scanEngine.models import EngineType
from django.contrib.auth.models import User
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role


class TestExtractAuthForURLActivity(TestCase):

    def setUp(self):
        self.domain = Domain.objects.create(name='test.example.com')
        self.engine = EngineType.objects.create(
            engine_name='test-engine-auth-extract',
            yaml_configuration='{}',
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=0,
            start_scan_date=timezone.now(),
        )

    @patch('reNgine.tasks.auth_discovery._fetch_with_proxy_retry')
    @patch('reNgine.tasks.auth_discovery._extract_login_forms')
    @patch('reNgine.temporal.activities.get_proxy_list', return_value=[])
    @patch('reNgine.temporal.activities.get_random_proxy', return_value=None)
    @patch('reNgine.temporal.activities._run_task')
    def test_extract_auth_saves_candidates(
        self, mock_run_task, mock_rand_proxy, mock_proxy_list, mock_extract_forms, mock_fetch
    ):
        mock_response = MagicMock()
        mock_response.text = '<html></html>'
        mock_fetch.return_value = (mock_response, None)
        mock_extract_forms.return_value = [{
            'action': 'http://example.com/login',
            'method': 'POST',
            'user_field': 'username',
            'pass_field': 'password',
            'hidden_fields': {},
            'all_fields': ['username', 'password'],
        }]

        from reNgine.temporal_activities import extract_auth_for_url_activity
        result = extract_auth_for_url_activity({
            'url': 'http://example.com/login',
            'scan_id': self.scan.id,
        })

        self.assertEqual(result['found'], 1)

    @patch('reNgine.tasks.auth_discovery._fetch_with_proxy_retry')
    @patch('reNgine.temporal.activities.get_proxy_list', return_value=[])
    @patch('reNgine.temporal.activities.get_random_proxy', return_value=None)
    @patch('reNgine.temporal.activities._run_task')
    def test_extract_auth_no_forms_returns_zero(
        self, mock_run_task, mock_rand_proxy, mock_proxy_list, mock_fetch
    ):
        mock_response = MagicMock()
        mock_response.text = '<html><body>No forms here</body></html>'
        mock_fetch.return_value = (mock_response, None)

        from reNgine.temporal_activities import extract_auth_for_url_activity
        with patch('reNgine.temporal.activities._extract_login_forms', return_value=[]):
            result = extract_auth_for_url_activity({
                'url': 'http://example.com/page',
                'scan_id': self.scan.id,
            })

        self.assertEqual(result['found'], 0)

    @patch('reNgine.tasks.auth_discovery._fetch_with_proxy_retry',
           side_effect=Exception("connection refused"))
    @patch('reNgine.temporal.activities.get_proxy_list', return_value=[])
    @patch('reNgine.temporal.activities.get_random_proxy', return_value=None)
    @patch('reNgine.temporal.activities._run_task')
    def test_extract_auth_fetch_failure_raises(
        self, mock_run_task, mock_rand_proxy, mock_proxy_list, mock_fetch
    ):
        from reNgine.temporal_activities import extract_auth_for_url_activity
        with self.assertRaises(Exception):
            extract_auth_for_url_activity({
                'url': 'http://example.com/login',
                'scan_id': self.scan.id,
            })

    @patch('reNgine.tasks.auth_discovery._fetch_with_proxy_retry')
    @patch('reNgine.tasks.auth_discovery._extract_login_forms')
    @patch('reNgine.temporal.activities.get_proxy_list')
    @patch('reNgine.temporal.activities.get_random_proxy')
    @patch('reNgine.temporal.activities._run_task')
    def test_extract_auth_activity_filters_socks_proxies(
        self, mock_run_task, mock_rand_proxy, mock_proxy_list, mock_extract_forms, mock_fetch
    ):
        mock_proxy_list.return_value = []
        mock_rand_proxy.return_value = 'http://http-ip'
        mock_response = MagicMock()
        mock_response.text = '<html></html>'
        mock_fetch.return_value = (mock_response, None)
        mock_extract_forms.return_value = []

        from reNgine.temporal_activities import extract_auth_for_url_activity
        extract_auth_for_url_activity({
            'url': 'http://example.com/login',
            'scan_id': self.scan.id,
        })

        mock_fetch.assert_called_once()
        called_proxy_list = mock_fetch.call_args[0][1]
        self.assertEqual(called_proxy_list, ['http://http-ip'])
        mock_rand_proxy.assert_called_once_with(http_only=True)

    @patch('reNgine.tasks.auth_discovery._fetch_with_proxy_retry')
    @patch('reNgine.tasks.auth_discovery._extract_login_forms')
    @patch('reNgine.temporal.activities.get_proxy_list')
    @patch('reNgine.temporal.activities.get_random_proxy')
    @patch('reNgine.temporal.activities._run_task')
    def test_extract_auth_activity_falls_back_to_http_only_random_proxy(
        self, mock_run_task, mock_rand_proxy, mock_proxy_list, mock_extract_forms, mock_fetch
    ):
        mock_proxy_list.return_value = []
        mock_rand_proxy.return_value = 'http://random-http'
        mock_response = MagicMock()
        mock_response.text = '<html></html>'
        mock_fetch.return_value = (mock_response, None)
        mock_extract_forms.return_value = []

        from reNgine.temporal_activities import extract_auth_for_url_activity
        extract_auth_for_url_activity({
            'url': 'http://example.com/login',
            'scan_id': self.scan.id,
        })

        mock_fetch.assert_called_once()
        called_proxy_list = mock_fetch.call_args[0][1]
        self.assertEqual(called_proxy_list, ['http://random-http'])
        mock_rand_proxy.assert_called_once_with(http_only=True)

    @patch('reNgine.tasks.auth_discovery._fetch_with_proxy_retry')
    @patch('reNgine.tasks.auth_discovery._extract_login_forms')
    @patch('reNgine.temporal.activities.get_proxy_list', return_value=[])
    @patch('reNgine.temporal.activities.get_random_proxy', return_value=None)
    @patch('reNgine.temporal.activities._run_task')
    def test_extract_auth_updates_status_and_triggers_crawl_for_status_0(
        self, mock_run_task, mock_rand_proxy, mock_proxy_list, mock_extract_forms, mock_fetch
    ):
        from startScan.models import EndPoint, Subdomain
        subdomain = Subdomain.objects.create(
            scan_history=self.scan,
            name='example.com',
            target_domain=self.domain,
        )
        ep = EndPoint.objects.create(
            scan_history=self.scan,
            subdomain=subdomain,
            http_url='http://example.com/login',
            http_status=0,
        )

        mock_response = MagicMock()
        mock_response.text = '<html></html>'
        mock_response.status_code = 200
        mock_fetch.return_value = (mock_response, None)
        mock_extract_forms.return_value = [{
            'action': 'http://example.com/login',
            'method': 'POST',
            'user_field': 'username',
            'pass_field': 'password',
            'hidden_fields': {},
            'all_fields': ['username', 'password'],
        }]

        from reNgine.temporal_activities import extract_auth_for_url_activity
        result = extract_auth_for_url_activity({
            'url': 'http://example.com/login',
            'scan_id': self.scan.id,
        })

        self.assertEqual(result['found'], 1)
        ep.refresh_from_db()
        self.assertEqual(ep.http_status, 200)

        # Assert mock_run_task was called to trigger http_crawl
        mock_run_task.assert_called_once()
        args, kwargs = mock_run_task.call_args
        self.assertEqual(kwargs['task_name'], 'http_crawl_auth')
        self.assertEqual(kwargs['urls'], ['http://example.com/login'])
        self.assertEqual(kwargs['recrawl'], True)

        mock_fetch.assert_called_once()
        called_proxy_list = mock_fetch.call_args[0][1]
        self.assertEqual(called_proxy_list, [])
        mock_rand_proxy.assert_called_once_with(http_only=True)


class TestDirectoryFileDispatchView(TestCase):

    def setUp(self):
        self.user = User.objects.create_user('dispatchuser', password='testpass')
        assign_role(self.user, 'penetration_tester')
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        self.client.force_login(self.user)
        self.domain = Domain.objects.create(name='dispatch-test.example.com')
        self.engine = EngineType.objects.create(
            engine_name='test-engine-dispatch',
            yaml_configuration='{}',
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=0,
            start_scan_date=timezone.now(),
        )

    @patch('api.views.run_and_close')
    @patch('api.views.TemporalClientProvider')
    def test_dispatch_scan_vuln_returns_dispatched(self, mock_tc, mock_run):
        mock_run.return_value = 'wf-test-123'
        response = self.client.post('/api/action/directory-file/dispatch/', {
            'url': 'http://example.com/admin/',
            'action': 'scan_vuln',
            'scan_id': self.scan.id,
        }, format='json')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['status'], 'dispatched')
        self.assertIn('workflow_id', response.data)

    @patch('api.views.run_and_close')
    @patch('api.views.TemporalClientProvider')
    def test_dispatch_extract_auth_returns_dispatched(self, mock_tc, mock_run):
        mock_run.return_value = 'wf-auth-123'
        response = self.client.post('/api/action/directory-file/dispatch/', {
            'url': 'http://example.com/login.php',
            'action': 'extract_auth',
            'scan_id': self.scan.id,
        }, format='json')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['status'], 'dispatched')

    def test_dispatch_unknown_action_returns_400(self):
        response = self.client.post('/api/action/directory-file/dispatch/', {
            'url': 'http://example.com/',
            'action': 'do_something_invalid',
            'scan_id': self.scan.id,
        }, format='json')
        self.assertEqual(response.status_code, 400)
        self.assertIn('error', response.data)

    def test_dispatch_missing_fields_returns_400(self):
        response = self.client.post('/api/action/directory-file/dispatch/', {
            'url': 'http://example.com/',
        }, format='json')
        self.assertEqual(response.status_code, 400)

    def test_dispatch_brute_test_without_plugin_returns_403(self):
        response = self.client.post('/api/action/directory-file/dispatch/', {
            'url': 'http://example.com/login',
            'action': 'brute_test',
            'scan_id': self.scan.id,
        }, format='json')
        self.assertEqual(response.status_code, 403)

    @patch('api.views.run_and_close')
    @patch('api.views.TemporalClientProvider')
    @unittest.skip("Plugin tests are skipped for now")
    def test_dispatch_brute_test_with_plugin_enabled(self, mock_tc, mock_run):
        from plugins.models import Plugin
        Plugin.objects.create(
            name='Credential Intelligence',
            slug='credential_intelligence',
            version='1.4.0',
            is_enabled=True,
            anchor_step='web_api_discovery',
        )
        mock_run.return_value = 'wf-brute-123'
        response = self.client.post('/api/action/directory-file/dispatch/', {
            'url': 'http://example.com/login',
            'action': 'brute_test',
            'scan_id': self.scan.id,
        }, format='json')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['status'], 'dispatched')

    def test_dispatch_requires_authentication(self):
        unauthenticated = APIClient()
        response = unauthenticated.post('/api/action/directory-file/dispatch/', {
            'url': 'http://example.com/',
            'action': 'scan_vuln',
            'scan_id': self.scan.id,
        }, format='json')
        # LoginRequiredMiddleware redirects (302) unauthenticated requests to login;
        # DRF itself would return 401/403 — both mean the endpoint is protected.
        self.assertIn(response.status_code, [401, 403, 302])

    def test_dispatch_rejects_non_http_url(self):
        response = self.client.post('/api/action/directory-file/dispatch/', {
            'url': 'file:///etc/passwd',
            'action': 'scan_vuln',
            'scan_id': self.scan.id,
        }, format='json')
        self.assertEqual(response.status_code, 400)
        self.assertIn('error', response.data)

    def test_dispatch_rejects_nonexistent_scan_id(self):
        response = self.client.post('/api/action/directory-file/dispatch/', {
            'url': 'http://example.com/path',
            'action': 'scan_vuln',
            'scan_id': 999999,
        }, format='json')
        self.assertEqual(response.status_code, 404)
        self.assertIn('error', response.data)

    def test_dispatch_requires_modify_scan_results_permission(self):
        from django.contrib.auth.models import User
        from rest_framework.test import APIClient
        # A fresh user with no role assignments has no extra permissions
        plain_user = User.objects.create_user('plain_dispatch', password='testpass')
        c = APIClient()
        c.force_authenticate(user=plain_user)
        c.force_login(plain_user)
        response = c.post('/api/action/directory-file/dispatch/', {
            'url': 'http://example.com/',
            'action': 'scan_vuln',
            'scan_id': 1,
        }, format='json')
        self.assertIn(response.status_code, [401, 403, 302])


from startScan.models import DirectoryFile


class TestDirectoryFileDeleteView(TestCase):

    def setUp(self):
        self.user = User.objects.create_user('deluser', password='testpass')
        assign_role(self.user, 'penetration_tester')
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        self.client.force_login(self.user)
        self.file1 = DirectoryFile.objects.create(
            name='L2FkbWlu',
            url='http://example.com/admin',
            http_status=200,
            length=1234,
        )
        self.file2 = DirectoryFile.objects.create(
            name='L2xvZ2lu',
            url='http://example.com/login',
            http_status=200,
            length=500,
        )

    def test_delete_records_by_ids(self):
        response = self.client.post('/api/action/directory-file/delete/', {
            'directory_file_ids': [self.file1.id, self.file2.id],
        }, format='json')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['deleted'], 2)
        self.assertFalse(DirectoryFile.objects.filter(id=self.file1.id).exists())
        self.assertFalse(DirectoryFile.objects.filter(id=self.file2.id).exists())

    def test_delete_missing_ids_returns_400(self):
        response = self.client.post('/api/action/directory-file/delete/', {}, format='json')
        self.assertEqual(response.status_code, 400)

    def test_delete_empty_list_returns_400(self):
        response = self.client.post('/api/action/directory-file/delete/', {
            'directory_file_ids': [],
        }, format='json')
        self.assertEqual(response.status_code, 400)

    def test_delete_requires_authentication(self):
        unauthenticated = APIClient()
        response = unauthenticated.post('/api/action/directory-file/delete/', {
            'directory_file_ids': [self.file1.id],
        }, format='json')
        # LoginRequiredMiddleware redirects (302) unauthenticated requests to login
        self.assertIn(response.status_code, [401, 403, 302])

    def test_delete_rejects_more_than_500_ids(self):
        response = self.client.post('/api/action/directory-file/delete/', {
            'directory_file_ids': list(range(1, 502)),
        }, format='json')
        self.assertEqual(response.status_code, 400)
        self.assertIn('error', response.data)

    def test_delete_requires_modify_scan_results_permission(self):
        from django.contrib.auth.models import User
        from rest_framework.test import APIClient
        plain_user = User.objects.create_user('plain_delete', password='testpass')
        c = APIClient()
        c.force_authenticate(user=plain_user)
        c.force_login(plain_user)
        response = c.post('/api/action/directory-file/delete/', {
            'directory_file_ids': [self.file1.id],
        }, format='json')
        self.assertIn(response.status_code, [401, 403, 302])
