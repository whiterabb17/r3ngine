import socket
from unittest.mock import MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role

from dashboard.models import Project
from mcp.keys import display_prefix, generate_mcp_secret, hash_mcp_secret
from mcp.models import McpApiKey, SafePocAttempt
from mcp.safe_poc import (
    abort_attempt,
    approve_attempt,
    execute_attempt,
    propose_attempt,
    update_attempt,
)
from mcp.safe_poc_catalog import (
    CatalogError,
    normalize_params,
    run_template,
)
from mcp.tool_map import tool_name_for
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Vulnerability
from targetApp.models import Domain

User = get_user_model()


def mcp_client_with_session(user, transport='stdio'):
    secret = generate_mcp_secret()
    McpApiKey.objects.create(
        user=user,
        name=f'k-{user.username}',
        prefix=display_prefix(secret),
        key_hash=hash_mcp_secret(secret),
    )
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f'Bearer {secret}')
    sid = client.post('/api/mcp/sessions/', {
        'transport': transport,
        'client_name': 'test',
        'client_version': '0',
        'agent_id': hash_mcp_secret(secret),
        'provider': 'test',
        'ide': 'test',
        'device_id': 'test-device',
        'hostname': 'test-host',
        'username': user.username,
    }, format='json').json()['session_id']
    client.credentials(
        HTTP_AUTHORIZATION=f'Bearer {secret}',
        HTTP_X_MCP_SESSION_ID=str(sid),
    )
    return client


class SafePocCatalogTests(TestCase):
    def test_unknown_template_rejected(self):
        with self.assertRaises(CatalogError):
            normalize_params('sqlmap_dump', {}, vuln_url='https://app.example.com/')

    def test_denied_path_rejected(self):
        with self.assertRaises(CatalogError):
            normalize_params(
                'marker_reflect',
                {'param_name': 'q', 'base_url': 'https://app.example.com/.env'},
                vuln_url='https://app.example.com/.env',
            )

    def test_flag_requires_marker_and_path(self):
        with self.assertRaises(CatalogError):
            normalize_params(
                'flag_canary_read',
                {'expected_marker': 'canary12345'},
                vuln_url='https://app.example.com/index.html',
            )
        params = normalize_params(
            'flag_canary_read',
            {'expected_marker': 'canary12345'},
            vuln_url='https://app.example.com/flag.txt',
        )
        self.assertEqual(params['expected_marker'], 'canary12345')

    def test_flag_rejects_empty_allowed_paths_bypass(self):
        """endswith('') is True for every path — blank allowlist entries must not pass."""
        with self.assertRaises(CatalogError):
            normalize_params(
                'flag_canary_read',
                {
                    'expected_marker': 'canary12345',
                    'allowed_paths': ['', '  ', None],
                    'base_url': 'https://app.example.com/index.html',
                },
                vuln_url='https://app.example.com/index.html',
            )
        params = normalize_params(
            'flag_canary_read',
            {
                'expected_marker': 'canary12345',
                'allowed_paths': ['', '/canary.txt'],
                'base_url': 'https://app.example.com/canary.txt',
            },
            vuln_url='https://app.example.com/canary.txt',
        )
        self.assertEqual(params['allowed_paths'], ['/canary.txt'])

    def test_open_redirect_host_allowlist(self):
        with self.assertRaises(CatalogError):
            normalize_params(
                'open_redirect_safe',
                {'param_name': 'next', 'redirect_target': 'https://evil.example/'},
                vuln_url='https://app.example.com/login',
            )

    @patch('mcp.safe_poc_catalog._resolve_public_ips', return_value=['93.184.216.34'])
    @patch('mcp.safe_poc_catalog.requests.get')
    def test_marker_reflect_hit(self, mock_get, _mock_dns):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = 'hello r3n-abc1234567890 world'
        mock_get.return_value = resp
        result = run_template(
            'marker_reflect',
            {
                'param_name': 'q',
                'marker': 'r3n-abc1234567890',
                'method': 'GET',
                'base_url': 'https://app.example.com/search',
            },
            allowed_hosts={'app.example.com'},
        )
        self.assertTrue(result['matched'])
        self.assertGreaterEqual(result['confidence'], 0.8)

    @patch('mcp.safe_poc_catalog._resolve_public_ips', return_value=['93.184.216.34'])
    @patch('mcp.safe_poc_catalog.requests.get')
    def test_calc_echo_hit(self, mock_get, _mock_dns):
        resp = MagicMock()
        resp.status_code = 200
        resp.text = 'result=49'
        mock_get.return_value = resp
        result = run_template(
            'calc_echo',
            {
                'param_name': 'tpl',
                'probe_index': 0,
                'method': 'GET',
                'base_url': 'https://app.example.com/page',
            },
            allowed_hosts={'app.example.com'},
        )
        self.assertTrue(result['matched'])

    @patch('mcp.safe_poc_catalog._resolve_public_ips', return_value=['93.184.216.34'])
    @patch('mcp.safe_poc_catalog.requests.get')
    def test_authz_status_delta(self, mock_get, _mock_dns):
        a = MagicMock()
        a.status_code = 200
        a.content = b'ok'
        b = MagicMock()
        b.status_code = 403
        b.content = b'no'
        mock_get.side_effect = [a, b]
        result = run_template(
            'authz_status_delta',
            {
                'url_a': 'https://app.example.com/obj/1',
                'url_b': 'https://app.example.com/obj/2',
                'cookie_name': 'session',
                'cookie_value': 'tok-abc',
            },
            allowed_hosts={'app.example.com'},
        )
        self.assertTrue(result['matched'])
        self.assertTrue(result['request']['cookies_applied'])
        self.assertNotIn('body', result['response'])
        # Same cookie jar on both requests — avoids false positives from missing auth on B.
        self.assertEqual(mock_get.call_count, 2)
        for call in mock_get.call_args_list:
            self.assertEqual(call.kwargs.get('cookies'), {'session': 'tok-abc'})

    @patch('mcp.safe_poc_catalog._resolve_public_ips', return_value=['93.184.216.34'])
    @patch('mcp.safe_poc_catalog.requests.get')
    def test_redirect_to_private_ip_blocked(self, mock_get, _mock_dns):
        redirect = MagicMock()
        redirect.status_code = 302
        redirect.headers = {'Location': 'http://169.254.169.254/latest/meta-data/'}
        redirect.text = ''
        mock_get.return_value = redirect
        result = run_template(
            'marker_reflect',
            {
                'param_name': 'q',
                'marker': 'r3n-redirectssrf01',
                'method': 'GET',
                'base_url': 'https://app.example.com/search',
            },
            allowed_hosts={'app.example.com'},
        )
        self.assertFalse(result['matched'])
        self.assertEqual(result.get('error'), 'catalog_error')
        self.assertEqual(mock_get.call_count, 1)
        self.assertFalse(mock_get.call_args.kwargs.get('allow_redirects', True))

    @patch('mcp.safe_poc_catalog.socket.getaddrinfo')
    def test_resolve_rejects_private_answer(self, mock_gai):
        """DNS answers that resolve to private/reserved IPs must fail closed."""
        from mcp.safe_poc_catalog import CatalogError, _resolve_public_ips

        mock_gai.return_value = [
            (socket.AF_INET, socket.SOCK_STREAM, 6, '', ('10.0.0.1', 0)),
        ]
        with self.assertRaises(CatalogError) as ctx:
            _resolve_public_ips('evil.example.com')
        self.assertIn('private or reserved', str(ctx.exception))

    def test_resolve_rejects_literal_private(self):
        from mcp.safe_poc_catalog import CatalogError, _resolve_public_ips

        with self.assertRaises(CatalogError):
            _resolve_public_ips('169.254.169.254')


class SafePocServiceTests(TestCase):
    def setUp(self):
        self.project = Project.objects.create(
            name='PoC Project',
            slug='poc-project',
            insert_date=timezone.now(),
        )
        self.engine = EngineType.objects.create(engine_name='Default', yaml_configuration='')
        self.domain = Domain.objects.create(
            name='poc.example.com',
            project=self.project,
            insert_date=timezone.now(),
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=2,
            start_scan_date=timezone.now(),
        )
        self.vuln = Vulnerability.objects.create(
            name='Reflected XSS',
            severity=2,
            scan_history=self.scan,
            target_domain=self.domain,
            http_url='https://poc.example.com/search?q=1',
            validation_status='new',
        )
        self.user = User.objects.create_user(username='poc-pt', password='x')
        assign_role(self.user, 'penetration_tester')

    def test_propose_rejects_forbidden_keys(self):
        with self.assertRaises(Exception) as ctx:
            propose_attempt(
                vulnerability_id=self.vuln.id,
                template_id='marker_reflect',
                params={'param_name': 'q', 'payload': 'alert(1)'},
                user=self.user,
            )
        self.assertIn('forbidden', str(ctx.exception).lower())

    def test_propose_rejects_unknown_template(self):
        with self.assertRaises(Exception):
            propose_attempt(
                vulnerability_id=self.vuln.id,
                template_id='exploiting_sqli',
                params={'param_name': 'q'},
                user=self.user,
            )

    def test_propose_and_update_operator_lock(self):
        attempt = propose_attempt(
            vulnerability_id=self.vuln.id,
            template_id='marker_reflect',
            params={'param_name': 'q'},
            rationale='test',
            user=self.user,
        )
        self.assertEqual(attempt.status, SafePocAttempt.STATUS_PROPOSED)
        self.assertIn('marker', attempt.params)

        # Agent update does not set the lock.
        update_attempt(
            attempt,
            params={'param_name': 'q', 'marker': 'r3n-agentupdate001'},
            user=self.user,
            is_operator=False,
        )
        attempt.refresh_from_db()
        self.assertFalse(attempt.operator_edited)

        # Real operator (JWT/UI) sets the lock.
        update_attempt(
            attempt,
            params={'param_name': 'q', 'marker': 'r3n-operatorlock01'},
            user=self.user,
            is_operator=True,
        )
        attempt.refresh_from_db()
        self.assertTrue(attempt.operator_edited)
        with self.assertRaises(Exception) as ctx:
            update_attempt(
                attempt,
                params={'param_name': 'q'},
                user=self.user,
                is_operator=False,
            )
        self.assertEqual(ctx.exception.status, 403)

    def test_mcp_update_ignores_forged_operator_flag(self):
        client = mcp_client_with_session(self.user)
        proposed = client.post('/api/mcp/safe-poc/propose/', {
            'vulnerability_id': self.vuln.id,
            'template_id': 'marker_reflect',
            'params': {'param_name': 'q'},
        }, format='json')
        self.assertEqual(proposed.status_code, 201, proposed.content)
        attempt_id = proposed.json()['id']
        res = client.post(f'/api/mcp/safe-poc/{attempt_id}/update/', {
            'operator': True,
            'params': {'param_name': 'q', 'marker': 'r3n-forgedoperat01'},
        }, format='json')
        self.assertEqual(res.status_code, 200, res.content)
        self.assertFalse(res.json()['operator_edited'])

    @patch('mcp.safe_poc._start_safe_poc_workflow', return_value='safe-poc-1')
    def test_approve_starts_workflow(self, _mock_start):
        attempt = propose_attempt(
            vulnerability_id=self.vuln.id,
            template_id='marker_reflect',
            params={'param_name': 'q'},
            user=self.user,
        )
        approved = approve_attempt(attempt, user=self.user)
        self.assertEqual(approved.status, SafePocAttempt.STATUS_RUNNING)
        self.assertEqual(approved.temporal_workflow_id, 'safe-poc-1')
        # Concurrent second approve must fail closed.
        with self.assertRaises(Exception) as ctx:
            approve_attempt(approved, user=self.user)
        self.assertEqual(ctx.exception.status, 409)

    @patch('mcp.safe_poc._cancel_workflow')
    @patch('mcp.safe_poc._start_safe_poc_workflow', side_effect=RuntimeError('temporal down'))
    def test_approve_start_failure_respects_abort(self, _mock_start, _mock_cancel):
        attempt = propose_attempt(
            vulnerability_id=self.vuln.id,
            template_id='marker_reflect',
            params={'param_name': 'q'},
            user=self.user,
        )

        def _abort_during_start(_attempt_id):
            abort_attempt(attempt, user=self.user)
            raise RuntimeError('temporal down')

        with patch('mcp.safe_poc._start_safe_poc_workflow', side_effect=_abort_during_start):
            with self.assertRaises(Exception) as ctx:
                approve_attempt(attempt, user=self.user)
            self.assertEqual(ctx.exception.status, 502)
        attempt.refresh_from_db()
        self.assertEqual(attempt.status, SafePocAttempt.STATUS_ABORTED)
        self.assertIsNone(attempt.result)

    @patch('mcp.safe_poc._cancel_workflow')
    def test_abort_proposed(self, _mock_cancel):
        attempt = propose_attempt(
            vulnerability_id=self.vuln.id,
            template_id='marker_reflect',
            params={'param_name': 'q'},
            user=self.user,
        )
        aborted = abort_attempt(attempt, user=self.user)
        self.assertEqual(aborted.status, SafePocAttempt.STATUS_ABORTED)

    @patch('mcp.safe_poc._cancel_workflow')
    @patch('mcp.safe_poc.run_template')
    def test_abort_wins_over_execute_result(self, mock_run, _mock_cancel):
        """Concurrent abort must not be overwritten by a late execute write."""
        attempt = propose_attempt(
            vulnerability_id=self.vuln.id,
            template_id='marker_reflect',
            params={'param_name': 'q', 'marker': 'r3n-abortrace00001'},
            user=self.user,
        )
        attempt.status = SafePocAttempt.STATUS_RUNNING
        attempt.save(update_fields=['status'])

        def _probe_then_abort(*_a, **_k):
            abort_attempt(attempt, user=self.user)
            return {
                'matched': True,
                'confidence': 0.9,
                'summary': 'should not persist',
                'request': {},
                'response': {},
            }

        mock_run.side_effect = _probe_then_abort
        out = execute_attempt(attempt.id)
        self.assertTrue(out.get('aborted'))
        attempt.refresh_from_db()
        self.assertEqual(attempt.status, SafePocAttempt.STATUS_ABORTED)
        self.assertIsNone(attempt.result)

    @patch('mcp.safe_poc._cancel_workflow')
    def test_mark_failed_respects_abort(self, _mock_cancel):
        from reNgine.temporal.activities.safe_poc import _mark_attempt_failed

        attempt = propose_attempt(
            vulnerability_id=self.vuln.id,
            template_id='marker_reflect',
            params={'param_name': 'q', 'marker': 'r3n-markfailabort1'},
            user=self.user,
        )
        attempt.status = SafePocAttempt.STATUS_RUNNING
        attempt.save(update_fields=['status'])
        abort_attempt(attempt, user=self.user)
        out = _mark_attempt_failed(attempt.id, 'boom')
        self.assertTrue(out.get('aborted'))
        attempt.refresh_from_db()
        self.assertEqual(attempt.status, SafePocAttempt.STATUS_ABORTED)

    @patch('mcp.safe_poc_catalog._resolve_public_ips', return_value=['93.184.216.34'])
    @patch('mcp.safe_poc_catalog.requests.get')
    def test_execute_nests_enrichment(self, mock_get, _mock_dns):
        attempt = propose_attempt(
            vulnerability_id=self.vuln.id,
            template_id='marker_reflect',
            params={'param_name': 'q', 'marker': 'r3n-executemarker1'},
            user=self.user,
        )
        attempt.status = SafePocAttempt.STATUS_RUNNING
        attempt.save(update_fields=['status'])
        resp = MagicMock()
        resp.status_code = 200
        resp.text = 'x r3n-executemarker1 y'
        mock_get.return_value = resp
        out = execute_attempt(attempt.id)
        self.assertEqual(out['status'], SafePocAttempt.STATUS_SUCCEEDED)
        self.vuln.refresh_from_db()
        poc = (self.vuln.agent_enrichment or {}).get('poc') or {}
        self.assertEqual(poc.get('last_attempt_id'), attempt.id)
        self.assertEqual(poc.get('outcome'), 'succeeded')
        self.assertEqual(self.vuln.validation_status, 'new')


class SafePocApiTests(TestCase):
    def setUp(self):
        self.project = Project.objects.create(
            name='PoC API',
            slug='poc-api',
            insert_date=timezone.now(),
        )
        self.engine = EngineType.objects.create(engine_name='Default', yaml_configuration='')
        self.domain = Domain.objects.create(
            name='api-poc.example.com',
            project=self.project,
            insert_date=timezone.now(),
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=2,
            start_scan_date=timezone.now(),
        )
        self.vuln = Vulnerability.objects.create(
            name='Open Redirect',
            severity=2,
            scan_history=self.scan,
            target_domain=self.domain,
            http_url='https://api-poc.example.com/go',
            validation_status='new',
        )
        self.pentester = User.objects.create_user(username='poc-api-pt', password='x')
        assign_role(self.pentester, 'penetration_tester')
        self.auditor = User.objects.create_user(username='poc-api-aud', password='x')
        assign_role(self.auditor, 'auditor')
        self.pt = mcp_client_with_session(self.pentester)
        self.aud = mcp_client_with_session(self.auditor)

    def test_tool_map_routes(self):
        self.assertEqual(
            tool_name_for('POST', '/api/mcp/safe-poc/propose/'),
            'r3ngine_propose_safe_poc',
        )
        self.assertEqual(
            tool_name_for('POST', '/api/mcp/safe-poc/12/approve/'),
            'r3ngine_approve_safe_poc',
        )
        self.assertEqual(
            tool_name_for('GET', '/api/mcp/safe-poc/'),
            'r3ngine_list_safe_pocs',
        )
        self.assertEqual(
            tool_name_for('POST', '/api/mcp/safe-poc/run/'),
            'r3ngine_run_safe_poc',
        )

    def test_propose_and_direct_run_410(self):
        res = self.pt.post('/api/mcp/safe-poc/propose/', {
            'vulnerability_id': self.vuln.id,
            'template_id': 'marker_reflect',
            'params': {'param_name': 'q'},
            'rationale': 'api test',
        }, format='json')
        self.assertEqual(res.status_code, 201, res.content)
        body = res.json()
        self.assertEqual(body['status'], 'proposed')
        self.assertEqual(body['template_id'], 'marker_reflect')

        run = self.pt.post('/api/mcp/safe-poc/run/', {
            'vulnerability_id': self.vuln.id,
            'template_id': 'marker_reflect',
        }, format='json')
        self.assertEqual(run.status_code, 410)

        listed = self.pt.get('/api/mcp/safe-poc/', {'project_slug': 'poc-api'})
        self.assertEqual(listed.status_code, 200)
        self.assertGreaterEqual(listed.json()['count'], 1)

    def test_auditor_cannot_propose(self):
        res = self.aud.post('/api/mcp/safe-poc/propose/', {
            'vulnerability_id': self.vuln.id,
            'template_id': 'marker_reflect',
            'params': {'param_name': 'q'},
        }, format='json')
        self.assertIn(res.status_code, (403, 401))

    @patch('mcp.safe_poc._start_safe_poc_workflow', return_value='safe-poc-api-1')
    def test_approve_via_api(self, _mock_start):
        proposed = self.pt.post('/api/mcp/safe-poc/propose/', {
            'vulnerability_id': self.vuln.id,
            'template_id': 'marker_reflect',
            'params': {'param_name': 'q'},
        }, format='json').json()
        res = self.pt.post(f"/api/mcp/safe-poc/{proposed['id']}/approve/", {}, format='json')
        self.assertEqual(res.status_code, 200, res.content)
        self.assertEqual(res.json()['status'], 'running')
