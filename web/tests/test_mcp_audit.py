from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role

from mcp.keys import display_prefix, generate_mcp_secret, hash_mcp_secret
from mcp.models import McpApiKey, McpAuditEvent, McpSession
from mcp.redact import redact_payload

User = get_user_model()


class RedactTests(SimpleTestCase):
    def test_redacts_authorization_and_api_key(self):
        body, truncated = redact_payload({
            'Authorization': 'Bearer r3n_mcp_secret',
            'nested': {'R3NGINE_MCP_API_KEY': 'r3n_mcp_secret'},
            'ok': 1,
        })
        self.assertFalse(truncated)
        self.assertEqual(body['Authorization'], '[REDACTED]')
        self.assertEqual(body['nested']['R3NGINE_MCP_API_KEY'], '[REDACTED]')
        self.assertEqual(body['ok'], 1)

    def test_redacts_cookie_value_in_nested_params(self):
        body, truncated = redact_payload({
            'template_id': 'authz_status_delta',
            'params': {
                'url_a': 'https://app.example.com/1',
                'url_b': 'https://app.example.com/2',
                'cookie_name': 'session',
                'cookie_value': 'super-secret-session',
            },
        })
        self.assertFalse(truncated)
        self.assertEqual(body['params']['cookie_value'], '[REDACTED]')
        self.assertEqual(body['params']['cookie_name'], 'session')
        self.assertEqual(body['params']['url_a'], 'https://app.example.com/1')

    def test_truncates_over_64kib(self):
        huge = {'blob': 'a' * 70000}
        body, truncated = redact_payload(huge)
        self.assertTrue(truncated)
        self.assertTrue(body.get('truncated'))


class McpAuditApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='aud', password='x')
        assign_role(self.user, 'penetration_tester')
        self.secret = generate_mcp_secret()
        McpApiKey.objects.create(
            user=self.user,
            name='k',
            prefix=display_prefix(self.secret),
            key_hash=hash_mcp_secret(self.secret),
        )
        self.mcp = APIClient()
        self.mcp.credentials(HTTP_AUTHORIZATION=f'Bearer {self.secret}')
        self.ui = APIClient()
        self.ui.force_authenticate(user=self.user)
        self.ui.force_login(self.user)

    def test_session_open_writes_audit_and_heartbeat_does_not(self):
        sid = self.mcp.post('/api/mcp/sessions/', {
            'transport': 'stdio',
            'client_name': 'cursor',
            'client_version': '1',
            'agent_id': 'c' * 64,
            'provider': 'cursor',
            'ide': 'cursor',
            'device_id': 'dev',
            'hostname': 'host',
            'username': 'aud',
        }, format='json').json()['session_id']
        self.assertTrue(McpAuditEvent.objects.filter(tool_name='session_open', session_id=sid).exists())
        before = McpAuditEvent.objects.count()
        hb = self.mcp.post(
            f'/api/mcp/sessions/{sid}/heartbeat/',
            format='json',
            HTTP_X_MCP_SESSION_ID=str(sid),
        )
        self.assertEqual(hb.status_code, 204)
        self.assertEqual(McpAuditEvent.objects.count(), before)
        listed = self.ui.get(f'/api/mcp/sessions/{sid}/events/')
        self.assertEqual(listed.status_code, 200)
        tools = [item['tool_name'] for item in listed.json()['items']]
        self.assertIn('session_open', tools)
        self.assertNotIn('', [t for t in tools if 'heartbeat' in t])

    def test_session_events_do_not_leak_another_users_agent_fingerprint(self):
        other = User.objects.create_user(username='aud-other', password='x')
        assign_role(other, 'penetration_tester')
        secret = generate_mcp_secret()
        McpApiKey.objects.create(
            user=other,
            name='k',
            prefix=display_prefix(secret),
            key_hash=hash_mcp_secret(secret),
        )
        other_mcp = APIClient()
        other_mcp.credentials(HTTP_AUTHORIZATION=f'Bearer {secret}')
        fingerprint = {
            'transport': 'stdio',
            'client_name': 'cursor',
            'client_version': '1',
            'agent_id': 'c' * 64,
            'provider': 'cursor',
            'ide': 'cursor',
            'device_id': 'dev',
            'hostname': 'host',
            'username': 'shared-os-user',
        }
        mine = self.mcp.post('/api/mcp/sessions/', fingerprint, format='json').json()['session_id']
        theirs = other_mcp.post('/api/mcp/sessions/', fingerprint, format='json').json()['session_id']
        listed = self.ui.get(f'/api/mcp/sessions/{mine}/events/')
        self.assertEqual(listed.status_code, 200)
        session_ids = {item['session_id'] for item in listed.json()['items']}
        self.assertIn(str(mine), session_ids)
        self.assertNotIn(str(theirs), session_ids)

    def test_audit_payload_includes_agent_and_key_for_replay(self):
        fingerprint = {
            'transport': 'stdio',
            'client_name': 'cursor',
            'client_version': '1',
            'agent_id': 'c' * 64,
            'provider': 'cursor',
            'ide': 'cursor',
            'device_id': 'dev',
            'os_name': 'windows',
            'hostname': 'host',
            'username': 'aud',
        }
        sid = self.mcp.post('/api/mcp/sessions/', fingerprint, format='json').json()['session_id']
        listed = self.ui.get('/api/mcp/audit/')
        self.assertEqual(listed.status_code, 200)
        row = next(item for item in listed.json()['items'] if item['session_id'] == str(sid))
        self.assertEqual(row['agent_id'], 'c' * 64)
        self.assertEqual(row['provider'], 'cursor')
        self.assertEqual(row['hostname'], 'host')
        self.assertEqual(row['os_name'], 'windows')
        self.assertEqual(row['agent_username'], 'aud')
        self.assertEqual(row['key_name'], 'k')
        self.assertTrue(row['key_prefix'])
        self.assertEqual(row['transport'], 'stdio')
        events = self.ui.get(f'/api/mcp/sessions/{sid}/events/')
        self.assertEqual(events.status_code, 200)
        event = events.json()['items'][0]
        self.assertEqual(event['agent_id'], 'c' * 64)
        self.assertEqual(event['key_name'], 'k')

    def test_audit_replay_survives_missing_session(self):
        key = McpApiKey.objects.get(user=self.user, name='k')
        McpAuditEvent.objects.create(
            session=None,
            key=key,
            user=self.user,
            tool_name='list_targets',
            method='GET',
            path='/api/mcp/targets/',
            status_code=200,
            duration_ms=4,
            request_body={'limit': 10},
            response_body={'count': 0},
        )
        listed = self.ui.get('/api/mcp/audit/')
        self.assertEqual(listed.status_code, 200)
        row = next(item for item in listed.json()['items'] if item['tool_name'] == 'list_targets')
        self.assertIsNone(row['agent_id'])
        self.assertEqual(row['provider'], '')
        self.assertEqual(row['key_name'], 'k')
        self.assertEqual(row['request_body'], {'limit': 10})
        self.assertEqual(row['response_body'], {'count': 0})
        self.assertFalse(McpSession.objects.filter(events__id=row['id']).exists())
