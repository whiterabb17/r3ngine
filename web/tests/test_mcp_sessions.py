from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role

from mcp.keys import display_prefix, generate_mcp_secret, hash_mcp_secret
from mcp.models import McpAgentBan, McpApiKey, McpAuditEvent, McpSession

User = get_user_model()

AGENT_A = 'a' * 64
AGENT_B = 'b' * 64


def agent_body(agent_id=AGENT_A, **extra):
    payload = {
        'transport': 'stdio',
        'client_name': 'cursor',
        'client_version': '1.0.0',
        'agent_id': agent_id,
        'provider': 'cursor',
        'ide': 'cursor',
        'device_id': 'machine-guid',
        'os': 'win32-x64',
        'hostname': 'dev-box',
        'username': 'lizelle',
    }
    payload.update(extra)
    return payload


class McpSessionTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='sess', password='x')
        assign_role(self.user, 'penetration_tester')
        self.admin = User.objects.create_user(username='sess-admin', password='x')
        assign_role(self.admin, 'sys_admin')
        self.secret = generate_mcp_secret()
        self.key = McpApiKey.objects.create(
            user=self.user,
            name='cursor',
            prefix=display_prefix(self.secret),
            key_hash=hash_mcp_secret(self.secret),
        )
        self.mcp = APIClient()
        self.mcp.credentials(HTTP_AUTHORIZATION=f'Bearer {self.secret}')
        self.ui = APIClient()
        self.ui.force_authenticate(user=self.user)
        self.ui.force_login(self.user)
        self.admin_ui = APIClient()
        self.admin_ui.force_authenticate(user=self.admin)
        self.admin_ui.force_login(self.admin)

    def test_open_session_returns_id(self):
        res = self.mcp.post('/api/mcp/sessions/', agent_body(), format='json')
        self.assertEqual(res.status_code, 201)
        self.assertTrue(McpSession.objects.filter(pk=res.json()['session_id']).exists())
        self.assertEqual(res.json()['agent_id'], AGENT_A)

    def test_reconnect_reuses_the_same_agent_session(self):
        first = self.mcp.post('/api/mcp/sessions/', agent_body(), format='json').json()
        second = self.mcp.post('/api/mcp/sessions/', agent_body(), format='json')
        self.assertEqual(second.status_code, 200)
        self.assertTrue(second.json()['reused'])
        self.assertEqual(second.json()['session_id'], first['session_id'])
        self.assertEqual(McpSession.objects.filter(agent_id=AGENT_A).count(), 1)
        listed = self.ui.get('/api/mcp/sessions/')
        self.assertEqual(listed.json()['count'], 1)
        item = listed.json()['items'][0]
        self.assertEqual(item['key_name'], 'cursor')
        self.assertEqual(item['provider'], 'cursor')
        self.assertEqual(item['hostname'], 'dev-box')

    def test_heartbeat_unknown_session_is_401(self):
        res = self.mcp.post(
            '/api/mcp/sessions/00000000-0000-0000-0000-000000000000/heartbeat/',
            format='json',
            HTTP_X_MCP_SESSION_ID='00000000-0000-0000-0000-000000000000',
        )
        self.assertEqual(res.status_code, 401)

    def test_ban_blocks_reconnect_with_same_fingerprint(self):
        sid = self.mcp.post('/api/mcp/sessions/', agent_body(), format='json').json()['session_id']
        rev = self.ui.post(f'/api/mcp/sessions/{sid}/revoke/', format='json')
        self.assertEqual(rev.status_code, 200)
        hb = self.mcp.post(
            f'/api/mcp/sessions/{sid}/heartbeat/',
            format='json',
            HTTP_X_MCP_SESSION_ID=str(sid),
        )
        self.assertEqual(hb.status_code, 401)
        blocked = self.mcp.post('/api/mcp/sessions/', agent_body(), format='json')
        self.assertEqual(blocked.status_code, 403)
        other = self.mcp.post('/api/mcp/sessions/', agent_body(AGENT_B, hostname='other-box'), format='json')
        self.assertEqual(other.status_code, 201)

    def test_pentester_cannot_delete_agent(self):
        self.mcp.post('/api/mcp/sessions/', agent_body(), format='json')
        res = self.ui.delete(f'/api/mcp/agents/{AGENT_A}/', {'persist_ban': True}, format='json')
        self.assertEqual(res.status_code, 403)

    def test_admin_delete_can_persist_or_clear_ban(self):
        sid = self.mcp.post('/api/mcp/sessions/', agent_body(), format='json').json()['session_id']
        self.ui.post(f'/api/mcp/sessions/{sid}/revoke/', format='json')
        self.assertTrue(McpAgentBan.objects.filter(agent_id=AGENT_A).exists())
        self.assertTrue(McpAuditEvent.objects.filter(session__agent_id=AGENT_A).exists())
        deleted = self.admin_ui.delete(
            f'/api/mcp/agents/{AGENT_A}/', {'persist_ban': True}, format='json'
        )
        self.assertEqual(deleted.status_code, 200)
        self.assertTrue(deleted.json()['persist_ban'])
        self.assertFalse(McpAuditEvent.objects.filter(session__agent_id=AGENT_A).exists())
        self.assertTrue(McpAgentBan.objects.filter(agent_id=AGENT_A).exists())
        still_banned = self.mcp.post('/api/mcp/sessions/', agent_body(), format='json')
        self.assertEqual(still_banned.status_code, 403)

        fresh = self.mcp.post('/api/mcp/sessions/', agent_body(AGENT_B), format='json')
        self.assertEqual(fresh.status_code, 201)
        unban = self.admin_ui.delete(
            f'/api/mcp/agents/{AGENT_B}/', {'persist_ban': False}, format='json'
        )
        self.assertEqual(unban.status_code, 200)
        self.assertTrue(unban.json()['unbanned'])
        again = self.mcp.post('/api/mcp/sessions/', agent_body(AGENT_B), format='json')
        self.assertIn(again.status_code, (200, 201))
