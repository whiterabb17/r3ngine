from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role

from mcp.keys import display_prefix, generate_mcp_secret, hash_mcp_secret
from mcp.models import McpApiKey, McpInstanceSettings

User = get_user_model()


class McpKeyApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='mcp-ui', password='x')
        assign_role(self.user, 'penetration_tester')
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        self.client.force_login(self.user)

    def test_generate_returns_secret_once_and_stores_hash(self):
        res = self.client.post('/api/mcp/keys/', {'name': 'cursor'}, format='json')
        self.assertEqual(res.status_code, 201)
        secret = res.json()['secret']
        self.assertTrue(secret.startswith('r3n_mcp_'))
        row = McpApiKey.objects.get(user=self.user, name='cursor')
        self.assertEqual(row.key_hash, hash_mcp_secret(secret))
        listed = self.client.get('/api/mcp/keys/')
        self.assertNotIn(secret, str(listed.json()))
        self.assertIn(row.prefix, str(listed.json()))

    def test_regenerate_invalidates_old_secret(self):
        first = self.client.post('/api/mcp/keys/', {'name': 'a'}, format='json').json()
        key_id = first['id']
        old = first['secret']
        second = self.client.post(f'/api/mcp/keys/{key_id}/regenerate/', format='json').json()
        self.assertNotEqual(old, second['secret'])
        self.assertEqual(
            McpApiKey.objects.get(pk=key_id).key_hash,
            hash_mcp_secret(second['secret']),
        )

    def test_revoke_sets_revoked_at(self):
        created = self.client.post('/api/mcp/keys/', {'name': 'b'}, format='json').json()
        res = self.client.post(f'/api/mcp/keys/{created["id"]}/revoke/', format='json')
        self.assertEqual(res.status_code, 200)
        self.assertIsNotNone(McpApiKey.objects.get(pk=created['id']).revoked_at)


class McpSettingsApiTests(TestCase):
    def setUp(self):
        self.admin = User.objects.create_user(username='mcp-admin', password='x')
        assign_role(self.admin, 'sys_admin')
        self.pentester = User.objects.create_user(username='mcp-pt', password='x')
        assign_role(self.pentester, 'penetration_tester')

    def _login(self, user):
        client = APIClient()
        client.force_authenticate(user=user)
        client.force_login(user)
        return client

    def test_pentester_cannot_patch_transport(self):
        res = self._login(self.pentester).patch(
            '/api/mcp/settings/', {'transport_mode': 'http'}, format='json'
        )
        self.assertEqual(res.status_code, 403)

    def test_admin_can_patch_transport(self):
        res = self._login(self.admin).patch(
            '/api/mcp/settings/', {'transport_mode': 'both'}, format='json'
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(McpInstanceSettings.get_solo().transport_mode, 'both')

    def test_admin_mcp_key_cannot_patch_transport(self):
        secret = generate_mcp_secret()
        McpApiKey.objects.create(
            user=self.admin,
            name='agent',
            prefix=display_prefix(secret),
            key_hash=hash_mcp_secret(secret),
        )
        mcp = APIClient()
        mcp.credentials(HTTP_AUTHORIZATION=f'Bearer {secret}')
        res = mcp.patch('/api/mcp/settings/', {'transport_mode': 'http'}, format='json')
        self.assertIn(res.status_code, (401, 403))
        self.assertNotEqual(McpInstanceSettings.get_solo().transport_mode, 'http')
