from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role

from mcp.keys import display_prefix, generate_mcp_secret, hash_mcp_secret
from mcp.models import McpApiKey
from mcp.plugins_gate import mcp_tools_from_manifest, serialize_plugin
from mcp.tool_map import tool_name_for
from plugins.models import Plugin

User = get_user_model()


def mcp_client_with_session(user, transport='stdio'):
    secret = generate_mcp_secret()
    McpApiKey.objects.create(
        user=user,
        name='k',
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
    return client, sid


class McpPluginDiscoveryTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='mcp-plugins', password='x')
        assign_role(self.user, 'auditor')
        self.client, self.sid = mcp_client_with_session(self.user)

    def test_list_plugins_empty(self):
        res = self.client.get('/api/mcp/plugins/')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['results'], [])

    def test_list_plugins_only_enabled(self):
        Plugin.objects.create(
            name='AD Intelligence',
            slug='active_directory',
            version='1.1.1',
            is_enabled=True,
            anchor_step='standalone',
            manifest={
                'mcp': {
                    'tools': [
                        'r3ngine_list_ad_assessments',
                        'r3ngine_get_ad_report',
                    ],
                },
            },
        )
        Plugin.objects.create(
            name='Disabled',
            slug='disabled_plugin',
            version='0.1.0',
            is_enabled=False,
            anchor_step='standalone',
            manifest={'mcp': {'tools': ['r3ngine_never']}},
        )
        res = self.client.get('/api/mcp/plugins/')
        self.assertEqual(res.status_code, 200)
        results = res.json()['results']
        self.assertEqual(len(results), 1)
        self.assertEqual(results[0]['slug'], 'active_directory')
        self.assertEqual(
            results[0]['mcp_tools'],
            ['r3ngine_list_ad_assessments', 'r3ngine_get_ad_report'],
        )

    def test_get_plugin_404_when_missing(self):
        res = self.client.get('/api/mcp/plugins/active_directory/')
        self.assertEqual(res.status_code, 404)
        body = res.json()
        self.assertEqual(body['reason'], 'plugin_not_installed')
        self.assertEqual(body['slug'], 'active_directory')

    def test_get_plugin_404_when_disabled(self):
        Plugin.objects.create(
            name='AD',
            slug='active_directory',
            version='1.0.0',
            is_enabled=False,
            anchor_step='standalone',
            manifest={},
        )
        res = self.client.get('/api/mcp/plugins/active_directory/')
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['reason'], 'plugin_disabled')

    def test_get_plugin_ok(self):
        Plugin.objects.create(
            name='AD Intelligence',
            slug='active_directory',
            version='1.1.1',
            is_enabled=True,
            anchor_step='standalone',
            manifest={'mcp': {'tools': ['r3ngine_list_ad_assessments']}},
        )
        res = self.client.get('/api/mcp/plugins/active_directory/')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['slug'], 'active_directory')
        self.assertEqual(res.json()['mcp_tools'], ['r3ngine_list_ad_assessments'])

    def test_capabilities_includes_plugins(self):
        Plugin.objects.create(
            name='AD',
            slug='active_directory',
            version='1.1.1',
            is_enabled=True,
            anchor_step='standalone',
            manifest={'mcp': {'tools': ['r3ngine_get_ad_report']}},
        )
        res = self.client.get('/api/mcp/capabilities/')
        self.assertEqual(res.status_code, 200)
        plugins = res.json().get('plugins') or []
        self.assertTrue(any(p['slug'] == 'active_directory' for p in plugins))


class McpPluginGateHelpersTests(TestCase):
    def test_mcp_tools_from_manifest(self):
        self.assertEqual(mcp_tools_from_manifest(None), [])
        self.assertEqual(mcp_tools_from_manifest({}), [])
        self.assertEqual(
            mcp_tools_from_manifest({'mcp': {'tools': ['a', 'b']}}),
            ['a', 'b'],
        )

    def test_serialize_plugin(self):
        p = Plugin(
            name='X',
            slug='x',
            version='1',
            is_enabled=True,
            anchor_step='standalone',
            manifest={'mcp': {'tools': ['t1']}},
        )
        data = serialize_plugin(p)
        self.assertEqual(data['slug'], 'x')
        self.assertEqual(data['mcp_tools'], ['t1'])

    def test_tool_map_plugin_and_ad_paths(self):
        self.assertEqual(tool_name_for('GET', '/api/mcp/plugins/'), 'r3ngine_list_plugins')
        self.assertEqual(
            tool_name_for('GET', '/api/mcp/plugins/active_directory/'),
            'r3ngine_get_plugin',
        )
        self.assertEqual(
            tool_name_for('GET', '/api/mcp/ad/assessments/'),
            'r3ngine_list_ad_assessments',
        )
        self.assertEqual(
            tool_name_for('POST', '/api/mcp/ad/assessments/start/'),
            'r3ngine_start_ad_assessment',
        )
        self.assertEqual(
            tool_name_for('POST', '/api/mcp/ad/assessments/3/ingest/'),
            'r3ngine_ingest_ad_data',
        )
        self.assertEqual(
            tool_name_for('GET', '/api/mcp/ad/assessments/3/findings/'),
            'r3ngine_list_ad_findings',
        )
        self.assertEqual(
            tool_name_for('GET', '/api/mcp/ad/assessments/3/attack-paths/'),
            'r3ngine_get_ad_attack_paths',
        )
        self.assertEqual(
            tool_name_for('GET', '/api/mcp/ad/assessments/3/report/'),
            'r3ngine_get_ad_report',
        )
        self.assertEqual(
            tool_name_for('GET', '/api/mcp/ad/assessments/3/'),
            'r3ngine_get_ad_assessment',
        )


class McpAdPluginGateTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='mcp-ad', password='x')
        assign_role(self.user, 'penetration_tester')
        self.client, self.sid = mcp_client_with_session(self.user)

    def test_ad_list_404_when_plugin_missing(self):
        res = self.client.get('/api/mcp/ad/assessments/')
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['reason'], 'plugin_not_installed')

    def test_ad_list_404_when_backend_missing(self):
        Plugin.objects.create(
            name='AD',
            slug='active_directory',
            version='1.1.1',
            is_enabled=True,
            anchor_step='standalone',
            manifest={'mcp': {'tools': ['r3ngine_list_ad_assessments']}},
        )
        # Plugin row exists but plugins_data backend is not installed in test env.
        res = self.client.get('/api/mcp/ad/assessments/')
        self.assertEqual(res.status_code, 404)
        self.assertIn(res.json()['reason'], (
            'plugin_backend_missing',
            'plugin_not_installed',
        ))

    def test_ad_start_404_when_plugin_missing(self):
        res = self.client.post(
            '/api/mcp/ad/assessments/start/',
            {'target_domain': 'corp.example.local'},
            format='json',
        )
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['reason'], 'plugin_not_installed')

    def test_ad_report_404_when_plugin_missing(self):
        res = self.client.get('/api/mcp/ad/assessments/1/report/')
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['reason'], 'plugin_not_installed')


class McpOtherPluginGateTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='mcp-other', password='x')
        assign_role(self.user, 'penetration_tester')
        self.client, self.sid = mcp_client_with_session(self.user)

    def test_credential_list_404_when_missing(self):
        res = self.client.get('/api/mcp/credentials/tasks/')
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['reason'], 'plugin_not_installed')

    def test_compliance_list_404_when_missing(self):
        res = self.client.get('/api/mcp/compliance/assessments/')
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['reason'], 'plugin_not_installed')

    def test_burp_list_404_when_missing(self):
        res = self.client.get('/api/mcp/burp/issues/')
        self.assertEqual(res.status_code, 404)
        self.assertEqual(res.json()['reason'], 'plugin_not_installed')

    def test_tool_map_extra_plugin_paths(self):
        self.assertEqual(
            tool_name_for('GET', '/api/mcp/credentials/tasks/'),
            'r3ngine_list_credential_tasks',
        )
        self.assertEqual(
            tool_name_for('POST', '/api/mcp/credentials/tasks/start/'),
            'r3ngine_start_credential_task',
        )
        self.assertEqual(
            tool_name_for('GET', '/api/mcp/compliance/assessments/'),
            'r3ngine_list_compliance_assessments',
        )
        self.assertEqual(
            tool_name_for('POST', '/api/mcp/compliance/controls/9/enrich/'),
            'r3ngine_enrich_compliance_control',
        )
        self.assertEqual(
            tool_name_for('GET', '/api/mcp/burp/issues/'),
            'r3ngine_list_burp_issues',
        )
        self.assertEqual(
            tool_name_for('POST', '/api/mcp/burp/sync/import/'),
            'r3ngine_start_burp_sync',
        )
