from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.db import DatabaseError
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role

from dashboard.models import Project
from mcp.keys import display_prefix, generate_mcp_secret, hash_mcp_secret
from mcp.models import McpApiKey, McpAuditEvent
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Vulnerability
from targetApp.models import Domain

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


class McpReadTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='mcp-read', password='x')
        assign_role(self.user, 'auditor')
        self.project = Project.objects.create(
            name='Read Project',
            slug='read-project',
            insert_date=timezone.now(),
        )
        self.engine = EngineType.objects.create(engine_name='Default', yaml_configuration='')
        self.domain = Domain.objects.create(
            name='example.com',
            project=self.project,
            insert_date=timezone.now(),
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=2,
            start_scan_date=timezone.now(),
        )
        self.client, self.sid = mcp_client_with_session(self.user)

    def test_health_requires_session(self):
        secret = generate_mcp_secret()
        McpApiKey.objects.create(
            user=self.user,
            name='nosess',
            prefix=display_prefix(secret),
            key_hash=hash_mcp_secret(secret),
        )
        bare = APIClient()
        bare.credentials(HTTP_AUTHORIZATION=f'Bearer {secret}')
        res = bare.get('/api/mcp/health/')
        self.assertEqual(res.status_code, 401)

    def test_failed_audit_write_is_logged_not_swallowed(self):
        with patch('mcp.views.audit.write_audit_event', side_effect=DatabaseError('audit table locked')), \
                self.assertLogs('mcp.views.audit', level='ERROR') as logs:
            res = self.client.get('/api/mcp/targets/?project_slug=read-project')
        # The tool call itself still answers; the lost audit row is on record.
        self.assertEqual(res.status_code, 200)
        self.assertIn('MCP audit write failed for GET /api/mcp/targets/', logs.output[0])
        self.assertNotIn('audit table locked', res.content.decode())

    def test_list_targets_and_audit_tool_name(self):
        res = self.client.get('/api/mcp/targets/?project_slug=read-project')
        self.assertEqual(res.status_code, 200)
        names = [item['name'] for item in res.json()['items']]
        self.assertIn('example.com', names)
        self.assertTrue(
            McpAuditEvent.objects.filter(
                session_id=self.sid,
                tool_name='r3ngine_list_targets',
            ).exists()
        )

    def test_list_scans_and_health(self):
        scans = self.client.get('/api/mcp/scans/?project_slug=read-project')
        self.assertEqual(scans.status_code, 200)
        self.assertEqual(scans.json()['items'][0]['id'], self.scan.id)
        health = self.client.get('/api/mcp/health/')
        self.assertEqual(health.status_code, 200)
        self.assertEqual(health.json()['database']['status'], 'up')
        self.assertNotIn('results_dir', str(scans.json()))

    def test_list_vulnerabilities_filters_severity(self):
        Vulnerability.objects.create(
            name='SQLi',
            severity=3,
            scan_history=self.scan,
            target_domain=self.domain,
        )
        Vulnerability.objects.create(
            name='Info',
            severity=0,
            scan_history=self.scan,
            target_domain=self.domain,
        )
        res = self.client.get('/api/mcp/vulnerabilities/?scan_id=%s&severity=3' % self.scan.id)
        self.assertEqual(res.status_code, 200)
        names = [item['name'] for item in res.json()['items']]
        self.assertEqual(names, ['SQLi'])
        self.assertNotIn('curl_command', str(res.json()))
        self.assertNotIn('password', str(res.json()))

    def test_search_paginates_across_types(self):
        Vulnerability.objects.create(
            name='example xss',
            severity=2,
            scan_history=self.scan,
            target_domain=self.domain,
        )
        first = self.client.get('/api/mcp/search/?query=example&limit=1&offset=0')
        self.assertEqual(first.status_code, 200)
        body = first.json()
        self.assertEqual(body['total_count'], 3)
        self.assertEqual(body['count'], 1)
        self.assertTrue(body['has_more'])
        self.assertEqual(body['next_offset'], 1)
        self.assertEqual(body['items'][0]['type'], 'target')

        second = self.client.get('/api/mcp/search/?query=example&limit=1&offset=1')
        self.assertEqual(second.json()['items'][0]['type'], 'scan')
        third = self.client.get('/api/mcp/search/?query=example&limit=1&offset=2')
        self.assertEqual(third.json()['items'][0]['type'], 'vulnerability')
        done = self.client.get('/api/mcp/search/?query=example&limit=1&offset=3')
        self.assertEqual(done.json()['items'], [])
        self.assertFalse(done.json()['has_more'])
