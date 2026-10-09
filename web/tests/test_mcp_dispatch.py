from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework.response import Response
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role

from dashboard.models import Project
from mcp.keys import display_prefix, generate_mcp_secret, hash_mcp_secret
from mcp.models import McpApiKey
from scanEngine.models import EngineType
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
    return client


class McpDispatchTests(TestCase):
    def setUp(self):
        self.project = Project.objects.create(
            name='Dispatch Project',
            slug='dispatch-project',
            insert_date=timezone.now(),
        )
        self.engine = EngineType.objects.create(engine_name='Default', yaml_configuration='')
        self.domain = Domain.objects.create(
            name='dispatch.example.com',
            project=self.project,
            insert_date=timezone.now(),
        )

    def _user(self, username, role):
        user = User.objects.create_user(username=username, password='x')
        assign_role(user, role)
        return user

    def test_auditor_start_scan_403(self):
        client = mcp_client_with_session(self._user('aud', 'auditor'))
        res = client.post(
            '/api/mcp/scans/start/',
            {'domain_id': self.domain.id, 'engine_id': self.engine.id},
            format='json',
        )
        self.assertEqual(res.status_code, 403)

    @patch('mcp.views.dispatch.InitiateScan.post', return_value=Response({'ok': True}, status=200))
    def test_pentester_start_scan_calls_wrapper(self, mocked):
        client = mcp_client_with_session(self._user('pt', 'penetration_tester'))
        res = client.post(
            '/api/mcp/scans/start/',
            {'domain_id': self.domain.id, 'engine_id': self.engine.id},
            format='json',
        )
        self.assertEqual(res.status_code, 200)
        mocked.assert_called()

    def test_auditor_email_discovery_403(self):
        client = mcp_client_with_session(self._user('aud2', 'auditor'))
        res = client.post('/api/mcp/email-discovery/start/', {'scan_id': 1}, format='json')
        self.assertEqual(res.status_code, 403)

    @patch(
        'mcp.views.dispatch.StartEmailDiscoveryView.post',
        return_value=Response({'job_id': 'j1'}, status=202),
    )
    def test_pentester_email_discovery_calls_wrapper(self, mocked):
        client = mcp_client_with_session(self._user('pt2', 'penetration_tester'))
        res = client.post('/api/mcp/email-discovery/start/', {'scan_id': 1}, format='json')
        self.assertEqual(res.status_code, 202)
        mocked.assert_called()

    @patch(
        'mcp.views.dispatch.UnpauseScan.post',
        return_value=Response({'status': True, 'resumed_count': 1}, status=200),
    )
    def test_resume_scan_unpauses_and_maps_scan_id(self, mocked):
        client = mcp_client_with_session(self._user('pt3', 'penetration_tester'))
        res = client.post('/api/mcp/scans/resume/', {'scan_id': 42}, format='json')
        self.assertEqual(res.status_code, 200)
        mocked.assert_called()
        request = mocked.call_args[0][0]
        self.assertEqual(list(request.data.get('scan_ids')), [42])
