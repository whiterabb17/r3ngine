"""OSINT staging agent verify + operator bulk actions."""
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role

from dashboard.models import Project
from mcp.keys import display_prefix, generate_mcp_secret, hash_mcp_secret
from mcp.models import McpApiKey
from reNgine.definitions import SUCCESS_TASK
from scanEngine.models import EngineType
from startScan.models import OsintStaging, ScanHistory
from targetApp.models import Domain

User = get_user_model()


def mcp_client_with_session(user):
    secret = generate_mcp_secret()
    McpApiKey.objects.create(
        user=user,
        name='osint-k',
        prefix=display_prefix(secret),
        key_hash=hash_mcp_secret(secret),
    )
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f'Bearer {secret}')
    sid = client.post('/api/mcp/sessions/', {
        'transport': 'stdio',
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


class OsintStagingVerifyTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='osint-v', password='x')
        assign_role(self.user, 'penetration_tester')
        self.project = Project.objects.create(
            name='OSINT', slug='osint-project', insert_date=timezone.now(),
        )
        self.engine = EngineType.objects.create(engine_name='OE', yaml_configuration='')
        self.domain = Domain.objects.create(
            name='osint.example.com', project=self.project, insert_date=timezone.now(),
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=SUCCESS_TASK,
            start_scan_date=timezone.now(),
            tasks=['osint', 'spiderfoot_scan'],
        )
        self.row_keep = OsintStaging.objects.create(
            scan_history=self.scan,
            target_domain=self.domain,
            osint_type='Employee',
            content='Rare Unique Name',
            source='theHarvester',
            confidence=80,
            status='pending',
        )
        self.row_noise = OsintStaging.objects.create(
            scan_history=self.scan,
            target_domain=self.domain,
            osint_type='Employee',
            content='John',
            source='spiderfoot',
            confidence=20,
            status='pending',
        )
        self.row_other = OsintStaging.objects.create(
            scan_history=self.scan,
            target_domain=self.domain,
            osint_type='Email',
            content='info@osint.example.com',
            source='crawled',
            confidence=50,
            status='pending',
        )

    def test_mcp_list_staging_pending(self):
        client = mcp_client_with_session(self.user)
        res = client.get('/api/mcp/osint-staging/', {'scan_id': self.scan.id})
        self.assertEqual(res.status_code, 200, res.content)
        body = res.json()
        self.assertGreaterEqual(body['total_count'], 3)
        ids = {item['id'] for item in body['items']}
        self.assertIn(self.row_keep.id, ids)

    def test_mcp_verify_sets_flags(self):
        client = mcp_client_with_session(self.user)
        res = client.post('/api/mcp/osint-staging/verify/', {
            'scan_id': self.scan.id,
            'updates': [
                {'id': self.row_keep.id, 'agent_verified': True},
                {'id': self.row_noise.id, 'agent_verified': False},
            ],
        }, format='json')
        self.assertEqual(res.status_code, 200, res.content)
        self.row_keep.refresh_from_db()
        self.row_noise.refresh_from_db()
        self.row_other.refresh_from_db()
        self.assertIs(self.row_keep.agent_verified, True)
        self.assertIs(self.row_noise.agent_verified, False)
        self.assertIsNone(self.row_other.agent_verified)
        self.assertIsNotNone(self.row_keep.agent_verified_at)

    def test_mcp_verify_requires_scan_id_and_scopes_rows(self):
        other_domain = Domain.objects.create(
            name='other-osint.example.com', project=self.project, insert_date=timezone.now(),
        )
        other_scan = ScanHistory.objects.create(
            domain=other_domain,
            scan_type=self.engine,
            scan_status=SUCCESS_TASK,
            start_scan_date=timezone.now(),
            tasks=['osint'],
        )
        other_row = OsintStaging.objects.create(
            scan_history=other_scan,
            target_domain=other_domain,
            osint_type='Employee',
            content='Other Scan Person',
            source='theHarvester',
            confidence=70,
            status='pending',
        )
        client = mcp_client_with_session(self.user)
        missing = client.post('/api/mcp/osint-staging/verify/', {
            'updates': [{'id': self.row_keep.id, 'agent_verified': True}],
        }, format='json')
        self.assertEqual(missing.status_code, 400, missing.content)

        res = client.post('/api/mcp/osint-staging/verify/', {
            'scan_id': self.scan.id,
            'updates': [
                {'id': self.row_keep.id, 'agent_verified': True},
                {'id': other_row.id, 'agent_verified': True},
            ],
        }, format='json')
        self.assertEqual(res.status_code, 200, res.content)
        body = res.json()
        self.assertEqual(body['updated_count'], 1)
        self.assertEqual(body['updated'][0]['id'], self.row_keep.id)
        other_row.refresh_from_db()
        self.assertIsNone(other_row.agent_verified)

    def test_clear_all_pending(self):
        client = APIClient()
        client.force_authenticate(user=self.user)
        client.force_login(self.user)
        res = client.post('/api/osintStaging/clear_all/', {'scan_id': self.scan.id}, format='json')
        self.assertEqual(res.status_code, 200, res.content)
        self.assertEqual(
            OsintStaging.objects.filter(scan_history=self.scan, status='pending').count(),
            0,
        )

    def test_add_verified_and_clear_fp(self):
        self.row_keep.agent_verified = True
        self.row_keep.save(update_fields=['agent_verified'])
        self.row_noise.agent_verified = False
        self.row_noise.save(update_fields=['agent_verified'])

        client = APIClient()
        client.force_authenticate(user=self.user)
        client.force_login(self.user)

        with self.settings(DEBUG=True):
            # persist_osint_item may touch DB heavily; still assert status flip for verified
            res = client.post(
                '/api/osintStaging/add_verified/',
                {'scan_id': self.scan.id},
                format='json',
            )
        self.assertEqual(res.status_code, 200, res.content)
        self.row_keep.refresh_from_db()
        self.assertEqual(self.row_keep.status, 'validated')

        res_fp = client.post(
            '/api/osintStaging/clear_false_positives/',
            {'scan_id': self.scan.id},
            format='json',
        )
        self.assertEqual(res_fp.status_code, 200, res_fp.content)
        self.assertFalse(OsintStaging.objects.filter(pk=self.row_noise.id).exists())
        self.assertTrue(OsintStaging.objects.filter(pk=self.row_other.id).exists())
