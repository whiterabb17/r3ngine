from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role

from dashboard.models import Project
from mcp.keys import display_prefix, generate_mcp_secret, hash_mcp_secret
from mcp.models import McpApiKey
from recon_note.models import TodoNote
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain
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


class McpNotesTests(TestCase):
    def setUp(self):
        self.project = Project.objects.create(
            name='Notes Project',
            slug='notes-project',
            insert_date=timezone.now(),
        )
        self.engine = EngineType.objects.create(engine_name='Default', yaml_configuration='')
        self.domain = Domain.objects.create(
            name='notes.example.com',
            project=self.project,
            insert_date=timezone.now(),
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=2,
            start_scan_date=timezone.now(),
        )
        self.subdomain = Subdomain.objects.create(
            name='www.notes.example.com',
            scan_history=self.scan,
            target_domain=self.domain,
        )
        self.pentester = User.objects.create_user(username='notes-pt', password='x')
        assign_role(self.pentester, 'penetration_tester')
        self.auditor = User.objects.create_user(username='notes-aud', password='x')
        assign_role(self.auditor, 'auditor')
        self.pt = mcp_client_with_session(self.pentester)
        self.aud = mcp_client_with_session(self.auditor)

    def test_create_list_and_filter_by_scan(self):
        created = self.pt.post(
            '/api/mcp/notes/',
            {
                'project': 'notes-project',
                'title': 'Finding note',
                'description': 'Check TLS',
                'scan_id': self.scan.id,
                'is_important': True,
            },
            format='json',
        )
        self.assertEqual(created.status_code, 201)
        body = created.json()
        self.assertEqual(body['title'], 'Finding note')
        self.assertEqual(body['scan_id'], self.scan.id)
        self.assertEqual(body['domain_name'], 'notes.example.com')
        self.assertTrue(body['is_important'])

        listed = self.aud.get(f'/api/mcp/notes/?project=notes-project&scan_id={self.scan.id}')
        self.assertEqual(listed.status_code, 200)
        ids = [item['id'] for item in listed.json()['items']]
        self.assertIn(body['id'], ids)

        by_target = self.aud.get(f'/api/mcp/notes/?target_id={self.domain.id}')
        self.assertEqual(by_target.status_code, 200)
        self.assertIn(body['id'], [item['id'] for item in by_target.json()['items']])

    def test_create_with_subdomain_links_scan(self):
        res = self.pt.post(
            '/api/mcp/notes/',
            {
                'project': 'notes-project',
                'title': 'Host note',
                'subdomain_id': self.subdomain.id,
            },
            format='json',
        )
        self.assertEqual(res.status_code, 201)
        self.assertEqual(res.json()['subdomain_id'], self.subdomain.id)
        self.assertEqual(res.json()['scan_id'], self.scan.id)
        self.assertEqual(res.json()['subdomain_name'], 'www.notes.example.com')

    def test_update_note_fields(self):
        note = TodoNote.objects.create(
            title='Old',
            description='before',
            project=self.project,
            scan_history=self.scan,
        )
        res = self.pt.patch(
            f'/api/mcp/notes/{note.id}/',
            {
                'title': 'New title',
                'description': 'after',
                'is_done': True,
                'is_important': True,
            },
            format='json',
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['title'], 'New title')
        self.assertEqual(res.json()['description'], 'after')
        self.assertTrue(res.json()['is_done'])
        self.assertTrue(res.json()['is_important'])
        note.refresh_from_db()
        self.assertEqual(note.title, 'New title')
        self.assertTrue(note.is_done)

        got = self.aud.get(f'/api/mcp/notes/{note.id}/')
        self.assertEqual(got.status_code, 200)
        self.assertEqual(got.json()['title'], 'New title')

    def test_auditor_cannot_create_or_update(self):
        create = self.aud.post(
            '/api/mcp/notes/',
            {'project': 'notes-project', 'title': 'Nope'},
            format='json',
        )
        self.assertEqual(create.status_code, 403)
        note = TodoNote.objects.create(title='Keep', project=self.project)
        update = self.aud.patch(
            f'/api/mcp/notes/{note.id}/',
            {'title': 'Hacked'},
            format='json',
        )
        self.assertEqual(update.status_code, 403)
        note.refresh_from_db()
        self.assertEqual(note.title, 'Keep')

    def test_delete_not_allowed(self):
        note = TodoNote.objects.create(title='Stay', project=self.project)
        res = self.pt.delete(f'/api/mcp/notes/{note.id}/')
        self.assertEqual(res.status_code, 405)
        self.assertTrue(TodoNote.objects.filter(pk=note.id).exists())
