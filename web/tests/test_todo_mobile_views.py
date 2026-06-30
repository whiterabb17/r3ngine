from django.test import TestCase
from django.contrib.auth import get_user_model
from django.utils import timezone
from rest_framework.test import APIClient
from startScan.models import ScanHistory
from recon_note.models import TodoNote
from dashboard.models import Project

User = get_user_model()


class TodoMobileViewTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='testuser', password='testpass123'
        )
        self.client.force_login(self.user)
        self.project = Project.objects.create(
            name='Test Project', slug='test-project', insert_date=timezone.now()
        )
        self.note = TodoNote.objects.create(
            title='Check XSS',
            description='Verify reflected XSS on login form',
            is_done=False,
            is_important=False,
            project=self.project,
        )

    def test_list_todos_requires_auth(self):
        anon_client = APIClient()  # unauthenticated — avoids logout() middleware issue
        resp = anon_client.get('/mapi/todos/')
        self.assertEqual(resp.status_code, 401)

    def test_list_todos_filtered_by_project(self):
        other_project = Project.objects.create(name='Other', slug='other', insert_date=timezone.now())
        TodoNote.objects.create(
            title='Other note', project=other_project
        )
        resp = self.client.get('/mapi/todos/?project=test-project')
        self.assertEqual(resp.status_code, 200)
        ids = [n['id'] for n in resp.json()['todos']]
        self.assertIn(self.note.id, ids)
        self.assertEqual(len(ids), 1)

    def test_create_todo(self):
        resp = self.client.post(
            '/mapi/todos/',
            {'title': 'New note', 'description': 'desc', 'project': 'test-project'},
            content_type='application/json',
        )
        self.assertEqual(resp.status_code, 201)
        data = resp.json()
        self.assertEqual(data['title'], 'New note')
        self.assertFalse(data['is_done'])

    def test_create_todo_missing_title_returns_400(self):
        resp = self.client.post(
            '/mapi/todos/',
            {'description': 'no title', 'project': 'test-project'},
            content_type='application/json',
        )
        self.assertEqual(resp.status_code, 400)

    def test_patch_todo_toggle_done(self):
        resp = self.client.patch(
            f'/mapi/todos/{self.note.id}/',
            {'is_done': True},
            content_type='application/json',
        )
        self.assertEqual(resp.status_code, 200)
        self.note.refresh_from_db()
        self.assertTrue(self.note.is_done)

    def test_patch_todo_toggle_important(self):
        resp = self.client.patch(
            f'/mapi/todos/{self.note.id}/',
            {'is_important': True},
            content_type='application/json',
        )
        self.assertEqual(resp.status_code, 200)
        self.note.refresh_from_db()
        self.assertTrue(self.note.is_important)

    def test_delete_todo(self):
        resp = self.client.delete(f'/mapi/todos/{self.note.id}/')
        self.assertEqual(resp.status_code, 204)
        self.assertFalse(TodoNote.objects.filter(id=self.note.id).exists())

    def test_delete_todo_not_found(self):
        resp = self.client.delete('/mapi/todos/99999/')
        self.assertEqual(resp.status_code, 404)
