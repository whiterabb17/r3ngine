"""Remote worker registration and heartbeat authentication."""
import importlib
from types import SimpleNamespace

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role

from reNgine.utils.request import client_ip
from reNgine.utils.secret_tokens import hash_token
from scanEngine.models import WORKER_TOKEN_PREFIX, ScanWorker

WORKERS_URL = '/api/workers/'
HEARTBEAT_URL = '/api/settings/workers/heartbeat/'


def _client_for(role: str) -> APIClient:
    user = User.objects.create_user(username=f'user-{role}', password='x')
    assign_role(user, role)
    client = APIClient()
    # LoginRequiredMiddleware checks the session before DRF authenticates.
    client.force_login(user)
    return client


class ScanWorkerApiTests(TestCase):

    def test_sys_admin_creates_worker_and_sees_token_once(self):
        client = _client_for('sys_admin')

        resp = client.post(WORKERS_URL, {'name': 'worker-eu-1'}, format='json')

        self.assertEqual(resp.status_code, 201, resp.data)
        token = resp.data['auth_token']
        self.assertTrue(token.startswith(WORKER_TOKEN_PREFIX))
        worker = ScanWorker.objects.get(name='worker-eu-1')
        self.assertEqual(worker.auth_token_hash, hash_token(token))
        self.assertEqual(worker.task_queue, 'worker-eu-1')

        listed = client.get(WORKERS_URL).data
        rows = listed['results'] if isinstance(listed, dict) else listed
        self.assertEqual(len(rows), 1)
        self.assertNotIn('auth_token', rows[0])
        self.assertNotIn('auth_token_hash', rows[0])

    def test_client_supplied_token_is_ignored(self):
        client = _client_for('sys_admin')

        resp = client.post(WORKERS_URL, {'name': 'w', 'auth_token': 'chosen-by-client'}, format='json')

        self.assertEqual(resp.status_code, 201, resp.data)
        self.assertNotEqual(resp.data['auth_token'], 'chosen-by-client')

    def test_auditor_can_list_but_not_create(self):
        client = _client_for('auditor')

        self.assertEqual(client.get(WORKERS_URL).status_code, 200)
        self.assertEqual(client.post(WORKERS_URL, {'name': 'w'}, format='json').status_code, 403)

    def test_penetration_tester_cannot_create_or_delete(self):
        worker = ScanWorker.objects.create(name='w', task_queue='w', auth_token_hash=hash_token('t'))
        client = _client_for('penetration_tester')

        self.assertEqual(client.post(WORKERS_URL, {'name': 'x'}, format='json').status_code, 403)
        self.assertEqual(client.delete(f'{WORKERS_URL}{worker.id}/').status_code, 403)
        self.assertTrue(ScanWorker.objects.filter(pk=worker.pk).exists())


class WorkerHeartbeatTests(TestCase):

    def setUp(self):
        self.worker = ScanWorker.objects.create(
            name='worker-1', task_queue='worker-1', auth_token_hash=hash_token('secret-token'),
        )
        self.client = APIClient()

    def test_valid_token_records_heartbeat_and_real_ip(self):
        resp = self.client.post(
            HEARTBEAT_URL,
            {'worker_name': 'worker-1', 'token': 'secret-token'},
            format='json',
            HTTP_X_REAL_IP='198.51.100.7',
            HTTP_X_FORWARDED_FOR='203.0.113.99, 198.51.100.7',
        )

        self.assertEqual(resp.status_code, 200)
        self.worker.refresh_from_db()
        self.assertIsNotNone(self.worker.last_heartbeat)
        # The spoofable left-most X-Forwarded-For entry is not trusted.
        self.assertEqual(self.worker.ip_address, '198.51.100.7')

    def test_wrong_token_is_rejected(self):
        resp = self.client.post(
            HEARTBEAT_URL, {'worker_name': 'worker-1', 'token': 'nope'}, format='json',
        )

        self.assertEqual(resp.status_code, 403)
        self.worker.refresh_from_db()
        self.assertIsNone(self.worker.last_heartbeat)

    def test_token_hash_is_not_accepted_as_token(self):
        resp = self.client.post(
            HEARTBEAT_URL,
            {'worker_name': 'worker-1', 'token': self.worker.auth_token_hash},
            format='json',
        )

        self.assertEqual(resp.status_code, 403)

    def test_non_string_token_is_bad_request(self):
        resp = self.client.post(
            HEARTBEAT_URL, {'worker_name': 'worker-1', 'token': ['secret-token']}, format='json',
        )

        self.assertEqual(resp.status_code, 400)

    def test_inactive_worker_is_rejected(self):
        self.worker.is_active = False
        self.worker.save(update_fields=['is_active'])

        resp = self.client.post(
            HEARTBEAT_URL,
            {'worker_name': 'worker-1', 'token': 'secret-token'},
            format='json',
        )

        self.assertEqual(resp.status_code, 403)
        self.worker.refresh_from_db()
        self.assertIsNone(self.worker.last_heartbeat)


class ClientIpTests(SimpleTestCase):

    def test_prefers_x_real_ip(self):
        request = SimpleNamespace(META={'HTTP_X_REAL_IP': '192.0.2.1', 'REMOTE_ADDR': '10.0.0.2'})
        self.assertEqual(client_ip(request), '192.0.2.1')

    def test_strips_port_from_remote_addr(self):
        request = SimpleNamespace(META={'REMOTE_ADDR': '192.0.2.5:51234'})
        self.assertEqual(client_ip(request), '192.0.2.5')

    def test_unwraps_bracketed_ipv6(self):
        request = SimpleNamespace(META={'REMOTE_ADDR': '[2001:db8::1]:443'})
        self.assertEqual(client_ip(request), '2001:db8::1')

    def test_missing_address_is_none(self):
        self.assertIsNone(client_ip(SimpleNamespace(META={})))


class HashExistingTokensMigrationTests(SimpleTestCase):

    def test_existing_plaintext_tokens_are_hashed(self):
        migration = importlib.import_module('scanEngine.migrations.0019_scanworker_hash_auth_token')
        saved = []

        class FakeWorker:
            auth_token = 'legacy-token'
            auth_token_hash = None

            def save(self, update_fields):
                saved.append(update_fields)

        worker = FakeWorker()
        fake_apps = SimpleNamespace(
            get_model=lambda *_: SimpleNamespace(objects=SimpleNamespace(all=lambda: [worker])),
        )

        migration.hash_existing_tokens(fake_apps, None)

        self.assertEqual(worker.auth_token_hash, hash_token('legacy-token'))
        self.assertEqual(saved, [['auth_token_hash']])

    def test_null_or_empty_tokens_get_unique_placeholder_hashes(self):
        migration = importlib.import_module('scanEngine.migrations.0019_scanworker_hash_auth_token')
        saved = []

        class FakeWorker:
            def __init__(self, pk, token):
                self.pk = pk
                self.auth_token = token
                self.auth_token_hash = None

            def save(self, update_fields):
                saved.append((self.pk, update_fields, self.auth_token_hash))

        empty = FakeWorker(1, '')
        missing = FakeWorker(2, None)
        fake_apps = SimpleNamespace(
            get_model=lambda *_: SimpleNamespace(
                objects=SimpleNamespace(all=lambda: [empty, missing]),
            ),
        )

        migration.hash_existing_tokens(fake_apps, None)

        self.assertEqual(len(empty.auth_token_hash), 64)
        self.assertEqual(len(missing.auth_token_hash), 64)
        self.assertNotEqual(empty.auth_token_hash, missing.auth_token_hash)
        self.assertNotEqual(empty.auth_token_hash, hash_token(''))
        self.assertEqual([s[0] for s in saved], [1, 2])
