"""Tests for reNgine.ollama_manager and the Ollama/Tor service endpoints.

Ollama and Tor are compose services the app never starts or stops; the
endpoints report reachability and how to enable them. HTTP and sockets are
mocked.
"""
from unittest.mock import MagicMock, patch

import requests
from django.contrib.auth import get_user_model
from django.test import SimpleTestCase, TestCase
from django.utils import timezone
from rolepermissions.roles import assign_role

from dashboard.models import Project
from reNgine.ollama_manager import OLLAMA_ENABLE_HINT, OLLAMA_STOP_HINT, OllamaManager, OllamaUnavailableError
from scanEngine.models import Proxy


def _response(status_code=200, payload=None):
    response = MagicMock()
    response.status_code = status_code
    response.json.return_value = payload if payload is not None else {}
    return response


class OllamaManagerTests(SimpleTestCase):

    @patch('reNgine.ollama_manager.requests.get', return_value=_response(200, {'version': '0.5.1'}))
    def test_running_when_version_endpoint_answers(self, get):
        manager = OllamaManager('http://ollama.test:11434/')
        self.assertTrue(manager.is_running())
        get.assert_called_with('http://ollama.test:11434/api/version', timeout=3.0)
        status = manager.status()
        self.assertEqual(status, {'running': True, 'url': 'http://ollama.test:11434', 'version': '0.5.1', 'hint': None})

    @patch('reNgine.ollama_manager.requests.get', side_effect=requests.ConnectionError('refused'))
    def test_not_running_when_connection_fails(self, _get):
        status = OllamaManager().status()
        self.assertFalse(status['running'])
        self.assertIsNone(status['version'])
        self.assertEqual(status['hint'], OLLAMA_ENABLE_HINT)
        self.assertIn('COMPOSE_PROFILES=ollama', status['hint'])

    @patch('reNgine.ollama_manager.requests.get', return_value=_response(502))
    def test_not_running_on_non_200(self, _get):
        self.assertFalse(OllamaManager().is_running())

    @patch('reNgine.ollama_manager.requests.get', side_effect=requests.ConnectionError('refused'))
    def test_require_running_raises_with_hint(self, _get):
        with self.assertRaises(OllamaUnavailableError) as ctx:
            OllamaManager().require_running()
        self.assertEqual(str(ctx.exception), OLLAMA_ENABLE_HINT)

    def test_no_docker_client_anywhere(self):
        import reNgine.ollama_manager as module
        self.assertFalse(hasattr(module, 'docker'))
        self.assertFalse(hasattr(OllamaManager, 'start'))
        self.assertFalse(hasattr(OllamaManager, 'stop'))


class ServiceEndpointTests(TestCase):

    def setUp(self):
        User = get_user_model()
        self.user = User.objects.create_user(username='svc-admin', password='x')
        assign_role(self.user, 'sys_admin')
        self.project = Project.objects.create(name='Svc', slug='svc-project', insert_date=timezone.now())
        self.client.force_login(self.user)

    def test_ollama_status_reports_hint_when_down(self):
        with patch('reNgine.ollama_manager.requests.get', side_effect=requests.ConnectionError('refused')):
            res = self.client.get('/scanEngine/svc-project/ollama/service_status', HTTP_ACCEPT='application/json')
        self.assertEqual(res.status_code, 200, res.content)
        body = res.json()
        self.assertEqual(body['status'], 'success')
        self.assertFalse(body['running'])
        self.assertEqual(body['hint'], OLLAMA_ENABLE_HINT)

    def test_ollama_start_is_refused_with_enable_hint(self):
        with patch('reNgine.ollama_manager.requests.get', side_effect=requests.ConnectionError('refused')):
            res = self.client.post('/scanEngine/svc-project/ollama/service_start', HTTP_ACCEPT='application/json')
        self.assertEqual(res.status_code, 503, res.content)
        self.assertEqual(res.json()['message'], OLLAMA_ENABLE_HINT)

    def test_ollama_start_reports_already_running(self):
        with patch('reNgine.ollama_manager.requests.get', return_value=_response(200, {'version': '0.5.1'})):
            res = self.client.post('/scanEngine/svc-project/ollama/service_start', HTTP_ACCEPT='application/json')
        self.assertEqual(res.status_code, 200, res.content)
        self.assertEqual(res.json()['status'], 'success')

    def test_ollama_stop_explains_the_host_command(self):
        res = self.client.post('/scanEngine/svc-project/ollama/service_stop', HTTP_ACCEPT='application/json')
        self.assertEqual(res.status_code, 501, res.content)
        self.assertEqual(res.json()['message'], OLLAMA_STOP_HINT)

    def test_tor_status_endpoint_returns_status_payload(self):
        with patch('reNgine.tor_manager.socket.create_connection', side_effect=ConnectionRefusedError()):
            res = self.client.get('/api/rengine/tor-status/', HTTP_ACCEPT='application/json')
        self.assertEqual(res.status_code, 200, res.content)
        body = res.json()
        self.assertFalse(body['running'])
        self.assertIn('COMPOSE_PROFILES=tor', body['hint'])

    def test_enabling_tor_mode_is_refused_while_tor_is_down(self):
        with patch('reNgine.tor_manager.socket.create_connection', side_effect=ConnectionRefusedError()):
            res = self.client.post(
                '/scanEngine/svc-project/proxy_settings',
                {'use_tor': 'on', 'proxies': '', 'priority_proxies': ''},
                HTTP_ACCEPT='application/json',
            )
        self.assertEqual(res.status_code, 503, res.content)
        self.assertIn('COMPOSE_PROFILES=tor', res.json()['message'])
        self.assertFalse(Proxy.objects.get().use_tor)

    def test_enabling_tor_mode_succeeds_when_tor_answers(self):
        connection = MagicMock()
        connection.__enter__ = MagicMock(return_value=connection)
        connection.__exit__ = MagicMock(return_value=False)
        with patch('reNgine.tor_manager.socket.create_connection', return_value=connection):
            res = self.client.post(
                '/scanEngine/svc-project/proxy_settings',
                {'use_tor': 'on', 'proxies': '', 'priority_proxies': ''},
                HTTP_ACCEPT='application/json',
            )
        self.assertEqual(res.status_code, 200, res.content)
        self.assertEqual(res.json()['status'], 'success')
        self.assertTrue(Proxy.objects.get().use_tor)

    def test_disabling_tor_mode_needs_no_probe(self):
        Proxy.objects.create(use_tor=True)
        with patch('reNgine.tor_manager.socket.create_connection') as create_connection:
            res = self.client.post(
                '/scanEngine/svc-project/proxy_settings',
                {'proxies': '', 'priority_proxies': ''},
                HTTP_ACCEPT='application/json',
            )
        self.assertEqual(res.status_code, 200, res.content)
        create_connection.assert_not_called()
        self.assertFalse(Proxy.objects.get().use_tor)
