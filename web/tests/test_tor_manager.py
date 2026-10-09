"""Tests for reNgine.tor_manager: reachability probe, enable hint, circuit rotation.

Tor is a compose service the app never starts; the manager only checks the
SOCKS port and talks to the control port. No Docker, no network: sockets and
stem are mocked.
"""
import os
from unittest import TestCase
from unittest.mock import MagicMock, patch

from reNgine.tor_manager import (
    TOR_CONTROL_PASSWORD_ENV,
    TOR_ENABLE_HINT,
    TOR_PASSWORD_HINT,
    TorManager,
    TorUnavailableError,
)


class TestTorManagerProbe(TestCase):

    @patch('reNgine.tor_manager.socket.create_connection')
    def test_is_running_true_when_socks_port_accepts(self, create_connection):
        create_connection.return_value.__enter__ = MagicMock(return_value=MagicMock())
        create_connection.return_value.__exit__ = MagicMock(return_value=False)
        tm = TorManager(socks_host='tor.test', socks_port=19050)
        self.assertTrue(tm.is_running())
        create_connection.assert_called_once()
        self.assertEqual(create_connection.call_args[0][0], ('tor.test', 19050))

    @patch('reNgine.tor_manager.socket.create_connection', side_effect=ConnectionRefusedError())
    def test_is_running_false_when_refused(self, _create_connection):
        self.assertFalse(TorManager().is_running())

    @patch('reNgine.tor_manager.socket.create_connection', side_effect=OSError('Name or service not known'))
    def test_is_running_false_when_host_unknown(self, _create_connection):
        self.assertFalse(TorManager().is_running())

    def test_status_carries_the_enable_hint_only_while_down(self):
        tm = TorManager()
        with patch.object(tm, 'is_running', return_value=False):
            down = tm.status()
        with patch.object(tm, 'is_running', return_value=True):
            up = tm.status()
        self.assertFalse(down['running'])
        self.assertEqual(down['hint'], TOR_ENABLE_HINT)
        self.assertIn('COMPOSE_PROFILES=tor', down['hint'])
        self.assertTrue(up['running'])
        self.assertIsNone(up['hint'])
        self.assertEqual(up['host'], 'tor')
        self.assertEqual(up['port'], 9050)

    def test_require_running_raises_with_hint(self):
        tm = TorManager()
        with patch.object(tm, 'is_running', return_value=False):
            with self.assertRaises(TorUnavailableError) as ctx:
                tm.require_running()
        self.assertEqual(str(ctx.exception), TOR_ENABLE_HINT)

    def test_no_docker_client_anywhere(self):
        import reNgine.tor_manager as module
        self.assertFalse(hasattr(module, 'docker'))
        self.assertFalse(hasattr(TorManager, 'start'))
        self.assertFalse(hasattr(TorManager, 'stop'))


class TestTorManagerCircuit(TestCase):

    def test_new_circuit_requires_the_password_env(self):
        with patch.dict(os.environ, {}, clear=False):
            os.environ.pop(TOR_CONTROL_PASSWORD_ENV, None)
            with self.assertRaises(TorUnavailableError) as ctx:
                TorManager().new_circuit()
        self.assertEqual(str(ctx.exception), TOR_PASSWORD_HINT)

    def test_new_circuit_requires_tor_to_answer(self):
        tm = TorManager()
        with patch.dict(os.environ, {TOR_CONTROL_PASSWORD_ENV: 'secret'}), \
                patch.object(tm, 'is_running', return_value=False):
            with self.assertRaises(TorUnavailableError):
                tm.new_circuit()

    def test_new_circuit_authenticates_and_signals_newnym(self):
        from stem import Signal

        tm = TorManager(control_host='tor.test', control_port=19051)
        controller = MagicMock()
        from_port = MagicMock()
        from_port.return_value.__enter__ = MagicMock(return_value=controller)
        from_port.return_value.__exit__ = MagicMock(return_value=False)
        with patch.dict(os.environ, {TOR_CONTROL_PASSWORD_ENV: 'secret'}), \
                patch.object(tm, 'is_running', return_value=True), \
                patch('stem.control.Controller.from_port', from_port):
            tm.new_circuit(settle_seconds=0)
        from_port.assert_called_once_with(address='tor.test', port=19051)
        controller.authenticate.assert_called_once_with(password='secret')
        controller.signal.assert_called_once_with(Signal.NEWNYM)

    def test_new_circuit_reraises_control_port_errors(self):
        tm = TorManager()
        with patch.dict(os.environ, {TOR_CONTROL_PASSWORD_ENV: 'secret'}), \
                patch.object(tm, 'is_running', return_value=True), \
                patch('stem.control.Controller.from_port', side_effect=OSError('control port closed')):
            with self.assertRaises(OSError):
                tm.new_circuit(settle_seconds=0)
