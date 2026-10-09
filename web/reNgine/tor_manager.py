"""Reachability and circuit control for the ``tor`` compose service.

Tor is an opt-in compose service (``profiles: ["tor"]`` in
``docker/docker-compose.yml``); the application no longer creates or stops
the container and needs no Docker socket. This module only answers "is the
SOCKS port up", explains how to enable the service when it is not, and asks
the control port for a new circuit.

The control-port password is ``TOR_CONTROL_PASSWORD`` from ``.env``: compose
passes the same value to the ``tor`` service (which hashes it into its torrc)
and to the containers that call :meth:`TorManager.new_circuit`.
"""
from __future__ import annotations

import logging
import os
import socket
import time
from typing import Optional

logger = logging.getLogger(__name__)

TOR_SOCKS_HOST = 'tor'
TOR_SOCKS_PORT = 9050
TOR_CONTROL_HOST = 'tor'
TOR_CONTROL_PORT = 9051
TOR_CONTROL_PASSWORD_ENV = 'TOR_CONTROL_PASSWORD'

PROBE_TIMEOUT_SECONDS = 2.0

TOR_ENABLE_HINT = (
    "Tor is not running. It is an optional service: set COMPOSE_PROFILES=tor and "
    "TOR_CONTROL_PASSWORD in .env and run `make up` (or `make up-tor`), then enable TOR Mode again."
)
TOR_PASSWORD_HINT = (
    f"{TOR_CONTROL_PASSWORD_ENV} is not set for this container, so Tor circuits cannot be "
    "rotated. Set it in .env (the tor service uses the same value) and recreate the stack."
)


class TorUnavailableError(Exception):
    """Tor is not reachable, or cannot be controlled, from this process."""


class TorManager:
    """Status of the ``tor`` service as seen from this container."""

    def __init__(
        self,
        socks_host: str = TOR_SOCKS_HOST,
        socks_port: int = TOR_SOCKS_PORT,
        control_host: str = TOR_CONTROL_HOST,
        control_port: int = TOR_CONTROL_PORT,
    ) -> None:
        self.socks_host = socks_host
        self.socks_port = socks_port
        self.control_host = control_host
        self.control_port = control_port

    @staticmethod
    def enable_hint() -> str:
        return TOR_ENABLE_HINT

    def is_running(self) -> bool:
        """True when the SOCKS port accepts a TCP connection."""
        try:
            with socket.create_connection((self.socks_host, self.socks_port), timeout=PROBE_TIMEOUT_SECONDS):
                return True
        except OSError as exc:
            logger.debug('[TorManager] %s:%s not reachable: %s', self.socks_host, self.socks_port, exc)
            return False

    def status(self) -> dict:
        """Status payload for the UI: whether Tor answers and how to enable it."""
        running = self.is_running()
        return {
            'running': running,
            'host': self.socks_host,
            'port': self.socks_port,
            'hint': None if running else TOR_ENABLE_HINT,
        }

    def require_running(self) -> None:
        """Raise ``TorUnavailableError`` (with the enable hint) unless Tor answers."""
        if not self.is_running():
            raise TorUnavailableError(TOR_ENABLE_HINT)

    def control_password(self) -> Optional[str]:
        return os.environ.get(TOR_CONTROL_PASSWORD_ENV) or None

    def new_circuit(self, settle_seconds: float = 2.0) -> None:
        """Ask Tor for a new circuit (NEWNYM) over the control port."""
        password = self.control_password()
        if not password:
            raise TorUnavailableError(TOR_PASSWORD_HINT)
        self.require_running()
        try:
            from stem import Signal
            from stem.control import Controller
            with Controller.from_port(address=self.control_host, port=self.control_port) as ctrl:
                ctrl.authenticate(password=password)
                ctrl.signal(Signal.NEWNYM)
                if settle_seconds > 0:
                    time.sleep(settle_seconds)
        except Exception as e:
            logger.warning("[TorManager] Failed to rotate circuit: %s", e)
            raise
