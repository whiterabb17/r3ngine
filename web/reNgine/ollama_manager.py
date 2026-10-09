"""Reachability of the ``ollama`` compose service.

Ollama is an opt-in compose service (``profiles: ["ollama"]`` in
``docker/docker-compose.yml``). The application does not start or stop the
container — that needed a Docker socket — it only reports whether the HTTP API
answers and how to enable the service when it does not. Model pulls and
deletes go through the API as before (``api.views.llm.OllamaManager``).
"""
from __future__ import annotations

import logging

import requests

from reNgine.definitions import OLLAMA_INSTANCE

logger = logging.getLogger(__name__)

PROBE_TIMEOUT_SECONDS = 3.0

OLLAMA_ENABLE_HINT = (
    "Ollama is not running. It is an optional service: set COMPOSE_PROFILES=ollama in .env "
    "and run `make up` (or `make up-ollama`). Models can be pulled once it answers."
)
OLLAMA_STOP_HINT = (
    "Ollama runs as a compose service; stop it from the host with `make stop-ollama`."
)


class OllamaUnavailableError(Exception):
    """Ollama is not reachable from this process."""


class OllamaManager:
    """Status of the ``ollama`` service as seen from this container."""

    def __init__(self, base_url: str = OLLAMA_INSTANCE) -> None:
        self.base_url = base_url.rstrip('/')

    @staticmethod
    def enable_hint() -> str:
        return OLLAMA_ENABLE_HINT

    @staticmethod
    def stop_hint() -> str:
        return OLLAMA_STOP_HINT

    def version(self) -> str | None:
        """Ollama's version string, or None when the API does not answer."""
        try:
            response = requests.get(f'{self.base_url}/api/version', timeout=PROBE_TIMEOUT_SECONDS)
        except requests.RequestException as exc:
            logger.debug('[OllamaManager] %s not reachable: %s', self.base_url, exc)
            return None
        if response.status_code != 200:
            return None
        try:
            return str(response.json().get('version') or '') or 'unknown'
        except ValueError:
            return 'unknown'

    def is_running(self) -> bool:
        return self.version() is not None

    def status(self) -> dict:
        """Status payload for the UI: whether Ollama answers and how to enable it."""
        version = self.version()
        return {
            'running': version is not None,
            'url': self.base_url,
            'version': version,
            'hint': None if version is not None else OLLAMA_ENABLE_HINT,
        }

    def require_running(self) -> None:
        if not self.is_running():
            raise OllamaUnavailableError(OLLAMA_ENABLE_HINT)
