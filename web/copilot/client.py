"""HTTP client for the assessment-copilot sidecar (never AI Hub / LLMConfig)."""
from __future__ import annotations

import logging
import os
from typing import Any

import requests

logger = logging.getLogger(__name__)

DEFAULT_COPILOT_URL = 'http://assessment-copilot:8091'
TIMEOUT = 120


def copilot_base_url() -> str:
    return (os.environ.get('ASSESSMENT_COPILOT_URL') or DEFAULT_COPILOT_URL).rstrip('/')


def copilot_health() -> dict[str, Any]:
    url = f'{copilot_base_url()}/health'
    try:
        resp = requests.get(url, timeout=5)
        if resp.status_code >= 400:
            return {
                'reachable': False,
                'status': 'error',
                'hint': (
                    'Assessment Copilot returned an error. '
                    'Start with `make up-copilot` (compose profile `copilot`).'
                ),
                'detail': resp.text[:300],
            }
        data = resp.json()
        data['reachable'] = True
        if data.get('status') != 'ok':
            data['hint'] = (
                'Copilot is up but shared ollama may be down or empty. '
                'Pull a model into ollama, e.g. '
                '`docker exec <ollama> ollama pull qwen2.5:7b-instruct`.'
            )
        return data
    except requests.RequestException as exc:
        return {
            'reachable': False,
            'status': 'down',
            'hint': (
                'Assessment Copilot is not reachable. '
                'Enable with COMPOSE_PROFILES=copilot or `make up-copilot`.'
            ),
            'detail': str(exc),
        }


def copilot_chat(
    messages: list[dict[str, str]],
    *,
    model: str | None = None,
    scope: str = 'project',
    project_id: str | int | None = None,
    org_id: str | int | None = None,
    boost_terms: list[str] | None = None,
) -> dict[str, Any]:
    payload: dict[str, Any] = {
        'messages': messages,
        'scope': scope,
        'project_id': project_id,
        'org_id': org_id,
    }
    if model:
        payload['model'] = model
    if boost_terms:
        payload['boost_terms'] = list(boost_terms)[:40]
    try:
        resp = requests.post(
            f'{copilot_base_url()}/chat',
            json=payload,
            timeout=TIMEOUT,
        )
    except requests.RequestException as exc:
        raise CopilotClientError(f'copilot unreachable: {exc}', status=503) from exc
    if resp.status_code >= 400:
        raise CopilotClientError(
            f'copilot chat failed: {resp.text[:500]}',
            status=502,
        )
    return resp.json()


def copilot_index(
    documents: list[dict[str, Any]],
    playbooks: list[dict[str, Any]] | None = None,
) -> dict[str, Any]:
    payload = {'documents': documents, 'playbooks': playbooks or []}
    try:
        resp = requests.post(
            f'{copilot_base_url()}/index',
            json=payload,
            timeout=60,
        )
    except requests.RequestException as exc:
        raise CopilotClientError(f'copilot unreachable: {exc}', status=503) from exc
    if resp.status_code >= 400:
        raise CopilotClientError(
            f'copilot index failed: {resp.text[:500]}',
            status=502,
        )
    return resp.json()


def copilot_models() -> dict[str, Any]:
    try:
        resp = requests.get(f'{copilot_base_url()}/models', timeout=10)
    except requests.RequestException as exc:
        raise CopilotClientError(f'copilot unreachable: {exc}', status=503) from exc
    if resp.status_code >= 400:
        raise CopilotClientError(resp.text[:500], status=502)
    return resp.json()


class CopilotClientError(Exception):
    def __init__(self, message: str, status: int = 500):
        super().__init__(message)
        self.status = status
