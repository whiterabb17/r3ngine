"""HTTP calls to the cloud LLM providers.

Shared by the report generators (reNgine.llm) and the AI Hub connection test, so
both send the same request to the same URL. Errors are raised, not returned:
requests exceptions for transport and HTTP status failures, LLMResponseError
for a 200 whose body has no text.

Rate limits (429), overload (529) and gateway errors (5xx) are retried a couple
of times, honouring Retry-After. The budget stays under the 5-minute heartbeat
timeout of the activities that make these calls: three 60 s attempts plus at
most 2 x 20 s of waiting.
"""
import logging
import time
from urllib.parse import quote, urlparse

import requests

from reNgine.definitions import ANTHROPIC, GEMINI, OPENAI, OPENAI_COMPATIBLE

logger = logging.getLogger(__name__)

OPENAI_BASE_URL = 'https://api.openai.com/v1'
ANTHROPIC_MESSAGES_URL = 'https://api.anthropic.com/v1/messages'
ANTHROPIC_VERSION = '2023-06-01'
# Anthropic requires max_tokens. Every Claude model can produce this much, the
# oldest (claude-3-haiku) at most exactly this; 1024 cut long reports off.
ANTHROPIC_DEFAULT_MAX_TOKENS = 4096
GEMINI_BASE_URL = 'https://generativelanguage.googleapis.com/v1beta'

CLOUD_PROVIDERS = (OPENAI, OPENAI_COMPATIBLE, ANTHROPIC, GEMINI)

# 529 is Anthropic's "overloaded".
RETRY_STATUSES = frozenset({429, 500, 502, 503, 504, 529})
DEFAULT_RETRIES = 2
MAX_RETRY_DELAY_SECONDS = 20

INVALID_BASE_URL_MESSAGE = (
    'Base URL must be an http:// or https:// URL without credentials, a query string or a fragment, '
    'e.g. https://gateway.example.com/v1'
)


class LLMResponseError(ValueError):
    """The provider answered, but not with text we can use."""


def normalize_base_url(url: str | None) -> str:
    """The base URL of an OpenAI-compatible API, without a trailing slash.

    Raises ValueError unless it is an http(s) URL with a host and nothing that
    would be sent somewhere unexpected (credentials, query, fragment).
    """
    value = (url or '').strip()
    parsed = urlparse(value)
    if (
        parsed.scheme not in ('http', 'https')
        or not parsed.hostname
        or parsed.username or parsed.password or parsed.query or parsed.fragment
    ):
        raise ValueError(INVALID_BASE_URL_MESSAGE)
    return value.rstrip('/')


def complete(
    provider: str,
    *,
    api_key: str,
    model: str,
    system: str,
    user: str,
    max_tokens: int | None = None,
    base_url: str | None = None,
    timeout: int = 60,
    retries: int = DEFAULT_RETRIES,
) -> str:
    """Send one system + user turn to the provider and return the reply text.

    ``retries`` is how many times a rate-limited, overloaded or unreachable
    provider is asked again; the AI Hub connection test passes 0.
    """
    if provider == OPENAI:
        return _openai_chat(OPENAI_BASE_URL, api_key, model, system, user, max_tokens, timeout, retries)
    if provider == OPENAI_COMPATIBLE:
        return _openai_chat(normalize_base_url(base_url), api_key, model, system, user, max_tokens, timeout, retries)
    if provider == ANTHROPIC:
        return _anthropic_messages(api_key, model, system, user, max_tokens, timeout, retries)
    if provider == GEMINI:
        return _gemini_generate(api_key, model, system, user, timeout, retries)
    raise ValueError(f'Unsupported LLM provider: {provider}')


def list_openai_compatible_models(base_url: str | None, api_key: str | None, timeout: int = 10) -> list[str]:
    """Model ids from GET <base_url>/models, the OpenAI list format most gateways serve."""
    headers = {'Authorization': f'Bearer {api_key}'} if api_key else {}
    response = requests.get(f'{normalize_base_url(base_url)}/models', headers=headers, timeout=timeout)
    response.raise_for_status()
    data = response.json().get('data', [])
    return sorted({m['id'] for m in data if isinstance(m, dict) and isinstance(m.get('id'), str)})


def _openai_chat(base_url, api_key, model, system, user, max_tokens, timeout, retries) -> str:
    url = f'{base_url}/chat/completions'
    headers = {'Authorization': f'Bearer {api_key}', 'Content-Type': 'application/json'}
    payload = {
        'model': model,
        'messages': [
            {'role': 'system', 'content': system},
            {'role': 'user', 'content': user},
        ],
    }
    if max_tokens is not None:
        payload['max_tokens'] = max_tokens
    response = _post(url, retries, headers=headers, json=payload, timeout=timeout)
    # Newer OpenAI models reject max_tokens and ask for max_completion_tokens.
    if (
        response.status_code == 400
        and 'max_tokens' in payload
        and 'max_tokens' in response.text
        and 'max_completion_tokens' in response.text
    ):
        payload['max_completion_tokens'] = payload.pop('max_tokens')
        response = _post(url, retries, headers=headers, json=payload, timeout=timeout)
    response.raise_for_status()
    try:
        content = response.json()['choices'][0]['message']['content']
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise LLMResponseError('Unexpected chat completion response format') from exc
    if not isinstance(content, str):
        raise LLMResponseError('Chat completion returned no text')
    return content


def _anthropic_messages(api_key, model, system, user, max_tokens, timeout, retries) -> str:
    response = _post(
        ANTHROPIC_MESSAGES_URL,
        retries,
        headers={
            'x-api-key': api_key,
            'anthropic-version': ANTHROPIC_VERSION,
            'content-type': 'application/json',
        },
        json={
            'model': model,
            'max_tokens': max_tokens or ANTHROPIC_DEFAULT_MAX_TOKENS,
            'system': system,
            'messages': [{'role': 'user', 'content': user}],
        },
        timeout=timeout,
    )
    response.raise_for_status()
    try:
        block = response.json()['content'][0]
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise LLMResponseError('Unexpected Anthropic response format') from exc
    if block.get('type') != 'text':
        raise LLMResponseError(f"Unexpected Anthropic response content type: {block.get('type')}")
    return block['text']


def _gemini_generate(api_key, model, system, user, timeout, retries) -> str:
    response = _post(
        f"{GEMINI_BASE_URL}/models/{quote(model, safe='')}:generateContent",
        retries,
        headers={'x-goog-api-key': api_key, 'Content-Type': 'application/json'},
        json={'contents': [{'parts': [{'text': f'{system}\n\n{user}'}]}]},
        timeout=timeout,
    )
    response.raise_for_status()
    try:
        return response.json()['candidates'][0]['content']['parts'][0]['text']
    except (KeyError, IndexError, TypeError, ValueError) as exc:
        raise LLMResponseError('Unexpected Gemini response format') from exc


def _post(url: str, retries: int, **kwargs) -> requests.Response:
    """requests.post, asked again up to ``retries`` times on RETRY_STATUSES or a failed connection.

    A read timeout is not retried: the provider may still be working on the
    request, and another full timeout would not help.
    """
    for attempt in range(retries + 1):
        last_attempt = attempt == retries
        try:
            response = requests.post(url, **kwargs)
        except requests.exceptions.ConnectionError:
            if last_attempt:
                raise
            delay = _retry_delay(attempt, None)
            logger.warning("LLM request to %s failed to connect, retrying in %.0f s", url, delay)
            time.sleep(delay)
            continue
        if last_attempt or response.status_code not in RETRY_STATUSES:
            return response
        delay = _retry_delay(attempt, response.headers.get('Retry-After'))
        logger.warning("LLM request to %s got HTTP %s, retrying in %.0f s", url, response.status_code, delay)
        time.sleep(delay)
    raise AssertionError('unreachable')


def _retry_delay(attempt: int, retry_after: str | None) -> float:
    """Retry-After in seconds when the provider sent one, else 2 s, 4 s, ...; capped."""
    try:
        seconds = float(retry_after)
    except (TypeError, ValueError):
        seconds = 2.0 ** (attempt + 1)
    return max(0.0, min(seconds, MAX_RETRY_DELAY_SECONDS))
