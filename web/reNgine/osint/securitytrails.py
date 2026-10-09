"""SecurityTrails subdomain lookup.

Uses the documented REST API rather than the ``securitytrails.com/list/apex_domain``
web page, which needs a browser session. One lookup costs one query of the
account's monthly quota, so callers should make a single request per apex domain.
"""
import logging

import requests
import validators

logger = logging.getLogger(__name__)

API_BASE = 'https://api.securitytrails.com/v1'
TIMEOUT_SECONDS = 30


class SecurityTrailsError(Exception):
    """Raised with a message that is safe to log and show to the user."""


def fetch_securitytrails_subdomains(domain: str, api_key: str) -> list[str]:
    """Return the fully qualified subdomains SecurityTrails knows for ``domain``.

    Raises:
        SecurityTrailsError: the key is rejected, the quota is spent, or the
            request fails.
    """
    if not api_key:
        raise SecurityTrailsError('SecurityTrails API key not configured')
    if not validators.domain(domain):
        raise SecurityTrailsError('SecurityTrails lookup needs a domain name')

    try:
        response = requests.get(
            f'{API_BASE}/domain/{domain}/subdomains',
            params={'children_only': 'false', 'include_inactive': 'true'},
            headers={'APIKEY': api_key, 'Accept': 'application/json'},
            timeout=TIMEOUT_SECONDS,
        )
    except requests.RequestException as exc:
        raise SecurityTrailsError(f'SecurityTrails request failed: {type(exc).__name__}') from exc

    if response.status_code in (401, 403):
        raise SecurityTrailsError('SecurityTrails rejected the API key')
    if response.status_code == 429:
        raise SecurityTrailsError('SecurityTrails quota or rate limit exceeded')
    if not response.ok:
        raise SecurityTrailsError(f'SecurityTrails returned HTTP {response.status_code}')

    try:
        payload = response.json()
    except ValueError as exc:
        raise SecurityTrailsError('SecurityTrails returned a non-JSON response') from exc

    if (payload.get('meta') or {}).get('limit_reached'):
        logger.warning('SecurityTrails result for %s is truncated by the plan limit', domain)

    suffix = f'.{domain.lower()}'
    subdomains = set()
    for label in payload.get('subdomains') or []:
        if not isinstance(label, str):
            continue
        label = label.strip().strip('.').lower()
        if label:
            subdomains.add(f'{label}{suffix}')
    return sorted(subdomains)
