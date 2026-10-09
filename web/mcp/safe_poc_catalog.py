"""SAFE PoC template catalog — server builds probes; agents only pick template_id + typed params.

No freeform payloads. No ValidationResult.payload writes from this module.
"""
from __future__ import annotations

import hashlib
import ipaddress
import logging
import re
import socket
import threading
import time
import uuid
from contextlib import contextmanager
from typing import Any, Optional
from urllib.parse import parse_qsl, urlencode, urljoin, urlparse, urlunparse

import requests

logger = logging.getLogger(__name__)

# Serializes DNS pin around each outbound request (getaddrinfo is process-global).
_DNS_PIN_LOCK = threading.Lock()

TEMPLATE_IDS = frozenset({
    'marker_reflect',
    'calc_echo',
    'authz_status_delta',
    'open_redirect_safe',
    'flag_canary_read',
})

SAFE_REDIRECT_HOSTS = frozenset({
    'example.com',
    'www.example.com',
})

CALC_PROBES = (
    '{{7*7}}',
    '${7*7}',
    '<%= 7*7 %>',
    '#{7*7}',
    '{{= 7*7}}',
)

HTTP_TIMEOUT_SEC = 10
MAX_BODY_STORE = 512
MAX_REDIRECTS = 3

# Path / host denylist (substring / exact patterns, case-insensitive).
_DENY_PATH_RE = re.compile(
    r'(^|/)('
    r'\.env|'
    r'etc/passwd|'
    r'etc/shadow|'
    r'proc/self|'
    r'windows/system32|'
    r'wp-admin/install|'
    r'phpmyadmin|'
    r'admin/delete|'
    r'account/delete|'
    r'user/delete'
    r')(/|$)',
    re.I,
)
_DENY_HOST_RE = re.compile(
    r'(^|\.)('
    r'169\.254\.169\.254|'
    r'metadata\.google\.internal|'
    r'metadata\.azure\.com'
    r')$',
    re.I,
)

_PARAM_NAME_RE = re.compile(r'^[A-Za-z0-9_.\-]{1,64}$')
_MARKER_RE = re.compile(r'^[A-Za-z0-9_\-]{8,128}$')


class CatalogError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _digest(text: str, limit: int = MAX_BODY_STORE) -> dict[str, Any]:
    raw = text or ''
    truncated = raw[:limit]
    return {
        'sha256': hashlib.sha256(raw.encode('utf-8', errors='replace')).hexdigest()[:16],
        'length': len(raw),
        'preview': truncated,
        'truncated': len(raw) > limit,
    }


def _length_bucket(n: int) -> str:
    if n < 100:
        return 'lt100'
    if n < 1000:
        return 'lt1k'
    if n < 10000:
        return 'lt10k'
    if n < 100000:
        return 'lt100k'
    return 'gte100k'


def assert_url_not_denied(url: str) -> None:
    parsed = urlparse(url)
    if parsed.scheme not in ('http', 'https'):
        logger.warning('safe_poc denylist: bad scheme url=%s', url[:200])
        raise CatalogError('only http/https URLs allowed')
    if parsed.username or parsed.password:
        logger.warning('safe_poc denylist: credentialed url blocked')
        raise CatalogError('URLs with credentials are not allowed')
    host = (parsed.hostname or '').lower()
    if not host:
        raise CatalogError('URL host required')
    if host == 'localhost' or host.endswith('.localhost'):
        logger.warning('safe_poc denylist: localhost blocked host=%s', host)
        raise CatalogError('localhost targets are not allowed')
    if _DENY_HOST_RE.search(host):
        logger.warning('safe_poc denylist: denied host=%s', host)
        raise CatalogError('denied host')
    path = parsed.path or '/'
    if _DENY_PATH_RE.search(path):
        logger.warning('safe_poc denylist: denied path=%s host=%s', path[:120], host)
        raise CatalogError('denied path')
    # Block literal IP literals that are private / link-local / metadata.
    try:
        ip = ipaddress.ip_address(host)
        if (
            ip.is_private
            or ip.is_loopback
            or ip.is_link_local
            or ip.is_reserved
            or ip.is_multicast
        ):
            logger.warning('safe_poc denylist: private/reserved IP host=%s', host)
            raise CatalogError('private or reserved IP targets are not allowed')
    except ValueError:
        pass


def assert_host_in_scope(url: str, allowed_hosts: set[str]) -> None:
    host = (urlparse(url).hostname or '').lower()
    if not host:
        raise CatalogError('URL host required')
    allowed = {h.lower() for h in allowed_hosts if h}
    if host not in allowed:
        # Allow subdomain of target apex if apex is in scope
        if not any(host == a or host.endswith('.' + a) for a in allowed):
            logger.warning(
                'safe_poc scope reject host=%s allowed=%s',
                host,
                sorted(allowed)[:20],
            )
            raise CatalogError(f'host {host} is out of scope for this vulnerability')


def _ip_is_blocked(ip: ipaddress._BaseAddress) -> bool:
    return bool(
        ip.is_private
        or ip.is_loopback
        or ip.is_link_local
        or ip.is_reserved
        or ip.is_multicast
        or ip.is_unspecified
    )


def _resolve_public_ips(hostname: str) -> list[str]:
    """Resolve hostname and return public IPs only.

    Fail closed: DNS failure, empty results, or any private/reserved address
    raises CatalogError. Literal IPs are returned as a single-element list
    after the same private/reserved checks.
    """
    try:
        literal = ipaddress.ip_address(hostname)
        if _ip_is_blocked(literal):
            logger.warning('safe_poc DNS block literal private/reserved host=%s', hostname)
            raise CatalogError('private or reserved IP targets are not allowed')
        return [hostname]
    except ValueError:
        pass

    try:
        infos = socket.getaddrinfo(hostname, None)
    except socket.gaierror as exc:
        logger.warning('safe_poc DNS resolve failed host=%s err=%s', hostname, exc)
        raise CatalogError(f'DNS resolution failed for {hostname}') from exc

    public: list[str] = []
    seen: set[str] = set()
    for info in infos:
        addr = info[4][0]
        try:
            ip = ipaddress.ip_address(addr)
        except ValueError:
            continue
        if _ip_is_blocked(ip):
            logger.warning(
                'safe_poc DNS private/reserved block host=%s addr=%s',
                hostname,
                addr,
            )
            raise CatalogError('resolved host points to a private or reserved address')
        if addr not in seen:
            seen.add(addr)
            public.append(addr)
    if not public:
        logger.warning('safe_poc DNS no usable addresses host=%s', hostname)
        raise CatalogError(f'no usable addresses for {hostname}')
    return public


@contextmanager
def _pin_dns(hostname: str, pinned_ip: str):
    """Pin ``getaddrinfo(hostname)`` to ``pinned_ip`` for one request.

    Prevents DNS rebinding between the SSRF pre-check and ``requests``' own
    lookup. Locked because ``socket.getaddrinfo`` is process-global.
    """
    if not hostname or hostname == pinned_ip:
        yield
        return
    with _DNS_PIN_LOCK:
        original = socket.getaddrinfo

        def _pinned(host, port, family=0, type=0, proto=0, flags=0):
            if host == hostname:
                return original(pinned_ip, port, family, type, proto, flags)
            return original(host, port, family, type, proto, flags)

        socket.getaddrinfo = _pinned  # type: ignore[assignment]
        try:
            logger.debug('safe_poc DNS pin host=%s -> %s', hostname, pinned_ip)
            yield
        finally:
            socket.getaddrinfo = original


def normalize_params(template_id: str, params: Any, *, vuln_url: str) -> dict:
    if params is None:
        params = {}
    if not isinstance(params, dict):
        raise CatalogError('params must be an object')
    if template_id not in TEMPLATE_IDS:
        raise CatalogError(f'unknown template_id: {template_id}')

    out: dict[str, Any] = {}

    if template_id == 'marker_reflect':
        param_name = str(params.get('param_name') or '').strip()
        if not _PARAM_NAME_RE.match(param_name):
            raise CatalogError('param_name required (alphanumeric/._-)')
        marker = str(params.get('marker') or f'r3n-{uuid.uuid4().hex[:16]}')
        if not _MARKER_RE.match(marker):
            raise CatalogError('marker must be 8-128 safe characters')
        method = str(params.get('method') or 'GET').upper()
        if method not in ('GET', 'POST'):
            raise CatalogError('method must be GET or POST')
        out = {
            'param_name': param_name,
            'marker': marker,
            'method': method,
            'base_url': str(params.get('base_url') or vuln_url).strip(),
        }

    elif template_id == 'calc_echo':
        param_name = str(params.get('param_name') or '').strip()
        if not _PARAM_NAME_RE.match(param_name):
            raise CatalogError('param_name required (alphanumeric/._-)')
        try:
            probe_index = int(params.get('probe_index') or 0)
        except (TypeError, ValueError) as exc:
            raise CatalogError('probe_index must be an integer') from exc
        if probe_index < 0 or probe_index >= len(CALC_PROBES):
            raise CatalogError(f'probe_index must be 0..{len(CALC_PROBES) - 1}')
        out = {
            'param_name': param_name,
            'probe_index': probe_index,
            'method': 'GET',
            'base_url': str(params.get('base_url') or vuln_url).strip(),
        }

    elif template_id == 'authz_status_delta':
        url_a = str(params.get('url_a') or '').strip()
        url_b = str(params.get('url_b') or '').strip()
        if not url_a or not url_b:
            raise CatalogError('url_a and url_b are required')
        out = {
            'url_a': url_a,
            'url_b': url_b,
            'cookie_name': str(params.get('cookie_name') or '').strip()[:64] or None,
            # Cookie value is operator-supplied; never echoed in results.
            'cookie_value': str(params.get('cookie_value') or '')[:4096] or None,
        }
        if out['cookie_name'] and not out['cookie_value']:
            raise CatalogError('cookie_value required when cookie_name is set')

    elif template_id == 'open_redirect_safe':
        param_name = str(params.get('param_name') or '').strip()
        if not _PARAM_NAME_RE.match(param_name):
            raise CatalogError('param_name required (alphanumeric/._-)')
        target = str(params.get('redirect_target') or 'https://example.com/').strip()
        parsed = urlparse(target)
        host = (parsed.hostname or '').lower()
        if host not in SAFE_REDIRECT_HOSTS:
            raise CatalogError(
                f'redirect_target host must be one of {sorted(SAFE_REDIRECT_HOSTS)}'
            )
        out = {
            'param_name': param_name,
            'redirect_target': target,
            'base_url': str(params.get('base_url') or vuln_url).strip(),
        }

    elif template_id == 'flag_canary_read':
        expected = str(params.get('expected_marker') or '').strip()
        if not _MARKER_RE.match(expected):
            raise CatalogError('expected_marker required (8-128 safe characters)')
        allowed_paths = params.get('allowed_paths') or []
        if allowed_paths is not None and not isinstance(allowed_paths, list):
            raise CatalogError('allowed_paths must be a list')
        clean_paths = [str(p)[:200] for p in (allowed_paths or [])][:10]
        base_url = str(params.get('base_url') or vuln_url).strip()
        path = urlparse(base_url).path or '/'
        if not (
            path.lower().endswith('flag.txt')
            or any(path == ap or path.endswith(ap) for ap in clean_paths)
        ):
            raise CatalogError(
                'flag_canary_read requires path ending in flag.txt or listed in allowed_paths'
            )
        out = {
            'expected_marker': expected,
            'allowed_paths': clean_paths,
            'base_url': base_url,
        }

    # Shared URL checks for templates that carry a URL
    urls_to_check = []
    if 'base_url' in out:
        urls_to_check.append(out['base_url'])
    if 'url_a' in out:
        urls_to_check.extend([out['url_a'], out['url_b']])
    for u in urls_to_check:
        assert_url_not_denied(u)

    return out


def _with_query_param(url: str, name: str, value: str) -> str:
    parsed = urlparse(url)
    q = dict(parse_qsl(parsed.query, keep_blank_values=True))
    q[name] = value
    return urlunparse(parsed._replace(query=urlencode(q)))


def _validate_request_url(url: str, allowed_hosts: Optional[set[str]]) -> str:
    """Validate denylist/scope/DNS and return a public IP to pin for this hop."""
    assert_url_not_denied(url)
    if allowed_hosts is not None:
        assert_host_in_scope(url, allowed_hosts)
    host = urlparse(url).hostname
    if not host:
        raise CatalogError('URL host required')
    ips = _resolve_public_ips(host)
    return ips[0]


def _follow_redirects_safely(
    method: str,
    url: str,
    *,
    allowed_hosts: Optional[set[str]],
    cookies: Optional[dict] = None,
    data: Optional[dict] = None,
    follow_redirects: bool = True,
) -> requests.Response:
    """Issue HTTP request without blind redirect following (SSRF-safe).

    Each redirect hop is re-checked against denylist, scope, and DNS private-IP
    resolution. DNS is pinned for the hop so ``requests`` cannot rebind to a
    private address after the pre-check.
    """
    current = url
    pinned_ip = _validate_request_url(current, allowed_hosts)
    headers = {'User-Agent': 'r3ngine-safe-poc/1.0'}
    for _ in range(MAX_REDIRECTS + 1):
        host = urlparse(current).hostname or ''
        with _pin_dns(host, pinned_ip):
            if method == 'GET':
                resp = requests.get(
                    current,
                    timeout=HTTP_TIMEOUT_SEC,
                    cookies=cookies or {},
                    allow_redirects=False,
                    headers=headers,
                )
            elif method == 'POST':
                resp = requests.post(
                    current,
                    data=data or {},
                    timeout=HTTP_TIMEOUT_SEC,
                    cookies=cookies or {},
                    allow_redirects=False,
                    headers=headers,
                )
            else:
                raise CatalogError(f'unsupported method {method}')

        if not follow_redirects or resp.status_code not in (301, 302, 303, 307, 308):
            return resp
        location = resp.headers.get('Location') or resp.headers.get('location')
        if not location:
            return resp
        next_url = urljoin(current, location)
        logger.info(
            'safe_poc redirect hop status=%s from=%s to=%s',
            resp.status_code,
            current[:200],
            next_url[:200],
        )
        try:
            pinned_ip = _validate_request_url(next_url, allowed_hosts)
        except CatalogError:
            logger.warning(
                'safe_poc redirect hop blocked from=%s to=%s',
                current[:200],
                next_url[:200],
            )
            raise
        # After first hop, POST becomes GET for 301/302/303 (browser-like).
        if method == 'POST' and resp.status_code in (301, 302, 303):
            method = 'GET'
            data = None
        current = next_url
    raise CatalogError('too many redirects')


def _http_get(
    url: str,
    *,
    allowed_hosts: Optional[set[str]] = None,
    cookies: Optional[dict] = None,
    allow_redirects: bool = True,
) -> requests.Response:
    return _follow_redirects_safely(
        'GET',
        url,
        allowed_hosts=allowed_hosts,
        cookies=cookies,
        follow_redirects=allow_redirects,
    )


def _http_post_form(
    url: str,
    data: dict,
    *,
    allowed_hosts: Optional[set[str]] = None,
) -> requests.Response:
    return _follow_redirects_safely(
        'POST',
        url,
        allowed_hosts=allowed_hosts,
        data=data,
        follow_redirects=True,
    )


def run_template(
    template_id: str,
    params: dict,
    *,
    allowed_hosts: set[str],
) -> dict[str, Any]:
    """Execute one catalog template. Returns result dict (never raises for miss)."""
    started = time.monotonic()
    try:
        if template_id == 'marker_reflect':
            return _run_marker_reflect(params, allowed_hosts=allowed_hosts, started=started)
        if template_id == 'calc_echo':
            return _run_calc_echo(params, allowed_hosts=allowed_hosts, started=started)
        if template_id == 'authz_status_delta':
            return _run_authz_status_delta(params, allowed_hosts=allowed_hosts, started=started)
        if template_id == 'open_redirect_safe':
            return _run_open_redirect_safe(params, allowed_hosts=allowed_hosts, started=started)
        if template_id == 'flag_canary_read':
            return _run_flag_canary_read(params, allowed_hosts=allowed_hosts, started=started)
        return {
            'matched': False,
            'confidence': 0.0,
            'summary': f'unknown template {template_id}',
            'error': 'unknown_template',
            'duration_ms': int((time.monotonic() - started) * 1000),
        }
    except CatalogError as exc:
        logger.warning(
            'safe_poc catalog_error template=%s err=%s',
            template_id,
            exc,
        )
        return {
            'matched': False,
            'confidence': 0.0,
            'summary': str(exc),
            'error': 'catalog_error',
            'duration_ms': int((time.monotonic() - started) * 1000),
        }
    except requests.RequestException as exc:
        logger.warning(
            'safe_poc http_error template=%s err=%s: %s',
            template_id,
            exc.__class__.__name__,
            exc,
            exc_info=True,
        )
        return {
            'matched': False,
            'confidence': 0.0,
            'summary': f'HTTP error: {exc.__class__.__name__}',
            'error': 'http_error',
            'duration_ms': int((time.monotonic() - started) * 1000),
        }


def _run_marker_reflect(params: dict, *, allowed_hosts: set[str], started: float) -> dict:
    base = params['base_url']
    assert_url_not_denied(base)
    assert_host_in_scope(base, allowed_hosts)
    marker = params['marker']
    name = params['param_name']
    if params.get('method') == 'POST':
        resp = _http_post_form(base, {name: marker}, allowed_hosts=allowed_hosts)
        req_desc = {'method': 'POST', 'url': base, 'param': name}
    else:
        url = _with_query_param(base, name, marker)
        resp = _http_get(url, allowed_hosts=allowed_hosts)
        req_desc = {'method': 'GET', 'url': url, 'param': name}
    body = resp.text or ''
    matched = marker in body
    return {
        'matched': matched,
        'confidence': 0.9 if matched else 0.2,
        'summary': (
            f'marker reflected in response (status={resp.status_code})'
            if matched
            else f'marker not found (status={resp.status_code})'
        ),
        'request': req_desc,
        'response': {
            'status': resp.status_code,
            'length_bucket': _length_bucket(len(body)),
            'body': _digest(body),
        },
        'duration_ms': int((time.monotonic() - started) * 1000),
    }


def _run_calc_echo(params: dict, *, allowed_hosts: set[str], started: float) -> dict:
    base = params['base_url']
    assert_url_not_denied(base)
    assert_host_in_scope(base, allowed_hosts)
    probe = CALC_PROBES[params['probe_index']]
    url = _with_query_param(base, params['param_name'], probe)
    resp = _http_get(url, allowed_hosts=allowed_hosts)
    body = resp.text or ''
    matched = '49' in body
    return {
        'matched': matched,
        'confidence': 0.85 if matched else 0.2,
        'summary': (
            f'calc probe produced 49 (status={resp.status_code})'
            if matched
            else f'calc probe did not yield 49 (status={resp.status_code})'
        ),
        'request': {'method': 'GET', 'url': url, 'probe': probe},
        'response': {
            'status': resp.status_code,
            'length_bucket': _length_bucket(len(body)),
            'body': _digest(body),
        },
        'duration_ms': int((time.monotonic() - started) * 1000),
    }


def _run_authz_status_delta(params: dict, *, allowed_hosts: set[str], started: float) -> dict:
    """Compare status codes for url_a vs url_b under the *same* session cookies.

    Both requests reuse the operator-supplied cookie jar when present. Stripping
    cookies on B previously caused false positives (auth missing ≠ object ACL).
    """
    url_a = params['url_a']
    url_b = params['url_b']
    for u in (url_a, url_b):
        assert_url_not_denied(u)
        assert_host_in_scope(u, allowed_hosts)
    cookies = None
    if params.get('cookie_name') and params.get('cookie_value'):
        cookies = {params['cookie_name']: params['cookie_value']}
    # Same jar on both hops — object-level authz requires a shared session.
    resp_a = _http_get(url_a, allowed_hosts=allowed_hosts, cookies=cookies)
    resp_b = _http_get(url_b, allowed_hosts=allowed_hosts, cookies=cookies)
    status_a, status_b = resp_a.status_code, resp_b.status_code
    matched = status_a != status_b
    return {
        'matched': matched,
        'confidence': 0.75 if matched else 0.25,
        'summary': (
            f'status delta {status_a} vs {status_b}'
            if matched
            else f'no status delta ({status_a} == {status_b})'
        ),
        'request': {
            'method': 'GET',
            'url_a': url_a,
            'url_b': url_b,
            'cookie_name': params.get('cookie_name') or None,
            'cookies_applied': bool(cookies),
        },
        'response': {
            'status_a': status_a,
            'status_b': status_b,
            'length_bucket_a': _length_bucket(len(resp_a.content or b'')),
            'length_bucket_b': _length_bucket(len(resp_b.content or b'')),
        },
        'duration_ms': int((time.monotonic() - started) * 1000),
    }


def _run_open_redirect_safe(params: dict, *, allowed_hosts: set[str], started: float) -> dict:
    base = params['base_url']
    assert_url_not_denied(base)
    assert_host_in_scope(base, allowed_hosts)
    target = params['redirect_target']
    url = _with_query_param(base, params['param_name'], target)
    resp = _http_get(url, allowed_hosts=allowed_hosts, allow_redirects=False)
    location = resp.headers.get('Location') or resp.headers.get('location') or ''
    loc_host = (urlparse(urljoin(url, location)).hostname or '').lower() if location else ''
    matched = bool(location) and loc_host in SAFE_REDIRECT_HOSTS
    return {
        'matched': matched,
        'confidence': 0.85 if matched else 0.2,
        'summary': (
            f'redirect Location host={loc_host} (status={resp.status_code})'
            if location
            else f'no Location header (status={resp.status_code})'
        ),
        'request': {'method': 'GET', 'url': url},
        'response': {
            'status': resp.status_code,
            'location_host': loc_host or None,
            'location_digest': _digest(location) if location else None,
        },
        'duration_ms': int((time.monotonic() - started) * 1000),
    }


def _run_flag_canary_read(params: dict, *, allowed_hosts: set[str], started: float) -> dict:
    base = params['base_url']
    assert_url_not_denied(base)
    assert_host_in_scope(base, allowed_hosts)
    resp = _http_get(base, allowed_hosts=allowed_hosts)
    body = resp.text or ''
    expected = params['expected_marker']
    matched = expected in body
    return {
        'matched': matched,
        'confidence': 0.9 if matched else 0.2,
        'summary': (
            f'expected marker found (status={resp.status_code})'
            if matched
            else f'expected marker missing (status={resp.status_code})'
        ),
        'request': {'method': 'GET', 'url': base},
        'response': {
            'status': resp.status_code,
            'length_bucket': _length_bucket(len(body)),
            'body': _digest(body),
        },
        'duration_ms': int((time.monotonic() - started) * 1000),
    }
