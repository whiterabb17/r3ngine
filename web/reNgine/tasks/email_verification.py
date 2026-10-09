"""Mailbox verification via check-if-email-exists (Reacher). Replaces smtp-user-enum."""
from __future__ import annotations

import ipaddress
import json
import logging
import os
import re
import secrets
import shutil
import time
from urllib.parse import urlparse

import requests
import validators

from reNgine.utils.task import run_command, save_email

logger = logging.getLogger(__name__)

SMTP_USERNAMES_WORDLIST = '/usr/src/wordlist/smtp-usernames.txt'
CLI_BINARY = 'check_if_email_exists'
FINDING_CONFIRMED_CAP = 20
SENTINEL_COUNT = 2
HTTP_BODY_CAP = 64 * 1024
# CLI run_command timeout is cfg timeout plus this pad (process teardown / overrun).
CLI_TIMEOUT_PAD_SECONDS = 5
# RunEmailSecurityActivity start_to_close is 2 hours (MasterScanWorkflow and
# SingleTaskRetry). When remaining time is unknown, reserve SPF/DMARC/DKIM +
# swaks/certs. The activity passes elapsed remaining_seconds so a long SMTP
# sweep cannot still run a full-budget loop after shared work.
ACTIVITY_START_TO_CLOSE_SECONDS = 120 * 60
SHARED_WORK_RESERVE_SECONDS = 15 * 60
PERSIST_SLACK_SECONDS = 60
ACTIVITY_BUDGET_SECONDS = ACTIVITY_START_TO_CLOSE_SECONDS - SHARED_WORK_RESERVE_SECONDS

_CTRL = re.compile(r'[\x00-\x1f\x7f]')
_BLOCKED_HOSTS = frozenset({'metadata.google.internal', '169.254.169.254'})
_DEFAULTS = {
    'enabled': True,
    'http_url': '',
    'timeout': 15,
    'max_candidates': 200,
    'delay_ms': 250,
}
_UNKNOWN = {
    'is_reachable': 'unknown',
    'is_catch_all': False,
    'is_role_account': False,
    'is_disposable': False,
    'mx_accepts_mail': False,
}


def is_in_scope_email(address: str, domain: str) -> bool:
    if not address or not domain:
        return False
    if not isinstance(address, str) or not isinstance(domain, str):
        return False
    if len(address) > 254:
        return False
    if _CTRL.search(address):
        return False
    if not validators.email(address):
        return False
    host = address.rsplit('@', 1)[-1].lower().rstrip('.')
    return host == domain.lower().rstrip('.')


def parse_mailbox_config(
    yaml_configuration: dict | None,
    remaining_seconds: float | None = None,
) -> dict:
    root = yaml_configuration or {}
    if not isinstance(root, dict):
        root = {}
    section = root.get('email_security') or {}
    if not isinstance(section, dict):
        section = {}
    raw = section.get('mailbox_verification') or {}
    if not isinstance(raw, dict):
        raw = {}
    cfg = dict(_DEFAULTS)
    if 'enabled' in raw:
        cfg['enabled'] = bool(raw['enabled'])
    http_url = raw.get('http_url') or ''
    cfg['http_url'] = http_url.strip() if isinstance(http_url, str) else ''
    for key, lo, hi in (
        ('timeout', 1, 120),
        ('max_candidates', 1, 1000),
        ('delay_ms', 0, 10000),
    ):
        if key not in raw:
            continue
        try:
            cfg[key] = max(lo, min(hi, int(raw[key])))
        except (TypeError, ValueError):
            pass
    per_check = max(
        1.0,
        float(cfg['timeout']) + CLI_TIMEOUT_PAD_SECONDS + (cfg['delay_ms'] / 1000.0),
    )
    budget = _mailbox_budget_seconds(remaining_seconds)
    affordable = int(budget / per_check) - SENTINEL_COUNT
    if cfg['max_candidates'] > affordable:
        logger.warning(
            '[mailbox_verify] clamping max_candidates from %s to %s to fit activity budget',
            cfg['max_candidates'],
            max(0, affordable),
        )
        cfg['max_candidates'] = max(0, affordable)
    return cfg


def _mailbox_budget_seconds(remaining_seconds: float | None) -> int:
    """Seconds available for sentinels + candidates (persist slack already subtracted)."""
    cap = ACTIVITY_START_TO_CLOSE_SECONDS - PERSIST_SLACK_SECONDS
    if remaining_seconds is None:
        return min(ACTIVITY_BUDGET_SECONDS, cap)
    try:
        leftover = float(remaining_seconds) - PERSIST_SLACK_SECONDS
    except (TypeError, ValueError):
        return min(ACTIVITY_BUDGET_SECONDS, cap)
    return max(0, min(int(leftover), cap))


def validate_reacher_http_url(raw: str) -> str | None:
    if not raw or not isinstance(raw, str):
        return None
    parsed = urlparse(raw.strip())
    if parsed.scheme not in ('http', 'https'):
        return None
    if parsed.username or parsed.password:
        return None
    host = (parsed.hostname or '').lower()
    if not host:
        return None
    if host in _BLOCKED_HOSTS:
        return None
    try:
        ip = ipaddress.ip_address(host)
        if ip.is_link_local:
            return None
    except ValueError:
        pass
    return '%s://%s' % (parsed.scheme, parsed.netloc)


def _email_patterns(first: str, last: str, domain: str) -> list[str]:
    f = first[0].lower()
    first = first.lower()
    last = last.lower()
    return [
        '%s@%s' % (first, domain),
        '%s.%s@%s' % (f, last, domain),
        '%s.%s@%s' % (first, last, domain),
        '%s%s@%s' % (f, last, domain),
        '%s%s@%s' % (first, last[0], domain),
        '%s@%s' % (last, domain),
    ]


def build_candidates(domain: str, scan, wordlist_path: str, max_candidates: int) -> list[str]:
    ordered: list[str] = []
    seen: set[str] = set()

    def _add(address: str) -> None:
        if len(ordered) >= max_candidates:
            return
        if not is_in_scope_email(address, domain):
            return
        key = address.lower()
        if key in seen:
            return
        seen.add(key)
        ordered.append(address.lower())

    # Discovered OSINT / scan emails and employee patterns first so the
    # username wordlist cannot consume the entire max_candidates budget.
    for email in scan.emails.all():
        _add(email.address or '')

    for emp in scan.employees.all():
        parts = (emp.name or '').strip().split()
        if len(parts) < 2:
            continue
        first, last = parts[0], parts[-1]
        if not first or not last:
            continue
        for pattern in _email_patterns(first, last, domain):
            _add(pattern)

    if wordlist_path and os.path.isfile(wordlist_path):
        try:
            with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as handle:
                for line in handle:
                    if len(ordered) >= max_candidates:
                        break
                    local = line.strip()
                    if not local or local.startswith('#'):
                        continue
                    _add('%s@%s' % (local, domain))
        except OSError as exc:
            logger.warning('[mailbox_verify] wordlist unreadable: %s', exc)
    return ordered


def _empty_result(address: str, extra: dict | None = None) -> dict:
    result = {'input': address}
    result.update(_UNKNOWN)
    if extra:
        result.update(extra)
    return result


def parse_socks_proxy(proxy_url: str | None) -> dict | None:
    if not proxy_url or not isinstance(proxy_url, str):
        return None
    parsed = urlparse(proxy_url.strip())
    scheme = (parsed.scheme or '').lower()
    # Reacher SMTP verification supports SOCKS5 only (confirmed on the
    # orchestrator binary: --proxy-host is documented as SOCKS5).
    if scheme not in ('socks5', 'socks5h'):
        return None
    host = parsed.hostname
    if not host:
        return None
    if any(ch in host for ch in ('\x00', '\n', '\r', ' ', '\t')):
        return None
    port = parsed.port or 1080
    return {
        'host': host,
        'port': int(port),
        'username': parsed.username or '',
        'password': parsed.password or '',
    }


def _cli_proxy_argv(socks: dict) -> list[str]:
    """Host/port (and username) as clap long-options. Password stays off argv."""
    args = [
        '--proxy-host=%s' % socks['host'],
        '--proxy-port=%s' % socks['port'],
    ]
    if socks.get('username'):
        args.append('--proxy-username=%s' % socks['username'])
    return args


def _cli_proxy_env(socks: dict) -> dict:
    env = os.environ.copy()
    env['PROXY_HOST'] = socks['host']
    env['PROXY_PORT'] = str(socks['port'])
    if socks.get('username'):
        env['PROXY_USERNAME'] = socks['username']
    if socks.get('password'):
        env['PROXY_PASSWORD'] = socks['password']
    return env


def _normalize_reacher_payload(address: str, payload: dict) -> dict:
    misc = payload.get('misc') or {}
    mx = payload.get('mx') or {}
    smtp = payload.get('smtp') or {}
    reachable = payload.get('is_reachable') or 'unknown'
    if reachable not in ('safe', 'risky', 'invalid', 'unknown'):
        reachable = 'unknown'
    return {
        'input': address,
        'is_reachable': reachable,
        'is_catch_all': bool(smtp.get('is_catch_all')),
        'is_role_account': bool(misc.get('is_role_account')),
        'is_disposable': bool(misc.get('is_disposable')),
        'mx_accepts_mail': bool(mx.get('accepts_mail')),
    }


def _optional_id(value):
    try:
        if value is None:
            return None
        return int(value)
    except (TypeError, ValueError):
        return None


def _verify_via_cli(address: str, timeout: int, socks: dict | None, scan_id=None, activity_id=None) -> dict:
    cmd = [CLI_BINARY]
    env = None
    if socks:
        # Host/port are first-class CLI args (check_if_email_exists --help).
        # Password is env-only: run_command stores argv on the Command row and
        # redact_proxy_credentials only masks URL userinfo, not --proxy-password.
        cmd.extend(_cli_proxy_argv(socks))
        env = _cli_proxy_env(socks)
    cmd.append(address)
    try:
        return_code, output = run_command(
            cmd,
            timeout=timeout + CLI_TIMEOUT_PAD_SECONDS,
            shell=False,
            env=env,
            scan_id=_optional_id(scan_id),
            activity_id=_optional_id(activity_id),
        )
    except Exception as exc:
        logger.warning('[mailbox_verify] CLI error for %s: %s', address, exc)
        return _empty_result(address)
    try:
        payload = json.loads(output)
    except (TypeError, ValueError, json.JSONDecodeError):
        return _empty_result(address)
    if not isinstance(payload, dict):
        return _empty_result(address)
    return _normalize_reacher_payload(address, payload)


def _read_capped(response) -> bytes:
    chunks = []
    total = 0
    for chunk in response.iter_content(chunk_size=4096):
        if not chunk:
            continue
        total += len(chunk)
        if total > HTTP_BODY_CAP:
            return b''
        chunks.append(chunk)
    return b''.join(chunks)


def _verify_via_http(address: str, origin: str, timeout: int, socks: dict | None) -> dict:
    url = origin.rstrip('/') + '/v0/check_email'
    body = {'to_email': address}
    if socks:
        proxy_obj = {'host': socks['host'], 'port': socks['port']}
        if socks.get('username'):
            proxy_obj['username'] = socks['username']
        if socks.get('password'):
            proxy_obj['password'] = socks['password']
        body['proxy'] = proxy_obj
    try:
        response = requests.post(
            url,
            json=body,
            timeout=timeout,
            allow_redirects=False,
            stream=True,
        )
    except Exception as exc:
        logger.warning('[mailbox_verify] HTTP error for %s: %s', address, exc)
        return _empty_result(address)
    if response.status_code < 200 or response.status_code >= 300:
        return _empty_result(address)
    raw = _read_capped(response)
    if not raw:
        return _empty_result(address)
    try:
        payload = json.loads(raw.decode('utf-8', errors='replace'))
    except (ValueError, json.JSONDecodeError):
        return _empty_result(address)
    if not isinstance(payload, dict):
        return _empty_result(address)
    return _normalize_reacher_payload(address, payload)


def verify_address(address: str, options: dict) -> dict:
    domain = options.get('domain') or ''
    if not is_in_scope_email(address, domain):
        return _empty_result(address)
    timeout = int(options.get('timeout') or 15)
    http_url = options.get('http_url') or ''
    socks = parse_socks_proxy(options.get('proxy_url'))
    if http_url:
        origin = validate_reacher_http_url(http_url)
        if not origin:
            return _empty_result(address, {'error': 'bad_http_url'})
        return _verify_via_http(address, origin, timeout, socks)
    return _verify_via_cli(
        address,
        timeout,
        socks,
        scan_id=options.get('scan_id'),
        activity_id=options.get('activity_id'),
    )


def _is_activity_cancelled() -> bool:
    try:
        from temporalio import activity
        return activity.in_activity() and activity.is_cancelled()
    except Exception:
        return False


def _sentinel_address(domain: str) -> str:
    return 'r3n-nx-%s@%s' % (secrets.token_hex(6), domain.lower())


def _merge_metadata(email_obj, result: dict) -> None:
    meta = dict(email_obj.metadata or {})
    meta['is_reachable'] = result.get('is_reachable')
    meta['is_role_account'] = result.get('is_role_account')
    meta['is_disposable'] = result.get('is_disposable')
    meta['is_catch_all'] = result.get('is_catch_all')
    meta['mx_accepts_mail'] = result.get('mx_accepts_mail')
    email_obj.metadata = meta
    email_obj.save(update_fields=['metadata'])


def _existing_email(address: str, scan=None):
    """Case-insensitive lookup. Prefer a row already on this scan."""
    from startScan.models import Email as EmailModel
    if scan is not None:
        on_scan = scan.emails.filter(address__iexact=address).first()
        if on_scan:
            return on_scan
    return EmailModel.objects.filter(address__iexact=address).first()


def _persist_verified(address: str, scan, result: dict):
    """Reuse the existing Email row when casing differs; do not create a duplicate."""
    from startScan.models import Email as EmailModel
    existing = _existing_email(address, scan)
    if existing:
        if scan is not None:
            scan.emails.add(existing)
        _merge_metadata(existing, result)
        return existing
    email_obj, _created = save_email(
        address, scan_history=scan, source=EmailModel.SOURCE_MAILBOX_VERIFY,
    )
    if email_obj:
        _merge_metadata(email_obj, result)
    return email_obj


def verify_domain_mailboxes(
    domain: str,
    scan,
    yaml_cfg: dict | None,
    proxy_url: str | None = None,
    remaining_seconds: float | None = None,
    activity_id=None,
) -> dict:
    empty = {
        'catch_all': False,
        'checked': 0,
        'confirmed': [],
        'findings': [],
        'skipped_reason': None,
    }
    cfg = parse_mailbox_config(yaml_cfg, remaining_seconds=remaining_seconds)
    if not cfg['enabled']:
        empty['skipped_reason'] = 'disabled'
        return empty
    if cfg['http_url']:
        if not validate_reacher_http_url(cfg['http_url']):
            logger.warning('[mailbox_verify] rejecting http_url; not falling back to CLI')
            empty['skipped_reason'] = 'bad_http_url'
            return empty
    elif shutil.which(CLI_BINARY) is None:
        logger.warning('[mailbox_verify] %s not on PATH', CLI_BINARY)
        empty['skipped_reason'] = 'binary_missing'
        return empty

    per_check = max(
        1.0,
        float(cfg['timeout']) + CLI_TIMEOUT_PAD_SECONDS + (cfg['delay_ms'] / 1000.0),
    )
    if remaining_seconds is not None:
        try:
            left = float(remaining_seconds)
        except (TypeError, ValueError):
            left = None
        else:
            if left < (SENTINEL_COUNT * per_check) + PERSIST_SLACK_SECONDS:
                logger.warning('[mailbox_verify] not enough activity time remaining; skipping')
                empty['skipped_reason'] = 'timeout_budget'
                return empty

    options = {
        'timeout': cfg['timeout'],
        'http_url': cfg['http_url'],
        'proxy_url': proxy_url,
        'domain': domain,
        'scan_id': getattr(scan, 'id', None),
        'activity_id': activity_id,
    }
    if proxy_url and not parse_socks_proxy(proxy_url):
        scheme = ''
        if isinstance(proxy_url, str):
            scheme = (urlparse(proxy_url.strip()).scheme or '').lower()
        if scheme in ('socks4', 'socks4a'):
            logger.warning('[mailbox_verify] ignoring SOCKS4 proxy; Reacher SMTP verify needs SOCKS5')
        else:
            logger.warning('[mailbox_verify] ignoring non-SOCKS5 proxy')
        options['proxy_url'] = None

    sentinels = [_sentinel_address(domain) for _ in range(SENTINEL_COUNT)]
    catch_all = False
    checked = 0
    cancelled = False
    for sentinel in sentinels:
        if _is_activity_cancelled():
            cancelled = True
            break
        result = verify_address(sentinel, options)
        checked += 1
        if result.get('is_catch_all') or result.get('is_reachable') == 'safe':
            catch_all = True
            break
        time.sleep(cfg['delay_ms'] / 1000.0)

    if cancelled:
        empty['checked'] = checked
        empty['skipped_reason'] = 'cancelled'
        return empty

    if catch_all:
        return {
            'catch_all': True,
            'checked': checked,
            'confirmed': [],
            'findings': [{
                'name': 'MX Catch-All Configured',
                'severity': 0,
                'description': (
                    'MX for %s accepts remaining recipients (catch-all). '
                    'Mailbox confirmation is not reliable; no addresses were recorded from this step.'
                    % domain
                ),
            }],
            'skipped_reason': None,
        }

    candidates = build_candidates(
        domain, scan, SMTP_USERNAMES_WORDLIST, cfg['max_candidates']
    )
    confirmed: list[str] = []

    for address in candidates:
        if _is_activity_cancelled():
            cancelled = True
            break
        result = verify_address(address, options)
        checked += 1
        reachable = result.get('is_reachable')
        if reachable == 'safe':
            email_obj = _persist_verified(address, scan, result)
            if email_obj:
                confirmed.append(address)
        elif reachable in ('risky', 'unknown', 'invalid'):
            existing = _existing_email(address, scan)
            if existing:
                _merge_metadata(existing, result)
        time.sleep(cfg['delay_ms'] / 1000.0)

    findings = []
    if confirmed:
        shown = confirmed[:FINDING_CONFIRMED_CAP]
        extra = len(confirmed) - len(shown)
        desc = '%d valid mailbox(es) confirmed for %s via MX/SMTP RCPT: %s' % (
            len(confirmed), domain, ', '.join(shown),
        )
        if extra > 0:
            desc += ' (+%d more)' % extra
        findings.append({
            'name': 'Valid Mailboxes Confirmed',
            'severity': 2,
            'description': desc,
        })
    return {
        'catch_all': False,
        'checked': checked,
        'confirmed': confirmed,
        'findings': findings,
        'skipped_reason': 'cancelled' if cancelled else None,
    }
