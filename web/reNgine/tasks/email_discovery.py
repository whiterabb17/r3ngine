"""Email discovery orchestrator — runs multiple tools to collect emails for a domain."""
import json
import logging
import os
import re
import requests
import smtplib
import subprocess
import tempfile
import uuid
from typing import Callable

import redis
from django.conf import settings

from reNgine.utils.task import save_email
from reNgine.osint.hunter_lookup import run_hunter_lookup, HunterQuotaExhausted
from dashboard.models import HunterIOAPIKey
from startScan.models import ScanHistory
from startScan.models import Screenshot
from startScan.models import Employee

logger = logging.getLogger(__name__)

__all__ = [
    'run_email_discovery',
    'run_hunter_discovery',
    'run_harvester_discovery',
    'run_phonebook_discovery',
    'run_pattern_inference',
    'run_crawled_extraction',
    '_push_to_stream',
    '_check_stop_signal',
    '_set_active',
    '_get_active_job',
    '_clear_active',
]

_TOOL_ORDER = [
    ('hunter',    'run_hunter_discovery'),
    ('harvester', 'run_harvester_discovery'),
    ('phonebook', 'run_phonebook_discovery'),
    ('pattern',   'run_pattern_inference'),
    ('crawled',   'run_crawled_extraction'),
]

EMAIL_PATTERN = re.compile(r'[\w.+\-]+@[\w\-]+(?:\.[\w\-]+)+')

MAX_PATTERN_CANDIDATES = 30


# ── Redis helpers ─────────────────────────────────────────────────────────────

def _redis() -> redis.StrictRedis:
    return redis.StrictRedis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        password=settings.REDIS_PASSWORD,
        db=0,
        decode_responses=True,
    )


def _push_to_stream(scan_id: int, event: dict) -> None:
    r = _redis()
    r.xadd(f'scan:logs:{scan_id}', {'data': json.dumps(event)})


def _check_stop_signal(job_id: str) -> bool:
    return bool(_redis().exists(f'email_discovery:{job_id}:stop'))


def _set_active(scan_id: int, job_id: str) -> None:
    r = _redis()
    r.set(f'email_discovery:{scan_id}:active', job_id, ex=3600)
    r.set(f'email_discovery:job:{job_id}:scan_id', str(scan_id), ex=3600)


def _get_active_job(scan_id: int) -> str | None:
    return _redis().get(f'email_discovery:{scan_id}:active')


def _clear_active(scan_id: int) -> None:
    job_id = _redis().get(f'email_discovery:{scan_id}:active')
    r = _redis()
    r.delete(f'email_discovery:{scan_id}:active')
    if job_id:
        r.delete(f'email_discovery:{job_id}:stop')


# ── Orchestrator ──────────────────────────────────────────────────────────────

def run_email_discovery(scan_id: int, domain: str, job_id: str) -> None:
    """Run all email discovery tools sequentially, pushing progress to scan log stream."""
    tool_fns: dict[str, Callable] = {
        'hunter':    run_hunter_discovery,
        'harvester': run_harvester_discovery,
        'phonebook': run_phonebook_discovery,
        'pattern':   run_pattern_inference,
        'crawled':   run_crawled_extraction,
    }

    total = 0
    sources: dict[str, int] = {}

    for tool_key, _ in _TOOL_ORDER:
        if _check_stop_signal(job_id):
            _push_to_stream(scan_id, {
                'type': 'email_discovery_progress',
                'job_id': job_id,
                'tool': tool_key,
                'status': 'cancelled',
                'found': 0,
                'message': '',
            })
            break

        _push_to_stream(scan_id, {
            'type': 'email_discovery_progress',
            'job_id': job_id,
            'tool': tool_key,
            'status': 'running',
            'found': 0,
            'message': '',
        })

        try:
            found = tool_fns[tool_key](scan_id, domain)
            total += found
            sources[tool_key] = found
            _push_to_stream(scan_id, {
                'type': 'email_discovery_progress',
                'job_id': job_id,
                'tool': tool_key,
                'status': 'done',
                'found': found,
                'message': '',
            })
        except Exception as exc:
            sources[tool_key] = 0
            logger.error('[EMAIL_DISCOVERY] tool=%s scan_id=%s error=%s', tool_key, scan_id, exc)
            _push_to_stream(scan_id, {
                'type': 'email_discovery_progress',
                'job_id': job_id,
                'tool': tool_key,
                'status': 'error',
                'found': 0,
                'message': str(exc)[:200],
            })

    _push_to_stream(scan_id, {
        'type': 'email_discovery_complete',
        'job_id': job_id,
        'total_found': total,
        'sources': sources,
    })
    _clear_active(scan_id)
    logger.info('[EMAIL_DISCOVERY] COMPLETE scan_id=%s total=%d', scan_id, total)


# ── Hunter.io wrapper ─────────────────────────────────────────────────────────

def run_hunter_discovery(scan_id: int, domain: str) -> int:
    """Run Hunter.io domain-search and return count of newly saved emails."""
    api_key_obj = HunterIOAPIKey.objects.filter().first()
    if not api_key_obj or not api_key_obj.key:
        logger.info('[EMAIL_DISCOVERY] Hunter: no API key configured — skipping')
        return 0

    try:
        result = run_hunter_lookup(domain, scan_id, api_key_obj.key)
        return result.get('emails', 0)
    except HunterQuotaExhausted:
        logger.warning('[EMAIL_DISCOVERY] Hunter quota exhausted for %s', domain)
        raise
    except Exception as exc:
        logger.error('[EMAIL_DISCOVERY] Hunter error: %s', exc)
        raise


# ── theHarvester wrapper ──────────────────────────────────────────────────────

def run_harvester_discovery(scan_id: int, domain: str) -> int:
    """Run theHarvester and return count of newly saved emails."""
    theHarvester_dir = '/usr/src/github/theHarvester'

    with tempfile.TemporaryDirectory() as tmpdir:
        output_json = os.path.join(tmpdir, 'harvester_out')
        cmd = ['uv', 'run', 'theHarvester', '-d', domain, '-b', 'all', '-f', output_json]

        proc = subprocess.run(
            cmd,
            cwd=theHarvester_dir,
            capture_output=True,
            timeout=300,
        )

        output_file = f'{output_json}.json'
        if not os.path.isfile(output_file):
            logger.warning('[EMAIL_DISCOVERY] theHarvester produced no output file for %s', domain)
            return 0

        with open(output_file, 'r') as f:
            data = json.load(f)

    scan_history = ScanHistory.objects.get(pk=scan_id)
    count = 0
    for address in data.get('emails', []):
        email, created = save_email(address, scan_history=scan_history, source='harvester')
        if email and created:
            count += 1
    return count


# ── phonebook.cz scraper ──────────────────────────────────────────────────────

def run_phonebook_discovery(scan_id: int, domain: str) -> int:
    """Scrape phonebook.cz for emails associated with the domain."""
    scan_history = ScanHistory.objects.get(pk=scan_id)
    url = f'https://phonebook.cz/search/?term={domain}&type=email'
    try:
        resp = requests.get(url, timeout=20, headers={'User-Agent': 'Mozilla/5.0'})
    except requests.RequestException as exc:
        logger.warning('[EMAIL_DISCOVERY] phonebook.cz request failed: %s', exc)
        raise

    if resp.status_code != 200:
        raise RuntimeError('phonebook.cz HTTP %d' % resp.status_code)

    found_addresses = set(EMAIL_PATTERN.findall(resp.text))
    domain_addresses = {a for a in found_addresses if a.lower().endswith(f'@{domain}')}

    count = 0
    for address in domain_addresses:
        email, created = save_email(address, scan_history=scan_history, source='phonebook')
        if email and created:
            count += 1
    return count


# ── Crawled URL email extraction ──────────────────────────────────────────────

def run_crawled_extraction(scan_id: int, domain: str) -> int:
    """Extract emails from saved HTML files recorded in Screenshot records for this scan."""
    scan_history = ScanHistory.objects.get(pk=scan_id)
    html_paths = (
        Screenshot.objects
        .filter(scan_history=scan_history)
        .exclude(html_path='')
        .exclude(html_path__isnull=True)
        .values_list('html_path', flat=True)
    )

    count = 0
    seen: set[str] = set()
    for html_path in html_paths:
        try:
            with open(html_path, 'r', encoding='utf-8', errors='ignore') as f:
                content = f.read()
        except OSError:
            logger.debug('[EMAIL_DISCOVERY] crawled: cannot read %s', html_path)
            continue

        for address in EMAIL_PATTERN.findall(content):
            address_lower = address.lower()
            if address_lower in seen:
                continue
            seen.add(address_lower)
            if not address_lower.endswith('@%s' % domain):
                continue
            email, created = save_email(address_lower, scan_history=scan_history, source='crawled')
            if email and created:
                count += 1
    return count


# ── SMTP helpers ──────────────────────────────────────────────────────────────

def _smtp_verify_email(email: str, domain: str, timeout: int = 5) -> bool:
    """Verify email existence via SMTP RCPT TO against the domain MX record."""
    try:
        import dns.resolver
        mx_records = dns.resolver.resolve(domain, 'MX', lifetime=10)
        mx_host = sorted(mx_records, key=lambda r: r.preference)[0].exchange.to_text().rstrip('.')
    except Exception:
        return False

    try:
        with smtplib.SMTP(timeout=timeout) as smtp:
            smtp.connect(mx_host, 25)
            smtp.ehlo('verify.local')
            smtp.mail('')
            code, _ = smtp.rcpt(email)
            return code == 250
    except Exception:
        return False


def _email_patterns(first: str, last: str, domain: str) -> list[str]:
    """Generate 6 common email format candidates."""
    f = first[0].lower()
    first = first.lower()
    last = last.lower()
    return [
        f'{first}@{domain}',
        f'{f}.{last}@{domain}',
        f'{first}.{last}@{domain}',
        f'{f}{last}@{domain}',
        f'{first}{last[0]}@{domain}',
        f'{last}@{domain}',
    ]


# ── Pattern inference ─────────────────────────────────────────────────────────

def run_pattern_inference(scan_id: int, domain: str) -> int:
    """Generate likely email formats from known employees and verify via SMTP."""
    scan_history = ScanHistory.objects.get(pk=scan_id)
    employees = (
        Employee.objects
        .filter(employees__in=[scan_history])
        .exclude(name='')
    )

    candidates: list[str] = []
    for emp in employees:
        parts = (emp.name or '').strip().split()
        if len(parts) < 2:
            continue
        first, last = parts[0], parts[-1]
        candidates.extend(_email_patterns(first, last, domain))
        if len(candidates) >= MAX_PATTERN_CANDIDATES:
            break

    count = 0
    for address in candidates[:MAX_PATTERN_CANDIDATES]:
        if _smtp_verify_email(address, domain):
            email, created = save_email(address, scan_history=scan_history, source='pattern')
            if email and created:
                count += 1
    return count
