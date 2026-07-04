"""Employee intelligence orchestrator — discovers employees/names/positions for a domain."""
import json
import logging
import os
import subprocess
import tempfile
import uuid
from typing import Callable

import redis
from django.conf import settings

from reNgine.utils.task import save_employee
from startScan.models import ScanHistory

logger = logging.getLogger(__name__)

__all__ = [
    'run_employee_intelligence',
    '_push_to_stream',
    '_check_stop_signal',
    '_set_active',
    '_get_active_job',
    '_clear_active',
    '_redis',
]

_TOOL_ORDER = [
    ('theharvester', '_run_theharvester_employees'),
    ('linkedint',    '_run_linkedint_employees'),
    ('hunter',       '_run_hunter_employees'),
]


def _safe_error_message(exc: Exception) -> str:
    if isinstance(exc, subprocess.TimeoutExpired):
        return 'Tool timed out'
    if isinstance(exc, RuntimeError):
        return str(exc)[:120]
    return 'Internal error'


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
    _redis().xadd(f'scan:logs:{scan_id}', {'data': json.dumps(event)})


def _check_stop_signal(job_id: str) -> bool:
    return bool(_redis().exists(f'employee_intel:{job_id}:stop'))


def _set_active(scan_id: int, job_id: str) -> None:
    r = _redis()
    r.set(f'employee_intel:{scan_id}:active', job_id, ex=3600)
    r.set(f'employee_intel:job:{job_id}:scan_id', str(scan_id), ex=3600)


def _get_active_job(scan_id: int) -> str | None:
    return _redis().get(f'employee_intel:{scan_id}:active')


def _clear_active(scan_id: int) -> None:
    r = _redis()
    job_id = r.get(f'employee_intel:{scan_id}:active')
    r.delete(f'employee_intel:{scan_id}:active')
    if job_id:
        r.delete(f'employee_intel:{job_id}:stop')


# ── Tool runners ──────────────────────────────────────────────────────────────

def _run_theharvester_employees(scan_id: int, domain: str) -> int:
    """Run theHarvester with linkedin/google sources, return count of new employees saved."""
    scan_history = ScanHistory.objects.get(pk=scan_id)
    theharvester_dir = '/usr/src/github/theHarvester'

    with tempfile.TemporaryDirectory() as tmpdir:
        output_json = os.path.join(tmpdir, 'employees.json')
        cmd = [
            'uv', 'run', 'theHarvester',
            '-d', domain,
            '-b', 'linkedin,google',
            '-f', output_json,
        ]
        subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=120,
            cwd=theharvester_dir,
        )

        if not os.path.isfile(output_json):
            return 0

        with open(output_json) as f:
            data = json.load(f)

    count = 0
    for name in data.get('linkedin_people', []) + data.get('twitter_people', []):
        _, created = save_employee(name, scan_history=scan_history)
        if created:
            count += 1
    return count


def _run_linkedint_employees(scan_id: int, domain: str) -> int:
    """Run LinkedIn Intelligence scraper, return count of new employees saved."""
    from reNgine.tasks.osint import run_linkedint

    company_name = domain.split('.')[0]
    before = ScanHistory.objects.get(pk=scan_id).employees.count()
    run_linkedint(company_name, scan_id)
    after = ScanHistory.objects.get(pk=scan_id).employees.count()
    return max(0, after - before)


def _run_hunter_employees(scan_id: int, domain: str) -> int:
    """Run Hunter.io domain-search and email-finder, return count of new employees saved."""
    from dashboard.models import HunterIOAPIKey
    from reNgine.osint.hunter_lookup import run_hunter_lookup

    key_obj = HunterIOAPIKey.objects.first()
    if not key_obj or not key_obj.key:
        raise RuntimeError('Hunter.io API key not configured — add it in Settings')

    result = run_hunter_lookup(domain, scan_id, key_obj.key)
    return result.get('employees', 0)


# ── Orchestrator ──────────────────────────────────────────────────────────────

def run_employee_intelligence(scan_id: int, domain: str, job_id: str) -> None:
    """Run all employee intelligence tools sequentially, pushing progress to scan log stream."""
    tool_fns: dict[str, Callable] = {
        'theharvester': _run_theharvester_employees,
        'linkedint':    _run_linkedint_employees,
        'hunter':       _run_hunter_employees,
    }

    total = 0
    sources: dict[str, int] = {}

    for tool_key, _ in _TOOL_ORDER:
        if _check_stop_signal(job_id):
            _push_to_stream(scan_id, {
                'type': 'employee_intel_progress',
                'job_id': job_id,
                'tool': tool_key,
                'status': 'cancelled',
                'found': 0,
                'message': '',
            })
            break

        _push_to_stream(scan_id, {
            'type': 'employee_intel_progress',
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
                'type': 'employee_intel_progress',
                'job_id': job_id,
                'tool': tool_key,
                'status': 'done',
                'found': found,
                'message': '',
            })
        except Exception as exc:
            sources[tool_key] = 0
            logger.error(
                '[EMPLOYEE_INTEL] tool=%s scan_id=%s error=%s',
                tool_key, scan_id, exc, exc_info=True,
            )
            _push_to_stream(scan_id, {
                'type': 'employee_intel_progress',
                'job_id': job_id,
                'tool': tool_key,
                'status': 'error',
                'found': 0,
                'message': _safe_error_message(exc),
            })

    _push_to_stream(scan_id, {
        'type': 'employee_intel_complete',
        'job_id': job_id,
        'total_found': total,
        'sources': sources,
    })
    _clear_active(scan_id)
    logger.info('[EMPLOYEE_INTEL] COMPLETE scan_id=%s total=%d', scan_id, total)
