import logging
import os
import subprocess
import sys
from typing import TYPE_CHECKING

from django.conf import settings

from dashboard.models import HunterIOAPIKey
from startScan.models import EmailBreach
from reNgine.utils.task import save_email

if TYPE_CHECKING:
    from startScan.models import ScanHistory

logger = logging.getLogger(__name__)

_RESULTS_BASE = os.path.realpath(getattr(settings, 'RENGINE_RESULTS', '/usr/src/scan_results'))

_WHATBREACH_VENV = '/usr/src/github/WhatBreach/.venv/bin/python3'
_WHATBREACH_PYTHON = _WHATBREACH_VENV if os.path.exists(_WHATBREACH_VENV) else sys.executable
_WHATBREACH_SCRIPT = '/usr/src/github/WhatBreach/whatbreach.py'
_WHATBREACH_HOME = os.path.expanduser('~/.whatbreach_home')
_TOKENS_PATH = os.path.join(_WHATBREACH_HOME, 'tokens')
# Token filename confirmed by inspecting ~/.whatbreach_home/tokens/ after first container build.
# The WhatBreach tool initialises a plain-text file named 'hunter.io' (not JSON).
_HUNTER_TOKEN_FILE = os.path.join(_TOKENS_PATH, 'hunter.io')


def _ensure_whatbreach_hunter_key(hunter_key: str) -> None:
    """Write Hunter.io key into WhatBreach token file. No-op if key already present."""
    os.makedirs(_TOKENS_PATH, exist_ok=True)
    # Re-derive token_file at call time so tests can patch _TOKENS_PATH.
    token_file = os.path.join(_TOKENS_PATH, 'hunter.io')
    if os.path.exists(token_file):
        with open(token_file, 'r') as fh:
            if hunter_key in fh.read():
                return
    with open(token_file, 'w') as fh:
        fh.write(hunter_key)
    logger.info("WhatBreach Hunter.io token written to %s", token_file)


def run_whatbreach(
    self,
    host: str,
    scan_history: 'ScanHistory',
    results_dir: str,
    download_databases: bool = False,
) -> int:
    """Run WhatBreach for all emails found in the scan.

    Returns the number of new EmailBreach rows created with source='whatbreach'.
    """
    logger.info(
        "run_whatbreach | START | host=%s scan_id=%s download=%s",
        host, scan_history.id, download_databases,
    )

    hunter_key_obj = HunterIOAPIKey.objects.first()
    if not hunter_key_obj or not hunter_key_obj.key:
        logger.warning("run_whatbreach | SKIP | no Hunter.io API key configured")
        return 0

    emails = list(scan_history.emails.values_list('address', flat=True))
    if not emails:
        logger.warning("run_whatbreach | SKIP | no emails found for scan_id=%s", scan_history.id)
        return 0

    resolved_dir = os.path.realpath(results_dir)
    if not resolved_dir.startswith(_RESULTS_BASE):
        logger.error("run_whatbreach | ABORT | results_dir outside expected base: %s", results_dir)
        return 0

    emails_file = os.path.join(resolved_dir, 'whatbreach_emails.txt')
    with open(emails_file, 'w') as fh:
        fh.write('\n'.join(emails))

    _ensure_whatbreach_hunter_key(hunter_key_obj.key)

    cmd = [
        _WHATBREACH_PYTHON, _WHATBREACH_SCRIPT,
        '-l', emails_file,
        '-sH', '-dP', '-vH',
        '-s', resolved_dir,
    ]
    if download_databases:
        cmd.append('-d')

    created_count = 0
    current_email: str | None = None

    stdin_data = (b'y\n' * 50) if download_databases else None

    try:
        with subprocess.Popen(
            cmd,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            stdin=subprocess.PIPE,
        ) as proc:
            if stdin_data:
                proc.stdin.write(stdin_data)
            proc.stdin.close()

            for raw_line in proc.stdout:
                line = raw_line.decode('utf-8', errors='replace').strip()
                _track, _created = _parse_line(line, current_email, scan_history)
                if _track is not None:
                    current_email = _track
                created_count += _created

            proc.wait()
    except Exception as exc:
        logger.error("run_whatbreach | ERROR | %s", exc, exc_info=True)
        return created_count

    logger.info(
        "run_whatbreach | COMPLETE | scan_id=%s breaches_created=%d",
        scan_history.id, created_count,
    )
    return created_count


def _parse_line(
    line: str,
    current_email: str | None,
    scan_history: 'ScanHistory',
) -> tuple[str | None, int]:
    """Parse one stdout line from WhatBreach.

    Returns (new_current_email_or_None, breach_rows_created).
    current_email is updated only when a new email header line is found.
    """
    if '[ i ] starting search on single email address:' in line:
        email = line.split('address:', 1)[-1].strip()
        return email, 0

    if current_email and '|' in line and 'Breach/Paste' not in line and '---' not in line:
        parts = [p.strip() for p in line.split('|', 1)]
        if len(parts) == 2 and parts[0]:
            breach_name = parts[0]
            _, created = EmailBreach.objects.get_or_create(
                scan_history=scan_history,
                email_address=current_email,
                breach_name=breach_name,
                source='whatbreach',
            )
            return None, (1 if created else 0)

    if '->' in line and '@' in line:
        # Hunter.io discovered email — save and associate with scan
        candidate = line.split('->', 1)[-1].strip()
        if '@' in candidate and '.' in candidate.split('@')[-1]:
            save_email(candidate, scan_history=scan_history)

    return None, 0
