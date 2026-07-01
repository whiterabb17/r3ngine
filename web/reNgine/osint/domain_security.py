"""Domain security module — SPF/DMARC email spoofability check via Spoofy.

Spoofy (https://github.com/MattKeeley/Spoofy) must run from its own directory
because it loads data files relative to cwd.

Results are persisted as an OsintStaging record with osint_type='domain_security'
so they appear in the existing OSINT staging UI without requiring new model fields.
"""
import json
import logging

from reNgine.utils.task import run_command
from startScan.models import OsintStaging
from targetApp.models import Domain
from scanEngine.models import Proxy
from reNgine.common_func import get_random_proxy

logger = logging.getLogger(__name__)

# Spoofy install paths — uv creates .venv
_SPOOFY_PYTHON = '/usr/src/github/Spoofy/.venv/bin/python3'
_SPOOFY_DIR = '/usr/src/github/Spoofy'


def run_spoofcheck(self, host: str, scan_history, results_dir: str) -> None:
    """Check if a domain is vulnerable to email spoofing via SPF/DMARC analysis.

    Invokes Spoofy with JSON output, parses the result, and persists it as an
    OsintStaging record linked to the scan and target domain.  If Spoofy is not
    installed the function logs an error and returns without raising.

    Args:
        self: Activity/task self object (unused directly; kept for call-site
              consistency with other osint helpers).
        host: Target domain name to check.
        scan_history: ScanHistory model instance.
        results_dir: Path to the scan results directory (unused by Spoofy; kept
                     for API consistency).
    """
    import os as _os

    if not _os.path.exists(_SPOOFY_PYTHON):
        logger.error(
            "Spoofy not found at %s — skipping domain security check for %s",
            _SPOOFY_PYTHON,
            host,
        )
        return

    proxy_obj = Proxy.objects.first()
    proxy = get_random_proxy() if proxy_obj and proxy_obj.use_proxy else None

    cmd = [_SPOOFY_PYTHON, 'spoofy.py', '-d', host, '-o', 'json']

    if proxy:
        cmd = ['proxychains4', '-q'] + cmd

    logger.info("Spoofy starting for %s", host)
    return_code, output = run_command(cmd, cwd=_SPOOFY_DIR)

    if not output or not output.strip():
        logger.info(
            "Spoofy produced no output for %s (exit_code=%s)",
            host,
            return_code,
        )
        return

    result = _parse_spoofy_output(output, host)
    if result is None:
        # Parsing failed entirely — already logged inside helper
        return

    domain_obj = Domain.objects.filter(name=host).first()

    OsintStaging.objects.update_or_create(
        scan_history=scan_history,
        target_domain=domain_obj,
        osint_type='domain_security',
        content=host,
        defaults={
            'source': 'spoofy',
            'confidence': 95,
            'metadata': {'spoofcheck': result},
            'status': 'pending',
        },
    )

    logger.info(
        "Spoofy finished for %s — exit_code=%s spoofable=%s",
        host,
        return_code,
        result['spoofable'],
    )


# ---------------------------------------------------------------------------
# Internal helpers
# ---------------------------------------------------------------------------

def _parse_spoofy_output(output: str, host: str) -> dict | None:
    """Parse Spoofy output into a normalised result dict.

    Spoofy with ``-o json`` emits a JSON array of one object per domain.
    Without the flag it emits human-readable plain text.  Both paths are
    handled; plain text is the fallback for unexpected invocations.

    Returns a dict with keys ``raw``, ``spoofable``, ``spf``, ``dmarc``,
    ``spoofing_type``, or ``None`` if the output is empty after stripping.
    """
    stripped = output.strip()
    if not stripped:
        return None

    # --- JSON path (Spoofy -o json) ---
    if stripped.startswith('[') or stripped.startswith('{'):
        try:
            data = json.loads(stripped)
            # Spoofy -o json → array of one object
            if isinstance(data, list) and data:
                record = data[0]
            elif isinstance(data, dict):
                record = data
            else:
                record = {}

            return {
                'raw': stripped,
                'spoofable': bool(record.get('SPOOFING_POSSIBLE', False)),
                'spf': record.get('SPF') or '',
                'dmarc': record.get('DMARC') or '',
                'spoofing_type': record.get('SPOOFING_TYPE') or '',
            }
        except (json.JSONDecodeError, ValueError, TypeError) as exc:
            logger.debug("Spoofy JSON parse failed for %s: %s — falling back to text", host, exc)

    # --- Plain-text fallback ---
    lower = stripped.lower()
    # "[+] Spoofing possible" or "Spoofable: ..." indicates spoofable
    spoofable = (
        'spoofing possible' in lower
        or ('[+]' in lower and 'spoof' in lower)
    ) and 'not possible' not in lower

    return {
        'raw': stripped,
        'spoofable': spoofable,
        'spf': '',
        'dmarc': '',
        'spoofing_type': '',
    }
