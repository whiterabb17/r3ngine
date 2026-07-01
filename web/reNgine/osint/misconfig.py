import json
import logging
import shlex

from startScan.models import Dork
from reNgine.utils.task import run_command
from reNgine.utils.opsec import get_opsec_manager
from scanEngine.models import Proxy
from reNgine.common_func import get_random_proxy

logger = logging.getLogger(__name__)


def run_misconfig_mapper(self, host: str, scan_history, results_dir: str) -> None:
    """Detect third-party service misconfigurations for host using misconfig-mapper.

    Runs misconfig-mapper against the target domain and persists discovered
    misconfigured service URLs as Dork records linked to the scan history.

    Args:
        self: Activity/task self object (must have .scan attribute).
        host: Target domain name to scan.
        scan_history: ScanHistory model instance.
        results_dir: Path to the scan results directory.
    """
    proxy_obj = Proxy.objects.first()
    proxy = get_random_proxy() if proxy_obj and proxy_obj.use_proxy else None

    cmd = [
        'misconfig-mapper',
        '-target', host,
        '-as-domain', 'true',
        '-permutations', 'false',
        '-skip-ssl',
        '-service', '*',
        '-verbose', '0',
    ]

    opsec = get_opsec_manager()
    if opsec.is_enabled():
        # apply_stealth works on a string command; rebuild as string for opsec then re-split.
        cmd_str = ' '.join(cmd)
        cmd_str = opsec.apply_stealth('misconfig_mapper', cmd_str, proxy)
        cmd = shlex.split(cmd_str)

    if proxy and not opsec.is_enabled():
        cmd = ['proxychains4', '-q'] + cmd

    logger.info("misconfig-mapper starting for %s", host)
    return_code, output = run_command(cmd, cwd=results_dir)

    if not output or not output.strip():
        logger.info(
            "misconfig-mapper produced no output for %s (exit_code=%s)",
            host,
            return_code,
        )
        return

    findings = _parse_output(output, host)
    saved = 0
    for finding in findings:
        url = (finding.get('url') or '').strip()
        service = (finding.get('service') or 'misconfig').strip()
        if url:
            dork, _ = Dork.objects.get_or_create(
                type='misconfig_%s' % service,
                url=url,
            )
            scan_history.dorks.add(dork)
            saved += 1

    logger.info(
        "misconfig-mapper finished for %s — exit_code=%s, saved=%d",
        host,
        return_code,
        saved,
    )


def _parse_output(output: str, host: str) -> list:
    """Parse misconfig-mapper output into a list of finding dicts.

    misconfig-mapper may emit:
      - A JSON array:  [{...}, {...}]
      - JSONL:         one JSON object per line

    Returns an empty list on malformed or empty output rather than raising.
    """
    stripped = output.strip()
    if not stripped:
        return []

    # Attempt JSON array first.
    if stripped.startswith('['):
        try:
            findings = json.loads(stripped)
            if isinstance(findings, list):
                return findings
        except (json.JSONDecodeError, ValueError):
            pass

    # Fall back to JSONL: parse each non-empty line independently.
    findings = []
    for line in stripped.splitlines():
        line = line.strip()
        if not line or not line.startswith('{'):
            continue
        try:
            obj = json.loads(line)
            if isinstance(obj, dict):
                findings.append(obj)
        except (json.JSONDecodeError, ValueError):
            pass

    if not findings and stripped:
        line_count = len([ln for ln in stripped.splitlines() if ln.strip()])
        logger.info(
            "misconfig-mapper non-JSON output for %s — %d lines, exit_code ignored",
            host,
            line_count,
        )

    return findings
