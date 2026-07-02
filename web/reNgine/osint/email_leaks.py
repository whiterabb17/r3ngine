import json
import logging

from reNgine.utils.task import run_command, save_email
from reNgine.tasks.persistence import save_secret_leak
from dashboard.models import LeakSearchAPIKey
from scanEngine.models import Proxy
from reNgine.common_func import get_random_proxy

logger = logging.getLogger(__name__)


def run_emailfinder(self, host: str, scan_history, results_dir: str) -> None:
    """Discover emails associated with host using emailfinder."""
    proxy_obj = Proxy.objects.first()
    proxy = get_random_proxy() if proxy_obj and proxy_obj.use_proxy else None

    cmd = ['emailfinder', '-d', host]
    if proxy:
        cmd = ['proxychains4', '-q'] + cmd

    logger.info("emailfinder starting for %s", host)
    return_code, output = run_command(cmd, cwd=results_dir)

    for line in output.splitlines():
        line = line.strip()
        if '@' in line and '.' in line:
            save_email(line, scan_history, source='emailfinder')

    logger.info("emailfinder finished for %s — exit_code=%s", host, return_code)


def run_leaksearch(self, host: str, scan_history, results_dir: str) -> None:
    """Search for credential leaks using LeakSearch.

    Skips gracefully if no LeakSearchAPIKey is configured.
    """
    key_obj = LeakSearchAPIKey.objects.first()
    if not key_obj:
        logger.warning("LeakSearch: no API key configured — skipping for %s", host)
        return

    proxy_obj = Proxy.objects.first()
    proxy = get_random_proxy() if proxy_obj and proxy_obj.use_proxy else None

    cmd = ['leaksearch', '-q', host, '-k', key_obj.key, '--json']
    if proxy:
        cmd = ['proxychains4', '-q'] + cmd

    logger.info("LeakSearch starting for %s", host)
    return_code, output = run_command(cmd, cwd=results_dir)

    try:
        results = json.loads(output) if output.strip() else []
        for entry in results:
            email = entry.get('email', host)
            password = entry.get('password', '')
            if password:
                save_secret_leak(
                    scan_history=scan_history,
                    tool_name='LeakSearch',
                    secret_type='credential',
                    source_url=f'leaksearch://{host}',
                    match_content=f"{email}:{password}",
                )
    except (json.JSONDecodeError, TypeError):
        # Non-JSON output; log raw line count only
        count = len([line for line in output.splitlines() if line.strip()])
        logger.info("LeakSearch raw output for %s: %d lines", host, count)

    logger.info("LeakSearch finished for %s — exit_code=%s", host, return_code)
