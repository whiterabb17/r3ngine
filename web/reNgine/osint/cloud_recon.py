import json
import logging

from reNgine.utils.task import run_command, save_subdomain, save_employee
from scanEngine.models import Proxy
from reNgine.common_func import get_random_proxy

logger = logging.getLogger(__name__)

_PYTHON = '/usr/src/github/msftrecon/.venv/bin/python3'
_SCRIPT = '/usr/src/github/msftrecon/msftrecon/msftrecon.py'


def run_msftrecon(self, host: str, scan_history, results_dir: str) -> None:
    """Map Microsoft 365 and Azure tenant presence for host.

    Runs msftrecon with JSON output and persists discovered domains as
    subdomains and any employee-style strings via save_employee.
    """
    proxy_obj = Proxy.objects.first()
    proxy = get_random_proxy() if proxy_obj and proxy_obj.use_proxy else None

    cmd = [_PYTHON, _SCRIPT, '-d', host, '-j']
    if proxy:
        cmd = ['proxychains4', '-q'] + cmd

    logger.info("msftrecon starting for %s", host)
    return_code, output = run_command(cmd, cwd=results_dir)

    if not output or not output.strip():
        logger.info("msftrecon produced no output for %s (exit_code=%s)", host, return_code)
        return

    try:
        data = json.loads(output)
    except (json.JSONDecodeError, ValueError):
        logger.warning(
            "msftrecon: non-JSON output for %s — %d chars, exit_code=%s",
            host,
            len(output),
            return_code,
        )
        return

    ctx = {'scan_history_id': scan_history.id}

    # Persist domains discovered by msftrecon as subdomains
    for domain_name in data.get('domains', []):
        domain_name = (domain_name or '').strip().lower()
        if domain_name:
            save_subdomain(domain_name, ctx=ctx)

    # Persist tenant name as an employee-style record if present
    tenant = (data.get('tenant') or '').strip()
    if tenant:
        save_employee(tenant, designation='msftrecon-tenant', scan_history=scan_history)

    logger.info(
        "msftrecon finished for %s — exit_code=%s, domains=%d",
        host,
        return_code,
        len(data.get('domains', [])),
    )
