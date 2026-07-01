import logging
import requests

from startScan.models import Dork, Subdomain
from reNgine.utils.task import run_command
from reNgine.tasks.persistence import save_secret_leak
from scanEngine.models import Proxy
from reNgine.common_func import get_random_proxy

logger = logging.getLogger(__name__)

_SWAGGER_PATHS = [
    '/swagger.json',
    '/swagger.yaml',
    '/openapi.json',
    '/openapi.yaml',
    '/api-docs',
    '/api-docs.json',
    '/swagger-ui.html',
    '/v1/swagger.json',
    '/v2/swagger.json',
    '/v3/api-docs',
    '/api/swagger.json',
]

# SwaggerSpy is installed via git clone + uv venv (not on PyPI).
# Confirmed working: /usr/src/github/SwaggerSpy/.venv/bin/python3 2026-07-01
_SWAGGERSPY_PYTHON = '/usr/src/github/SwaggerSpy/.venv/bin/python3'
_SWAGGERSPY_DIR = '/usr/src/github/SwaggerSpy'


def _get_proxy() -> str | None:
    proxy_obj = Proxy.objects.first()
    return get_random_proxy() if proxy_obj and proxy_obj.use_proxy else None


def run_porch_pirate(self, host: str, scan_history, results_dir: str) -> None:
    """Search public Postman workspaces for leaked secrets related to host."""
    proxy = _get_proxy()
    cmd = ['porch-pirate', '-s', host, '-l', '25', '--dump']
    if proxy:
        cmd = ['proxychains4', '-q'] + cmd

    logger.info("porch-pirate starting for %s", host)
    return_code, output = run_command(cmd, cwd=results_dir)

    for line in output.splitlines():
        line = line.strip()
        if line and ('=' in line or ':' in line):
            save_secret_leak(
                scan_history=scan_history,
                tool_name='porch-pirate',
                secret_type='postman_leak',
                source_url='postman://%s' % host,
                match_content=line,
            )

    logger.info("porch-pirate finished for %s — exit_code=%s", host, return_code)


def run_postleaks(self, host: str, scan_history, results_dir: str) -> None:
    """Search public Postman workspaces for credential leaks using postleaksNg.

    Binary is postleaksNg (capital N and G) — confirmed 2026-07-01.
    """
    proxy = _get_proxy()
    # Binary installed as 'postleaksNg' (capital N and G), not 'postleakng'
    cmd = ['postleaksNg', '-k', host, '--output', results_dir, '-t', '10']
    if proxy:
        cmd = ['proxychains4', '-q'] + cmd

    logger.info("postleaksNg starting for %s", host)
    return_code, output = run_command(cmd, cwd=results_dir)

    for line in output.splitlines():
        line = line.strip()
        if line:
            save_secret_leak(
                scan_history=scan_history,
                tool_name='postleaksNg',
                secret_type='postman_leak',
                source_url='postman://%s' % host,
                match_content=line,
            )

    logger.info("postleaksNg finished for %s — exit_code=%s", host, return_code)


def run_swaggerspy_internet(self, host: str, scan_history, results_dir: str) -> None:
    """Discover Swagger/OpenAPI specs for host via internet/GitHub search using SwaggerSpy.

    SwaggerSpy is installed via git clone + uv venv at /usr/src/github/SwaggerSpy.
    Must be executed from its own directory so relative imports resolve correctly.
    """
    proxy = _get_proxy()
    cmd = [_SWAGGERSPY_PYTHON, 'swaggerspy.py', host]
    if proxy:
        cmd = ['proxychains4', '-q'] + cmd

    logger.info("SwaggerSpy (internet) starting for %s", host)
    return_code, output = run_command(cmd, cwd=_SWAGGERSPY_DIR)

    for line in output.splitlines():
        url = line.strip()
        if url.startswith('http'):
            dork, _ = Dork.objects.get_or_create(type='swagger_spec', url=url)
            scan_history.dorks.add(dork)

    logger.info("SwaggerSpy (internet) finished for %s — exit_code=%s", host, return_code)


def run_swaggerspy_path_mode(self, host: str, scan_history, results_dir: str) -> None:
    """Probe confirmed live subdomains for common Swagger/OpenAPI endpoint paths.

    This path-probe variant is called from post_crawl_osint() (Task 9) after
    crawling has populated confirmed live subdomains with http_url values.
    """
    proxy = _get_proxy()
    proxies_dict = {'http': proxy, 'https': proxy} if proxy else None
    timeout = 10

    live_subdomains = Subdomain.objects.filter(
        scan_history=scan_history,
        http_status__in=[200, 201, 301, 302, 401, 403],
    ).exclude(http_url='').values_list('http_url', flat=True)

    found = 0
    for base_url in live_subdomains:
        base_url = base_url.rstrip('/')
        for path in _SWAGGER_PATHS:
            probe_url = '%s%s' % (base_url, path)
            try:
                resp = requests.get(
                    probe_url,
                    proxies=proxies_dict,
                    timeout=timeout,
                    verify=False,
                )
                if resp.status_code == 200 and any(
                    kw in resp.text[:512]
                    for kw in ('"swagger"', '"openapi"', 'swagger:', 'openapi:')
                ):
                    dork, _ = Dork.objects.get_or_create(type='swagger_spec', url=probe_url)
                    scan_history.dorks.add(dork)
                    found += 1
                    logger.info("SwaggerSpy path found: %s", probe_url)
            except Exception as exc:
                logger.debug("swaggerspy_path probe failed for %s: %s", probe_url, exc)

    logger.info("SwaggerSpy (path mode) finished for %s — %d specs found", host, found)
