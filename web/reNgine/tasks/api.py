"""
api_tasks.py — API security extensions for web_api_discovery.

Adds jwt_tool (JWT algorithm confusion / forging) and graphql-cop
(GraphQL security audit) to the per-URL scan loop.
"""
import json
import logging
import os

from reNgine.common_func import save_vulnerability
from reNgine.definitions import FFUF_DEFAULT_API_WORDLIST_PATH, GRAPHQL_COP, JWT_TOOL, USE_API_WORDLIST
from reNgine.utils.task import run_command

logger = logging.getLogger(__name__)

_GRAPHQL_COP_SEVERITY_MAP = {
    'low': 1,
    'medium': 2,
    'high': 3,
    'critical': 4,
}

_JWT_TOOL_PATH = '/usr/src/github/jwt_tool/jwt_tool.py'


def run_jwt_scan(self, ctx, url, subdomain, results_dir):
    """Run jwt_tool in all-attack mode against a URL and save confirmed findings."""
    subdomain_name = subdomain.name.replace('.', '_')
    output_file = f'{results_dir}/jwt_{subdomain_name}.txt'
    cmd = (
        f'python3 {_JWT_TOOL_PATH} -t {url} -M at -np 2>&1 | tee {output_file}'
    )
    logger.warning(f'Running jwt_tool on {url}')
    run_command(
        cmd,
        shell=True,
        history_file=self.history_file,
        scan_id=self.scan_id,
        activity_id=self.activity_id,
    )

    if not os.path.isfile(output_file):
        return

    try:
        with open(output_file, 'r') as f:
            lines = f.readlines()
    except Exception as e:
        logger.error(f'jwt_tool output read error for {url}: {e}')
        return

    for line in lines:
        line = line.strip()
        if not line.startswith('[+]'):
            continue
        # Extract the description after the last ": " or just use the full line
        description = line[3:].strip()
        name_part = description.split('Here:')[0].strip() if 'Here:' in description else description
        save_vulnerability(
            target_domain=self.domain,
            scan_history=self.scan,
            name=f'JWT: {name_part[:120]}',
            description=description,
            severity=3,
            type='Broken Authentication',
            source='jwt_tool',
            http_url=url,
            dedup_fields=['name', 'http_url', 'scan_history'],
        )


def run_graphql_cop(self, ctx, url, subdomain):
    """Run graphql-cop against all /graphql endpoints and save findings."""
    from startScan.models import EndPoint

    candidate_urls = set()
    # Collect existing /graphql endpoints
    for ep in EndPoint.objects.filter(scan_history=self.scan, http_url__icontains='/graphql'):
        candidate_urls.add(ep.http_url)
    # Always try appending /graphql to the base URL
    base = url.rstrip('/')
    candidate_urls.add(f'{base}/graphql')

    for graphql_url in candidate_urls:
        output_file = (
            f'{self.results_dir}/graphqlcop_{graphql_url.replace("://", "_").replace("/", "_")[:80]}.json'
        )
        cmd = f'python3 /usr/src/github/graphql-cop/graphql-cop.py -t {graphql_url} -o json 2>/dev/null | tee {output_file}'
        logger.warning(f'Running graphql-cop on {graphql_url}')
        run_command(
            cmd,
            shell=True,
            history_file=self.history_file,
            scan_id=self.scan_id,
            activity_id=self.activity_id,
        )

        if not os.path.isfile(output_file):
            continue

        try:
            with open(output_file, 'r') as f:
                findings = json.load(f)
        except Exception as e:
            logger.error(f'graphql-cop JSON parse error for {graphql_url}: {e}')
            continue

        if not isinstance(findings, list):
            continue

        for entry in findings:
            if not entry.get('result'):
                continue
            severity_str = str(entry.get('severity', 'low')).lower()
            severity_int = _GRAPHQL_COP_SEVERITY_MAP.get(severity_str, 1)
            save_vulnerability(
                target_domain=self.domain,
                scan_history=self.scan,
                name=f"GraphQL: {entry.get('name', 'Unknown')}",
                description=entry.get('description', ''),
                severity=severity_int,
                type='GraphQL',
                source='graphql-cop',
                http_url=graphql_url,
                dedup_fields=['name', 'http_url', 'scan_history'],
            )


def resolve_wordlist_path(config, default_path):
    """Return API wordlist path when use_api_wordlist is set, else return default_path."""
    if not config.get(USE_API_WORDLIST, False):
        return default_path
    if os.path.isfile(FFUF_DEFAULT_API_WORDLIST_PATH):
        return FFUF_DEFAULT_API_WORDLIST_PATH
    logger.warning(
        f'API wordlist not found at {FFUF_DEFAULT_API_WORDLIST_PATH}; '
        'falling back to default wordlist.'
    )
    return default_path
