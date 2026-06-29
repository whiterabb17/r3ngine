"""
firewall_tasks.py — TLS deep audit extensions for firewall_vpn_scan.

Runs testssl.sh (per-finding Vulnerability records) and queries crt.sh
certificate transparency logs (feeds subdomain pipeline).
"""
import json
import logging
import os
import tempfile

import requests

from reNgine.common_func import save_vulnerability
from reNgine.definitions import ENABLE_CRT_SH, ENABLE_TESTSSL
from reNgine.utils.task import run_command, save_subdomain

logger = logging.getLogger(__name__)

_TESTSSL_SEVERITY_MAP = {
    'ok': 0,
    'info': 0,
    'low': 1,
    'medium': 2,
    'high': 3,
    'critical': 4,
}


def run_tls_deep_audit(self, ctx, config):
    """Run testssl.sh against each SSL port; store one Vulnerability per finding."""
    ssl_ports = config.get('ports', [443, 4444, 8443])
    target = self.domain.name

    for port in ssl_ports:
        output_json = f'{self.results_dir}/testssl_{target}_{port}.json'
        cmd = (
            f'testssl.sh --jsonfile {output_json} --color 0 --quiet '
            f'{target}:{port}'
        )
        logger.warning(f'Running testssl.sh on {target}:{port}')
        run_command(
            cmd,
            shell=True,
            history_file=self.history_file,
            scan_id=self.scan_id,
            activity_id=self.activity_id,
        )

        if not os.path.isfile(output_json):
            continue

        try:
            with open(output_json, 'r') as f:
                findings = json.load(f)
        except Exception as e:
            logger.error(f'testssl.sh JSON parse error for {target}:{port}: {e}')
            continue

        if not isinstance(findings, list):
            findings = findings.get('scanResult', [])
            if isinstance(findings, dict):
                findings = [findings]

        for entry in findings:
            severity_str = str(entry.get('severity', 'info')).lower()
            severity_int = _TESTSSL_SEVERITY_MAP.get(severity_str, 0)
            if severity_int == 0:
                continue

            finding_id = entry.get('id', 'unknown')
            finding_text = entry.get('finding', '')
            save_vulnerability(
                target_domain=self.domain,
                scan_history=self.scan,
                name=f'TLS: {finding_id}',
                description=finding_text,
                severity=severity_int,
                type='SSL/TLS',
                source='testssl.sh',
                http_url=f'https://{target}:{port}',
                dedup_fields=['name', 'http_url', 'scan_history'],
            )


def run_crt_sh(self, ctx, target):
    """Query crt.sh and feed discovered certificate names into the subdomain pipeline."""
    logger.warning(f'Querying crt.sh for {target}')
    try:
        resp = requests.get(
            f'https://crt.sh/?q=%.{target}&output=json',
            timeout=30,
        )
        resp.raise_for_status()
        entries = resp.json()
    except Exception as e:
        logger.error(f'crt.sh request failed for {target}: {e}')
        return

    seen = set()
    for entry in entries:
        raw = entry.get('name_value', '')
        for name in raw.split('\n'):
            name = name.strip().lstrip('*.').lower()
            if not name or name in seen:
                continue
            if not name.endswith(target):
                continue
            seen.add(name)
            save_subdomain(name, ctx=ctx)
