"""
dns_tasks.py — DNS security scan task.

Standalone task registered as RunDNSSecurityActivity in Temporal.
Checks for: zone transfer (AXFR), dangling CNAMEs, DNSSEC configuration,
DNS amplification risk, and optionally subdomain brute-force via fierce.
"""
import json
import logging
import os
import subprocess

from reNgine.common_func import save_vulnerability
from reNgine.definitions import (
    DNS_AMPLIFICATION_THRESHOLD,
    DNS_SECURITY,
    ENABLE_AXFR,
    ENABLE_DNS_BRUTE,
    ENABLE_DNSSEC_CHECK,
)
from reNgine.utils.task import run_command, save_subdomain

logger = logging.getLogger(__name__)

_DANGLING_CNAME_PATTERNS = (
    '.amazonaws.com',
    '.azurewebsites.net',
    '.s3.amazonaws.com',
    '.cloudapp.azure.com',
    '.herokuapp.com',
    '.github.io',
)


def dns_security(self, host=None, ctx={}, description=None):
    """DNS security scan: AXFR, DNSSEC, amplification, optional brute-force."""
    config = (self.yaml_configuration.get(DNS_SECURITY) or {}) if hasattr(self, 'yaml_configuration') else {}
    target = host or (self.domain.name if hasattr(self, 'domain') else None)
    if not target:
        logger.error('dns_security: no target host available.')
        return False

    enable_axfr = config.get(ENABLE_AXFR, True)
    enable_dnssec = config.get(ENABLE_DNSSEC_CHECK, True)
    enable_brute = config.get(ENABLE_DNS_BRUTE, False)
    amp_threshold = config.get(DNS_AMPLIFICATION_THRESHOLD, 10)

    results_dir = getattr(self, 'results_dir', '/usr/src/scan_results')

    if enable_axfr:
        _check_axfr(self, ctx, target, results_dir)

    if enable_axfr:
        _check_amplification(self, ctx, target, amp_threshold)

    if enable_dnssec:
        _check_dnssec(self, ctx, target)

    if enable_brute:
        _brute_subdomains(self, ctx, target, results_dir)

    return True


# ---------------------------------------------------------------------------
# AXFR and dangling CNAME
# ---------------------------------------------------------------------------

def _check_axfr(self, ctx, target, results_dir):
    output_json = f'{results_dir}/dnsrecon_axfr_{target.replace(".", "_")}.json'
    cmd = f'dnsrecon -d {target} -t axfr --json {output_json} 2>/dev/null'
    logger.warning(f'Running dnsrecon AXFR check for {target}')
    run_command(
        cmd,
        shell=True,
        history_file=getattr(self, 'history_file', None),
        scan_id=getattr(self, 'scan_id', None),
        activity_id=getattr(self, 'activity_id', None),
    )

    if not os.path.isfile(output_json):
        return

    try:
        with open(output_json, 'r') as f:
            records = json.load(f)
    except Exception as e:
        logger.error(f'dnsrecon AXFR parse error for {target}: {e}')
        return

    if not isinstance(records, list):
        return

    # More than 5 records from a nameserver → AXFR succeeded
    axfr_records = [r for r in records if r.get('type') in ('A', 'AAAA', 'MX', 'NS', 'CNAME', 'TXT', 'SRV')]
    if len(axfr_records) > 5:
        save_vulnerability(
            target_domain=self.domain,
            scan_history=self.scan,
            name='DNS Zone Transfer Allowed (AXFR)',
            description=(
                f'A DNS zone transfer for {target} succeeded and returned '
                f'{len(axfr_records)} records. Full zone enumeration exposes '
                'internal infrastructure to attackers.'
            ),
            severity=4,
            type='DNS',
            source='dnsrecon',
            http_url=f'dns://{target}',
            dedup_fields=['name', 'http_url', 'scan_history'],
        )

    # Check CNAME records for dangling pointers
    for record in records:
        if record.get('type') != 'CNAME':
            continue
        cname_target = record.get('target', '')
        if not any(cname_target.endswith(p) for p in _DANGLING_CNAME_PATTERNS):
            continue
        # Check whether the CNAME resolves
        try:
            result = subprocess.run(
                ['dig', '+short', cname_target, '@8.8.8.8'],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if not result.stdout.strip() or 'NXDOMAIN' in result.stdout:
                subdomain_name = record.get('name', '').rstrip('.')
                save_vulnerability(
                    target_domain=self.domain,
                    scan_history=self.scan,
                    name='Dangling DNS CNAME',
                    description=(
                        f'{subdomain_name} CNAME points to {cname_target} '
                        'which does not resolve (possible subdomain takeover).'
                    ),
                    severity=2,
                    type='DNS',
                    source='dig',
                    http_url=f'dns://{subdomain_name}',
                    dedup_fields=['name', 'http_url', 'scan_history'],
                )
                if subdomain_name and subdomain_name.endswith(target):
                    save_subdomain(subdomain_name, ctx=ctx)
        except Exception as e:
            logger.error(f'CNAME resolution check failed for {cname_target}: {e}')


# ---------------------------------------------------------------------------
# DNS amplification
# ---------------------------------------------------------------------------

def _check_amplification(self, ctx, target, amp_threshold):
    logger.warning(f'Running DNS amplification check for {target}')
    try:
        result = subprocess.run(
            ['dig', '+short', 'ANY', target, '@8.8.8.8'],
            capture_output=True,
            text=True,
            timeout=15,
        )
        response_bytes = len(result.stdout.encode())
        ratio = response_bytes // 45  # ~45-byte UDP request
        if ratio > amp_threshold:
            save_vulnerability(
                target_domain=self.domain,
                scan_history=self.scan,
                name='DNS Amplification Risk',
                description=(
                    f'ANY query for {target} returned ~{response_bytes} bytes '
                    f'(amplification ratio ≈ {ratio}×). '
                    'The nameserver may be abused for UDP amplification attacks.'
                ),
                severity=1,
                type='DNS',
                source='dig',
                http_url=f'dns://{target}',
                dedup_fields=['name', 'http_url', 'scan_history'],
            )
    except Exception as e:
        logger.error(f'DNS amplification check failed for {target}: {e}')


# ---------------------------------------------------------------------------
# DNSSEC
# ---------------------------------------------------------------------------

def _check_dnssec(self, ctx, target):
    logger.warning(f'Checking DNSSEC configuration for {target}')
    try:
        result = subprocess.run(
            ['dig', '+dnssec', '+short', 'DS', target, '@8.8.8.8'],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if not result.stdout.strip():
            save_vulnerability(
                target_domain=self.domain,
                scan_history=self.scan,
                name='DNSSEC Not Configured',
                description=(
                    f'No DS record found for {target}. '
                    'DNSSEC is not enabled, allowing DNS cache poisoning attacks.'
                ),
                severity=2,
                type='DNS',
                source='dig',
                http_url=f'dns://{target}',
                dedup_fields=['name', 'http_url', 'scan_history'],
            )
    except Exception as e:
        logger.error(f'DNSSEC check failed for {target}: {e}')


# ---------------------------------------------------------------------------
# Subdomain brute-force via fierce
# ---------------------------------------------------------------------------

def _brute_subdomains(self, ctx, target, results_dir):
    wordlist = '/usr/src/wordlist/default_wordlist/deepmagic.com-prefixes-top50000.txt'
    if not os.path.isfile(wordlist):
        logger.warning(f'fierce wordlist not found at {wordlist}; skipping brute-force.')
        return

    output_file = f'{results_dir}/fierce_{target.replace(".", "_")}.txt'
    cmd = (
        f'fierce --domain {target} --dns-servers 8.8.8.8 '
        f'--subdomains {wordlist} 2>&1 | tee {output_file}'
    )
    logger.warning(f'Running fierce brute-force for {target}')
    run_command(
        cmd,
        shell=True,
        history_file=getattr(self, 'history_file', None),
        scan_id=getattr(self, 'scan_id', None),
        activity_id=getattr(self, 'activity_id', None),
    )

    if not os.path.isfile(output_file):
        return

    try:
        with open(output_file, 'r') as f:
            lines = f.readlines()
    except Exception as e:
        logger.error(f'fierce output read error for {target}: {e}')
        return

    for line in lines:
        # fierce outputs: "Found: subdomain.example.com. (1.2.3.4)"
        if not line.strip().startswith('Found:'):
            continue
        parts = line.strip().split()
        if len(parts) < 2:
            continue
        subdomain_name = parts[1].rstrip('.').lower()
        if not subdomain_name.endswith(target):
            continue
        save_subdomain(subdomain_name, ctx=ctx)
        if len(parts) >= 3:
            ip = parts[2].strip('()')
            from reNgine.tasks import save_ip_address
            from startScan.models import Subdomain as SubdomainModel
            subdomain_obj = SubdomainModel.objects.filter(
                name=subdomain_name,
                scan_history_id=ctx.get('scan_history_id'),
            ).first()
            if subdomain_obj and ip:
                try:
                    save_ip_address(
                        ip,
                        subdomain=subdomain_obj,
                        scan_id=ctx.get('scan_history_id'),
                        activity_id=getattr(self, 'activity_id', None),
                    )
                except Exception as e:
                    logger.error(f'save_ip_address failed for {ip}: {e}')
