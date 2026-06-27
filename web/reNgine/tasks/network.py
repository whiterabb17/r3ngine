"""
network.py — Protocol-specific enumeration extensions for port_scan.

After naabu + optional nmap finish, checks discovered ports and dispatches
protocol-specific tools: enum4linux-ng (SMB), onesixtyone + snmpwalk (SNMP),
ldapsearch (LDAP), rdp-sec-check (RDP).
"""
import json
import logging
import os
import subprocess

from reNgine.common_func import save_vulnerability
from reNgine.utils.task import run_command

logger = logging.getLogger(__name__)


def run_network_enum(self, ctx, ports_data):
    """Enumerate services on well-known protocol ports discovered by naabu/nmap."""
    for host, port_list in ports_data.items():
        port_set = set(int(p) for p in port_list)

        # SMB — port 445
        if 445 in port_set:
            _smb_enum(self, ctx, host)

        # SNMP — port 161
        if 161 in port_set:
            _snmp_enum(self, ctx, host)

        # LDAP — port 389 or 636
        if 389 in port_set or 636 in port_set:
            _ldap_enum(self, ctx, host)

        # RDP — port 3389
        if 3389 in port_set:
            _rdp_enum(self, ctx, host)


# ---------------------------------------------------------------------------
# Protocol helpers
# ---------------------------------------------------------------------------

def _smb_enum(self, ctx, host):
    output_json = f'{self.results_dir}/enum4linux_{host.replace(".", "_")}.json'
    cmd = f'enum4linux-ng -A {host} -oJ {output_json}'
    logger.warning(f'Running enum4linux-ng on {host}')
    try:
        run_command(
            cmd,
            shell=True,
            history_file=self.history_file,
            scan_id=self.scan_id,
            activity_id=self.activity_id,
        )
        if not os.path.isfile(output_json):
            return
        with open(output_json, 'r') as f:
            data = json.load(f)
        sessions = data.get('sessions_possible', {})
        if sessions.get('null_user') or sessions.get('anonymous'):
            save_vulnerability(
                target_domain=self.domain,
                scan_history=self.scan,
                name='SMB Null Session Allowed',
                description=(
                    f'enum4linux-ng confirmed that SMB null session is permitted on {host}. '
                    'Unauthenticated users may enumerate shares, users, and policies.'
                ),
                severity=3,
                type='SMB',
                source='enum4linux-ng',
                http_url=f'smb://{host}:445',
                dedup_fields=['name', 'http_url', 'scan_history'],
            )
    except Exception as e:
        logger.error(f'SMB enum failed for {host}: {e}')


def _snmp_enum(self, ctx, host):
    logger.warning(f'Running SNMP enumeration on {host}')
    communities = ['public', 'private', 'manager']
    found_community = None

    for community in communities:
        try:
            result = subprocess.run(
                ['onesixtyone', '-c', '/dev/stdin', host],
                input=community,
                capture_output=True,
                text=True,
                timeout=15,
            )
            if host in result.stdout and community in result.stdout:
                found_community = community
                break
        except Exception as e:
            logger.error(f'onesixtyone failed for {host}: {e}')
            break

    if found_community:
        save_vulnerability(
            target_domain=self.domain,
            scan_history=self.scan,
            name='SNMP Community String Exposed',
            description=(
                f'SNMP community string "{found_community}" is valid on {host}. '
                'Attackers can read MIB data or reconfigure network devices.'
            ),
            severity=2,
            type='SNMP',
            source='onesixtyone',
            http_url=f'udp://{host}:161',
            dedup_fields=['name', 'http_url', 'scan_history'],
        )

        # Estimate amplification factor via snmpwalk response size
        try:
            result = subprocess.run(
                ['snmpwalk', '-v2c', '-c', found_community, host],
                capture_output=True,
                text=True,
                timeout=30,
            )
            response_bytes = len(result.stdout.encode())
            # UDP request is ~45 bytes; amplification if ratio > 10
            if response_bytes > 450:
                save_vulnerability(
                    target_domain=self.domain,
                    scan_history=self.scan,
                    name='SNMP Amplification Risk',
                    description=(
                        f'SNMP walk on {host} returned ~{response_bytes} bytes. '
                        f'Amplification ratio ≈ {response_bytes // 45}×. '
                        'Host may be abused for UDP amplification attacks.'
                    ),
                    severity=1,
                    type='SNMP',
                    source='snmpwalk',
                    http_url=f'udp://{host}:161',
                    dedup_fields=['name', 'http_url', 'scan_history'],
                )
        except Exception as e:
            logger.error(f'snmpwalk failed for {host}: {e}')


def _ldap_enum(self, ctx, host):
    logger.warning(f'Running LDAP anonymous bind check on {host}')
    try:
        result = subprocess.run(
            ['ldapsearch', '-x', '-H', f'ldap://{host}', '-b', '', '-s', 'base'],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if 'namingContexts' in result.stdout or 'defaultNamingContext' in result.stdout:
            save_vulnerability(
                target_domain=self.domain,
                scan_history=self.scan,
                name='LDAP Anonymous Bind Allowed',
                description=(
                    f'LDAP anonymous bind succeeded on {host}. '
                    'Directory base DN is exposed without authentication.'
                ),
                severity=2,
                type='LDAP',
                source='ldapsearch',
                http_url=f'ldap://{host}:389',
                dedup_fields=['name', 'http_url', 'scan_history'],
            )
    except Exception as e:
        logger.error(f'LDAP enum failed for {host}: {e}')


def _rdp_enum(self, ctx, host):
    logger.warning(f'Running rdp-sec-check on {host}')
    try:
        result = subprocess.run(
            ['rdp-sec-check', host],
            capture_output=True,
            text=True,
            timeout=30,
        )
        output = result.stdout + result.stderr
        findings = []
        if 'NLA not required' in output or 'CredSSP' not in output:
            findings.append(('RDP NLA Not Required', 'Network Level Authentication is not enforced.', 2))
        if 'RC4' in output:
            findings.append(('RDP Weak Cipher: RC4', 'RC4 cipher is negotiated for RDP sessions.', 1))
        if 'Low' in output and 'encryption' in output.lower():
            findings.append(('RDP Low Encryption Level', 'RDP is configured with low encryption level.', 1))

        for name, description, severity in findings:
            save_vulnerability(
                target_domain=self.domain,
                scan_history=self.scan,
                name=name,
                description=f'{description} Host: {host}',
                severity=severity,
                type='RDP',
                source='rdp-sec-check',
                http_url=f'rdp://{host}:3389',
                dedup_fields=['name', 'http_url', 'scan_history'],
            )
    except Exception as e:
        logger.error(f'rdp-sec-check failed for {host}: {e}')
