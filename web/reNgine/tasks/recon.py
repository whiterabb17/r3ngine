"""
Recon task functions for network-layer and domain intelligence tools.

These functions follow the TemporalTaskProxy interface used by temporal_activities.py.
Each function:
  1. Builds a tool command from yaml_configuration
  2. Runs the subprocess
  3. Parses output and persists findings to the database
  4. Returns True on success (or graceful non-fatal failure)

Severity mapping (matches Vulnerability.severity IntegerField):
  critical=4, high=3, medium=2, low=1, info=0
"""
import json
import logging
import os
import re
import socket
import subprocess
from typing import List, Optional

from reNgine.utils.logger import get_module_logger

logger = get_module_logger(__name__)

# Severity string -> integer map matching NUCLEI_SEVERITY_MAP in definitions.py
_SEVERITY = {'critical': 4, 'high': 3, 'medium': 2, 'low': 1, 'info': 0, 'unknown': -1}


def dnsx_scan(self, scan_history_id: int, domain_id: int,
              subdomain: str = None, subdomains: List[str] = None,
              wordlist: str = None) -> bool:
    """Resolve DNS records for subdomains/hosts using dnsx.

    Discovered hostnames are upserted as Subdomain records (scan-history-linked).
    Used in: DomainReconWorkflow, SubdomainReconWorkflow.
    """
    from startScan.models import ScanHistory, Subdomain
    from targetApp.models import Domain
    from django.db import transaction

    targets = subdomains or ([subdomain] if subdomain else [])
    if not targets:
        logger.log_line("[DNSX]", "SKIP", "no targets provided")
        return True

    input_file = f"/tmp/dnsx_input_{scan_history_id}.txt"
    output_file = f"/tmp/dnsx_output_{scan_history_id}.json"

    try:
        with open(input_file, 'w') as f:
            f.write('\n'.join(targets))

        cmd = ['dnsx', '-l', input_file, '-resp', '-recon', '-json', '-o', output_file, '-silent']
        if wordlist:
            cmd += ['-w', wordlist]

        logger.log_line("[DNSX]", "START", "resolving %d targets" % len(targets))
        subprocess.run(cmd, capture_output=True, text=True, timeout=300)

        if not os.path.exists(output_file):
            logger.log_line("[DNSX]", "WARN", "no output produced")
            return True

        records_to_upsert = []
        try:
            domain_obj = Domain.objects.get(pk=domain_id)
        except Domain.DoesNotExist:
            domain_obj = None

        with open(output_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    data = json.loads(line)
                except json.JSONDecodeError:
                    continue
                host = data.get('host', '').strip()
                if host:
                    records_to_upsert.append(host)

        if records_to_upsert:
            subdomains_to_create = []
            for host in records_to_upsert:
                if not Subdomain.objects.filter(
                    scan_history_id=scan_history_id, name=host
                ).exists():
                    subdomains_to_create.append(Subdomain(
                        scan_history_id=scan_history_id,
                        target_domain=domain_obj,
                        name=host,
                    ))
            if subdomains_to_create:
                with transaction.atomic():
                    Subdomain.objects.bulk_create(subdomains_to_create, ignore_conflicts=True)
                logger.log_line(
                    "[DNSX]", "RESULT", "upserted %d subdomains" % len(subdomains_to_create),
                )

    finally:
        for fpath in [input_file, output_file]:
            try:
                os.remove(fpath)
            except FileNotFoundError:
                pass

    return True


def wafw00f_scan(self, scan_history_id: int, domain_id: int,
                 url: str = None, urls: List[str] = None) -> bool:
    """Detect WAF presence using wafw00f.

    Tags matching Subdomain records with the detected WAF via M2M.
    Used in: DomainReconWorkflow.
    """
    from startScan.models import Subdomain, Waf
    from urllib.parse import urlparse
    from django.db import transaction

    targets = urls or ([url] if url else [])
    if not targets:
        logger.log_line("[WAFW00F]", "SKIP", "no targets provided")
        return True

    for target_url in targets:
        try:
            cmd = ['wafw00f', target_url, '-o', '-', '-f', 'json']
            logger.log_line("[WAFW00F]", "START", "checking %s" % target_url)
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            try:
                data = json.loads(result.stdout)
                if data and data[0].get('detected'):
                    waf_name = data[0].get('firewall', 'Unknown WAF')
                    manufacturer = data[0].get('manufacturer', '')
                    waf_obj, _ = Waf.objects.get_or_create(
                        name=waf_name,
                        defaults={'manufacturer': manufacturer},
                    )
                    parsed = urlparse(target_url)
                    hostname = parsed.hostname or ''
                    with transaction.atomic():
                        for sub in Subdomain.objects.filter(
                            scan_history_id=scan_history_id,
                            name=hostname,
                        ):
                            sub.waf.add(waf_obj)
                    logger.log_line("[WAFW00F]", "RESULT", "WAF detected: %s" % waf_name)
            except (json.JSONDecodeError, IndexError, KeyError):
                pass
        except subprocess.TimeoutExpired:
            logger.log_line("[WAFW00F]", "WARN", "timed out for %s" % target_url)

    return True


def fping_scan(self, scan_history_id: int, cidr: str = None,
               targets: List[str] = None) -> List[str]:
    """Discover alive hosts in a CIDR range using fping ICMP probes.

    Returns list of alive IP address strings.
    Used in: CIDRReconWorkflow (probe phase).
    """
    probe_targets = targets or ([cidr] if cidr else [])
    if not probe_targets:
        return []

    alive: List[str] = []
    cmd = ['fping', '-a', '-A', '-g'] + probe_targets
    logger.log_line("[FPING]", "START", "probing %s" % ' '.join(probe_targets))

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        for line in result.stdout.splitlines():
            line = line.strip()
            if line and 'is alive' in line:
                alive.append(line.split()[0])
    except subprocess.TimeoutExpired:
        logger.log_line("[FPING]", "WARN", "fping timed out")

    logger.log_line("[FPING]", "RESULT", "found %d alive hosts" % len(alive))
    return alive


def arpscan_scan(self, scan_history_id: int, cidr: str = None) -> List[str]:
    """Discover LAN hosts via ARP using arp-scan.

    Returns list of IP address strings found via ARP.
    Used in: CIDRReconWorkflow (local network discovery).
    Requires: NET_RAW capability or --privileged container.
    """
    if not cidr:
        return []

    alive: List[str] = []
    cmd = ['arp-scan', '--plain', '--resolve', cidr]
    logger.log_line("[ARPSCAN]", "START", "ARP scanning %s" % cidr)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        for line in result.stdout.splitlines():
            parts = line.split('\t')
            if parts and parts[0].strip():
                alive.append(parts[0].strip())
    except subprocess.TimeoutExpired:
        logger.log_line("[ARPSCAN]", "WARN", "arp-scan timed out")

    logger.log_line("[ARPSCAN]", "RESULT", "found %d hosts via ARP" % len(alive))
    return alive


def getasn_scan(self, scan_history_id: int, domain_id: int, ips: List[str] = None) -> bool:
    """Enrich discovered IPs with ASN number, CIDR, and organization using getasn.

    Calls `getasn -ip <addr>` per IP and stores the result on IpAddress records.
    Used in: DomainReconWorkflow, HostReconWorkflow.
    """
    from startScan.models import IpAddress

    targets = ips or []
    if not targets:
        logger.log_line("[GETASN]", "SKIP", "no IPs to enrich")
        return True

    logger.log_line("[GETASN]", "START", "enriching %d IPs" % len(targets))
    enriched = 0

    for ip_addr in targets:
        try:
            result = subprocess.run(
                ['getasn', '-ip', ip_addr],
                capture_output=True, text=True, timeout=30,
            )
            line = result.stdout.strip()
            if not line:
                continue
            parts = line.split()
            # Expected: <IP> <ASN> <CIDR> <Org...>
            if len(parts) >= 3:
                asn = parts[1]
                if not asn.startswith('AS'):
                    logger.log_line("[GETASN]", "WARN", "unexpected token '%s' for %s, skipping" % (asn, ip_addr))
                    continue
                asn_cidr = parts[2]
                asn_org = ' '.join(parts[3:]) if len(parts) > 3 else ''
                updated = IpAddress.objects.filter(address=ip_addr).update(
                    asn=asn[:20],
                    asn_cidr=asn_cidr[:50],
                    asn_org=asn_org[:200],
                )
                if updated:
                    enriched += 1
        except subprocess.TimeoutExpired:
            logger.log_line("[GETASN]", "WARN", "timeout for %s" % ip_addr)
        except Exception as exc:
            from reNgine.utils.logger import format_exception_for_log
            logger.log_line("[GETASN]", "ERROR", "failed for %s: %s" % (ip_addr, format_exception_for_log(exc)), level="error")

    logger.log_line("[GETASN]", "RESULT", "enriched %d/%d IPs" % (enriched, len(targets)))
    return True


def netdetect_scan(self, scan_history_id: int, domain_id: int) -> List[str]:
    """Detect local network CIDR ranges by enumerating network interfaces.

    Uses psutil to find non-loopback IPv4 interfaces and computes each
    interface's network CIDR. Returns a list of CIDR strings.
    Used in: CIDRReconWorkflow (auto-discover when no explicit target given).
    """
    import ipaddress
    import psutil

    cidrs: List[str] = []
    logger.log_line("[NETDETECT]", "START", "enumerating network interfaces")

    for iface, addrs in psutil.net_if_addrs().items():
        if iface == 'lo':
            continue
        for addr in addrs:
            if addr.family != socket.AF_INET:
                continue
            if not addr.netmask:
                continue
            try:
                net = ipaddress.IPv4Network(
                    '%s/%s' % (addr.address, addr.netmask), strict=False
                )
                if net.is_loopback:
                    continue
                cidr_str = str(net)
                cidrs.append(cidr_str)
                logger.log_line("[NETDETECT]", "FOUND", "iface=%s cidr=%s" % (iface, cidr_str))
            except ValueError:
                logger.log_line("[NETDETECT]", "WARN", "invalid addr on %s" % iface)

    logger.log_line("[NETDETECT]", "RESULT", "detected %d CIDR ranges" % len(cidrs))
    return cidrs


def mapcidr_expand(self, scan_history_id: int, cidr: str) -> List[str]:
    """Expand a CIDR range to individual IP addresses using mapcidr.

    Returns list of IP strings.
    Used in: CIDRReconWorkflow before fping.
    """
    cmd = ['mapcidr', '-cidr', cidr, '-silent']
    logger.log_line("[MAPCIDR]", "START", "expanding %s" % cidr)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        ips = [line.strip() for line in result.stdout.splitlines() if line.strip()]
        logger.log_line("[MAPCIDR]", "RESULT", "expanded to %d IPs" % len(ips))
        return ips
    except subprocess.TimeoutExpired:
        logger.log_line("[MAPCIDR]", "WARN", "mapcidr timed out")
        return []


def sshaudit_scan(self, scan_history_id: int, host: str, port: int = 22) -> bool:
    """Audit SSH service configuration using ssh-audit.

    Saves CVE findings as Vulnerability records.
    Severity: cvss >= 9.0 → critical(4), >= 7.0 → high(3), >= 4.0 → medium(2), else low(1).
    Used in: HostReconWorkflow.
    """
    from startScan.models import Vulnerability
    from django.db import transaction

    cmd = ['ssh-audit', '-j', '-p', str(port), host]
    logger.log_line("[SSHAUDIT]", "START", "auditing %s:%d" % (host, port))

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=120)
        try:
            data = json.loads(result.stdout)
        except json.JSONDecodeError:
            logger.log_line("[SSHAUDIT]", "WARN", "failed to parse json output for %s" % host)
            return True

        cves = data.get('cves', [])
        vulns = []
        for cve in cves:
            cvss = float(cve.get('cvss', 0))
            if cvss >= 9.0:
                sev = 4  # critical
            elif cvss >= 7.0:
                sev = 3  # high
            elif cvss >= 4.0:
                sev = 2  # medium
            else:
                sev = 1  # low

            vulns.append(Vulnerability(
                scan_history_id=scan_history_id,
                name=cve.get('name', 'SSH Vulnerability'),
                severity=sev,
                description=cve.get('description', ''),
                source='sshaudit',
                http_url='%s:%d' % (host, port),
            ))

        if vulns:
            with transaction.atomic():
                Vulnerability.objects.bulk_create(vulns, ignore_conflicts=True)
            logger.log_line("[SSHAUDIT]", "RESULT", "saved %d SSH vulnerabilities" % len(vulns))

    except subprocess.TimeoutExpired:
        logger.log_line("[SSHAUDIT]", "WARN", "ssh-audit timed out for %s" % host)

    return True


def _enrich_finding_with_llm(name: str, cvss_score: float = None) -> tuple:
    """Helper to query LLM for a vulnerability description and cache it in CveId."""
    try:
        from dashboard.models import LLMConfig
        from startScan.models import CveId
        from reNgine.llm import LLMVulnerabilityReportGenerator
        
        config = LLMConfig.objects.filter(is_active=True).first()
        if not config:
            return "", "", ""
            
        cve_obj, created = CveId.objects.get_or_create(name=name)
        if created and cvss_score:
            cve_obj.cvss_v31_base_score = cvss_score
            cve_obj.save()
            
        if not cve_obj.ai_risk_assessment:
            report_gen = LLMVulnerabilityReportGenerator(logger=logger)
            prompt = f"Analyze the vulnerability or CVE {name}. "
            if cve_obj.cvss_v31_base_score:
                prompt += f"It has a CVSS base score of {cve_obj.cvss_v31_base_score}. "
            prompt += "Provide a detailed risk assessment, potential impact, and mitigation ideas."
            
            response = report_gen.get_vulnerability_description(prompt)
            if response and response.get('status'):
                desc = response.get('description', '')
                impact = response.get('impact', '')
                remediation = response.get('remediation', '')
                
                assessment = f"**Description**:\n{desc}\n\n**Impact**:\n{impact}\n\n**Mitigation**:\n{remediation}"
                cve_obj.ai_risk_assessment = assessment
                cve_obj.mitigation_ideas = remediation
                cve_obj.save()
                return desc, impact, remediation
            return "", "", ""
            
        # Already cached
        return cve_obj.ai_risk_assessment, "", cve_obj.mitigation_ideas or ""
    except Exception as e:
        logger.log_line("[LLM_ENRICH]", "WARN", "LLM enrichment failed for %s: %s" % (name, str(e)))
        return "", "", ""


def wpprobe_scan(self, scan_history_id: int, url: str) -> bool:
    """Scan WordPress site for vulnerable plugins using wpprobe.

    Saves findings as Vulnerability records.
    Used in: WordPressWorkflow.
    """
    from startScan.models import Vulnerability
    from django.db import transaction

    cmd = ['wpprobe', '-u', url, '-json']
    logger.log_line("[WPPROBE]", "START", "scanning %s" % url)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=300)
        findings = json.loads(result.stdout) if result.stdout.strip().startswith('[') else []
        vulns = []
        for finding in findings:
            sev_str = finding.get('severity', 'medium').lower()
            sev = _SEVERITY.get(sev_str, 2)
            vulns.append(Vulnerability(
                scan_history_id=scan_history_id,
                name=finding.get('cve', 'WordPress Plugin Vulnerability'),
                severity=sev,
                description='Plugin: %s v%s' % (
                    finding.get('plugin', ''), finding.get('version', '')),
                source='wpprobe',
                http_url=url,
            ))
        if vulns:
            with transaction.atomic():
                Vulnerability.objects.bulk_create(vulns, ignore_conflicts=True)
            logger.log_line("[WPPROBE]", "RESULT", "saved %d plugin vulnerabilities" % len(vulns))
    except (subprocess.TimeoutExpired, json.JSONDecodeError):
        logger.log_line("[WPPROBE]", "WARN", "wpprobe failed for %s" % url)

    return True


def search_vulns_scan(self, scan_history_id: int, service: str,
                      version: Optional[str], host: str, port: int,
                      subdomain_id: Optional[int] = None, domain_id: Optional[int] = None) -> bool:
    """Query vulners.com for CVEs/exploits for a discovered service+version.

    Called concurrently per service immediately after port scan completes.
    Saves findings as Vulnerability records. Skips when service is empty.

    VULNERS_API_KEY env var enables higher rate limits (optional).
    """
    import requests
    from startScan.models import Vulnerability
    from django.db import transaction

    if not service or not service.strip() or not version:
        return True

    query = ('%s %s' % (service, version)).strip() if version else service.strip()
    api_key = os.environ.get('VULNERS_API_KEY', '')
    url = 'https://vulners.com/api/v3/search/lucene/'
    params: dict = {
        'query': query,
        'fields': ['id', 'title', 'cvss', 'description', 'published'],
        'size': 10,
    }
    if api_key:
        params['apiKey'] = api_key

    logger.log_line("[SEARCH_VULNS]", "START", "querying vulners for %s" % query)

    try:
        resp = requests.get(url, params=params, timeout=15)
        resp.raise_for_status()
        results = resp.json().get('data', {}).get('search', [])
    except Exception as exc:
        logger.log_line("[SEARCH_VULNS]", "WARN", "vulners query failed: %s" % str(exc))
        return True

    if not results:
        logger.log_line("[SEARCH_VULNS]", "RESULT", "no results for %s" % query)
        return True

    vulns = []
    for item in results:
        cvss_data = item.get('cvss') or {}
        if isinstance(cvss_data, dict):
            cvss_score = float(cvss_data.get('score', 0))
        elif isinstance(cvss_data, (int, float)):
            cvss_score = float(cvss_data)
        else:
            cvss_score = 0.0

        if cvss_score >= 9.0:
            sev = 4  # critical
        elif cvss_score >= 7.0:
            sev = 3  # high
        elif cvss_score >= 4.0:
            sev = 2  # medium
        else:
            sev = 1  # low

        desc_llm, impact_llm, remediation_llm = _enrich_finding_with_llm(item.get('id', 'Service Vulnerability'), cvss_score)
        
        base_desc = '%s\n\nService: %s %s\nHost: %s:%d\nCVSS: %.1f\n\n%s' % (
            item.get('title', ''),
            service, version or '',
            host, port,
            cvss_score,
            item.get('description', ''),
        )
        if desc_llm:
            base_desc += '\n\n**AI Risk Assessment**:\n' + desc_llm

        vulns.append(Vulnerability(
            scan_history_id=scan_history_id,
            subdomain_id=subdomain_id,
            target_domain_id=domain_id,
            name=item.get('id', 'Service Vulnerability'),
            severity=sev,
            description=base_desc,
            impact=impact_llm if impact_llm else None,
            remediation=remediation_llm if remediation_llm else None,
            source='search_vulns',
            http_url='%s:%d' % (host, port),
        ))

    if vulns:
        with transaction.atomic():
            Vulnerability.objects.bulk_create(vulns, ignore_conflicts=True)
        logger.log_line(
            "[SEARCH_VULNS]", "RESULT",
            "saved %d vulns for %s on %s:%d" % (len(vulns), query, host, port),
        )

    return True


def bbot_scan(self, scan_history_id: int, domain_id: int, domain: Optional[str] = None) -> bool:
    """Discover subdomains using BBOT passive OSINT modules.

    Runs the bbot subdomain-enum preset and parses DNS_NAME events from NDJSON
    output into Subdomain records. Gated by yaml_configuration.subdomain_recon.bbot.
    Used in: SubdomainReconWorkflow.
    """
    import shutil
    from startScan.models import Subdomain
    from targetApp.models import Domain
    from django.db import transaction

    target = domain or ''
    if not target:
        logger.log_line("[BBOT]", "SKIP", "no domain provided")
        return True

    output_dir = f'/tmp/bbot_{scan_history_id}'
    output_file = f'{output_dir}/output.ndjson'

    try:
        cmd = [
            'bbot', '-t', target,
            '-p', 'subdomain-enum',
            '--silent', '--no-deps',
            '-o', output_dir,
            '-om', 'ndjson',
        ]
        logger.log_line("[BBOT]", "START", "scanning %s" % target)
        subprocess.run(cmd, capture_output=True, text=True, timeout=600)

        if not os.path.exists(output_file):
            logger.log_line("[BBOT]", "WARN", "no output produced for %s" % target)
            return True

        try:
            domain_obj = Domain.objects.get(pk=domain_id)
        except Domain.DoesNotExist:
            domain_obj = None

        new_names: List[str] = []
        with open(output_file) as f:
            for line in f:
                line = line.strip()
                if not line:
                    continue
                try:
                    event = json.loads(line)
                except json.JSONDecodeError:
                    continue
                if event.get('type') == 'DNS_NAME':
                    name = event.get('data', '').strip()
                    if name:
                        new_names.append(name)

        if new_names:
            with transaction.atomic():
                Subdomain.objects.bulk_create(
                    [Subdomain(scan_history_id=scan_history_id,
                               target_domain=domain_obj, name=n)
                     for n in new_names],
                    ignore_conflicts=True,
                )
            logger.log_line("[BBOT]", "RESULT", "saved %d new subdomains" % len(new_names))
        else:
            logger.log_line("[BBOT]", "RESULT", "no new subdomains found")

    except subprocess.TimeoutExpired:
        logger.log_line("[BBOT]", "WARN", "bbot timed out for %s" % target)
    finally:
        if os.path.exists(output_dir):
            shutil.rmtree(output_dir, ignore_errors=True)

    return True


def jswhois_scan(self, scan_history_id: int, domain_id: int, domain: Optional[str] = None) -> bool:
    """Fetch WHOIS data as JSON using the jswhois Go binary.

    Stores raw JSON in DomainInfo.whois_raw for the target domain.
    Used in: DomainReconWorkflow.
    """
    from targetApp.models import Domain

    target = domain or ''
    if not target:
        logger.log_line("[JSWHOIS]", "SKIP", "no domain provided")
        return True

    cmd = ['jswhois', '-j', target]
    logger.log_line("[JSWHOIS]", "START", "querying %s" % target)

    try:
        result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        raw = result.stdout.strip()
        if not raw:
            return True
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            logger.log_line("[JSWHOIS]", "WARN", "non-JSON output for %s" % target)
            return True

        domain_obj = Domain.objects.filter(pk=domain_id).first()
        if domain_obj and domain_obj.domain_info:
            domain_obj.domain_info.whois_raw = data
            domain_obj.domain_info.save(update_fields=['whois_raw'])
            logger.log_line("[JSWHOIS]", "RESULT", "stored whois_raw for %s" % target)
    except subprocess.TimeoutExpired:
        logger.log_line("[JSWHOIS]", "WARN", "timeout for %s" % target)

    return True


def whoisdomain_scan(self, scan_history_id: int, domain_id: int, domain: Optional[str] = None) -> bool:
    """Fetch WHOIS data using the whoisdomain Python CLI.

    Writes JSON output to a temp file, reads it, and stores in DomainInfo.whois_raw.
    Used in: DomainReconWorkflow.
    """
    from targetApp.models import Domain

    target = domain or ''
    if not target:
        logger.log_line("[WHOISDOMAIN]", "SKIP", "no domain provided")
        return True

    output_file = f'/tmp/whoisdomain_{scan_history_id}.json'
    cmd = ['whoisdomain', '-d', target, '-o', output_file]
    logger.log_line("[WHOISDOMAIN]", "START", "querying %s" % target)

    try:
        subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        if not os.path.exists(output_file):
            return True
        with open(output_file) as f:
            raw = f.read().strip()
        if not raw:
            return True
        try:
            data = json.loads(raw)
        except json.JSONDecodeError:
            logger.log_line("[WHOISDOMAIN]", "WARN", "non-JSON output for %s" % target)
            return True

        domain_obj = Domain.objects.filter(pk=domain_id).first()
        if domain_obj and domain_obj.domain_info:
            domain_obj.domain_info.whois_raw = data
            domain_obj.domain_info.save(update_fields=['whois_raw'])
            logger.log_line("[WHOISDOMAIN]", "RESULT", "stored whois_raw for %s" % target)
    except subprocess.TimeoutExpired:
        logger.log_line("[WHOISDOMAIN]", "WARN", "timeout for %s" % target)
    finally:
        if os.path.exists(output_file):
            os.remove(output_file)

    return True
