"""
Discovery and reconnaissance activities: Tier 1 of the scan pipeline plus the
host/network recon tools of the rengine-ng standalone workflows.
"""

from temporalio import activity
from reNgine.temporal.heartbeat import keep_alive

from reNgine.utils.logger import get_module_logger
from reNgine.temporal.activities.core import TemporalTaskProxy, _run_task

logger = get_module_logger(__name__)


# ===========================================================================
# Tier 1 — Discovery
# ===========================================================================

@activity.defn(name="RunSubdomainDiscoveryActivity")
def run_subdomain_discovery_activity(ctx: dict) -> bool:
    """Execute subdomain discovery tools (subfinder, amass, etc.) against the target.

    Delegates to the existing `subdomain_discovery` Celery task function which
    runs all configured discovery tools sequentially, writing results to the
    scan results directory and persisting discovered subdomains to the DB.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from reNgine.tasks import subdomain_discovery
    activity.logger.info("[RunSubdomainDiscoveryActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        subdomain_discovery,
        ctx,
        task_name='subdomain_discovery',
        description='Subdomain Discovery'
    )


@activity.defn(name="RunAmassIntelDiscoveryActivity")
def run_amass_intel_discovery_activity(ctx: dict) -> bool:
    """Run Amass Intel infrastructure discovery against the target domain.

    Delegates to the existing `amass_intel_discovery` task to find related
    root domains and IP ranges via WHOIS and other intelligence sources.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from reNgine.tasks import amass_intel_discovery
    from startScan.models import ScanHistory
    scan = ScanHistory.objects.filter(pk=ctx.get('scan_history_id')).first()
    host = scan.domain.name if scan else ctx.get('domain_name', '')
    activity.logger.info("[RunAmassIntelDiscoveryActivity] host=%s", host)
    return _run_task(
        amass_intel_discovery,
        ctx,
        task_name='amass_intel_discovery',
        description='Infrastructure Discovery',
        host=host
    )


@activity.defn(name="RunFirewallVPNScanActivity")
def run_firewall_vpn_scan_activity(ctx: dict) -> bool:
    """Detect firewall and VPN infrastructure protecting the target.

    Delegates to the existing `firewall_vpn_scan` task.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from reNgine.tasks import firewall_vpn_scan
    activity.logger.info("[RunFirewallVPNScanActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        firewall_vpn_scan,
        ctx,
        task_name='firewall_vpn_scan',
        description='Firewall & VPN Scan'
    )


@activity.defn(name="RunDNSSecurityActivity")
def run_dns_security_activity(ctx: dict) -> bool:
    """Run DNS security checks: AXFR, DNSSEC, amplification, optional brute-force.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from reNgine.tasks.dns import dns_security
    activity.logger.info("[RunDNSSecurityActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        dns_security,
        ctx,
        task_name='dns_security',
        description='DNS Security Scan'
    )


@activity.defn(name="ParseDiscoveryResultsActivity")
@keep_alive
def parse_discovery_results_activity(ctx: dict) -> bool:
    """Parse and persist discovery tier results to the database.

    After all Tier 1 tools finish, this activity consolidates output files,
    deduplicates subdomains, and writes them to the Subdomain model.
    In the current implementation, each discovery tool writes directly to the
    DB via save_subdomain(), so this is a lightweight verification pass.

    Args:
        ctx (dict): Temporal workflow context.

    Returns:
        bool: True on success.
    """
    from startScan.models import ScanHistory, Subdomain
    scan_id = ctx.get('scan_history_id')
    logger.log_line("[TEMPORAL]", "START", "task=parse_discovery_results scan_id=%s" % scan_id)
    count = Subdomain.objects.filter(scan_history_id=scan_id).count()
    activity.logger.info(
        "[ParseDiscoveryResultsActivity] scan_id=%s: %s subdomains persisted.", scan_id, count
    )
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=parse_discovery_results scan_id=%s subdomains=%d" % (scan_id, count))
    return True


# ---------------------------------------------------------------------------
# Phase 1 — rengine-ng workflow tool activities
# ---------------------------------------------------------------------------

@activity.defn(name="RunDNSXActivity")
def run_dnsx_activity(ctx: dict) -> bool:
    from reNgine.tasks.recon import dnsx_scan
    activity.logger.info("[RunDNSXActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        dnsx_scan, ctx, task_name='dnsx_scan', description='DNS Resolution (dnsx)',
        subdomain=ctx.get('subdomain'), subdomains=ctx.get('subdomains'),
        wordlist=ctx.get('wordlist'),
    )


@activity.defn(name="RunWAFW00FActivity")
def run_wafw00f_activity(ctx: dict) -> bool:
    from reNgine.tasks.recon import wafw00f_scan
    activity.logger.info("[RunWAFW00FActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        wafw00f_scan, ctx, task_name='wafw00f_scan', description='WAF Detection (wafw00f)',
        url=ctx.get('url'), urls=ctx.get('urls'),
    )


@activity.defn(name="RunFPingActivity")
def run_fping_activity(ctx: dict) -> list:
    from reNgine.tasks.recon import fping_scan
    activity.logger.info("[RunFPingActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        fping_scan, ctx, task_name='fping_scan', description='ICMP Host Discovery (fping)',
        cidr=ctx.get('cidr'), targets=ctx.get('targets'),
    )


@activity.defn(name="RunARPScanActivity")
def run_arpscan_activity(ctx: dict) -> list:
    from reNgine.tasks.recon import arpscan_scan
    activity.logger.info("[RunARPScanActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        arpscan_scan, ctx, task_name='arpscan_scan', description='ARP Host Discovery (arp-scan)',
        cidr=ctx.get('cidr'),
    )


@activity.defn(name="RunMapCIDRActivity")
def run_mapcidr_activity(ctx: dict) -> list:
    from reNgine.tasks.recon import mapcidr_expand
    activity.logger.info("[RunMapCIDRActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        mapcidr_expand, ctx, task_name='mapcidr_expand', description='CIDR Expansion (mapcidr)',
        cidr=ctx.get('cidr'),
    )


@activity.defn(name="RunSSHAuditActivity")
def run_sshaudit_activity(ctx: dict) -> bool:
    from reNgine.tasks.recon import sshaudit_scan
    activity.logger.info("[RunSSHAuditActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        sshaudit_scan, ctx, task_name='sshaudit_scan', description='SSH Audit (ssh-audit)',
        host=ctx.get('host', ''), port=ctx.get('port', 22),
    )


@activity.defn(name="GetDiscoveredServicesActivity")
def get_discovered_services_activity(ctx: dict) -> list:
    """Return services discovered by port scan for the current scan_history.

    Queries: ScanHistory → Subdomain.ip_addresses → IpAddress.ports → Port
    Returns list of {host, port, service, version} dicts.
    Called by MasterScanWorkflow and HostReconWorkflow after RunPortScanActivity.
    """
    from startScan.models import IpAddress

    scan_history_id = ctx.get('scan_history_id')
    logger.log_line("[TEMPORAL]", "START", "task=get_discovered_services scan_id=%s" % scan_history_id)
    if not scan_history_id:
        logger.log_line("[TEMPORAL]", "COMPLETE", "task=get_discovered_services scan_id=None services=0")
        return []

    services = []
    ip_qs = IpAddress.objects.filter(
        ip_addresses__scan_history_id=scan_history_id
    ).prefetch_related('ports').distinct()

    for ip in ip_qs:
        for port in ip.ports.all():
            if port.service_name:
                services.append({
                    'host': ip.address or '',
                    'port': port.number,
                    'service': port.service_name,
                    'version': None,
                })

    activity.logger.info(
        "[GetDiscoveredServicesActivity] scan_id=%s found %d services",
        scan_history_id, len(services),
    )
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=get_discovered_services scan_id=%s services=%d" % (scan_history_id, len(services)))
    return services


@activity.defn(name="GetDiscoveredIPsActivity")
def get_discovered_ips_activity(ctx: dict) -> list:
    """Return distinct IP address strings discovered for this scan."""
    from startScan.models import IpAddress
    scan_id = ctx.get('scan_history_id')
    logger.log_line("[TEMPORAL]", "START", "task=get_discovered_ips scan_id=%s" % scan_id)
    activity.logger.info("[GetDiscoveredIPsActivity] scan_id=%s", scan_id)
    if not scan_id:
        logger.log_line("[TEMPORAL]", "COMPLETE", "task=get_discovered_ips scan_id=%s ips=0" % scan_id)
        return []
    ips = (
        IpAddress.objects
        .filter(ip_addresses__scan_history_id=scan_id)
        .values_list('address', flat=True)
        .distinct()
    )
    result = list(ips)
    activity.logger.info("[GetDiscoveredIPsActivity] found %d IPs for scan_id=%s", len(result), scan_id)
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=get_discovered_ips scan_id=%s ips=%d" % (scan_id, len(result)))
    return result


@activity.defn(name="RunGetASNActivity")
def run_getasn_activity(ctx: dict) -> bool:
    from reNgine.tasks.recon import getasn_scan
    activity.logger.info("[RunGetASNActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        getasn_scan, ctx, task_name='getasn_scan',
        description='ASN Enrichment (getasn)', ips=ctx.get('ips', []),
    )


@activity.defn(name="RunNetDetectActivity")
def run_netdetect_activity(ctx: dict) -> list:
    from reNgine.tasks.recon import netdetect_scan
    scan_id = ctx.get('scan_history_id')
    logger.log_line("[TEMPORAL]", "START", "task=netdetect_scan scan_id=%s" % scan_id)
    activity.logger.info("[RunNetDetectActivity] scan_id=%s", scan_id)
    proxy = TemporalTaskProxy(ctx, task_name='netdetect_scan',
                              description='Network CIDR Detection (netdetect)')
    result = netdetect_scan(proxy, scan_id, ctx.get('domain_id'))
    cidrs = [c for c in result if c] if isinstance(result, list) else []
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=netdetect_scan scan_id=%s cidrs=%d" % (scan_id, len(cidrs)))
    return cidrs


@activity.defn(name="RunJsWhoisActivity")
def run_jswhois_activity(ctx: dict) -> bool:
    from reNgine.tasks.recon import jswhois_scan
    activity.logger.info("[RunJsWhoisActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        jswhois_scan, ctx, task_name='jswhois_scan',
        description='WHOIS Lookup (jswhois)', domain=ctx.get('domain'),
    )


@activity.defn(name="RunWhoisDomainActivity")
def run_whoisdomain_activity(ctx: dict) -> bool:
    from reNgine.tasks.recon import whoisdomain_scan
    activity.logger.info("[RunWhoisDomainActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        whoisdomain_scan, ctx, task_name='whoisdomain_scan',
        description='WHOIS Lookup (whoisdomain)', domain=ctx.get('domain'),
    )


@activity.defn(name="RunBBotActivity")
def run_bbot_activity(ctx: dict) -> bool:
    from reNgine.tasks.recon import bbot_scan
    activity.logger.info("[RunBBotActivity] scan_id=%s", ctx.get('scan_history_id'))
    return _run_task(
        bbot_scan, ctx, task_name='bbot_scan',
        description='OSINT Discovery (bbot)', domain=ctx.get('domain'),
    )
