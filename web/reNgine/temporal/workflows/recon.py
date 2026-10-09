"""
Standalone recon and URL workflows (rengine-ng Phase 2).

Each workflow here manages its own internal pipeline sequencing and can be
started directly or as a SubScanWorkflow child (see _STANDALONE_SUBSCAN_WORKFLOWS
in subscan.py). Deterministic orchestrators only.
"""

import asyncio
from datetime import timedelta
from temporalio import workflow

from reNgine.temporal.workflows._common import (
    _RETRY_INTERNAL,
    _RETRY_LONG_SCAN,
    _RETRY_NETWORK_SCAN,
    _RETRY_SCANNER,
    _fan_out_search_vulns,
)


# ---------------------------------------------------------------------------
# Phase 2 — rengine-ng standalone workflow helpers + 13 new workflows
# ---------------------------------------------------------------------------


@workflow.defn(name="UserHuntWorkflow")
class UserHuntWorkflow:
    """Standalone user/email OSINT workflow.

    Runs maigret for username targets and h8mail for email targets.
    Triggered directly from the API for email or username input.
    rengine-ng equivalent: user_hunt workflow.
    """

    @workflow.run
    async def run(self, ctx: dict) -> bool:
        target_type = ctx.get('target_type', 'username')

        if target_type == 'email':
            await workflow.execute_activity(
                "RunGenericTaskActivity",
                {**ctx, 'task_name': 'h8mail'},
                start_to_close_timeout=timedelta(minutes=30),
                retry_policy=_RETRY_NETWORK_SCAN,
                task_queue="python-orchestrator-queue",
            )
        else:
            await workflow.execute_activity(
                "RunGenericTaskActivity",
                {**ctx, 'task_name': 'maigret'},
                start_to_close_timeout=timedelta(minutes=30),
                retry_policy=_RETRY_NETWORK_SCAN,
                task_queue="python-orchestrator-queue",
            )
        return True


@workflow.defn(name="URLBypassWorkflow")
class URLBypassWorkflow:
    """Attempt 4xx URL bypass on a list of URLs using bup.

    rengine-ng equivalent: url_bypass workflow.
    """

    @workflow.run
    async def run(self, ctx: dict) -> bool:
        await workflow.execute_activity(
            "RunBUPActivity",
            ctx,
            start_to_close_timeout=timedelta(minutes=30),
            retry_policy=_RETRY_NETWORK_SCAN,
            task_queue="python-orchestrator-queue",
        )
        return True


@workflow.defn(name="WordPressWorkflow")
class WordPressWorkflow:
    """Standalone WordPress security assessment.

    Runs HTTP probe, wpscan, wpprobe, and nuclei (wordpress tag).
    rengine-ng equivalent: wordpress workflow.
    """

    @workflow.run
    async def run(self, ctx: dict) -> bool:
        await workflow.execute_activity(
            "RunHTTPCrawlActivity",
            ctx,
            start_to_close_timeout=timedelta(minutes=15),
            retry_policy=_RETRY_NETWORK_SCAN,
            task_queue="python-orchestrator-queue",
        )

        await asyncio.gather(
            workflow.execute_activity(
                "RunWpscanActivity",
                ctx,
                start_to_close_timeout=timedelta(hours=1),
                retry_policy=_RETRY_LONG_SCAN,
                task_queue="python-orchestrator-queue",
            ),
            workflow.execute_activity(
                "RunWPProbeActivity",
                ctx,
                start_to_close_timeout=timedelta(minutes=30),
                retry_policy=_RETRY_NETWORK_SCAN,
                task_queue="python-orchestrator-queue",
            ),
            workflow.execute_activity(
                "RunNucleiActivity",
                {**ctx, 'tags_override': ['wordpress'], 'severity': 'critical,high,medium,low'},
                start_to_close_timeout=timedelta(hours=2),
                retry_policy=_RETRY_LONG_SCAN,
                task_queue="python-orchestrator-queue",
            ),
        )

        await workflow.execute_activity(
            "RunWPTaintScanActivity",
            ctx,
            start_to_close_timeout=timedelta(hours=2),
            heartbeat_timeout=timedelta(minutes=5),
            retry_policy=_RETRY_SCANNER,
            task_queue="python-orchestrator-queue"
        )

        return True


@workflow.defn(name="HostReconWorkflow")
class HostReconWorkflow:
    """Standalone host/IP reconnaissance workflow.

    Port scan (naabu + nmap) → SSH audit → HTTP probe → optional nuclei.
    Fans out search_vulns per discovered service.
    rengine-ng equivalent: host_recon workflow.
    """

    @workflow.run
    async def run(self, ctx: dict) -> bool:
        yaml_config = ctx.get('yaml_configuration') or {}
        host_config = yaml_config.get('host_recon', {})
        run_nuclei = host_config.get('run_nuclei', False)

        await workflow.execute_activity(
            "RunPortScanActivity",
            {**ctx, 'port_scan_tool': 'naabu'},
            start_to_close_timeout=timedelta(minutes=30),
            retry_policy=_RETRY_NETWORK_SCAN,
            task_queue="python-orchestrator-queue",
        )

        await workflow.execute_activity(
            "RunPortScanActivity",
            {**ctx, 'port_scan_tool': 'nmap', 'version_detection': True},
            start_to_close_timeout=timedelta(minutes=30),
            retry_policy=_RETRY_NETWORK_SCAN,
            task_queue="python-orchestrator-queue",
        )

        # Fan out per-service CVE + exploit lookups
        services = await workflow.execute_activity(
            "GetDiscoveredServicesActivity",
            ctx,
            start_to_close_timeout=timedelta(minutes=5),
            retry_policy=_RETRY_INTERNAL,
            task_queue="python-orchestrator-queue",
        )
        await _fan_out_search_vulns(ctx, services or [])

        await asyncio.gather(
            workflow.execute_activity(
                "RunHTTPCrawlActivity",
                ctx,
                start_to_close_timeout=timedelta(minutes=15),
                retry_policy=_RETRY_NETWORK_SCAN,
                task_queue="python-orchestrator-queue",
            ),
            workflow.execute_activity(
                "RunSSHAuditActivity",
                {**ctx, 'port': 22},
                start_to_close_timeout=timedelta(minutes=10),
                retry_policy=_RETRY_NETWORK_SCAN,
                task_queue="python-orchestrator-queue",
            ),
        )

        # Enrich discovered IPs with ASN data (uses DB-backed IPs, not hostname string)
        host_ips = await workflow.execute_activity(
            "GetDiscoveredIPsActivity",
            ctx,
            start_to_close_timeout=timedelta(minutes=2),
            retry_policy=_RETRY_INTERNAL,
            task_queue="python-orchestrator-queue",
        )
        if host_ips:
            await workflow.execute_activity(
                "RunGetASNActivity",
                {**ctx, 'ips': host_ips},
                start_to_close_timeout=timedelta(minutes=5),
                retry_policy=_RETRY_NETWORK_SCAN,
                task_queue="python-orchestrator-queue",
            )

        if run_nuclei:
            await workflow.execute_activity(
                "RunNucleiActivity",
                {**ctx, 'tags_override': ['network', 'ssl'], 'severity': 'critical,high,medium'},
                start_to_close_timeout=timedelta(hours=2),
                retry_policy=_RETRY_LONG_SCAN,
                task_queue="python-orchestrator-queue",
            )
        return True


@workflow.defn(name="CIDRReconWorkflow")
class CIDRReconWorkflow:
    """Network CIDR reconnaissance workflow.

    Discovers alive hosts (ARP or ICMP), expands CIDR, port scans, HTTP probes.
    rengine-ng equivalent: cidr_recon workflow.
    """

    @workflow.run
    async def run(self, ctx: dict) -> bool:
        cidr = ctx.get('cidr', '')
        yaml_config = ctx.get('yaml_configuration') or {}
        cidr_config = yaml_config.get('cidr_recon', {})
        use_arp = cidr_config.get('use_arp', False)

        # Auto-detect CIDR from local network interfaces when no target is given
        if not cidr:
            detected = await workflow.execute_activity(
                "RunNetDetectActivity",
                ctx,
                start_to_close_timeout=timedelta(minutes=2),
                retry_policy=_RETRY_INTERNAL,
                task_queue="python-orchestrator-queue",
            )
            detected = [c for c in (detected or []) if c]
            if not detected:
                return True
            cidr = detected[0]
            ctx = {**ctx, 'cidr': cidr}

        if use_arp:
            await workflow.execute_activity(
                "RunARPScanActivity",
                {**ctx, 'cidr': cidr},
                start_to_close_timeout=timedelta(minutes=15),
                retry_policy=_RETRY_NETWORK_SCAN,
                task_queue="python-orchestrator-queue",
            )
        else:
            await workflow.execute_activity(
                "RunMapCIDRActivity",
                {**ctx, 'cidr': cidr},
                start_to_close_timeout=timedelta(minutes=5),
                retry_policy=_RETRY_INTERNAL,
                task_queue="python-orchestrator-queue",
            )
            await workflow.execute_activity(
                "RunFPingActivity",
                {**ctx, 'cidr': cidr},
                start_to_close_timeout=timedelta(minutes=15),
                retry_policy=_RETRY_NETWORK_SCAN,
                task_queue="python-orchestrator-queue",
            )

        await workflow.execute_activity(
            "RunPortScanActivity",
            {**ctx, 'port_scan_tool': 'nmap', 'version_detection': True},
            start_to_close_timeout=timedelta(hours=1),
            retry_policy=_RETRY_LONG_SCAN,
            task_queue="python-orchestrator-queue",
        )

        await workflow.execute_activity(
            "RunHTTPCrawlActivity",
            ctx,
            start_to_close_timeout=timedelta(minutes=30),
            retry_policy=_RETRY_NETWORK_SCAN,
            task_queue="python-orchestrator-queue",
        )
        return True


@workflow.defn(name="CodeScanWorkflow")
class CodeScanWorkflow:
    """Source code vulnerability and secrets scanning.

    Runs gitleaks, trufflehog (via secret_scanning), and semgrep in parallel.
    rengine-ng equivalent: code_scan workflow.
    """

    @workflow.run
    async def run(self, ctx: dict) -> bool:
        yaml_config = ctx.get('yaml_configuration') or {}
        audit_config = yaml_config.get('vigolium_audit', {})

        activities = [
            workflow.execute_activity(
                "RunGenericTaskActivity",
                {**ctx, 'task_name': 'gitleaks_scan'},
                start_to_close_timeout=timedelta(hours=1),
                retry_policy=_RETRY_LONG_SCAN,
                task_queue="python-orchestrator-queue",
            ),
            workflow.execute_activity(
                "RunSecretScanningActivity",
                ctx,
                start_to_close_timeout=timedelta(hours=1),
                retry_policy=_RETRY_LONG_SCAN,
                task_queue="python-orchestrator-queue",
            ),
            workflow.execute_activity(
                "RunSemgrepActivity",
                {**ctx, 'mode': 'vulnerability'},
                start_to_close_timeout=timedelta(hours=1),
                retry_policy=_RETRY_LONG_SCAN,
                task_queue="python-orchestrator-queue",
            ),
            workflow.execute_activity(
                "RunGrypeScanActivity",
                ctx,
                start_to_close_timeout=timedelta(hours=2),
                retry_policy=_RETRY_LONG_SCAN,
                task_queue="python-orchestrator-queue",
            ),
            workflow.execute_activity(
                "RunTrivySecretScanActivity",
                ctx,
                start_to_close_timeout=timedelta(hours=2),
                retry_policy=_RETRY_LONG_SCAN,
                task_queue="python-orchestrator-queue",
            ),
        ]

        if audit_config.get('run_vigolium_audit', True):
            # Timeout from config (seconds), default 1 hour; cap at 4 hours.
            try:
                audit_timeout_s = min(int(audit_config.get('timeout', 3600)), 14400)
            except (ValueError, TypeError):
                audit_timeout_s = 3600
            activities.append(
                workflow.execute_activity(
                    "RunVigoliumAuditActivity",
                    ctx,
                    start_to_close_timeout=timedelta(seconds=audit_timeout_s + 300),
                    retry_policy=_RETRY_LONG_SCAN,
                    task_queue="python-orchestrator-queue",
                )
            )

        await asyncio.gather(*activities)
        return True


@workflow.defn(name="DomainReconWorkflow")
class DomainReconWorkflow:
    """Lightweight standalone domain intelligence workflow.

    WHOIS + DNS resolution + passive URL collection (parallel), then
    HTTP probe + WAF detection + testssl (parallel if not passive).
    rengine-ng equivalent: domain_recon workflow.
    """

    @workflow.run
    async def run(self, ctx: dict) -> bool:
        yaml_config = ctx.get('yaml_configuration') or {}
        passive_only = yaml_config.get('domain_recon', {}).get('passive', False)

        await asyncio.gather(
            workflow.execute_activity(
                "RunGenericTaskActivity",
                {**ctx, 'task_name': 'whois'},
                start_to_close_timeout=timedelta(minutes=5),
                retry_policy=_RETRY_INTERNAL,
                task_queue="python-orchestrator-queue",
            ),
            workflow.execute_activity(
                "RunJsWhoisActivity",
                {**ctx, 'domain': ctx.get('domain')},
                start_to_close_timeout=timedelta(minutes=5),
                retry_policy=_RETRY_INTERNAL,
                task_queue="python-orchestrator-queue",
            ),
            workflow.execute_activity(
                "RunWhoisDomainActivity",
                {**ctx, 'domain': ctx.get('domain')},
                start_to_close_timeout=timedelta(minutes=5),
                retry_policy=_RETRY_INTERNAL,
                task_queue="python-orchestrator-queue",
            ),
            workflow.execute_activity(
                "RunDNSXActivity",
                {**ctx, 'subdomain': ctx.get('domain')},
                start_to_close_timeout=timedelta(minutes=10),
                retry_policy=_RETRY_NETWORK_SCAN,
                task_queue="python-orchestrator-queue",
            ),
            workflow.execute_activity(
                "RunXURLFind3rActivity",
                {**ctx, 'domain': ctx.get('domain')},
                start_to_close_timeout=timedelta(minutes=15),
                retry_policy=_RETRY_NETWORK_SCAN,
                task_queue="python-orchestrator-queue",
            ),
        )

        if not passive_only:
            await asyncio.gather(
                workflow.execute_activity(
                    "RunHTTPCrawlActivity",
                    ctx,
                    start_to_close_timeout=timedelta(minutes=15),
                    retry_policy=_RETRY_NETWORK_SCAN,
                    task_queue="python-orchestrator-queue",
                ),
                workflow.execute_activity(
                    "RunWAFDetectionActivity",
                    ctx,
                    start_to_close_timeout=timedelta(minutes=10),
                    retry_policy=_RETRY_NETWORK_SCAN,
                    task_queue="python-orchestrator-queue",
                ),
                workflow.execute_activity(
                    "RunWAFW00FActivity",
                    {**ctx, 'url': 'https://' + (ctx.get('domain') or '')},
                    start_to_close_timeout=timedelta(minutes=10),
                    retry_policy=_RETRY_NETWORK_SCAN,
                    task_queue="python-orchestrator-queue",
                ),
            )

        # Enrich discovered IPs with ASN data after initial discovery
        discovered_ips = await workflow.execute_activity(
            "GetDiscoveredIPsActivity",
            ctx,
            start_to_close_timeout=timedelta(minutes=2),
            retry_policy=_RETRY_INTERNAL,
            task_queue="python-orchestrator-queue",
        )
        if discovered_ips:
            await workflow.execute_activity(
                "RunGetASNActivity",
                {**ctx, 'ips': discovered_ips},
                start_to_close_timeout=timedelta(minutes=10),
                retry_policy=_RETRY_NETWORK_SCAN,
                task_queue="python-orchestrator-queue",
            )
        return True


@workflow.defn(name="SubdomainReconWorkflow")
class SubdomainReconWorkflow:
    """Standalone subdomain discovery and verification workflow.

    Passive (subfinder, gau) + optional brute (dnsx) + HTTP probe + takeover check.
    rengine-ng equivalent: subdomain_recon workflow.
    """

    @workflow.run
    async def run(self, ctx: dict) -> bool:
        yaml_config = ctx.get('yaml_configuration') or {}
        subdomain_config = yaml_config.get('subdomain_recon', {})
        passive_only = subdomain_config.get('passive', False)
        brute_dns = subdomain_config.get('brute_dns', False)
        run_bbot = subdomain_config.get('bbot', False)

        discovery_tasks = [
            workflow.execute_activity(
                "RunSubdomainDiscoveryActivity",
                ctx,
                start_to_close_timeout=timedelta(hours=1),
                retry_policy=_RETRY_LONG_SCAN,
                task_queue="python-orchestrator-queue",
            ),
            workflow.execute_activity(
                "RunFetchURLActivity",
                ctx,
                start_to_close_timeout=timedelta(minutes=30),
                retry_policy=_RETRY_NETWORK_SCAN,
                task_queue="python-orchestrator-queue",
            ),
        ]
        if brute_dns and not passive_only:
            discovery_tasks.append(
                workflow.execute_activity(
                    "RunDNSXActivity",
                    {**ctx, 'wordlist': 'combined_subdomains'},
                    start_to_close_timeout=timedelta(hours=2),
                    retry_policy=_RETRY_LONG_SCAN,
                    task_queue="python-orchestrator-queue",
                )
            )
        if run_bbot:
            discovery_tasks.append(
                workflow.execute_activity(
                    "RunBBotActivity",
                    {**ctx, 'domain': ctx.get('domain')},
                    start_to_close_timeout=timedelta(hours=2),
                    retry_policy=_RETRY_LONG_SCAN,
                    task_queue="python-orchestrator-queue",
                )
            )
        await asyncio.gather(*discovery_tasks)

        if not passive_only:
            await asyncio.gather(
                workflow.execute_activity(
                    "RunHTTPCrawlActivity",
                    ctx,
                    start_to_close_timeout=timedelta(minutes=30),
                    retry_policy=_RETRY_NETWORK_SCAN,
                    task_queue="python-orchestrator-queue",
                ),
                workflow.execute_activity(
                    "RunNucleiActivity",
                    {**ctx, 'tags_override': ['takeover'], 'severity': 'critical,high,medium'},
                    start_to_close_timeout=timedelta(hours=1),
                    retry_policy=_RETRY_LONG_SCAN,
                    task_queue="python-orchestrator-queue",
                ),
            )
        return True


@workflow.defn(name="URLCrawlWorkflow")
class URLCrawlWorkflow:
    """Standalone URL crawl and passive discovery workflow.

    Passive (xurlfind3r, urlfinder, gau) + active (katana, cariddi).
    Optional secret hunt (trufflehog) and OSINT on found emails (maigret).
    rengine-ng equivalent: url_crawl workflow.
    """

    @workflow.run
    async def run(self, ctx: dict) -> bool:
        yaml_config = ctx.get('yaml_configuration') or {}
        crawl_config = yaml_config.get('url_crawl', {})
        passive_only = crawl_config.get('passive', False)
        active_only = crawl_config.get('active', False)
        hunt_secrets = crawl_config.get('hunt_secrets', False)

        if not active_only:
            await asyncio.gather(
                workflow.execute_activity(
                    "RunXURLFind3rActivity",
                    ctx,
                    start_to_close_timeout=timedelta(minutes=30),
                    retry_policy=_RETRY_NETWORK_SCAN,
                    task_queue="python-orchestrator-queue",
                ),
                workflow.execute_activity(
                    "RunURLFinderActivity",
                    ctx,
                    start_to_close_timeout=timedelta(minutes=30),
                    retry_policy=_RETRY_NETWORK_SCAN,
                    task_queue="python-orchestrator-queue",
                ),
                workflow.execute_activity(
                    "RunFetchURLActivity",
                    ctx,
                    start_to_close_timeout=timedelta(minutes=30),
                    retry_policy=_RETRY_NETWORK_SCAN,
                    task_queue="python-orchestrator-queue",
                ),
            )

        if not passive_only:
            await asyncio.gather(
                workflow.execute_activity(
                    "RunDirFileFuzzActivity",
                    {**ctx, 'tool': 'katana'},
                    start_to_close_timeout=timedelta(hours=1),
                    retry_policy=_RETRY_LONG_SCAN,
                    task_queue="python-orchestrator-queue",
                ),
                workflow.execute_activity(
                    "RunCariddiActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=1),
                    retry_policy=_RETRY_LONG_SCAN,
                    task_queue="python-orchestrator-queue",
                ),
            )

            await workflow.execute_activity(
                "RunHTTPCrawlActivity",
                ctx,
                start_to_close_timeout=timedelta(minutes=30),
                retry_policy=_RETRY_NETWORK_SCAN,
                task_queue="python-orchestrator-queue",
            )

            if hunt_secrets:
                await asyncio.gather(
                    workflow.execute_activity(
                        "RunSecretScanningActivity",
                        ctx,
                        start_to_close_timeout=timedelta(hours=1),
                        retry_policy=_RETRY_LONG_SCAN,
                        task_queue="python-orchestrator-queue",
                    ),
                    workflow.execute_activity(
                        "RunGenericTaskActivity",
                        {**ctx, 'task_name': 'maigret'},
                        start_to_close_timeout=timedelta(minutes=30),
                        retry_policy=_RETRY_NETWORK_SCAN,
                        task_queue="python-orchestrator-queue",
                    ),
                )

            # Extract URL parameters from all crawled endpoints
            await workflow.execute_activity(
                "RunURLParserActivity",
                ctx,
                start_to_close_timeout=timedelta(minutes=10),
                retry_policy=_RETRY_INTERNAL,
                task_queue="python-orchestrator-queue",
            )
        return True


@workflow.defn(name="URLDirSearchWorkflow")
class URLDirSearchWorkflow:
    """Hidden directory and file discovery on web servers.

    HTTP probe → ffuf dir mode → optional katana + secret scan.
    rengine-ng equivalent: url_dirsearch workflow.
    """

    @workflow.run
    async def run(self, ctx: dict) -> bool:
        yaml_config = ctx.get('yaml_configuration') or {}
        dirsearch_config = yaml_config.get('url_dirsearch', {})
        hunt_secrets = dirsearch_config.get('hunt_secrets', False)

        await workflow.execute_activity(
            "RunHTTPCrawlActivity",
            ctx,
            start_to_close_timeout=timedelta(minutes=15),
            retry_policy=_RETRY_NETWORK_SCAN,
            task_queue="python-orchestrator-queue",
        )

        await workflow.execute_activity(
            "RunDirFileFuzzActivity",
            {**ctx, 'mode': 'directory'},
            start_to_close_timeout=timedelta(hours=2),
            retry_policy=_RETRY_LONG_SCAN,
            task_queue="python-orchestrator-queue",
        )

        if hunt_secrets:
            await workflow.execute_activity(
                "RunSecretScanningActivity",
                ctx,
                start_to_close_timeout=timedelta(hours=1),
                retry_policy=_RETRY_LONG_SCAN,
                task_queue="python-orchestrator-queue",
            )
        return True


@workflow.defn(name="URLFuzzWorkflow")
class URLFuzzWorkflow:
    """Comprehensive URL fuzzing with feroxbuster and/or ffuf.

    rengine-ng equivalent: url_fuzz workflow.
    """

    @workflow.run
    async def run(self, ctx: dict) -> bool:
        yaml_config = ctx.get('yaml_configuration') or {}
        fuzz_config = yaml_config.get('url_fuzz', {})
        hunt_secrets = fuzz_config.get('hunt_secrets', False)
        fuzzers = fuzz_config.get('fuzzers', ['ffuf'])

        fuzz_tasks = []
        if 'feroxbuster' in fuzzers:
            fuzz_tasks.append(
                workflow.execute_activity(
                    "RunFeroxbusterActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=2),
                    retry_policy=_RETRY_LONG_SCAN,
                    task_queue="python-orchestrator-queue",
                )
            )
        if 'ffuf' in fuzzers:
            fuzz_tasks.append(
                workflow.execute_activity(
                    "RunDirFileFuzzActivity",
                    ctx,
                    start_to_close_timeout=timedelta(hours=2),
                    retry_policy=_RETRY_LONG_SCAN,
                    task_queue="python-orchestrator-queue",
                )
            )
        if fuzz_tasks:
            await asyncio.gather(*fuzz_tasks)

        await workflow.execute_activity(
            "RunHTTPCrawlActivity",
            ctx,
            start_to_close_timeout=timedelta(minutes=15),
            retry_policy=_RETRY_NETWORK_SCAN,
            task_queue="python-orchestrator-queue",
        )

        if hunt_secrets:
            await workflow.execute_activity(
                "RunSecretScanningActivity",
                ctx,
                start_to_close_timeout=timedelta(hours=1),
                retry_policy=_RETRY_LONG_SCAN,
                task_queue="python-orchestrator-queue",
            )
        return True


@workflow.defn(name="URLParamsFuzzWorkflow")
class URLParamsFuzzWorkflow:
    """URL parameter discovery and fuzzing.

    HTTP probe → arjun parameter discovery → optional ffuf value fuzzing.
    rengine-ng equivalent: url_params_fuzz workflow.
    """

    @workflow.run
    async def run(self, ctx: dict) -> bool:
        yaml_config = ctx.get('yaml_configuration') or {}
        params_config = yaml_config.get('url_params_fuzz', {})
        fuzz_values = params_config.get('fuzz_values', False)
        hunt_secrets = params_config.get('hunt_secrets', False)

        await workflow.execute_activity(
            "RunHTTPCrawlActivity",
            ctx,
            start_to_close_timeout=timedelta(minutes=15),
            retry_policy=_RETRY_NETWORK_SCAN,
            task_queue="python-orchestrator-queue",
        )

        # Passive parameter harvest from already-crawled URLs
        await workflow.execute_activity(
            "RunURLParserActivity",
            ctx,
            start_to_close_timeout=timedelta(minutes=10),
            retry_policy=_RETRY_INTERNAL,
            task_queue="python-orchestrator-queue",
        )

        await workflow.execute_activity(
            "RunArjunActivity",
            ctx,
            start_to_close_timeout=timedelta(hours=1),
            retry_policy=_RETRY_LONG_SCAN,
            task_queue="python-orchestrator-queue",
        )

        if fuzz_values:
            await workflow.execute_activity(
                "RunDirFileFuzzActivity",
                {**ctx, 'mode': 'params'},
                start_to_close_timeout=timedelta(hours=2),
                retry_policy=_RETRY_LONG_SCAN,
                task_queue="python-orchestrator-queue",
            )

        if hunt_secrets:
            await workflow.execute_activity(
                "RunSecretScanningActivity",
                ctx,
                start_to_close_timeout=timedelta(hours=1),
                retry_policy=_RETRY_LONG_SCAN,
                task_queue="python-orchestrator-queue",
            )
        return True


@workflow.defn(name="URLVulnWorkflow")
class URLVulnWorkflow:
    """URL vulnerability scanning with gf pattern matching + dalfox + nuclei.

    Fans gf patterns (xss/lfi/ssrf/rce/idor/debug_logic) across provided URLs,
    attacks XSS candidates with dalfox, and optionally runs nuclei HTTP scan.
    rengine-ng equivalent: url_vuln workflow.
    """

    @workflow.run
    async def run(self, ctx: dict) -> bool:
        yaml_config = ctx.get('yaml_configuration') or {}
        vuln_config = yaml_config.get('url_vuln', {})
        run_nuclei = vuln_config.get('nuclei', False)

        urls = ctx.get('urls', [])
        if not urls:
            return True

        gf_patterns = ['xss', 'lfi', 'ssrf', 'rce', 'idor', 'debug_logic', 'interestingparams']
        gf_results = await asyncio.gather(*[
            workflow.execute_activity(
                "RunGFActivity",
                {**ctx, 'pattern': pattern, 'urls': urls},
                start_to_close_timeout=timedelta(minutes=5),
                retry_policy=_RETRY_INTERNAL,
                task_queue="python-orchestrator-queue",
            )
            for pattern in gf_patterns
        ])

        # First result is xss pattern matches
        xss_urls = gf_results[0] if gf_results and isinstance(gf_results[0], list) else []

        if xss_urls:
            await workflow.execute_activity(
                "RunDalfoxActivity",
                {**ctx, 'urls': xss_urls},
                start_to_close_timeout=timedelta(hours=1),
                retry_policy=_RETRY_LONG_SCAN,
                task_queue="python-orchestrator-queue",
            )

        if run_nuclei:
            await workflow.execute_activity(
                "RunNucleiActivity",
                {**ctx, 'exclude_tags': ['network', 'ssl', 'file', 'dns', 'osint'],
                 'severity': 'critical,high,medium'},
                start_to_close_timeout=timedelta(hours=2),
                retry_policy=_RETRY_LONG_SCAN,
                task_queue="python-orchestrator-queue",
            )
        return True


@workflow.defn(name="URLAuthExtractWorkflow")
class URLAuthExtractWorkflow:
    """Extract authentication form candidates from a single URL.

    Expects ctx: {'url': str, 'scan_id': int}.
    Delegates to ExtractAuthForURLActivity with a 10-minute timeout.
    """

    @workflow.run
    async def run(self, ctx: dict) -> dict:
        return await workflow.execute_activity(
            "ExtractAuthForURLActivity",
            ctx,
            start_to_close_timeout=timedelta(minutes=10),
            retry_policy=_RETRY_INTERNAL,
            task_queue="python-orchestrator-queue",
        )
