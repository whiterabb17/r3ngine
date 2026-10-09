"""SpiderFoot scan: streaming CSV parsing, per-type persistence handlers and the staging router.

Split out of the former reNgine/tasks/osint.py; re-exported by
reNgine.tasks.osint for backward compatibility.
"""
import logging
import subprocess
import os

from reNgine.common_func import *  # noqa: F401,F403
from reNgine.definitions import *  # noqa: F401,F403
from startScan.models import *  # noqa: F401,F403
from django.db import transaction
from reNgine.parsers import SpiderFootBatchParser
from reNgine.utils.task import save_email, save_employee, save_subdomain, save_endpoint
from reNgine.tasks.persistence import save_ip_address, save_secret_leak
from reNgine.tasks.certificate import run_certificate_intel
from reNgine.utils.graph import Neo4jManager
from redis import Redis

logger = logging.getLogger(__name__)

def spiderfoot_scan(self, host=None, ctx={}, description=None):
    """Run SpiderFoot scan on selected domain with real-time batch parsing."""
    # host selection logic based on user rules
    if not host:
        if self.subscan_id and self.subdomain:
            host = self.subdomain.name
        else:
            host = self.domain.name

    logger.warning(
        "[SPIDERFOOT] Starting scan for target: %s (Scan ID: %s, Subscan ID: %s)",
        host,
        self.scan_id,
        self.subscan_id,
    )

    if not self.yaml_configuration:
        # yaml_configuration may be empty when the engine YAML was not correctly passed
        # through ctx (e.g. Temporal replay edge-case, or test proxy with empty dict).
        # Fall back to loading the engine YAML directly from the DB via self.engine.
        if self.engine:
            import yaml as _yaml

            _raw = self.engine.yaml_configuration or ""
            self.yaml_configuration = _yaml.safe_load(_raw) or {}
            logger.warning(
                "[SPIDERFOOT] yaml_configuration was empty — reloaded from engine '%s' (id=%s)",
                self.engine.engine_name,
                self.engine.id,
            )
        else:
            logger.error(
                "[SPIDERFOOT] yaml_configuration is empty and no engine found! Check engine config."
            )

    config = self.yaml_configuration.get(SPIDERFOOT_SCAN) or {}
    modules = config.get("modules", "all")
    threads = config.get("threads") or self.yaml_configuration.get("threads", 5)
    intensity = config.get("intensity", "normal")  # normal, fast, deep

    # Spiderfoot CLI intensity mapping (profiles)
    profile_cmd = ""
    if intensity == "fast":
        profile_cmd = "-u footprint"
    elif intensity == "deep":
        profile_cmd = "-u all"

    if modules != "all":
        profile_cmd = f"-m {modules}"
    elif not profile_cmd:
        profile_cmd = "-u investigate"

    # Use global SF config
    sf_config_path = "/usr/src/github/spiderfoot/spiderfoot.cfg"
    sf_exec_path = "/usr/src/github/spiderfoot/sf.py"

    if not os.path.exists(sf_exec_path):
        logger.error(
            "[SPIDERFOOT] SpiderFoot executable not found at %s!", sf_exec_path
        )
        return

    if not os.path.exists(sf_config_path):
        logger.error(
            "[SPIDERFOOT] SpiderFoot config not found at %s. Task may fail or use defaults.",
            sf_config_path,
        )

    # Use CSV output for streaming. -r includes source data, -n strips newlines.
    cmd = f"python3 {sf_exec_path} -s {host} {profile_cmd} -max-threads {threads} -o csv -r -n"
    logger.warning("[SPIDERFOOT] Executing command: %s", cmd)

    # Check for custom spiderfoot keys and write to spiderfoot.cfg
    try:
        from dashboard.models import SpiderfootAPIKey

        sf_keys = SpiderfootAPIKey.objects.all()
        if sf_keys.exists() and os.path.exists(sf_config_path):
            with open(sf_config_path, "r") as f:
                original_lines = f.readlines()

            key_dict = {
                f"{k.module_name}:{k.key_name}": k.key_value
                for k in sf_keys
                if k.key_value
            }
            new_lines = []
            changed = False

            for line in original_lines:
                if "=" in line:
                    prefix = line.split("=")[0].strip()
                    if prefix in key_dict:
                        new_val = key_dict.pop(prefix)
                        expected_line = f"{prefix}={new_val}\n"
                        if line != expected_line:
                            new_lines.append(expected_line)
                            changed = True
                        else:
                            new_lines.append(line)
                    else:
                        new_lines.append(line)
                else:
                    new_lines.append(line)

            if key_dict:
                changed = True
                for k, v in key_dict.items():
                    new_lines.append(f"{k}={v}\n")

            if changed:
                with open(sf_config_path, "w") as f:
                    f.writelines(new_lines)
    except Exception as e:
        logger.error("[SPIDERFOOT] Failed to write API keys: %s", e)

    # Initialize stateful parser with Redis dedup
    from django.conf import settings

    redis_client = Redis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        password=settings.REDIS_PASSWORD,
        decode_responses=True,
    )
    parser = SpiderFootBatchParser(
        dedup_backend=redis_client, scan_id=self.scan_id, target_domain=self.domain.name
    )

    # Proxy List Integration
    proxy_str = None
    try:
        proxies = get_proxy_list()
        if proxies:
            proxy_str = "\n".join(proxies)
    except Exception as e:
        logger.debug("[SPIDERFOOT] Failed to fetch proxy list: %s", e)

    batch: list = []
    batch_size = 50  # keep transactions small for large scans

    # Stream output line-by-line via Popen — run_command buffers ALL stdout into a
    # DB field before returning, which causes a PostgreSQL allocation error when
    # SpiderFoot produces >~100 MB of CSV output.
    try:
        proc = subprocess.Popen(
            cmd,
            shell=True,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            text=True,
            bufsize=1,
        )
        try:
            for raw_line in proc.stdout:
                event = parser.parse_line(raw_line.rstrip("\n\r"))
                if not event:
                    continue
                batch.append(event)
                if len(batch) >= batch_size:
                    _process_spiderfoot_batch(self, batch, ctx, host)
                    batch = []

            if batch:
                _process_spiderfoot_batch(self, batch, ctx, host)

        finally:
            proc.stdout.close()
            return_code = proc.wait()
            if return_code != 0:
                stderr_tail = proc.stderr.read(2000)
                if stderr_tail:
                    logger.warning("[SPIDERFOOT] Process exited %s: %s", return_code, stderr_tail)
            proc.stderr.close()

    except Exception as e:
        logger.error("[SPIDERFOOT] Execution failed: %s", e)

    # Sync to Neo4j
    graph = Neo4jManager()
    graph.sync_scan_results(self.scan_id)
    graph.close()


# ---------------------------------------------------------------------------
# Per-type persistence handlers — called by TYPE_ROUTER
# ---------------------------------------------------------------------------


def _handle_subdomain(
    scan_history, domain, e_data, source_data, ctx, activity_id, metadata
):
    save_subdomain(e_data.lower(), ctx=ctx)


def _handle_email(
    scan_history, domain, e_data, source_data, ctx, activity_id, metadata
):
    save_email(e_data.lower(), scan_history=scan_history)


def _handle_employee(
    scan_history, domain, e_data, source_data, ctx, activity_id, metadata
):
    save_employee(e_data, scan_history=scan_history)


def _handle_url(scan_history, domain, e_data, source_data, ctx, activity_id, metadata):
    if is_valid_url(e_data):
        save_endpoint(e_data, ctx=ctx)


def _handle_ip(scan_history, domain, e_data, source_data, ctx, activity_id, metadata):
    save_ip_address(e_data, scan_id=scan_history.id, activity_id=activity_id)


def _handle_port(scan_history, domain, e_data, source_data, ctx, activity_id, metadata):
    if ":" in e_data:
        ip_part, port_part = e_data.split(":", 1)
        if port_part.isdigit():
            port_num = int(port_part)
            res = get_port_service_description(port_num)
            port_obj, _ = update_or_create_port(
                port_num,
                service_name=res.get("service_name"),
                description=res.get("description"),
            )
            ip_obj, _ = save_ip_address(
                ip_part, scan_id=scan_history.id, activity_id=activity_id
            )
            if ip_obj:
                ip_obj.ports.add(port_obj)
    elif e_data.isdigit():
        update_or_create_port(int(e_data))


def _handle_tech(scan_history, domain, e_data, source_data, ctx, activity_id, metadata):
    from django.core.exceptions import MultipleObjectsReturned

    try:
        tech_obj, _ = Technology.objects.get_or_create(name=e_data)
    except MultipleObjectsReturned:
        tech_obj = Technology.objects.filter(name=e_data).first()
    if source_data:
        subdomain = Subdomain.objects.filter(
            name=source_data, scan_history=scan_history
        ).first()
        if subdomain:
            subdomain.technologies.add(tech_obj)


def _handle_leak(scan_history, domain, e_data, source_data, ctx, activity_id, metadata):
    save_secret_leak(
        scan_history=scan_history,
        tool_name="SpiderFoot",
        secret_type=metadata.get("sf_type") or "Sensitive Data",
        source_url=source_data or "SpiderFoot Findings",
        match_content=e_data,
    )


def _handle_ssl(
    scan_history,
    domain,
    e_data: str,
    source_data: str,
    ctx,
    activity_id,
    metadata: dict,
) -> None:
    from startScan.models import CertificateIntelligence

    source_host = metadata.get("host") or source_data or ""
    results_dir = getattr(scan_history, "results_dir", None) or (ctx or {}).get(
        "results_dir", ""
    )

    if source_host and results_dir:
        try:
            logger.info(
                "[SSL] Running cert intel for scan %s via staging confirm",
                scan_history.id,
            )
            # run_certificate_intel rescans ALL live subdomains for this scan (not just source_host).
            # This is intentional — tlsx is idempotent and enriches the full cert intel for the scan.
            run_certificate_intel(scan_history.id, results_dir)
            return
        except Exception as exc:
            logger.error(
                "[SSL] cert intel failed for scan %s: %s", scan_history.id, exc
            )

    # Fallback: partial record with available fields
    logger.debug(
        "[SSL] Creating partial cert record for host %s", source_host or e_data
    )
    CertificateIntelligence.objects.get_or_create(
        target_domain=domain,
        host=source_host or e_data,
        defaults={
            "scan_history": scan_history,
            "subject_cn": metadata.get("subject_cn"),
            "issuer_cn": metadata.get("issuer"),
        },
    )


def _handle_dns(
    scan_history,
    domain,
    e_data: str,
    source_data: str,
    ctx,
    activity_id,
    metadata: dict,
) -> None:
    from startScan.models import DnsRecord, Subdomain

    record_type = metadata.get("record_type", "TXT")
    hostname = metadata.get("hostname") or source_data or ""

    subdomain_obj = None
    if hostname:
        subdomain_obj = Subdomain.objects.filter(
            name=hostname, scan_history=scan_history
        ).first()

    DnsRecord.objects.update_or_create(
        scan_history=scan_history,
        record_type=record_type,
        value=e_data,
        defaults={
            "target_domain": domain,
            "subdomain": subdomain_obj,
            "source": source_data or "",
            "raw_metadata": metadata,
        },
    )


def _handle_phone(
    scan_history,
    domain,
    e_data: str,
    source_data: str,
    ctx,
    activity_id,
    metadata: dict,
) -> None:
    from startScan.models import Employee

    employee = Employee.objects.create(
        name=None,
        metadata={
            "type": "phone",
            "phone": metadata.get("phone_number") or e_data,
            "source_url": source_data or "",
            "discovered_by": "SpiderFoot",
        },
    )
    if scan_history:
        scan_history.employees.add(employee)


def _handle_social(
    scan_history,
    domain,
    e_data: str,
    source_data: str,
    ctx,
    activity_id,
    metadata: dict,
) -> None:
    from startScan.models import Employee

    employee = Employee.objects.create(
        name=None,
        metadata={
            "type": "social",
            "social_url": metadata.get("profile_url") or e_data,
            "platform": metadata.get("platform", "Unknown"),
            "source": source_data or "",
            "discovered_by": "SpiderFoot",
        },
    )
    if scan_history:
        scan_history.employees.add(employee)


def _handle_os(
    scan_history,
    domain,
    e_data: str,
    source_data: str,
    ctx,
    activity_id,
    metadata: dict,
) -> None:
    from django.core.exceptions import MultipleObjectsReturned

    os_name = metadata.get("os_name") or e_data
    source_host = metadata.get("source_host") or source_data or ""

    try:
        tech_obj, _ = Technology.objects.get_or_create(name=os_name)
    except MultipleObjectsReturned:
        tech_obj = Technology.objects.filter(name=os_name).first()

    if source_host:
        subdomain = Subdomain.objects.filter(
            name=source_host, scan_history=scan_history
        ).first()
        if subdomain:
            subdomain.technologies.add(tech_obj)
        else:
            logger.debug(
                "[OSINT] OS handler: no subdomain found for host %s", source_host
            )


def _handle_crypto(
    scan_history,
    domain,
    e_data: str,
    source_data: str,
    ctx,
    activity_id,
    metadata: dict,
) -> None:
    address_type = metadata.get("address_type", "Unknown")
    logger.info(
        "[OSINT] Validated crypto address: %s %s (scan=%s)",
        address_type,
        e_data,
        scan_history.id,
    )


def _handle_hosting(
    scan_history,
    domain,
    e_data: str,
    source_data: str,
    ctx,
    activity_id,
    metadata: dict,
) -> None:
    co_domain = (metadata.get("co_hosted_domain") or e_data).lower()
    save_subdomain(co_domain, ctx=ctx)


# Populated with new handlers after Tasks 4-6; entries added incrementally.
TYPE_ROUTER: dict = {
    "Subdomain": _handle_subdomain,
    "Email": _handle_email,
    "Employee": _handle_employee,
    "URL": _handle_url,
    "IP": _handle_ip,
    "Port": _handle_port,
    "Tech": _handle_tech,
    "Leak": _handle_leak,
    "SSL": _handle_ssl,
    "DNS": _handle_dns,
    "Phone": _handle_phone,
    "Social": _handle_social,
    "OS": _handle_os,
    "Crypto": _handle_crypto,
    "Hosting": _handle_hosting,
}


def persist_osint_item(
    scan_history,
    domain,
    osint_type: str,
    e_data: str,
    confidence: int,
    source_data: str = None,
    event_type: str = None,  # deprecated — unused; handlers read metadata.get('sf_type') instead
    ctx: dict = None,
    activity_id=None,
    metadata: dict = None,
) -> None:
    """Route an OSINT item to the correct persistence handler via TYPE_ROUTER."""
    handler = TYPE_ROUTER.get(osint_type)
    if handler:
        handler(
            scan_history, domain, e_data, source_data, ctx, activity_id, metadata or {}
        )
    else:
        logger.debug("[OSINT] No handler for osint_type %s", osint_type)


_DNS_SF_TYPE_TO_RECORD = {
    "DNS_TXT_RECORD": "TXT",
    "DNS_MX_RECORD": "MX",
    "DNS_NS_RECORD": "NS",
    "NAME_SERVER_(DNS_NS_RECORDS)": "NS",
    "EMAIL_GATEWAY_(DNS_MX_RECORDS)": "MX",
    "RAW_DNS_RECORDS": "TXT",
    "PROVIDER_DNS": "NS",
}


def _enrich_metadata(event: dict, base_metadata: dict) -> dict:
    """Add type-specific structured keys to OsintStaging metadata for frontend rendering."""
    osint_type = event.get("osint_type", "")
    e_data = event.get("data", "")
    source_data = event.get("source_data", "")
    sf_type = event.get("type", "")

    extra: dict = {}

    if osint_type == "SSL":
        subject_cn = None
        issuer = None
        if "CN=" in e_data:
            parts = {}
            for segment in e_data.split(","):
                segment = segment.strip()
                if "=" in segment:
                    k, _, v = segment.partition("=")
                    parts[k.strip()] = v.strip()
            subject_cn = parts.get("CN")
            issuer = parts.get("O")
        extra = {
            "host": subject_cn or source_data or "",
            "subject_cn": subject_cn,
            "issuer": issuer,
        }

    elif osint_type == "DNS":
        extra = {
            "record_type": _DNS_SF_TYPE_TO_RECORD.get(sf_type, "TXT"),
            "hostname": source_data or "",
            "value": e_data,
        }

    elif osint_type == "Phone":
        extra = {
            "phone_number": e_data,
            "source_url": source_data or "",
        }

    elif osint_type == "Social":
        url_lower = e_data.lower()
        if "linkedin.com" in url_lower:
            platform = "LinkedIn"
        elif "twitter.com" in url_lower or "x.com" in url_lower:
            platform = "Twitter/X"
        elif "facebook.com" in url_lower:
            platform = "Facebook"
        elif "instagram.com" in url_lower:
            platform = "Instagram"
        elif "github.com" in url_lower:
            platform = "GitHub"
        else:
            platform = "Unknown"
        extra = {
            "platform": platform,
            "profile_url": e_data,
        }

    elif osint_type == "OS":
        extra = {
            "os_name": e_data,
            "source_host": source_data or "",
        }

    elif osint_type == "Crypto":
        extra = {
            "address_type": "ETH" if e_data.startswith("0x") else "BTC",
            "address": e_data,
        }

    elif osint_type == "Hosting":
        extra = {
            "co_hosted_domain": e_data,
        }

    return {**base_metadata, **extra}


def _process_spiderfoot_batch(self, batch, ctx, host):
    """Internal helper to process a batch of SpiderFoot findings with tiered validation."""
    try:
        with transaction.atomic():
            for event in batch:
                e_type = event.get("type")
                e_data = event.get("data")
                osint_type = event.get("osint_type")
                confidence = event.get("confidence", 0)

                if not osint_type or not e_data:
                    continue

                # Automated Persistence (High Confidence)
                if confidence > 80:
                    auto_meta = _enrich_metadata(
                        event,
                        {
                            "sf_type": e_type,
                            "source_data": event.get("source_data"),
                            "iocs": event.get("iocs"),
                        },
                    )
                    persist_osint_item(
                        scan_history=self.scan,
                        domain=self.domain,
                        osint_type=osint_type,
                        e_data=e_data,
                        confidence=confidence,
                        source_data=event.get("source_data"),
                        event_type=e_type,
                        ctx=ctx,
                        activity_id=self.activity_id,
                        metadata=auto_meta,
                    )

                # Staging Area (Moderate Confidence: 50% -> 80%)
                elif 50 <= confidence <= 80:
                    base_meta = {
                        "sf_type": e_type,
                        "source_data": event.get("source_data"),
                        "iocs": event.get("iocs"),
                    }
                    enriched_meta = _enrich_metadata(event, base_meta)
                    OsintStaging.objects.update_or_create(
                        scan_history=self.scan,
                        target_domain=self.domain,
                        content=e_data,
                        osint_type=osint_type,
                        defaults={
                            "source": event.get("source", "SpiderFoot"),
                            "confidence": confidence,
                            "metadata": enriched_meta,
                            "status": "pending",
                        },
                    )
                else:
                    # Discard low confidence noise
                    logger.debug(
                        "[SPIDERFOOT] Discarding low confidence finding: %s - %s (%s%%)",
                        osint_type,
                        e_data,
                        confidence,
                    )

        logger.warning(
            "Processed batch of %d SpiderFoot findings with validation.", len(batch)
        )
    except Exception as e:
        logger.error("Error processing SpiderFoot batch: %s", e)
