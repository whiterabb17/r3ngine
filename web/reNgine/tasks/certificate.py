"""
Certificate Intelligence Tasks

Shells out to `tlsx` in JSON mode to collect structured TLS/certificate data
for all live subdomains in a scan. Writes results to CertificateIntelligence.

No new pip dependencies — tlsx is already installed in the container.
"""

import json
import logging
import os
import shlex
import subprocess
import tempfile
from datetime import timezone as dt_timezone
from typing import List, Optional

from django.utils.dateparse import parse_datetime

logger = logging.getLogger(__name__)

# Cipher string fragments that indicate a weak/deprecated cipher.
WEAK_CIPHER_FRAGMENTS: frozenset = frozenset([
    "RC4", "DES", "NULL", "EXPORT", "ANON", "3DES", "MD5",
])

# Ports to probe for TLS certificates.
_TLS_PORTS = "443,8443,8080"


def is_weak_cipher(cipher: str) -> bool:
    """Return True if the cipher name contains a known-weak fragment."""
    upper = cipher.upper()
    return any(frag in upper for frag in WEAK_CIPHER_FRAGMENTS)


def parse_tlsx_json_line(line: str) -> Optional[dict]:
    """
    Parse a single JSON line from `tlsx -json` output.

    Returns a normalised dict on success, None on parse failure or empty line.
    Expected tlsx JSON keys (subset used):
        host, port, tls_version, cipher, not_before, not_after,
        subject_cn, subject_an, issuer_cn, issuer_org,
        fingerprint_hash.sha256, self_signed, mismatched
    """
    line = line.strip()
    if not line:
        return None
    try:
        raw = json.loads(line)
    except json.JSONDecodeError:
        return None

    fp_sha256 = None
    fp = raw.get("fingerprint_hash") or {}
    if isinstance(fp, dict):
        fp_sha256 = fp.get("sha256") or fp.get("sha-256")

    issuer_org_raw = raw.get("issuer_org") or []
    if isinstance(issuer_org_raw, list):
        issuer_org = issuer_org_raw[0] if issuer_org_raw else None
    else:
        issuer_org = str(issuer_org_raw)

    return {
        "host": raw.get("host", ""),
        "port": int(raw.get("port", 443)),
        "subject_cn": raw.get("subject_cn") or None,
        "subject_an": raw.get("subject_an") or [],
        "issuer_cn": raw.get("issuer_cn") or None,
        "issuer_org": issuer_org,
        "not_before": raw.get("not_before") or None,
        "not_after": raw.get("not_after") or None,
        "tls_version": raw.get("tls_version") or None,
        "cipher": raw.get("cipher") or None,
        "fingerprint_sha256": fp_sha256,
        "self_signed": bool(raw.get("self_signed", False)),
        "mismatched": bool(raw.get("mismatched", False)),
        "raw_json": raw,
    }


def _parse_dt(s: Optional[str]):
    """Parse an ISO-8601 datetime string, ensuring UTC tzinfo is attached."""
    if not s:
        return None
    dt = parse_datetime(s)
    if dt and dt.tzinfo is None:
        dt = dt.replace(tzinfo=dt_timezone.utc)
    return dt


def _is_expired(not_after_str: Optional[str]) -> bool:
    if not not_after_str:
        return False
    from django.utils import timezone
    dt = _parse_dt(not_after_str)
    if dt is None:
        return False
    return dt < timezone.now()


def run_certificate_intel(
    scan_history_id: int,
    results_dir: str,
) -> List["CertificateIntelligence"]:
    """
    Run tlsx against all live subdomains for this scan and persist results.

    Args:
        scan_history_id: ScanHistory.id
        results_dir: Base results directory for the scan (used for temp file).

    Returns:
        List of CertificateIntelligence instances created/updated.
    """
    from startScan.models import ScanHistory, Subdomain, CertificateIntelligence
    from django.utils import timezone

    try:
        scan = ScanHistory.objects.select_related("domain").get(id=scan_history_id)
    except ScanHistory.DoesNotExist:
        logger.error("certificate_tasks: ScanHistory %s not found", scan_history_id)
        return []

    domain = scan.domain

    live_subdomains = list(
        Subdomain.objects.filter(
            scan_history_id=scan_history_id,
            http_status__in=[200, 301, 302, 403, 401],
        ).select_related("target_domain")
        .values_list("name", flat=True)
    )

    if not live_subdomains:
        logger.info(
            "certificate_tasks: No live subdomains for scan %s. Skipping.", scan_history_id
        )
        return []

    logger.info(
        "certificate_tasks: Running cert intel on %d subdomains for scan %s",
        len(live_subdomains), scan_history_id,
    )

    results: List[CertificateIntelligence] = []

    with tempfile.NamedTemporaryFile(
        mode="w", suffix=".txt", dir=results_dir, delete=False
    ) as tmp:
        tmp.write("\n".join(live_subdomains))
        tmp_path = tmp.name

    try:
        cmd = shlex.split(
            f"tlsx -json -silent -ro -p {_TLS_PORTS} -list {tmp_path}"
        )
        proc = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=300,
        )
        output = proc.stdout or ""

        for line in output.splitlines():
            parsed = parse_tlsx_json_line(line)
            if not parsed:
                continue

            not_after_str = parsed["not_after"]
            not_before_str = parsed["not_before"]

            subdomain_obj = Subdomain.objects.filter(
                scan_history_id=scan_history_id,
                name=parsed["host"],
            ).first()

            fp = parsed["fingerprint_sha256"]

            defaults = {
                "scan_history": scan,
                "subdomain": subdomain_obj,
                "host": parsed["host"],
                "port": parsed["port"],
                "subject_cn": parsed["subject_cn"],
                "subject_an": parsed["subject_an"] or [],
                "issuer_cn": parsed["issuer_cn"],
                "issuer_org": parsed["issuer_org"],
                "not_before": _parse_dt(not_before_str),
                "not_after": _parse_dt(not_after_str),
                "tls_version": parsed["tls_version"],
                "cipher": parsed["cipher"],
                "fingerprint_sha256": fp,
                "self_signed": parsed["self_signed"],
                "mismatched": parsed["mismatched"],
                "is_expired": _is_expired(not_after_str),
                "has_weak_cipher": is_weak_cipher(parsed["cipher"] or ""),
                "raw_json": parsed["raw_json"],
            }

            if fp:
                obj, _ = CertificateIntelligence.objects.update_or_create(
                    target_domain=domain,
                    fingerprint_sha256=fp,
                    defaults=defaults,
                )
            else:
                obj = CertificateIntelligence.objects.create(
                    target_domain=domain,
                    **defaults,
                )
            results.append(obj)

    except subprocess.TimeoutExpired:
        logger.error("certificate_tasks: tlsx timed out for scan %s", scan_history_id)
    except FileNotFoundError:
        logger.error("certificate_tasks: tlsx not found in PATH for scan %s", scan_history_id)
    except Exception as exc:
        logger.error(
            "certificate_tasks: Unexpected error for scan %s: %s", scan_history_id, exc
        )
    finally:
        try:
            os.unlink(tmp_path)
        except OSError:
            pass

    logger.info(
        "certificate_tasks: Wrote %d CertificateIntelligence records for scan %s",
        len(results), scan_history_id,
    )
    return results


def resync_single_certificate(cert_id: int) -> Optional["CertificateIntelligence"]:
    """
    Re-run tlsx for a single CertificateIntelligence record's host.

    Fetches the record, probes only that host, and updates the record
    in-place. Returns the updated instance on success, None on any failure.
    """
    import re
    from startScan.models import CertificateIntelligence

    try:
        cert = CertificateIntelligence.objects.select_related(
            "scan_history__domain", "target_domain"
        ).get(id=cert_id)
    except CertificateIntelligence.DoesNotExist:
        logger.error("certificate_tasks: CertificateIntelligence %s not found", cert_id)
        return None

    host = cert.host

    # Validate host — allow only alphanumeric, hyphens, and dots (Rule 1.4).
    if not host or not re.match(r'^[a-zA-Z0-9.\-]+$', host):
        logger.error(
            "certificate_tasks: Unsafe host in cert %s, aborting resync", cert_id
        )
        return None

    logger.info(
        "certificate_tasks: Resyncing cert %s for host %s", cert_id, host
    )

    try:
        cmd = shlex.split(f"tlsx -json -silent -ro -p {_TLS_PORTS} -host {host}")
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
        output = proc.stdout or ""
    except subprocess.TimeoutExpired:
        logger.error(
            "certificate_tasks: tlsx timed out for cert %s host %s", cert_id, host
        )
        return None
    except FileNotFoundError:
        logger.error(
            "certificate_tasks: tlsx not found in PATH for cert %s", cert_id
        )
        return None
    except Exception as exc:
        logger.error(
            "certificate_tasks: Unexpected error for cert %s: %s", cert_id, exc
        )
        return None

    for line in output.splitlines():
        parsed = parse_tlsx_json_line(line)
        if not parsed or parsed["host"] != host:
            continue

        # Update all probe-derived fields in-place on the existing record.
        cert.port = parsed["port"]
        cert.subject_cn = parsed["subject_cn"]
        cert.subject_an = parsed["subject_an"] or []
        cert.issuer_cn = parsed["issuer_cn"]
        cert.issuer_org = parsed["issuer_org"]
        cert.not_before = _parse_dt(parsed["not_before"])
        cert.not_after = _parse_dt(parsed["not_after"])
        cert.tls_version = parsed["tls_version"]
        cert.cipher = parsed["cipher"]
        cert.fingerprint_sha256 = parsed["fingerprint_sha256"]
        cert.self_signed = parsed["self_signed"]
        cert.mismatched = parsed["mismatched"]
        cert.is_expired = _is_expired(parsed["not_after"])
        cert.has_weak_cipher = is_weak_cipher(parsed["cipher"] or "")
        cert.raw_json = parsed["raw_json"]
        cert.save()

        logger.info(
            "certificate_tasks: Resync complete for cert %s host %s", cert_id, host
        )
        return cert

    logger.warning(
        "certificate_tasks: No tlsx output matched host %s for cert %s", host, cert_id
    )
    return None
