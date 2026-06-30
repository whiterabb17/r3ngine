"""
APME Ingestion — Certificate Intelligence

Converts CertificateIntelligence records into APME graph nodes and edges.
Creates Certificate nodes with PROTECTS edges to service nodes.

Node ID format:  cert::{fingerprint_sha256}
                 cert::{host}:{port}   (fallback when no fingerprint)
Edge:            Certificate --[PROTECTS]--> service::{ip}:{port}
"""

import logging
from typing import List, Tuple

from apme.models.node import Node
from apme.models.edge import Edge
from apme.ingestion.correlation import ExposureCorrelator

logger = logging.getLogger(__name__)


def _make_id(prefix: str, value: str) -> str:
    return f"{prefix}::{value}"


def ingest_certificates(target_id: int) -> Tuple[List[Node], List[Edge]]:
    """
    Load all CertificateIntelligence for the domain and build APME nodes/edges.

    Args:
        target_id: Domain.id (not scan_history_id — APME ingests across all scans)

    Returns:
        (nodes, edges) tuple ready for GraphBuilder.
    """
    from startScan.models import CertificateIntelligence

    nodes: List[Node] = []
    edges: List[Edge] = []
    seen_ids: set = set()

    certs = (
        CertificateIntelligence.objects
        .filter(target_domain_id=target_id)
        .select_related("subdomain")
        .prefetch_related("subdomain__ip_addresses")
    )

    for cert in certs:
        fp = cert.fingerprint_sha256
        cert_id = _make_id("cert", fp) if fp else _make_id("cert", f"{cert.host}:{cert.port}")

        if cert_id in seen_ids:
            continue
        seen_ids.add(cert_id)

        # Lower confidence for suspicious certs
        confidence: float = 1.0
        if cert.is_expired or cert.self_signed:
            confidence = 0.6
        elif cert.has_weak_cipher:
            confidence = 0.75

        node = Node(
            id=cert_id,
            type="Certificate",
            subtype="x509",
            confidence=confidence,
            source="reNgine:certificate_intel",
            properties={
                "host": cert.host,
                "port": cert.port,
                "subject_cn": cert.subject_cn or "",
                "issuer_cn": cert.issuer_cn or "",
                "not_after": cert.not_after.isoformat() if cert.not_after else "",
                "is_expired": cert.is_expired,
                "self_signed": cert.self_signed,
                "has_weak_cipher": cert.has_weak_cipher,
                "mismatched": cert.mismatched,
                "tls_version": cert.tls_version or "",
                "cipher": cert.cipher or "",
                "sensitivity": (
                    "high" if (cert.is_expired or cert.self_signed or cert.has_weak_cipher)
                    else "low"
                ),
            },
        )
        nodes.append(node)

        # PROTECTS edges: cert → service nodes (via subdomain IPs)
        if cert.subdomain:
            for ip_obj in cert.subdomain.ip_addresses.all():
                service_id = _make_id("service", f"{ip_obj.address}:{cert.port}")
                try:
                    edges.append(Edge(
                        from_id=cert_id,
                        to_id=service_id,
                        type="PROTECTS",
                        confidence=confidence,
                        properties={"port": cert.port, "tls_version": cert.tls_version or ""},
                    ))
                except (ValueError, TypeError) as exc:
                    logger.warning("APME cert ingestion: %s", exc)

    logger.info(
        "APME Ingestion [certificates]: %d nodes, %d edges (target_id=%s)",
        len(nodes), len(edges), target_id,
    )

    correlator = ExposureCorrelator()
    return correlator.correlate(nodes, edges)
