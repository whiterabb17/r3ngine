"""
APME Ingestion — Assets

Converts reNgine Subdomain, IpAddress, Port, and EndPoint models
into APME graph nodes and edges.
"""

import logging
import uuid
from typing import List, Tuple

from apme.models.node import Node
from apme.models.edge import Edge
from apme.ingestion.correlation import ExposureCorrelator

logger = logging.getLogger(__name__)


def _make_id(prefix: str, value: str) -> str:
    return f"{prefix}::{value}"


def _infer_sensitivity(name: str) -> str:
    """
    Categorizes asset sensitivity based on keywords.
    Returns: 'high', 'medium', or 'low'
    """
    name_lower = name.lower()
    high_value_keywords = [
        "admin", "vpn", "db", "database", "internal", "stg", "staging",
        "prod", "production", "secure", "auth", "login", "sso", "identity",
        "vault", "secret", "jenkins", "gitlab", "nexus", "artifactory",
    ]
    medium_value_keywords = [
        "api", "dev", "test", "demo", "mail", "portal", "cloud", "aws",
        "azure", "gcp", "storage", "bucket", "app", "mobile",
    ]

    for kw in high_value_keywords:
        if kw in name_lower:
            return "high"
    for kw in medium_value_keywords:
        if kw in name_lower:
            return "medium"
    return "low"


def ingest_subdomains(target_id: int) -> Tuple[List[Node], List[Edge]]:
    """
    Ingests Subdomains and their IP addresses for a given target domain, including the root Domain.
    """
    from startScan.models import Subdomain, Domain

    nodes: List[Node] = []
    edges: List[Edge] = []

    # Ingest the root domain itself first if it exists
    try:
        root_domain = Domain.objects.get(id=target_id)
        root_node = Node(
            id=_make_id("domain", root_domain.name),
            type="Asset",
            subtype="domain",
            confidence=1.0,
            source="reNgine:domain_discovery",
            properties={
                "name": root_domain.name,
                "sensitivity": _infer_sensitivity(root_domain.name),
            },
        )
        nodes.append(root_node)
    except Domain.DoesNotExist:
        pass

    subdomains = Subdomain.objects.filter(
        target_domain_id=target_id
    ).prefetch_related("ip_addresses", "ip_addresses__ports")

    for sub in subdomains:
        # Domain node
        domain_node = Node(
            id=_make_id("domain", sub.name),
            type="Asset",
            subtype="domain",
            confidence=1.0,
            source="reNgine:subdomain_discovery",
            properties={
                "name": sub.name,
                "http_status": sub.http_status,
                "is_cdn": sub.is_cdn,
                "sensitivity": _infer_sensitivity(sub.name),
            },
        )
        nodes.append(domain_node)

        # IP Address nodes + RESOLVES_TO edges
        for ip_obj in sub.ip_addresses.all():
            ip_id = _make_id("ip", ip_obj.address)
            ip_node = Node(
                id=ip_id,
                type="Asset",
                subtype="ip",
                confidence=1.0,
                source="reNgine:ip_discovery",
                properties={
                    "address": ip_obj.address,
                    "is_cdn": ip_obj.is_cdn,
                    "is_private": ip_obj.is_private,
                },
            )
            nodes.append(ip_node)

            try:
                edges.append(Edge(
                    from_id=domain_node.id,
                    to_id=ip_id,
                    type="RESOLVES_TO",
                    confidence=1.0,
                ))
            except ValueError as exc:
                logger.warning(f"APME Ingestion: {exc}")

            # Port/Service nodes + HOSTS edges
            for port in ip_obj.ports.all():
                service_id = _make_id("service", f"{ip_obj.address}:{port.number}")
                service_node = Node(
                    id=service_id,
                    type="Asset",
                    subtype="service",
                    confidence=1.0,
                    source="reNgine:port_scan",
                    properties={
                        "port": port.number,
                        "service_name": port.service_name or "",
                        "is_uncommon": port.is_uncommon,
                    },
                )
                nodes.append(service_node)

                try:
                    edges.append(Edge(
                        from_id=ip_id,
                        to_id=service_id,
                        type="HOSTS",
                        confidence=1.0,
                    ))
                except ValueError as exc:
                    logger.warning(f"APME Ingestion: {exc}")

    logger.info(
        f"APME Ingestion [assets]: {len(nodes)} nodes, {len(edges)} edges "
        f"(target_id={target_id})"
    )
    
    correlator = ExposureCorrelator()
    return correlator.correlate(nodes, edges)


def ingest_endpoints(target_id: int) -> Tuple[List[Node], List[Edge]]:
    """Ingests EndPoint models for a given target linked to their subdomain."""
    from startScan.models import EndPoint

    nodes: List[Node] = []
    edges: List[Edge] = []

    endpoints = EndPoint.objects.filter(
        subdomain__target_domain_id=target_id
    ).select_related("subdomain")

    for ep in endpoints:
        ep_id = _make_id("endpoint", ep.http_url)
        ep_node = Node(
            id=ep_id,
            type="Asset",
            subtype="endpoint",
            confidence=1.0,
            source="reNgine:endpoint_discovery",
            properties={
                "url": ep.http_url,
                "http_status": ep.http_status,
                "matched_gf_patterns": ep.matched_gf_patterns or "",
                "sensitivity": _infer_sensitivity(ep.http_url),
            },
        )
        nodes.append(ep_node)

        if ep.subdomain:
            domain_id = _make_id("domain", ep.subdomain.name)
            try:
                edges.append(Edge(
                    from_id=domain_id,
                    to_id=ep_id,
                    type="HOSTS",
                    confidence=1.0,
                ))
            except ValueError as exc:
                logger.warning(f"APME Ingestion: {exc}")

    logger.info(
        f"APME Ingestion [endpoints]: {len(nodes)} nodes, {len(edges)} edges"
    )
    
    correlator = ExposureCorrelator()
    return correlator.correlate(nodes, edges)


# Technology subtype detection: keyword → APME subtype
_TECH_SUBTYPE_MAP = {
    "wordpress": "wordpress",
    "wp-": "wordpress",
    "drupal": "generic",
    "joomla": "generic",
    "php": "php",
    "java": "java",
    "spring": "spring",
    "jenkins": "jenkins",
    "python": "python",
    "django": "python",
    "flask": "python",
    "node": "nodejs",
    "express": "nodejs",
    "nginx": "nginx",
    "apache": "apache",
}


def _infer_tech_subtype(tech_name: str) -> str:
    name_lower = tech_name.lower()
    for keyword, subtype in _TECH_SUBTYPE_MAP.items():
        if keyword in name_lower:
            return subtype
    return "generic"


def ingest_technologies(target_id: int) -> Tuple[List[Node], List[Edge]]:
    """
    Ingests detected Technology records for a given target domain.

    Creates Technology APME nodes and USES_TECH edges from Asset nodes.
    Technology nodes enable tech-specific attack rules (e.g. WordPress → RCE,
    Java → deserialization) via constraint engine context flags.
    """
    from startScan.models import Subdomain

    nodes: List[Node] = []
    edges: List[Edge] = []

    subdomains = Subdomain.objects.filter(
        target_domain_id=target_id
    ).prefetch_related("technologies")

    seen_tech_ids: set = set()

    for sub in subdomains:
        asset_node_id = _make_id("domain", sub.name)

        for tech in sub.technologies.all():
            tech_node_id = _make_id("tech", str(tech.id))
            subtype = _infer_tech_subtype(tech.name)

            if tech_node_id not in seen_tech_ids:
                nodes.append(Node(
                    id=tech_node_id,
                    type="Technology",
                    subtype=subtype,
                    confidence=1.0,
                    source="reNgine:technology_detection",
                    properties={
                        "name": tech.name,
                        "version": getattr(tech, "version", "") or "",
                        "target_id": target_id,
                    },
                ))
                seen_tech_ids.add(tech_node_id)

            try:
                edges.append(Edge(
                    from_id=asset_node_id,
                    to_id=tech_node_id,
                    type="USES_TECH",
                    confidence=1.0,
                    properties={"tech_name": tech.name},
                ))
            except ValueError as exc:
                logger.warning("APME Ingestion [tech]: %s", exc)

    logger.info(
        "APME Ingestion [technologies]: %d nodes, %d edges (target_id=%s)",
        len(nodes), len(edges), target_id,
    )
    
    correlator = ExposureCorrelator()
    return correlator.correlate(nodes, edges)
