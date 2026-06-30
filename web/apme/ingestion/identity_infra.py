"""
APME Ingestion — Identity Infrastructure

Converts IdentityInfraDiscovery records into APME graph nodes and edges.

Node ID format:  identity_infra::{infra_type}::{host}
Edge:            service::{ip}:{port} --[AUTHENTICATES_VIA]--> IdentityInfra node
"""

import logging
from typing import List, Tuple

from apme.models.node import Node
from apme.models.edge import Edge
from apme.ingestion.correlation import ExposureCorrelator

logger = logging.getLogger(__name__)

# Ports known to be associated with each identity infrastructure type.
# Constrains AUTHENTICATES_VIA edges to semantically correct service nodes.
_INFRA_PORTS: dict = {
    "adfs": [443],
    "owa": [443, 80],
    "exchange": [443, 80],
    "ldap": [389, 636, 3268, 3269],
    "sso": [443, 80],
    "saml_idp": [443, 80],
    "vpn_portal": [443, 8443],
    "ntlm_endpoint": [443, 80],
    "generic_auth_portal": [443, 80, 8080, 8443],
}
_DEFAULT_PORTS = [443, 80]

# Maps IdentityInfraDiscovery.infra_type → APME Node.subtype
_INFRA_TYPE_TO_SUBTYPE: dict = {
    "adfs": "adfs",
    "owa": "owa",
    "exchange": "exchange",
    "ldap": "ldap",
    "sso": "sso",
    "saml_idp": "saml_idp",
    "vpn_portal": "vpn_portal",
    "ntlm_endpoint": "ntlm",
    "generic_auth_portal": "generic",
}


def _make_id(prefix: str, value: str) -> str:
    return "%s::%s" % (prefix, value)


def ingest_identity_infra(target_id: int) -> Tuple[List[Node], List[Edge]]:
    """
    Load all IdentityInfraDiscovery records for the domain and produce APME nodes/edges.

    Args:
        target_id: Domain.id

    Returns:
        (nodes, edges) tuple ready for GraphBuilder.
    """
    from startScan.models import IdentityInfraDiscovery

    nodes: List[Node] = []
    edges: List[Edge] = []
    seen_ids: set = set()

    records = (
        IdentityInfraDiscovery.objects
        .filter(target_domain_id=target_id)
        .select_related("subdomain")
        .prefetch_related("subdomain__ip_addresses")
    )

    for rec in records:
        node_id = _make_id("identity_infra", "%s::%s" % (rec.infra_type, rec.host))
        if node_id in seen_ids:
            continue
        seen_ids.add(node_id)

        subtype = _INFRA_TYPE_TO_SUBTYPE.get(rec.infra_type, "generic")
        confidence = rec.confidence_score

        node = Node(
            id=node_id,
            type="IdentityInfra",
            subtype=subtype,
            confidence=confidence,
            source="reNgine:identity_intel",
            properties={
                "host": rec.host,
                "url": rec.url or "",
                "infra_type": rec.infra_type,
                "detection_method": rec.detection_method,
                "is_externally_accessible": rec.is_externally_accessible,
                "sensitivity": "critical",
            },
        )
        nodes.append(node)

        # AUTHENTICATES_VIA edges: service nodes (via subdomain IPs) → this identity infra.
        # Use only the ports semantically associated with this infra type.
        if rec.subdomain:
            ports = _INFRA_PORTS.get(rec.infra_type, _DEFAULT_PORTS)
            for ip_obj in rec.subdomain.ip_addresses.all():
                for port in ports:
                    service_id = _make_id("service", "%s:%d" % (ip_obj.address, port))
                    try:
                        edges.append(Edge(
                            from_id=service_id,
                            to_id=node_id,
                            type="AUTHENTICATES_VIA",
                            confidence=confidence,
                            properties={"infra_type": rec.infra_type},
                        ))
                    except (ValueError, TypeError) as exc:
                        logger.warning("APME identity ingestion: %s", exc)

    logger.info(
        "APME Ingestion [identity_infra]: %d nodes, %d edges (target_id=%s)",
        len(nodes), len(edges), target_id,
    )

    correlator = ExposureCorrelator()
    return correlator.correlate(nodes, edges)
