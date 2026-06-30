"""
APME Ingestion — Organization and Application Graph Nodes

Synthesizes higher-level context nodes from existing scan data:
  - Organization: from Domain.project (when the FK exists)
  - Application: one node per distinct subdomain with a webserver fingerprint

These nodes anchor the top of the full chain:
  org::{slug} → PART_OF → subdomain → ... → Certificate/IdentityInfra
"""

import logging
from typing import List, Tuple

from apme.models.node import Node
from apme.models.edge import Edge
from apme.ingestion.correlation import ExposureCorrelator

logger = logging.getLogger(__name__)


def ingest_organizations(target_id: int) -> Tuple[List[Node], List[Edge]]:
    """
    Produce a single Organization node if Domain.project is set.

    Node ID: org::{project_slug}
    Edge:    org::{slug} --[PART_OF]--> subdomain::{domain_name}
    """
    nodes: List[Node] = []
    edges: List[Edge] = []

    from targetApp.models import Domain as TargetDomain
    try:
        domain = TargetDomain.objects.select_related("project").get(id=target_id)
    except TargetDomain.DoesNotExist:
        return [], []

    project = getattr(domain, "project", None)
    if not project:
        return [], []

    slug = getattr(project, "slug", None) or getattr(project, "name", "unknown")
    org_id = f"org::{slug}"

    node = Node(
        id=org_id,
        type="Organization",
        subtype="generic",
        confidence=1.0,
        source="reNgine:graph_expansion",
        properties={
            "name": getattr(project, "name", slug),
            "slug": slug,
        },
    )
    nodes.append(node)

    domain_node_id = f"subdomain::{domain.name}"
    try:
        edges.append(Edge(
            from_id=org_id,
            to_id=domain_node_id,
            type="PART_OF",
            confidence=1.0,
            properties={"domain": domain.name},
        ))
    except ValueError as exc:
        logger.warning("graph_expansion org edge: %s", exc)

    logger.info(
        "APME Ingestion [organizations]: 1 org node (target_id=%s, slug=%s)",
        target_id, slug,
    )
    correlator = ExposureCorrelator()
    return correlator.correlate(nodes, edges)


def ingest_applications(target_id: int) -> Tuple[List[Node], List[Edge]]:
    """
    Produce Application nodes — one per subdomain with a webserver fingerprint.

    Node ID: app::{subdomain_name}
    Edge:    app::{sub} --[PART_OF]--> subdomain::{sub}
    """
    from startScan.models import Subdomain

    nodes: List[Node] = []
    edges: List[Edge] = []
    seen: set = set()

    subdomains = Subdomain.objects.filter(
        target_domain_id=target_id,
        webserver__isnull=False,
    ).exclude(webserver="").only("name", "webserver", "http_url")

    for sub in subdomains:
        app_id = f"app::{sub.name}"
        if app_id in seen:
            continue
        seen.add(app_id)

        node = Node(
            id=app_id,
            type="Application",
            subtype="generic",
            confidence=0.90,
            source="reNgine:graph_expansion",
            properties={
                "name": sub.name,
                "webserver": sub.webserver or "",
                "url": sub.http_url or "",
                "sensitivity": "medium",
            },
        )
        nodes.append(node)

        sub_node_id = f"subdomain::{sub.name}"
        try:
            edges.append(Edge(
                from_id=app_id,
                to_id=sub_node_id,
                type="PART_OF",
                confidence=0.90,
                properties={"webserver": sub.webserver or ""},
            ))
        except ValueError as exc:
            logger.warning("graph_expansion app edge: %s", exc)

    logger.info(
        "APME Ingestion [applications]: %d app nodes, %d edges (target_id=%s)",
        len(nodes), len(edges), target_id,
    )
    correlator = ExposureCorrelator()
    return correlator.correlate(nodes, edges)
