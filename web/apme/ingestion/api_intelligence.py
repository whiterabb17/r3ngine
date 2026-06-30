"""
APME Ingestion — API Intelligence

Two-phase pipeline:
  Phase 1 (collect_api_intelligence): Groups existing EndPoint records by URL
           cluster and writes APIIntelligenceProfile records.
  Phase 2 (ingest_api_intelligence):  Reads APIIntelligenceProfile records and
           produces APIEndpoint APME nodes with DEPENDS_ON edges.

No outbound HTTP calls — reads only from existing EndPoint model data.
"""

import logging
import re
import urllib.parse
from collections import defaultdict
from typing import Dict, List, Optional, Tuple

from apme.models.node import Node
from apme.models.edge import Edge
from apme.ingestion.correlation import ExposureCorrelator

logger = logging.getLogger(__name__)

_GRAPHQL_URL_RE = re.compile(r"/graphql\b", re.IGNORECASE)
_REST_VERSION_RE = re.compile(r"/v\d+/|/api/", re.IGNORECASE)
_SOAP_RE = re.compile(r"\.asmx|/soap/|/wsdl\b", re.IGNORECASE)


def _classify_endpoint(url: str, content_type: Optional[str] = None) -> str:
    """Classify a single endpoint URL as rest/graphql/soap/generic."""
    parsed = urllib.parse.urlparse(url)
    path = parsed.path or ""
    if _GRAPHQL_URL_RE.search(path):
        return "graphql"
    if _SOAP_RE.search(path):
        return "soap"
    if _REST_VERSION_RE.search(path):
        return "rest"
    if content_type and "json" in content_type.lower():
        return "rest"
    return "generic"


def _path_prefix(url: str) -> str:
    """Extract the first two path segments as a base URL cluster key."""
    parsed = urllib.parse.urlparse(url)
    parts = [p for p in parsed.path.split("/") if p]
    prefix = "/" + "/".join(parts[:2]) if len(parts) >= 2 else (
        "/" + parts[0] if parts else "/"
    )
    return f"{parsed.scheme}://{parsed.netloc}{prefix}"


def collect_api_intelligence(scan_history_id: int) -> List:
    """
    Phase 1: Cluster EndPoint records and write APIIntelligenceProfile records.

    Groups endpoints by (base_url, api_type), where base_url is scheme + host
    + first two path segments. (The subdomain is therefore encoded inside
    base_url's netloc — no need to key it separately.) Writes one
    APIIntelligenceProfile per distinct cluster.
    """
    from startScan.models import (
        ScanHistory,
        EndPoint,
        APIIntelligenceProfile,
        Subdomain as SubdomainModel,
    )

    try:
        scan = ScanHistory.objects.select_related("domain").get(id=scan_history_id)
    except ScanHistory.DoesNotExist:
        logger.error("api_intelligence: ScanHistory %s not found", scan_history_id)
        return []

    domain = scan.domain

    endpoints = EndPoint.objects.filter(
        scan_history_id=scan_history_id,
        http_url__isnull=False,
    ).select_related("subdomain").only(
        "http_url", "http_status", "content_type", "subdomain"
    )

    # (base_url, api_type) → list of endpoint info
    clusters: Dict[Tuple[str, str], List[dict]] = defaultdict(list)

    for ep in endpoints:
        if not ep.http_url:
            continue
        content_type = getattr(ep, "content_type", None)
        api_type = _classify_endpoint(ep.http_url, content_type)
        base = _path_prefix(ep.http_url)
        clusters[(base, api_type)].append({
            "url": ep.http_url,
            "status": ep.http_status or 0,
        })

    # Pre-fetch every subdomain for the scan once. Avoids one .first() roundtrip
    # per cluster (could be hundreds for an API-heavy target).
    subdomain_index: Dict[str, "SubdomainModel"] = {
        s.name: s for s in SubdomainModel.objects.filter(
            scan_history_id=scan_history_id
        ).only("id", "name")
    }

    results = []

    for (base_url, api_type), ep_list in clusters.items():
        subdomain_name = urllib.parse.urlparse(base_url).hostname
        subdomain_obj = subdomain_index.get(subdomain_name) if subdomain_name else None

        obj, _ = APIIntelligenceProfile.objects.update_or_create(
            scan_history=scan,
            base_url=base_url,
            api_type=api_type,
            defaults={
                "target_domain": domain,
                "subdomain": subdomain_obj,
                "endpoint_count": len(ep_list),
                "raw_endpoints": ep_list[:200],
            },
        )
        results.append(obj)

    logger.info(
        "api_intelligence: Discovered %d API clusters for scan %s",
        len(results), scan_history_id,
    )
    return results


def ingest_api_intelligence(target_id: int) -> Tuple[List[Node], List[Edge]]:
    """
    Phase 2: Convert APIIntelligenceProfile records to APME APIEndpoint nodes.

    Node ID: api_endpoint::{base_url}
    Edge: app::{subdomain} --[DEPENDS_ON]--> api_endpoint::{base_url}
    """
    from startScan.models import APIIntelligenceProfile

    nodes: List[Node] = []
    edges: List[Edge] = []
    seen_ids: set = set()

    profiles = (
        APIIntelligenceProfile.objects
        .filter(target_domain_id=target_id)
        .select_related("subdomain")
    )

    for profile in profiles:
        node_id = f"api_endpoint::{profile.base_url}"
        if node_id in seen_ids:
            continue
        seen_ids.add(node_id)

        node = Node(
            id=node_id,
            type="APIEndpoint",
            subtype=profile.api_type,
            confidence=0.85,
            source="reNgine:api_intelligence",
            properties={
                "base_url": profile.base_url,
                "api_type": profile.api_type,
                "endpoint_count": profile.endpoint_count,
                "requires_auth": profile.requires_auth,
                "auth_scheme": profile.auth_scheme or "",
                "sensitivity": "high" if profile.requires_auth else "medium",
            },
        )
        nodes.append(node)

        if profile.subdomain:
            app_id = f"app::{profile.subdomain.name}"
            try:
                edges.append(Edge(
                    from_id=app_id,
                    to_id=node_id,
                    type="DEPENDS_ON",
                    confidence=0.80,
                    properties={"api_type": profile.api_type},
                ))
            except ValueError as exc:
                logger.warning("api_intelligence ingest edge: %s", exc)

    logger.info(
        "APME Ingestion [api_intelligence]: %d nodes, %d edges (target_id=%s)",
        len(nodes), len(edges), target_id,
    )

    correlator = ExposureCorrelator()
    return correlator.correlate(nodes, edges)
