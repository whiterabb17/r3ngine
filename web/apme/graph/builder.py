"""
APME Graph Builder

Constructs the attack graph using Neo4j (always available in reNgine).
Ingests normalized Node and Edge objects from the ingestion layer and persists
them to the graph database, wiring up relationships between assets,
vulnerabilities, credentials, and capabilities.

CRITICAL RULES:
- DO NOT create an edge if the relationship is unclear.
- ALL nodes must have a valid type from graph/schema.py.
- Confidence scores MUST be propagated to edges.
"""

import json as _json
import logging
from typing import List, Optional

from neo4j import GraphDatabase
from django.conf import settings

from apme.models.node import Node
from apme.models.edge import Edge

logger = logging.getLogger(__name__)


class GraphBuilder:
    """
    Manages the APME attack graph in Neo4j.
    Uses MERGE semantics to be idempotent — safe to run multiple times per scan.
    """

    def __init__(self):
        self._driver = None
        try:
            self._driver = GraphDatabase.driver(
                settings.NEO4J_URI,
                auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD),
            )
            logger.info("APME GraphBuilder connected to Neo4j.")
        except Exception as exc:
            logger.error(f"APME GraphBuilder failed to connect to Neo4j: {exc}")
            raise

    def close(self):
        if self._driver:
            self._driver.close()

    def query_node_degree(self, apme_id: str, scan_id: Optional[int] = None) -> int:
        """Return the number of relationships attached to a node (its degree).

        Args:
            apme_id (str): The unique identifier of the node to query.
            scan_id (int, optional): The unique ID of the scan to filter by.

        Returns:
            int: The degree of the node (count of connected edges). Returns 1 on failure.
        """
        if not self._driver:
            return 1
        try:
            with self._driver.session() as session:
                if scan_id is not None:
                    # Filter by both apme_id and scan_id to isolate the specific scan node
                    result = session.run(
                        "MATCH (n:APMENode {apme_id: $id, scan_id: $scan_id}) "
                        "RETURN COUNT { (n)--() } AS degree",
                        id=apme_id,
                        scan_id=scan_id,
                    )
                else:
                    # Fallback to matching only by apme_id if scan_id is not provided
                    result = session.run(
                        "MATCH (n:APMENode {apme_id: $id}) "
                        "RETURN COUNT { (n)--() } AS degree",
                        id=apme_id,
                    )
                
                # Retrieve first record safely to prevent "Expected a result with a single record, but found multiple."
                records = list(result)
                if records:
                    deg = records[0]["degree"]
                    if deg is not None:
                        return int(deg)
        except Exception as exc:
            logger.warning("APME: Failed to query node degree for %s: %s", apme_id, exc)
        return 1

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def add_nodes(self, nodes: List[Node], scan_id: int) -> None:
        """Persist a batch of nodes to Neo4j."""
        with self._driver.session() as session:
            for node in nodes:
                try:
                    session.execute_write(self._merge_node, node, scan_id)
                except Exception as exc:
                    logger.warning(f"APME: Failed to merge node {node.id}: {exc}")

    def add_edges(self, edges: List[Edge], scan_id: int) -> None:
        """
        Persist a batch of directed edges.
        FAIL SAFE: if either endpoint node does not exist, the edge is skipped.
        """
        with self._driver.session() as session:
            for edge in edges:
                try:
                    created = session.execute_write(self._merge_edge, edge, scan_id)
                    if not created:
                        logger.debug(
                            f"APME: Skipped edge {edge.from_id} -[{edge.type}]-> {edge.to_id} "
                            "(one or both endpoint nodes not found)."
                        )
                except Exception as exc:
                    logger.warning(
                        f"APME: Failed to merge edge {edge.from_id} -> {edge.to_id}: {exc}"
                    )

    def clear_scan(self, scan_id: int) -> None:
        """Remove all APME-labelled nodes/edges for a given scan."""
        with self._driver.session() as session:
            session.run(
                "MATCH (n:APMENode {scan_id: $scan_id}) DETACH DELETE n",
                scan_id=scan_id,
            )

    # -------------------------------------------------------------------------
    # Neo4j transaction helpers
    # -------------------------------------------------------------------------

    @staticmethod
    def _merge_node(tx, node: Node, scan_id: int) -> None:
        tx.run(
            """
            MERGE (n:APMENode {apme_id: $id, scan_id: $scan_id})
            SET n.type       = $type,
                n.subtype    = $subtype,
                n.confidence = $confidence,
                n.source     = $source,
                n.properties = $properties
            """,
            id=node.id,
            scan_id=scan_id,
            type=node.type,
            subtype=node.subtype,
            confidence=node.confidence,
            source=node.source,
            properties=str(node.properties),
        )

    @staticmethod
    def _merge_edge(tx, edge: "Edge", scan_id: int) -> bool:
        """
        Create a directed APME_EDGE between two APMENodes.
        Stores mitre_id and all constraint flags as explicit Neo4j properties
        so Cypher path queries can read them directly in rels projections.
        Auto-creates skeleton nodes for missing endpoints.

        Args:
            tx: The active Neo4j transaction.
            edge (Edge): The Edge object containing source, target, type, confidence, and properties.
            scan_id (int): The unique ID of the scan.

        Returns:
            bool: True if the relationship was successfully created/merged, False otherwise.
        """
        def infer_node_type(apme_id: str) -> tuple:
            """Infer the node type and subtype from its APME ID prefix."""
            if apme_id.startswith("domain::"):
                return "Asset", "domain"
            elif apme_id.startswith("ip::"):
                return "Asset", "ip"
            elif apme_id.startswith("service::"):
                return "Asset", "service"
            elif apme_id.startswith("endpoint::"):
                return "Asset", "endpoint"
            elif apme_id.startswith("vuln::"):
                return "Vulnerability", "generic"
            elif apme_id.startswith("tech::"):
                return "Technology", "generic"
            elif apme_id.startswith("credential::"):
                return "Credential", "generic_secret"
            elif apme_id.startswith("goal::capability::"):
                return "Capability", apme_id.split("::")[-1]
            elif apme_id.startswith("goal::privilege::"):
                return "Privilege", apme_id.split("::")[-1]
            elif apme_id.startswith("org::"):
                return "Organization", "generic"
            elif apme_id.startswith("app::"):
                return "Application", "generic"
            elif apme_id.startswith("identity_infra::"):
                return "IdentityInfra", "generic"
            elif apme_id.startswith("cert::"):
                return "Certificate", "generic"
            elif apme_id.startswith("api_endpoint::"):
                return "APIEndpoint", "generic"
            return "Asset", "generic"

        from_type, from_subtype = infer_node_type(edge.from_id)
        to_type, to_subtype = infer_node_type(edge.to_id)

        props = edge.properties
        result = tx.run(
            """
            MERGE (a:APMENode {apme_id: $from_id, scan_id: $scan_id})
            ON CREATE SET a.type = $from_type,
                          a.subtype = $from_subtype,
                          a.confidence = 0.5,
                          a.source = "APME:skeleton",
                          a.properties = '{}'

            MERGE (b:APMENode {apme_id: $to_id, scan_id: $scan_id})
            ON CREATE SET b.type = $to_type,
                          b.subtype = $to_subtype,
                          b.confidence = 0.5,
                          b.source = "APME:skeleton",
                          b.properties = '{}'

            MERGE (a)-[r:APME_EDGE {edge_type: $type, scan_id: $scan_id}]->(b)
            SET r.confidence                = $confidence,
                r.properties                = $properties_json,
                r.mitre_id                  = $mitre_id,
                r.requires_victim           = $requires_victim,
                r.requires_php              = $requires_php,
                r.requires_java             = $requires_java,
                r.requires_python           = $requires_python,
                r.requires_wordpress        = $requires_wordpress,
                r.endpoint_requires_auth    = $endpoint_requires_auth,
                r.requires_dotnet           = $requires_dotnet,
                r.requires_kubernetes       = $requires_kubernetes,
                r.requires_docker           = $requires_docker,
                r.requires_ruby             = $requires_ruby,
                r.requires_nodejs           = $requires_nodejs,
                r.requires_active_directory = $requires_active_directory,
                r.requires_mssql            = $requires_mssql,
                r.requires_oracle           = $requires_oracle,
                r.requires_redis            = $requires_redis,
                r.requires_drupal           = $requires_drupal,
                r.requires_joomla           = $requires_joomla,
                r.requires_magento          = $requires_magento
            RETURN r
            """,
            from_id=edge.from_id,
            to_id=edge.to_id,
            scan_id=scan_id,
            type=edge.type,
            confidence=edge.confidence,
            properties_json=_json.dumps(props),
            mitre_id=props.get("mitre_id", "unknown"),
            requires_victim=bool(props.get("requires_victim", False)),
            requires_php=bool(props.get("requires_php", False)),
            requires_java=bool(props.get("requires_java", False)),
            requires_python=bool(props.get("requires_python", False)),
            requires_wordpress=bool(props.get("requires_wordpress", False)),
            endpoint_requires_auth=bool(props.get("endpoint_requires_auth", False)),
            requires_dotnet=bool(props.get("requires_dotnet", False)),
            requires_kubernetes=bool(props.get("requires_kubernetes", False)),
            requires_docker=bool(props.get("requires_docker", False)),
            requires_ruby=bool(props.get("requires_ruby", False)),
            requires_nodejs=bool(props.get("requires_nodejs", False)),
            requires_active_directory=bool(props.get("requires_active_directory", False)),
            requires_mssql=bool(props.get("requires_mssql", False)),
            requires_oracle=bool(props.get("requires_oracle", False)),
            requires_redis=bool(props.get("requires_redis", False)),
            requires_drupal=bool(props.get("requires_drupal", False)),
            requires_joomla=bool(props.get("requires_joomla", False)),
            requires_magento=bool(props.get("requires_magento", False)),
            from_type=from_type,
            from_subtype=from_subtype,
            to_type=to_type,
            to_subtype=to_subtype,
        )
        return result.single() is not None
