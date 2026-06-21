"""
APME Pathfinder

Discovers attack paths in the Neo4j APME graph using BFS, DFS, and Dijkstra.

Phase 1 changes:
- All Cypher queries return mitre_id and constraint flags in rels projection
- min_edge_confidence filters low-confidence edges before traversal
- find_all_paths runs BFS + DFS + Dijkstra (was BFS + DFS only)
- _validate_and_build sets PathStep.mitre_technique and .mitre_tactic
- _edge_to_step_dict reads constraint flags from Neo4j rel properties
"""

import logging
import re
import uuid
from typing import Any, Dict, List, Optional

from neo4j import GraphDatabase
from django.conf import settings

from apme.engine.constraints import ConstraintEngine, PathContext
from apme.models.path import AttackPath, PathStep
from apme.utils.mitre import lookup as mitre_lookup

logger = logging.getLogger(__name__)

INTERNET_ENTRY_SUBTYPES = {"domain", "ip", "service", "endpoint"}

HIGH_VALUE_TARGET_SUBTYPES = {
    "domain_admin", "root", "admin", "db_access", "data_exfil",
    "rce_execution", "cloud_access", "authenticated_access", "pivot",
    "account_takeover", "credential_harvesting", "lateral_movement",
    "metadata_access", "code_exfiltration", "hvt_compromise",
    "supply_chain_compromise",
}

# Shared Cypher projections — inserted into all three query templates
_NODES_PROJECTION = (
    "[n in nodes(path) | {"
    "id: n.apme_id, type: n.type, subtype: n.subtype, "
    "confidence: n.confidence"
    "}] AS nodes"
)

_RELS_PROJECTION = (
    "[r in relationships(path) | {"
    "type: r.edge_type, "
    "confidence: r.confidence, "
    "mitre_id: r.mitre_id, "
    "requires_victim: r.requires_victim, "
    "requires_php: r.requires_php, "
    "requires_java: r.requires_java, "
    "requires_python: r.requires_python, "
    "requires_wordpress: r.requires_wordpress, "
    "endpoint_requires_auth: r.endpoint_requires_auth, "
    "requires_dotnet: r.requires_dotnet, "
    "requires_kubernetes: r.requires_kubernetes, "
    "requires_docker: r.requires_docker, "
    "requires_ruby: r.requires_ruby, "
    "requires_nodejs: r.requires_nodejs, "
    "requires_active_directory: r.requires_active_directory, "
    "requires_mssql: r.requires_mssql, "
    "requires_oracle: r.requires_oracle, "
    "requires_redis: r.requires_redis, "
    "requires_drupal: r.requires_drupal, "
    "requires_joomla: r.requires_joomla, "
    "requires_magento: r.requires_magento"
    "}] AS rels"
)


class Pathfinder:
    """Discovers attack paths in the Neo4j APME graph."""

    MAX_DEPTH = 8
    MAX_PATHS = 20
    DFS_MAX_DEPTH = 6
    MAX_ENTRY_POINTS = 50
    QUERY_TIMEOUT_MS = 30_000

    def __init__(self, min_edge_confidence: float = 0.20):
        self.min_edge_confidence = min_edge_confidence
        self._driver = None
        self._constraint_engine = ConstraintEngine()
        try:
            self._driver = GraphDatabase.driver(
                settings.NEO4J_URI,
                auth=(settings.NEO4J_USER, settings.NEO4J_PASSWORD),
            )
        except Exception as exc:
            logger.error("APME Pathfinder: Neo4j connection failed: %s", exc)
            raise

    def close(self):
        if self._driver:
            self._driver.close()

    # -------------------------------------------------------------------------
    # Public API
    # -------------------------------------------------------------------------

    def find_paths_bfs(self, scan_id, start_node_id, target_subtypes=None, top_n=5):
        targets = target_subtypes or list(HIGH_VALUE_TARGET_SUBTYPES)
        raw = self._bfs_query(scan_id, start_node_id, targets)
        return self._validate_and_build(raw, top_n)

    def find_paths_dfs(self, scan_id, start_node_id, target_subtypes=None, top_n=5):
        targets = target_subtypes or list(HIGH_VALUE_TARGET_SUBTYPES)
        raw = self._dfs_query(scan_id, start_node_id, targets)
        return self._validate_and_build(raw, top_n)

    def find_paths_dijkstra(self, scan_id, start_node_id, target_subtypes=None, top_n=5):
        targets = target_subtypes or list(HIGH_VALUE_TARGET_SUBTYPES)
        raw = self._dijkstra_query(scan_id, start_node_id, targets)
        return self._validate_and_build(raw, top_n)

    def find_all_paths(
        self,
        scan_id: int,
        start_node_ids: Optional[List[str]] = None,
        target_subtypes: Optional[List[str]] = None,
        top_n: int = 5,
    ) -> List[AttackPath]:
        """Run BFS + DFS + Dijkstra across all entry points, deduplicate, return top N."""
        entries = start_node_ids or self._get_internet_entry_points(scan_id)
        if len(entries) > self.MAX_ENTRY_POINTS:
            logger.warning(
                "APME Pathfinder: %d entry points exceed cap of %d, truncating",
                len(entries), self.MAX_ENTRY_POINTS,
            )
            entries = entries[:self.MAX_ENTRY_POINTS]
        logger.info("APME Pathfinder: querying %d entry points", len(entries))
        all_paths: List[AttackPath] = []

        for entry_id in entries:
            all_paths.extend(self.find_paths_bfs(scan_id, entry_id, target_subtypes, top_n))
            all_paths.extend(self.find_paths_dfs(scan_id, entry_id, target_subtypes, top_n))
            all_paths.extend(self.find_paths_dijkstra(scan_id, entry_id, target_subtypes, top_n))

        # Deduplicate by semantic fingerprint — same attack chain type, different instances
        seen: set = set()
        unique: List[AttackPath] = []
        for p in all_paths:
            key = "->".join(
                f"{s.edge_type}:{re.sub(r'::\\d+$', '', s.from_id)}:"
                f"{re.sub(r'::\\d+$', '', s.to_id)}"
                for s in p.steps
            )
            if key not in seen:
                seen.add(key)
                unique.append(p)

        # Sort descending by step count — richer chains first; scorer picks the best ones
        return sorted(unique, key=lambda p: len(p.steps), reverse=True)[:top_n]

    # -------------------------------------------------------------------------
    # Neo4j Queries
    # -------------------------------------------------------------------------

    def _bfs_query(self, scan_id, start_id, target_subtypes):
        query = (
            f"MATCH path = shortestPath("
            f"(start:APMENode {{apme_id: $start_id, scan_id: $scan_id}})"
            f"-[:APME_EDGE*1..{self.MAX_DEPTH}]->"
            f"(target:APMENode))"
            f" WHERE target.subtype IN $target_subtypes"
            f"   AND target.scan_id = $scan_id"
            f"   AND ALL(r IN relationships(path) WHERE r.confidence >= $min_conf)"
            f" RETURN {_NODES_PROJECTION}, {_RELS_PROJECTION}"
            f" LIMIT $limit"
        )
        return self._run_path_query(query, scan_id, start_id, target_subtypes)

    def _dfs_query(self, scan_id, start_id, target_subtypes):
        query = (
            f"MATCH path = "
            f"(start:APMENode {{apme_id: $start_id, scan_id: $scan_id}})"
            f"-[:APME_EDGE*2..6]->"
            f"(target:APMENode)"
            f" WHERE target.subtype IN $target_subtypes"
            f"   AND target.scan_id = $scan_id"
            f"   AND ALL(r IN relationships(path) WHERE r.confidence >= $min_conf)"
            f" RETURN {_NODES_PROJECTION}, {_RELS_PROJECTION}"
            f" LIMIT $limit"
        )
        return self._run_path_query(query, scan_id, start_id, target_subtypes)

    def _dijkstra_query(self, scan_id, start_id, target_subtypes):
        """Execute a Dijkstra-like shortest path query using native Cypher.
        
        Calculates path weight dynamically using REDUCE over (1.0 - confidence) 
        of relationships to find the path that maximizes confidence (minimizes cost).
        Falls back to DFS if any database errors occur.

        Args:
            scan_id (int): The ID of the scan to query within.
            start_id (str): The APME ID of the starting node.
            target_subtypes (list): List of high-value target subtypes to find paths to.
        
        Returns:
            list: A list of dicts containing the matching path nodes and relationships.
        """
        query = (
            f"MATCH path = (start:APMENode {{apme_id: $start_id, scan_id: $scan_id}})"
            f"-[:APME_EDGE*1..{self.MAX_DEPTH}]->"
            f"(target:APMENode {{scan_id: $scan_id}})"
            f" WHERE target.subtype IN $target_subtypes"
            f"   AND ALL(r IN relationships(path) WHERE r.confidence >= $min_conf)"
            f" RETURN {_NODES_PROJECTION}, {_RELS_PROJECTION},"
            f" REDUCE(cost = 0.0, r IN relationships(path) | cost + (1.0 - r.confidence)) AS weight"
            f" ORDER BY weight ASC"
            f" LIMIT $limit"
        )
        try:
            # Run the native Cypher query eagerly
            return self._run_path_query(query, scan_id, start_id, target_subtypes, raise_errors=True)
        except Exception as exc:
            logger.warning(
                "APME Pathfinder: Dijkstra query failed (%s), "
                "using high-confidence DFS fallback.",
                exc
            )
            saved_conf = self.min_edge_confidence
            self.min_edge_confidence = min(saved_conf + 0.10, 0.80)
            result = self._dfs_query(scan_id, start_id, target_subtypes)
            self.min_edge_confidence = saved_conf
            return result

    def _run_path_query(self, query, scan_id, start_id, target_subtypes, raise_errors=False):
        results = []
        if not self._driver:
            return results
        try:
            with self._driver.session() as session:
                result = session.run(
                    query,
                    scan_id=scan_id,
                    start_id=start_id,
                    target_subtypes=target_subtypes,
                    min_conf=self.min_edge_confidence,
                    limit=self.MAX_PATHS,
                    timeout=self.QUERY_TIMEOUT_MS,
                )
                # Eagerly consume the Bolt stream to avoid BufferError (object cannot be re-sized)
                # when reading large records from the network stream dynamically.
                records = list(result)
                for record in records:
                    results.append({"nodes": record["nodes"], "rels": record["rels"]})
        except Exception as exc:
            if raise_errors:
                raise
            logger.error("APME Pathfinder: Query failed: %s", exc)
        return results

    def _get_internet_entry_points(self, scan_id):
        if not self._driver:
            return []
        with self._driver.session() as session:
            result = session.run(
                "MATCH (n:APMENode) "
                "WHERE n.subtype IN $subtypes AND n.scan_id = $scan_id "
                "RETURN n.apme_id AS id",
                subtypes=list(INTERNET_ENTRY_SUBTYPES),
                scan_id=scan_id,
            )
            return [r["id"] for r in result]

    # -------------------------------------------------------------------------
    # Path Construction & Validation
    # -------------------------------------------------------------------------

    def _validate_and_build(self, raw_paths: List[Dict], top_n: int) -> List[AttackPath]:
        """Convert raw Neo4j path records into validated AttackPath objects."""
        validated: List[AttackPath] = []

        for raw in raw_paths:
            nodes = raw.get("nodes", [])
            rels = raw.get("rels", [])

            if len(nodes) < 2:
                continue

            steps: List[PathStep] = []
            context = PathContext()
            valid = True

            for i, rel in enumerate(rels):
                from_node = nodes[i]
                to_node = nodes[i + 1]
                edge_type = rel.get("type", "")
                confidence = float(rel.get("confidence") or 0.5)

                step_dict = self._edge_to_step_dict(edge_type, from_node, to_node, confidence, rel)

                if not self._constraint_engine.validate_step(step_dict, context):
                    valid = False
                    break

                self._constraint_engine.update_context(step_dict, context)

                # Resolve MITRE attribution from the edge's mitre_id property
                mitre_id = rel.get("mitre_id") or ""
                mitre_info = mitre_lookup(mitre_id) if mitre_id and mitre_id != "unknown" else {}

                steps.append(PathStep(
                    from_id=from_node.get("id", ""),
                    to_id=to_node.get("id", ""),
                    action=self._edge_to_action(edge_type, from_node, to_node),
                    confidence=confidence,
                    validated=step_dict.get("validated", False),
                    edge_type=edge_type,
                    mitre_technique=mitre_id if mitre_id not in ("", "unknown") else "",
                    mitre_tactic=mitre_info.get("tactic_slug", ""),
                    requires_victim=step_dict.get("requires_victim", False),
                ))

            if valid and steps:
                if len(steps) < 2:
                    continue
                path = AttackPath(
                    id=f"APT-{uuid.uuid4().hex[:6].upper()}",
                    start=nodes[0].get("id", ""),
                    end=nodes[-1].get("id", ""),
                    steps=steps,
                    entry_type="internet",
                )
                validated.append(path)

        return validated[:top_n]

    @staticmethod
    def _edge_to_step_dict(
        edge_type: str,
        from_node: Dict,
        to_node: Dict,
        confidence: float,
        rel: Optional[Dict] = None,
    ) -> Dict[str, Any]:
        """Map edge type + Neo4j rel properties to a step dict for ConstraintEngine."""
        rel = rel or {}
        step: Dict[str, Any] = {
            "action":               edge_type,
            "confidence":           confidence,
            "validated":            False,
            "to_id":                to_node.get("id", ""),
            "to_subtype":           to_node.get("subtype", ""),
            "requires_auth":        False,
            "requires_internal":    False,
            "requires_privilege":   "none",
            "grants_auth":          False,
            "grants_internal":      False,
            "grants_privilege":     None,
            # Phase 1 constraint flags — read from Neo4j rel properties
            "requires_victim":        bool(rel.get("requires_victim", False)),
            "requires_php":           bool(rel.get("requires_php", False)),
            "requires_java":          bool(rel.get("requires_java", False)),
            "requires_python":        bool(rel.get("requires_python", False)),
            "requires_wordpress":     bool(rel.get("requires_wordpress", False)),
            "endpoint_requires_auth": bool(rel.get("endpoint_requires_auth", False)),
            # Phase 2 constraint flags
            "requires_dotnet":           bool(rel.get("requires_dotnet", False)),
            "requires_kubernetes":       bool(rel.get("requires_kubernetes", False)),
            "requires_docker":           bool(rel.get("requires_docker", False)),
            "requires_ruby":             bool(rel.get("requires_ruby", False)),
            "requires_nodejs":           bool(rel.get("requires_nodejs", False)),
            "requires_active_directory": bool(rel.get("requires_active_directory", False)),
            "requires_mssql":            bool(rel.get("requires_mssql", False)),
            "requires_oracle":           bool(rel.get("requires_oracle", False)),
            "requires_redis":            bool(rel.get("requires_redis", False)),
            "requires_drupal":           bool(rel.get("requires_drupal", False)),
            "requires_joomla":           bool(rel.get("requires_joomla", False)),
            "requires_magento":          bool(rel.get("requires_magento", False)),
        }

        if edge_type == "AUTHENTICATES":
            step["grants_auth"] = True
        elif edge_type == "CONNECTED_TO":
            step["grants_internal"] = True
        elif edge_type == "ESCALATES_TO":
            step["grants_privilege"] = to_node.get("subtype", "user")
        elif edge_type == "LEADS_TO":
            if to_node.get("subtype") in {"pivot", "data_exfil", "lateral_movement"}:
                step["requires_internal"] = True

        return step

    @staticmethod
    def _edge_to_action(edge_type: str, from_node: Dict, to_node: Dict) -> str:
        templates = {
            "RESOLVES_TO":  "Resolve {src} to IP {dst}",
            "HOSTS":        "{src} hosts service {dst}",
            "EXPOSES":      "Service {src} exposes vulnerability {dst}",
            "LEADS_TO":     "Exploit {src} to gain {dst}",
            "AUTHENTICATES": "Use credential {src} to authenticate to {dst}",
            "ESCALATES_TO": "Escalate from {src} to {dst}",
            "TRUSTS":       "{src} trusts {dst} — lateral movement possible",
            "CONNECTED_TO": "Pivot via {src} to reach {dst}",
            "USES_TECH":    "{src} runs {dst}",
        }
        tpl = templates.get(edge_type, "{src} -> {dst}")
        return tpl.format(
            src=from_node.get("subtype", from_node.get("id", "?")),
            dst=to_node.get("subtype", to_node.get("id", "?")),
        )
