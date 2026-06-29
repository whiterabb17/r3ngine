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
    MAX_ENTRY_POINTS = 500
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
        return self._validate_and_build(raw, top_n, algo="bfs")

    def find_paths_dfs(self, scan_id, start_node_id, target_subtypes=None, top_n=5):
        targets = target_subtypes or list(HIGH_VALUE_TARGET_SUBTYPES)
        raw = self._dfs_query(scan_id, start_node_id, targets)
        return self._validate_and_build(raw, top_n, algo="dfs")

    def find_paths_dijkstra(self, scan_id, start_node_id, target_subtypes=None, top_n=5):
        targets = target_subtypes or list(HIGH_VALUE_TARGET_SUBTYPES)
        raw = self._dijkstra_query(scan_id, start_node_id, targets)
        return self._validate_and_build(raw, top_n, algo="dijkstra")

    def find_all_paths(
        self,
        scan_id: int,
        start_node_ids: Optional[List[str]] = None,
        target_subtypes: Optional[List[str]] = None,
        top_n: int = 5,
    ) -> List[AttackPath]:
        """Run BFS + DFS + Dijkstra across all entry points, deduplicate, return all.

        NOTE: We do NOT slice to top_n here — the scorer in the orchestrator needs
        the full ranked list to select the best paths. Slicing here would discard
        valid paths before scoring and cause zero-path results for large scans.
        """
        entries = start_node_ids or self._get_internet_entry_points(scan_id)
        if len(entries) > self.MAX_ENTRY_POINTS:
            logger.warning(
                "APME Pathfinder: %d entry points exceed cap of %d, truncating",
                len(entries), self.MAX_ENTRY_POINTS,
            )
            entries = entries[:self.MAX_ENTRY_POINTS]

        # Log entry point subtype distribution so truncation impact is visible
        if entries:
            entry_ids_sample = entries[:20]
            logger.info(
                "APME Pathfinder: querying %d entry points (sample: %s)",
                len(entries), entry_ids_sample,
            )
        else:
            logger.warning("APME Pathfinder: no internet entry points found for scan_id=%s", scan_id)

        all_paths: List[AttackPath] = []

        for entry_id in entries:
            all_paths.extend(self.find_paths_bfs(scan_id, entry_id, target_subtypes, top_n))
            all_paths.extend(self.find_paths_dfs(scan_id, entry_id, target_subtypes, top_n))
            all_paths.extend(self.find_paths_dijkstra(scan_id, entry_id, target_subtypes, top_n))

        logger.info(
            "APME Pathfinder: %d raw paths collected across all entry points and algorithms",
            len(all_paths),
        )

        # Deduplicate by semantic fingerprint — same attack chain type, different instances.
        # Pre-strip trailing numeric IDs outside the f-string (backslashes not allowed in
        # f-string expressions on Python 3.10).
        _strip_id = re.compile(r"::\d+$")
        seen: set = set()
        unique: List[AttackPath] = []
        for p in all_paths:
            parts = []
            for s in p.steps:
                from_stripped = _strip_id.sub("", s.from_id)
                to_stripped = _strip_id.sub("", s.to_id)
                parts.append(f"{s.edge_type}:{from_stripped}:{to_stripped}")
            key = "->".join(parts)
            if key not in seen:
                seen.add(key)
                unique.append(p)

        logger.info(
            "APME Pathfinder: %d unique paths after deduplication (from %d raw)",
            len(unique), len(all_paths),
        )

        # Sort descending by step count — richer chains first; scorer picks the best ones.
        # Do NOT slice here — the orchestrator scorer needs all candidates.
        return sorted(unique, key=lambda p: len(p.steps), reverse=True)

    # -------------------------------------------------------------------------
    # Neo4j Queries
    # -------------------------------------------------------------------------

    def _bfs_query(self, scan_id, start_id, target_subtypes):
        # Use a variable-length path match rather than shortestPath() so that
        # multiple distinct paths through different intermediate nodes are all
        # returned. shortestPath() would only find one path per (start, target)
        # pair, silently hiding longer but valid attack chains.
        query = (
            f"MATCH path = (start:APMENode {{apme_id: $start_id, scan_id: $scan_id}})"
            f"-[:APME_EDGE*1..{self.MAX_DEPTH}]->"
            f"(target:APMENode)"
            f" WHERE target.subtype IN $target_subtypes"
            f"   AND target.scan_id = $scan_id"
            f"   AND ALL(r IN relationships(path) WHERE r.confidence >= $min_conf)"
            f" RETURN {_NODES_PROJECTION}, {_RELS_PROJECTION}"
            f" ORDER BY length(path) ASC"
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
        """Return internet-facing entry point IDs ordered deterministically.

        ORDER BY subtype, id ensures that when the MAX_ENTRY_POINTS cap is hit,
        truncation is reproducible and not dependent on Neo4j's internal storage
        order (which could arbitrarily exclude productive entry types).
        Priority ordering: domain < endpoint < ip < service (alphabetical by subtype).
        """
        if not self._driver:
            return []
        with self._driver.session() as session:
            result = session.run(
                "MATCH (n:APMENode) "
                "WHERE n.subtype IN $subtypes AND n.scan_id = $scan_id "
                "RETURN n.apme_id AS id, n.subtype AS subtype "
                "ORDER BY n.subtype ASC, n.apme_id ASC",
                subtypes=list(INTERNET_ENTRY_SUBTYPES),
                scan_id=scan_id,
            )
            records = list(result)

        # Log subtype distribution so truncation impact is visible
        from collections import Counter
        subtype_counts = Counter(r["subtype"] for r in records)
        logger.info(
            "APME Pathfinder: entry point subtypes for scan_id=%s: %s (total=%d)",
            scan_id, dict(subtype_counts), len(records),
        )
        return [r["id"] for r in records]

    # -------------------------------------------------------------------------
    # Path Construction & Validation
    # -------------------------------------------------------------------------

    def _validate_and_build(
        self, raw_paths: List[Dict], top_n: int, algo: str = "?"
    ) -> List[AttackPath]:
        """Convert raw Neo4j path records into validated AttackPath objects.

        Tracks per-constraint rejection counts and logs them in aggregate so
        zero-path incidents can be diagnosed without re-running the scan.
        """
        validated: List[AttackPath] = []
        rejected_too_short = 0
        rejected_min_steps = 0
        rejection_counts: Dict[str, int] = {
            "confidence":       0,
            "cycle":            0,
            "auth":             0,
            "internal":         0,
            "privilege":        0,
            "victim":           0,
            "php":              0,
            "java":             0,
            "wordpress":        0,
            "endpoint_auth":    0,
            "path_confidence":  0,
            "dotnet":           0,
            "kubernetes":       0,
            "docker":           0,
            "ruby":             0,
            "nodejs":           0,
            "active_directory": 0,
            "mssql":            0,
            "oracle":           0,
            "redis":            0,
            "drupal":           0,
            "joomla":           0,
            "magento":          0,
        }

        for raw in raw_paths:
            nodes = raw.get("nodes", [])
            rels = raw.get("rels", [])

            if len(nodes) < 2:
                rejected_too_short += 1
                continue

            steps: List[PathStep] = []
            context = PathContext()
            valid = True
            rejection_reason: Optional[str] = None

            for i, rel in enumerate(rels):
                from_node = nodes[i]
                to_node = nodes[i + 1]
                edge_type = rel.get("type", "")
                confidence = float(rel.get("confidence") or 0.5)

                step_dict = self._edge_to_step_dict(edge_type, from_node, to_node, confidence, rel)

                # ── Inline constraint checking with reason tracking ──────────
                reason = self._check_constraint(step_dict, context)
                if reason:
                    rejection_counts[reason] = rejection_counts.get(reason, 0) + 1
                    rejection_reason = reason
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
                    rejected_min_steps += 1
                    continue
                path = AttackPath(
                    id=f"APT-{uuid.uuid4().hex[:6].upper()}",
                    start=nodes[0].get("id", ""),
                    end=nodes[-1].get("id", ""),
                    steps=steps,
                    entry_type="internet",
                )
                validated.append(path)

        total_raw = len(raw_paths)
        total_accepted = len(validated)
        total_rejected = total_raw - total_accepted
        active_rejections = {k: v for k, v in rejection_counts.items() if v > 0}

        if total_raw > 0:
            logger.info(
                "APME Pathfinder [%s]: %d/%d paths accepted | "
                "rejected_too_short=%d rejected_min_steps=%d | "
                "constraint_rejections=%s",
                algo, total_accepted, total_raw,
                rejected_too_short, rejected_min_steps,
                active_rejections if active_rejections else "none",
            )
        elif total_raw == 0:
            logger.debug("APME Pathfinder [%s]: no raw paths returned by Neo4j query.", algo)

        return validated[:top_n]

    @staticmethod
    def _check_constraint(step: Dict[str, Any], context: "PathContext") -> Optional[str]:
        """Run the constraint engine checks and return the name of the first
        failing constraint, or None if all pass.

        This mirrors ConstraintEngine.validate_step() but returns the reason
        string rather than a bool so _validate_and_build can track rejection stats.
        """
        _PRIVILEGE_ORDER = ["none", "user", "admin", "domain_admin", "root"]

        if step.get("confidence", 1.0) < 0.15:
            return "confidence"

        visited = context.visited_node_ids or set()
        to_id = step.get("to_id", "")
        if to_id and to_id in visited:
            return "cycle"

        if step.get("requires_auth") and not context.has_auth:
            return "auth"

        if step.get("requires_internal") and not context.has_internal_access:
            return "internal"

        required_priv = step.get("requires_privilege", "none")
        if required_priv in _PRIVILEGE_ORDER:
            if _PRIVILEGE_ORDER.index(context.privilege_level) < _PRIVILEGE_ORDER.index(required_priv):
                return "privilege"

        if step.get("requires_victim") and not context.has_victim_interaction:
            return "victim"

        if step.get("requires_php") and not context.has_php_tech:
            return "php"

        if step.get("requires_java") and not context.has_java_tech:
            return "java"

        if step.get("requires_wordpress") and not context.has_wordpress_tech:
            return "wordpress"

        if step.get("endpoint_requires_auth") and not context.has_auth:
            return "endpoint_auth"

        projected = context.path_confidence_product * step.get("confidence", 1.0)
        if projected < 0.05:
            return "path_confidence"

        if step.get("requires_dotnet") and not context.has_dotnet_tech:
            return "dotnet"

        if step.get("requires_kubernetes") and not context.has_kubernetes_tech:
            return "kubernetes"

        if step.get("requires_docker") and not context.has_docker_tech:
            return "docker"

        if step.get("requires_ruby") and not context.has_ruby_tech:
            return "ruby"

        if step.get("requires_nodejs") and not context.has_nodejs_tech:
            return "nodejs"

        if step.get("requires_active_directory") and not context.has_active_directory_tech:
            return "active_directory"

        if step.get("requires_mssql") and not context.has_mssql_tech:
            return "mssql"

        if step.get("requires_oracle") and not context.has_oracle_tech:
            return "oracle"

        if step.get("requires_redis") and not context.has_redis_tech:
            return "redis"

        if step.get("requires_drupal") and not context.has_drupal_tech:
            return "drupal"

        if step.get("requires_joomla") and not context.has_joomla_tech:
            return "joomla"

        if step.get("requires_magento") and not context.has_magento_tech:
            return "magento"

        return None

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
