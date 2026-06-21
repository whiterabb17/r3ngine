"""
APME Main Orchestrator

Coordinates the full Attack Path Modeling pipeline for a given scan:
  1. Ingest assets, vulnerabilities, credentials from reNgine DB
  2. Build the attack graph in Neo4j
  3. Enrich graph via the rules engine
  4. Identify entry points and targets
  5. Run pathfinding (BFS + DFS + Dijkstra)
  6. Apply constraints (drop unrealistic paths)
  7. Score all paths
  8. Persist results to ImpactAssessment / AttackPath records
  9. Return top N paths

PROCESS FLOW (per spec):
  Ingest -> Build Graph -> Enrich -> Entry Points -> Targets
  -> Pathfind -> Constrain -> Score -> Output
"""

import logging
from typing import Any, Dict, List, Optional

from apme.engine.pathfinder import Pathfinder
from apme.engine.scorer import Scorer
from apme.graph.builder import GraphBuilder
from apme.graph.enricher import GraphEnricher
from apme.ingestion.assets import ingest_subdomains, ingest_endpoints
from apme.ingestion.credentials import ingest_credentials
from apme.ingestion.vulnerabilities import ingest_vulnerabilities
from apme.models.node import Node
from apme.models.path import AttackPath
from apme.output.serializer import serialize_paths, serialize_path

logger = logging.getLogger(__name__)


class APMEOrchestrator:
    """
    Main entry point for the Attack Path Modeling Engine.
    Fully configuration-driven — no hardcoded attack chains.
    """

    def __init__(self, top_n: int = 5):
        self.top_n = top_n
        self._scorer = Scorer()

    def run(self, scan_history_id: int, heartbeat_fn=None) -> Dict[str, Any]:
        """
        Execute the full APME pipeline for a scan.

        Args:
            scan_history_id: The scan to model.
            heartbeat_fn: Optional callable invoked between pipeline steps
                          to report progress (e.g. Temporal activity.heartbeat).

        Returns a dict with path results suitable for persistence and API output.
        """
        def _heartbeat(detail: str):
            if heartbeat_fn:
                try:
                    heartbeat_fn(detail)
                except Exception:
                    pass

        logger.info(f"APME Orchestrator: Starting for scan_history_id={scan_history_id}")

        # Resolve Target Domain from ScanHistory to ensure we ingest ALL historical and current scan data
        from startScan.models import ScanHistory
        scan = ScanHistory.objects.get(id=scan_history_id)
        target_id = scan.domain_id

        asset_nodes, asset_edges = ingest_subdomains(target_id)
        ep_nodes, ep_edges = ingest_endpoints(target_id)
        vuln_nodes, vuln_edges = ingest_vulnerabilities(target_id)
        cred_nodes, cred_edges = ingest_credentials(target_id)

        all_nodes: List[Node] = []
        all_edges: List[Any] = []

        all_nodes.extend(asset_nodes + ep_nodes + vuln_nodes + cred_nodes)
        all_edges.extend(asset_edges + ep_edges + vuln_edges + cred_edges)

        # Technology ingestion (Phase 1)
        from apme.ingestion.assets import ingest_technologies
        tech_nodes, tech_edges = ingest_technologies(target_id)
        all_nodes.extend(tech_nodes)
        all_edges.extend(tech_edges)

        # Inject virtual goal nodes (Objectives) to ensure rules have targets
        goal_nodes = self._generate_virtual_goal_nodes(scan_history_id)
        all_nodes.extend(goal_nodes)

        logger.info(
            f"APME [1/7] Done. Nodes={len(all_nodes)}, Edges={len(all_edges)}"
        )

        if not all_nodes:
            logger.warning("APME: No data to model. Graph is empty. Aborting.")
            return {"total_paths": 0, "returned_paths": 0, "paths": []}

        _heartbeat("step 1/7 ingestion complete")

        # ── Step 2: Build Graph ───────────────────────────────────────────────
        logger.info("APME [2/7] Building Neo4j graph...")
        builder = GraphBuilder()
        try:
            builder.clear_scan(scan_history_id)
            builder.add_nodes(all_nodes, scan_history_id)
            builder.add_edges(all_edges, scan_history_id)
        except Exception as exc:
            logger.error(f"APME: Graph build failed: {exc}")
            builder.close()
            return {"total_paths": 0, "returned_paths": 0, "paths": [], "error": str(exc)}

        _heartbeat("step 2/7 graph built")

        # ── Step 3: Enrich Graph ──────────────────────────────────────────────
        logger.info("APME [3/7] Enriching graph via rules engine...")
        enricher = GraphEnricher(builder)
        derived_edges = enricher.enrich(all_nodes, scan_history_id)
        logger.info(f"APME [3/7] Derived {len(derived_edges)} new edges from rules.")

        _heartbeat("step 3/7 enrichment complete")

        # ── Step 4 & 5: Pathfinding ───────────────────────────────────────────
        logger.info("APME [4/7] Running pathfinding algorithms...")
        pathfinder = Pathfinder()
        try:
            paths = pathfinder.find_all_paths(scan_history_id, top_n=self.top_n * 3)
        except Exception as exc:
            logger.error(f"APME: Pathfinding failed: {exc}")
            paths = []
        finally:
            pathfinder.close()

        logger.info(f"APME [4/7] Found {len(paths)} candidate paths (pre-scoring).")
        _heartbeat("step 4/7 pathfinding complete")

        if not paths:
            logger.info("APME: No attack paths found for this scan.")
            builder.close()
            return {"total_paths": 0, "returned_paths": 0, "paths": []}

        # ── Step 6: Score Paths ───────────────────────────────────────────────
        logger.info("APME [5/7] Scoring paths...")
        node_index: Dict[str, Node] = {n.id: n for n in all_nodes}

        for path in paths:
            metadata = self._build_path_metadata(path, node_index, builder, scan_history_id)
            self._scorer.score(path, metadata)

        scored_paths = self._scorer.sort_paths(paths)
        scored_paths = self._scorer.deduplicate(scored_paths)
        scored_paths = self._scorer.sort_paths(scored_paths)

        _heartbeat("step 5/7 scoring complete")

        # ── Step 7: Persist & Return ──────────────────────────────────────────
        logger.info(f"APME [6/7] Persisting top {self.top_n} paths...")
        top_paths = scored_paths[: self.top_n]
        node_index = {n.id: n for n in all_nodes}
        self._persist_paths(top_paths, scan_history_id, node_index)

        builder.close()

        result = serialize_paths(scored_paths, node_index=node_index, top_n=self.top_n)
        logger.info(
            f"APME [7/7] Complete. "
            f"total_paths={result['total_paths']}, "
            f"returned={result['returned_paths']}"
        )
        return result

    # ──────────────────────────────────────────────────────────────────────────
    # Internal helpers
    # ──────────────────────────────────────────────────────────────────────────

    def _build_path_metadata(
        self, path: AttackPath, node_index: Dict[str, Node],
        builder: Optional["GraphBuilder"] = None,
        scan_id: Optional[int] = None,
    ) -> Dict[str, Any]:
        """Extract scoring metadata from path nodes.

        Args:
            path (AttackPath): The attack path object.
            node_index (Dict[str, Node]): Map of node ID to Node object.
            builder (GraphBuilder, optional): The active GraphBuilder instance.
            scan_id (int, optional): The unique ID of the scan.

        Returns:
            Dict[str, Any]: A dictionary containing scoring metadata.
        """
        max_severity = -1
        max_cvss = 0.0
        privilege_gained = "none"
        validated_steps = 0

        for step in path.steps:
            if step.validated:
                validated_steps += 1

            to_node = node_index.get(step.to_id)
            if to_node:
                if to_node.type == "Vulnerability":
                    sev = to_node.properties.get("severity", -1)
                    if sev > max_severity:
                        max_severity = sev
                    cvss = to_node.properties.get("cvss_score", 0.0)
                    if cvss > max_cvss:
                        max_cvss = cvss
                elif to_node.type == "Privilege":
                    privilege_gained = to_node.subtype

        # EPSS, CISA KEV, and Phase 5 vulnerability properties
        epss_percentile = 0.0
        has_cisa_kev = False
        path_confidence_product = 1.0
        has_poc = False
        has_exploit_url = False
        has_metasploit = False
        cve_published_date = None

        for step in path.steps:
            path_confidence_product *= step.confidence
            to_node = node_index.get(step.to_id)
            if to_node and to_node.type == "Vulnerability":
                epss_val = to_node.properties.get("epss_percentile") or 0.0
                if float(epss_val) > epss_percentile:
                    epss_percentile = float(epss_val)
                if to_node.properties.get("is_cisa_kev"):
                    has_cisa_kev = True
                if to_node.properties.get("is_poc"):
                    has_poc = True
                if to_node.properties.get("exploit_url"):
                    has_exploit_url = True
                if to_node.properties.get("has_metasploit"):
                    has_metasploit = True
                pub_date = to_node.properties.get("cve_published_date")
                if pub_date is not None and cve_published_date is None:
                    cve_published_date = pub_date

        # Target node sensitivity (final node in path)
        target_sensitivity = "low"
        last_step_node = node_index.get(path.end)
        if last_step_node:
            target_sensitivity = last_step_node.properties.get("sensitivity", "low")

        # Simplified Blast Radius based on target capability
        blast_radius = 1
        if path.end.startswith("goal::capability::"):
            cap = path.end.split("::")[-1]
            if cap in {"pivot", "rce_execution"}:
                blast_radius = 20
            elif cap in {"db_access", "data_exfil"}:
                blast_radius = 10
            elif cap == "internal_discovery":
                blast_radius = 15

        # Target node degree (connectivity) via Neo4j query
        target_node_degree = 1
        if builder and path.end:
            target_node_degree = builder.query_node_degree(path.end, scan_id)

        return {
            "severity": max_severity,
            "cvss_score": max_cvss,
            "privilege_gained": privilege_gained,
            "validated_steps": validated_steps,
            "target_sensitivity": target_sensitivity,
            "blast_radius": blast_radius,
            "epss_percentile":         epss_percentile,
            "has_cisa_kev":            has_cisa_kev,
            "path_confidence_product": min(max(path_confidence_product, 0.0), 1.0),
            "has_poc":                 has_poc,
            "has_exploit_url":         has_exploit_url,
            "has_metasploit":          has_metasploit,
            "cve_published_date":      cve_published_date,
            "target_node_degree":      target_node_degree,
        }

    def _generate_virtual_goal_nodes(self, scan_history_id: int) -> List[Node]:
        """
        Generates static 'Capability' and 'Privilege' nodes that serve as targets
        for attack rules. These are global objectives for the scan.
        """
        from apme.graph.schema import NODE_TYPES

        goal_nodes = []
        
        # Create Capability nodes
        for subtype in NODE_TYPES.get("Capability", []):
            goal_nodes.append(Node(
                id=f"goal::capability::{subtype}",
                type="Capability",
                subtype=subtype,
                confidence=1.0,
                source="APME:virtual_goal",
                properties={"description": f"Global objective: {subtype}"}
            ))

        # Create Privilege nodes
        for subtype in NODE_TYPES.get("Privilege", []):
            goal_nodes.append(Node(
                id=f"goal::privilege::{subtype}",
                type="Privilege",
                subtype=subtype,
                confidence=1.0,
                source="APME:virtual_goal",
                properties={"description": f"Privilege level: {subtype}"}
            ))

        return goal_nodes

    def _persist_paths(self, paths: List[AttackPath], scan_history_id: int, node_index: Dict[str, Node]) -> None:
        """
        Persist attack paths to reNgine's ImpactAssessment model.
        Each top-level path is stored as a simulated_path JSON blob.
        """
        try:
            from startScan.models import ImpactAssessment, ScanHistory, Vulnerability

            scan_history = ScanHistory.objects.get(id=scan_history_id)

            from apme.output.llm_narrator import LLMNarrator
            narrator = LLMNarrator()

            for path in paths:
                path_dict = path.to_dict()
                narrative = narrator.narrate(path, node_index)

                # Try to link to the most impactful vulnerability in the path
                vuln = self._find_representative_vuln(path, scan_history_id)

                if vuln:
                    # Update or create by vulnerability since vulnerability_id must be unique
                    ImpactAssessment.objects.update_or_create(
                        vulnerability=vuln,
                        defaults={
                            "scan_history": scan_history,
                            "simulated_path": path_dict,
                            "potential_attack_chain": {
                                "apme_path_id": path.id,
                                "risk": path.risk,
                                "score": path.score,
                                "steps": serialize_path(path, node_index)["steps"],
                                "narrative": narrative,
                                "metadata": self._build_path_metadata(path, node_index, scan_id=scan_history_id),
                            },
                            "potential_impact": narrative,
                            "remediation_priority": self._risk_to_priority(path.risk),
                            "is_ai_generated": False,
                        },
                    )
                else:
                    # Vulnerability is None, unique constraint doesn't apply, lookup by path ID
                    ImpactAssessment.objects.update_or_create(
                        scan_history=scan_history,
                        vulnerability=None,
                        potential_attack_chain__apme_path_id=path.id,
                        defaults={
                            "simulated_path": path_dict,
                            "potential_attack_chain": {
                                "apme_path_id": path.id,
                                "risk": path.risk,
                                "score": path.score,
                                "steps": serialize_path(path, node_index)["steps"],
                                "narrative": narrative,
                                "metadata": self._build_path_metadata(path, node_index, scan_id=scan_history_id),
                            },
                            "potential_impact": narrative,
                            "remediation_priority": self._risk_to_priority(path.risk),
                            "is_ai_generated": False,
                        },
                    )
                logger.debug(f"APME: Persisted path {path.id} with narrative.")

        except Exception as exc:
            logger.error(f"APME: Failed to persist paths: {exc}")

    @staticmethod
    def _find_representative_vuln(path: AttackPath, scan_history_id: int):
        """Find the most severe vulnerability mentioned in a path's steps."""
        try:
            from startScan.models import Vulnerability

            for step in path.steps:
                if step.from_id.startswith("vuln::"):
                    vuln_id = int(step.from_id.split("::")[-1])
                    return Vulnerability.objects.get(id=vuln_id)
                if step.to_id.startswith("vuln::"):
                    vuln_id = int(step.to_id.split("::")[-1])
                    return Vulnerability.objects.get(id=vuln_id)
        except Exception:
            pass
        return None

    @staticmethod
    def _risk_to_priority(risk: str) -> int:
        return {"critical": 5, "high": 4, "medium": 3, "low": 2}.get(risk, 1)
