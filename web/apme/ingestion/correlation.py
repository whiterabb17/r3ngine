import logging
from typing import List, Tuple, Dict
from apme.models.node import Node
from apme.models.edge import Edge

logger = logging.getLogger(__name__)

class ExposureCorrelator:
    """
    Correlates and deduplicates APME nodes and edges before graph insertion.
    Aggregates findings from multiple tools into Unified Assets and Vulnerabilities.
    """
    def __init__(self):
        self.nodes = []
        self.edges = []
        # Key: fingerprint, Value: Node
        self._vuln_cache: Dict[str, Node] = {}
        # Key: (from_id, to_id, type), Value: Edge
        self._edge_cache: Dict[Tuple[str, str, str], Edge] = {}
        # Key: original Node ID, Value: deduplicated Node ID
        self._id_map: Dict[str, str] = {}

    def correlate(self, nodes: List[Node], edges: List[Edge]) -> Tuple[List[Node], List[Edge]]:
        merged_nodes = []
        
        # 1. Deduplicate Vulnerabilities
        for node in nodes:
            if node.type == "Vulnerability":
                props = node.properties
                name = props.get("name", "").lower()
                cwe = props.get("cwe", "")
                target_id = props.get("target_id", "")
                http_url = props.get("http_url", "")
                
                # Semantic fingerprint: name/cwe + target + url
                fingerprint = f"{name}::{cwe}::{target_id}::{http_url}"
                
                if fingerprint in self._vuln_cache:
                    existing_node = self._vuln_cache[fingerprint]
                    # Merge properties
                    existing_node.confidence = max(existing_node.confidence, node.confidence)
                    
                    existing_sources = set([s.strip() for s in existing_node.source.split(",") if s.strip()])
                    new_sources = set([s.strip() for s in node.source.split(",") if s.strip()])
                    existing_node.source = ", ".join(existing_sources.union(new_sources))
                    
                    self._id_map[node.id] = existing_node.id
                else:
                    self._vuln_cache[fingerprint] = node
                    self._id_map[node.id] = node.id
            else:
                merged_nodes.append(node)
                self._id_map[node.id] = node.id
                
        merged_nodes.extend(self._vuln_cache.values())
        
        # 2. Update Edges with new IDs and deduplicate
        merged_edges = []
        for edge in edges:
            mapped_from = self._id_map.get(edge.from_id, edge.from_id)
            mapped_to = self._id_map.get(edge.to_id, edge.to_id)
            edge_key = (mapped_from, mapped_to, edge.type)
            
            if edge_key in self._edge_cache:
                existing_edge = self._edge_cache[edge_key]
                existing_edge.confidence = max(existing_edge.confidence, edge.confidence)
            else:
                edge.from_id = mapped_from
                edge.to_id = mapped_to
                self._edge_cache[edge_key] = edge
                
        merged_edges.extend(self._edge_cache.values())
        
        logger.info(f"ExposureCorrelator: Deduplicated {len(nodes)} nodes to {len(merged_nodes)}.")
        return merged_nodes, merged_edges
