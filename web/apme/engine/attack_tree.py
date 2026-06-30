"""
APME Attack Tree Construction

Builds hierarchical attack trees (AND/OR graphs) from linear pathfinding results.
Annotates leaf nodes with metrics (cost, skill, detectability) and mitigations.
"""
import uuid
import logging
from typing import List, Dict, Any

from apme.engine.pathfinder import Pathfinder
from apme.models.path import AttackPath
from apme.utils.mitre import infer_cost, infer_skill, get_mitigation

logger = logging.getLogger(__name__)

class AttackTreeBuilder:
    def __init__(self, scan_id: int):
        self.scan_id = scan_id
        self.pathfinder = Pathfinder()

    def build_tree(self, target_id: str) -> Dict[str, Any]:
        """
        Builds an Attack Tree with the target_id as the root node.
        Uses reversed BFS to find all paths from internet entry points to target.
        """
        tree = {
            "id": f"tree_{uuid.uuid4().hex[:8]}",
            "type": "OR",
            "goal": target_id,
            "children": []
        }
        
        try:
            # We fetch paths using pathfinder
            paths = self.pathfinder.find_all_paths(self.scan_id, top_n=20)
            target_paths = [p for p in paths if p.end == target_id]
            
            if not target_paths:
                return None
            
            for path in target_paths:
                and_node = {
                    "type": "AND",
                    "description": f"Attack Path via {path.start}",
                    "cost": "medium",
                    "skill": "medium",
                    "children": []
                }
                
                for step in path.steps:
                    leaf = {
                        "type": "LEAF",
                        "action": step.action,
                        "mitre_id": step.mitre_technique,
                        "cost": infer_cost(step.mitre_technique),
                        "skill": infer_skill(step.mitre_technique),
                        "detectability": "high" if getattr(step, 'requires_victim', False) else "low",
                        "mitigation": get_mitigation(step.mitre_technique)
                    }
                    and_node["children"].append(leaf)
                    
                tree["children"].append(and_node)
                
        except Exception as e:
            logger.error(f"Failed to build attack tree for {target_id}: {e}")
            return None
            
        return tree
