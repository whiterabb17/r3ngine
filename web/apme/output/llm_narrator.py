import logging
import json
from typing import Dict, Any, List

from apme.models.path import AttackPath
from reNgine.llm import LLMBaseGenerator

logger = logging.getLogger(__name__)

class LLMNarrator:
    """
    Converts technical graph paths into human-readable attack narratives.
    Uses the configured LLM to explain the 'how' and 'why' of a path.
    """

    def __init__(self):
        self.generator = LLMBaseGenerator(logger)

    def narrate(self, path: AttackPath, node_index: Dict[str, Any]) -> str:
        """
        Generates a natural language story for the given attack path.
        """
        if not path.steps:
            return "No steps provided in path."

        # 1. Build a simplified text representation of the path for the LLM
        narrative_context = []
        for i, step in enumerate(path.steps):
            from_node = node_index.get(step.from_id)
            to_node = node_index.get(step.to_id)
            
            from_name = from_node.properties.get("name") or from_node.id if from_node else step.from_id
            to_name = to_node.properties.get("name") or to_node.id if to_node else step.to_id
            
            # Enrich with taxonomy if available
            to_info = ""
            if to_node and to_node.type == "Vulnerability":
                cwe = to_node.properties.get("cwe", "unknown")
                tech = to_node.properties.get("technique", "unknown")
                to_info = f" ({cwe}, MITRE {tech})"

            narrative_context.append(
                f"Step {i+1}: From {from_name} to {to_name} via {step.edge_type}. "
                f"Action: {step.action}{to_info}. Confidence: {step.confidence:.2f}"
            )

        # 2. Prompt the LLM
        system_prompt = """
        You are a Cyber Security Analyst explaining attack paths to stakeholders.
        Convert the provided technical graph traversal into a compelling, professional attack story.
        
        Guidelines:
        - Use clear, active language.
        - Explain the impact of each step (e.g., 'This allows the attacker to...').
        - Highlight high-risk capabilities like pivoting or RCE.
        - Keep it concise but descriptive (2-4 paragraphs).
        - Use a 'Findings' and 'Scenario' structure.
        - CRITICAL: Do NOT include any conversational follow-up questions or offers of assistance (such as "Would you like to include a longer brief?"). Output ONLY the attack story.
        """
        
        user_message = (
            f"Attack Path ID: {path.id}\n"
            f"Risk Level: {path.risk.upper()} (Score: {path.score:.2f})\n"
            "Technical Steps:\n" + "\n".join(narrative_context)
        )

        try:
            narrative = self.generator._call_llm(system_prompt, user_message)
            if not narrative:
                return self._fallback_narration(path, node_index)
            return narrative
        except Exception as e:
            logger.error("APME Narration Error: %s", str(e))
            return self._fallback_narration(path, node_index)

    def _fallback_narration(self, path: AttackPath, node_index: Dict[str, Any]) -> str:
        """Basic rule-based narration if LLM fails."""
        start = path.start
        end = path.end
        return f"Attack path starts at {start} and reaches {end} via {len(path.steps)} steps. Risk is {path.risk}."
