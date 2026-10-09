from dataclasses import dataclass, field
from typing import Any, Dict, List, Optional


@dataclass
class PathStep:
    """A single step within an attack path."""
    from_id: str
    to_id: str
    action: str
    confidence: float = 0.0
    validated: bool = False
    edge_type: str = ""
    mitre_technique: str = ""
    mitre_tactic: str = ""
    requires_victim: bool = False

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from": self.from_id,
            "to": self.to_id,
            "action": self.action,
            "confidence": self.confidence,
            "validated": self.validated,
            "status": "validated" if self.validated else "inferred",
            "edge_type": self.edge_type,
            "mitre_technique": self.mitre_technique,
            "mitre_tactic": self.mitre_tactic,
        }


@dataclass
class AttackPath:
    """
    A complete attack path from an entry point to a target.
    Paths MUST be constraint-validated before being included in results.
    """
    id: str
    start: str
    end: str
    steps: List[PathStep] = field(default_factory=list)
    score: float = 0.0
    risk: str = "low"    # critical | high | medium | low | speculative
    entry_type: str = "internet"  # internet | credential | user_defined

    def to_dict(self) -> Dict[str, Any]:
        return {
            "path_id": self.id,
            "start": self.start,
            "end": self.end,
            "risk": self.risk,
            "score": round(self.score, 4),
            "entry_type": self.entry_type,
            "steps": [s.to_dict() for s in self.steps],
        }

    @property
    def fingerprint(self) -> str:
        return get_path_fingerprint(self.steps)


def get_path_fingerprint(steps: List[Any]) -> str:
    """
    Generate a stable semantic fingerprint for a list of steps.
    Each step can be a PathStep instance or a dictionary.
    """
    import re
    _strip_id = re.compile(r"::\d+$")
    parts = []
    for s in steps:
        if isinstance(s, dict):
            from_id = s.get("from") or s.get("from_id") or ""
            to_id = s.get("to") or s.get("to_id") or ""
            edge_type = s.get("edge_type") or ""
        else:
            from_id = getattr(s, "from_id", "")
            to_id = getattr(s, "to_id", "")
            edge_type = getattr(s, "edge_type", "")

        from_stripped = _strip_id.sub("", from_id)
        to_stripped = _strip_id.sub("", to_id)
        parts.append(f"{edge_type}:{from_stripped}:{to_stripped}")
    return "->".join(parts)

