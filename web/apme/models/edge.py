from dataclasses import dataclass, field
from typing import Any, Dict


# Canonical edge relationship types for the APME graph.
EDGE_TYPES = {
    "RESOLVES_TO",    # domain -> ip
    "HOSTS",          # ip -> service
    "EXPOSES",        # service -> vulnerability
    "LEADS_TO",       # vulnerability -> capability
    "AUTHENTICATES",  # credential -> service
    "ESCALATES_TO",   # identity -> privilege
    "TRUSTS",         # system -> system (lateral movement)
    "CONNECTED_TO",   # network pivot
    "USES_TECH",      # asset -> technology
    "PROTECTS",       # certificate -> endpoint
    "AUTHENTICATES_VIA",  # application -> identity infra
    "DEPENDS_ON",     # app -> api endpoint
    "TRUSTS_DOMAIN",  # domain -> trusted external domain
    "PART_OF",        # app/org -> parent domain node
}


@dataclass
class Edge:
    """
    Represents a directed edge in the attack graph.
    All edges MUST have a defined type from EDGE_TYPES.
    Fail-safe: edges with unknown types are rejected by the graph builder.
    """
    from_id: str
    to_id: str
    type: str
    properties: Dict[str, Any] = field(default_factory=dict)
    confidence: float = 1.0

    def __post_init__(self):
        if self.type not in EDGE_TYPES:
            raise ValueError(
                f"Invalid edge type '{self.type}'. Must be one of: {EDGE_TYPES}"
            )

    def to_dict(self) -> Dict[str, Any]:
        return {
            "from": self.from_id,
            "to": self.to_id,
            "type": self.type,
            "properties": self.properties,
            "confidence": self.confidence,
        }
