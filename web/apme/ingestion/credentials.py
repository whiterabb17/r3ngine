"""
APME Ingestion — Credentials

Converts reNgine SecretLeak records into APME Credential nodes,
with AUTHENTICATES edges pointing to the services they can access.
"""

import logging
from typing import List, Tuple

from apme.models.node import Node
from apme.models.edge import Edge

logger = logging.getLogger(__name__)

# Ordered patterns: first match wins. More specific entries MUST come first.
_CREDENTIAL_PATTERNS = [
    # Cloud API keys (check before generic "aws"/"api_key" patterns)
    ("akia",           "cloud_api_key"),   # AWS access key ID prefix
    ("aws",            "cloud_api_key"),
    ("gcp",            "cloud_api_key"),
    ("azure",          "cloud_api_key"),
    ("google_api",     "cloud_api_key"),
    # VCS tokens (check before generic "token")
    ("ghp_",           "github_token"),
    ("github",         "github_token"),
    ("gitlab",         "generic_secret"),
    # JWT (check before generic "token")
    ("jwt",            "jwt_token"),
    ("json web token", "jwt_token"),
    ("bearer",         "jwt_token"),
    # Database (check before generic "password")
    ("db_pass",        "db_password"),
    ("database_url",   "db_password"),
    ("mysql",          "db_password"),
    ("postgres",       "db_password"),
    ("mongodb",        "db_password"),
    # SSH
    ("ssh",            "ssh_key"),
    ("-----begin",     "ssh_key"),
    ("private key",    "ssh_key"),
    # Generic password/token/API (broad patterns — must come after specific ones)
    ("password",       "password"),
    ("api_key",        "api_key"),
    ("api key",        "api_key"),
    ("apikey",         "api_key"),
    ("token",          "token"),
    ("oauth",          "token"),
    ("certificate",    "certificate"),
    ("stripe",         "api_key"),
]


def _infer_credential_subtype(secret_type: str) -> str:
    lower = secret_type.lower()
    for keyword, subtype in _CREDENTIAL_PATTERNS:
        if keyword in lower:
            return subtype
    return "generic_secret"


def _make_id(prefix: str, value: str) -> str:
    return f"{prefix}::{value}"


def ingest_credentials(target_id: int) -> Tuple[List[Node], List[Edge]]:
    """
    Ingests SecretLeak records for a given target.
    """
    from startScan.models import SecretLeak

    nodes: List[Node] = []
    edges: List[Edge] = []

    leaks = SecretLeak.objects.filter(
        subdomain__target_domain_id=target_id
    ).select_related("subdomain")

    for leak in leaks:
        validated = leak.status == "verified"
        confidence = 0.90 if validated else 0.60

        subtype = _infer_credential_subtype(leak.secret_type)
        cred_node_id = _make_id("credential", str(leak.id))

        cred_node = Node(
            id=cred_node_id,
            type="Credential",
            subtype=subtype,
            confidence=confidence,
            source="reNgine:secret_discovery",
            properties={
                "secret_type": leak.secret_type,
                "source_url": leak.source_url,
                "validated": validated,
                "tool_name": leak.tool_name,
                "target_id": target_id,
            },
        )
        nodes.append(cred_node)

        # Wire credential to source domain via AUTHENTICATES
        if leak.subdomain:
            target_id = _make_id("domain", leak.subdomain.name)
            try:
                edges.append(Edge(
                    from_id=cred_node_id,
                    to_id=target_id,
                    type="AUTHENTICATES",
                    confidence=confidence,
                    properties={"validated": validated},
                ))
            except ValueError as exc:
                logger.warning("APME Ingestion: %s", exc)

    logger.info(
        "APME Ingestion [credentials]: %s nodes, %s edges (target_id=%s)", len(nodes), len(edges), target_id
    )
    return nodes, edges
