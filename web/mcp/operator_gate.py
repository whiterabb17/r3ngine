"""Resolve whether an update caller is a human operator vs an MCP agent.

MCP API-key sessions are always agents for edit-lock purposes. Client body
flags such as ``operator`` / ``_operator`` must never elevate privilege — that
previously bypassed ``operator_edited`` locks on follow-ups, attack-path
proposals, and SAFE PoC attempts.

JWT/UI (non-MCP) callers are operators and may set ``operator_edited``.
"""
from __future__ import annotations

import logging

logger = logging.getLogger(__name__)


def resolve_is_operator(request) -> bool:
    """Return True only for non-MCP (JWT/UI) callers or explicit server marker.

    ``request.mcp_operator`` may be set by trusted server code only — never
    derived from request body/query/headers supplied by the MCP client.
    """
    if getattr(request, 'mcp_key', None):
        elevated = bool(getattr(request, 'mcp_operator', False))
        if elevated:
            logger.info(
                'mcp_operator elevation for key_id=%s path=%s',
                getattr(getattr(request, 'mcp_key', None), 'pk', None),
                getattr(request, 'path', ''),
            )
        else:
            logger.debug(
                'MCP agent edit (is_operator=False) key_id=%s path=%s',
                getattr(getattr(request, 'mcp_key', None), 'pk', None),
                getattr(request, 'path', ''),
            )
        return elevated
    logger.debug('JWT/UI operator edit path=%s', getattr(request, 'path', ''))
    return True
