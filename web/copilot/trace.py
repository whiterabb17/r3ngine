"""Persist operator-visible Copilot Trace events (gateway is sole DB writer)."""
from __future__ import annotations

import json
import logging
import re
import uuid
from typing import Any

logger = logging.getLogger(__name__)

MAX_PAYLOAD_BYTES = 12_000
_SECRET_KEY_RE = re.compile(
    r'(pass|token|secret|cookie|authorization|api[_-]?key|credential)',
    re.I,
)


def new_turn_id() -> str:
    return uuid.uuid4().hex


def _redact(obj: Any) -> Any:
    if isinstance(obj, dict):
        out = {}
        for k, v in obj.items():
            if _SECRET_KEY_RE.search(str(k)):
                out[str(k)] = '[redacted]'
            else:
                out[str(k)] = _redact(v)
        return out
    if isinstance(obj, list):
        return [_redact(x) for x in obj[:50]]
    if isinstance(obj, str) and len(obj) > 2000:
        return obj[:2000] + '…'
    return obj


def _cap_payload(payload: dict[str, Any] | None) -> dict[str, Any]:
    data = _redact(payload or {})
    raw = json.dumps(data, ensure_ascii=False, default=str)
    if len(raw.encode('utf-8')) <= MAX_PAYLOAD_BYTES:
        return data if isinstance(data, dict) else {'value': data}
    return {
        'truncated': True,
        'preview': raw[:4000],
    }


def emit_trace(
    *,
    project_slug: str,
    event_type: str,
    summary: str = '',
    payload: dict[str, Any] | None = None,
    session=None,
    turn_id: str = '',
    proposal_id: int | None = None,
    msf_aux_attempt_id: int | None = None,
):
    from copilot.models import CopilotTraceEvent

    if not project_slug:
        return None
    try:
        return CopilotTraceEvent.objects.create(
            project_slug=project_slug,
            session=session,
            turn_id=(turn_id or '')[:64],
            event_type=event_type,
            summary=(summary or '')[:512],
            payload=_cap_payload(payload),
            proposal_id=proposal_id,
            msf_aux_attempt_id=msf_aux_attempt_id,
        )
    except Exception:
        logger.exception('copilot emit_trace failed type=%s', event_type)
        return None


def serialize_trace_event(ev) -> dict[str, Any]:
    return {
        'id': ev.id,
        'project_slug': ev.project_slug,
        'session_id': ev.session_id,
        'turn_id': ev.turn_id,
        'event_type': ev.event_type,
        'summary': ev.summary,
        'payload': ev.payload or {},
        'proposal_id': ev.proposal_id,
        'msf_aux_attempt_id': ev.msf_aux_attempt_id,
        'created_at': ev.created_at.isoformat() if ev.created_at else None,
    }


def list_trace_events(
    *,
    project_slug: str,
    session_id: int | None = None,
    turn_id: str | None = None,
    limit: int = 100,
):
    from copilot.models import CopilotTraceEvent

    qs = CopilotTraceEvent.objects.filter(project_slug=project_slug)
    if session_id:
        qs = qs.filter(session_id=session_id)
    if turn_id:
        qs = qs.filter(turn_id=turn_id)
    return list(qs.order_by('-created_at')[: max(1, min(limit, 500))])
