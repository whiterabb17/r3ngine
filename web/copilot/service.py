"""Copilot gateway logic — chat, proposals, approve delegates to existing gates."""
from __future__ import annotations

import logging
import re
from typing import Any

from django.db import transaction
from django.utils import timezone

from copilot.client import CopilotClientError, copilot_chat, copilot_health
from copilot.models import (
    CopilotActionProposal,
    CopilotMessage,
    CopilotSession,
    CopilotSettings,
)
from startScan.models import Vulnerability

logger = logging.getLogger(__name__)

_PROPOSAL_RE = re.compile(
    r'```proposal\s*(\{.*?\})\s*```',
    re.DOTALL | re.IGNORECASE,
)


class CopilotError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def get_or_create_settings(project_slug: str) -> CopilotSettings:
    obj, _ = CopilotSettings.objects.get_or_create(project_slug=project_slug)
    return obj


def serialize_settings(cfg: CopilotSettings) -> dict[str, Any]:
    return {
        'project_slug': cfg.project_slug,
        'enabled': cfg.enabled,
        'memory_scope': cfg.memory_scope,
        'model_id': cfg.model_id,
        'org_id': cfg.org_id,
        'updated_at': cfg.updated_at.isoformat() if cfg.updated_at else None,
    }


def serialize_session(session: CopilotSession, *, include_messages: bool = False) -> dict[str, Any]:
    data = {
        'id': session.id,
        'project_slug': session.project_slug,
        'scan_id': session.scan_id,
        'assessment_id': session.assessment_id,
        'title': session.title,
        'created_at': session.created_at.isoformat() if session.created_at else None,
        'updated_at': session.updated_at.isoformat() if session.updated_at else None,
        'message_count': session.messages.count(),
    }
    if include_messages:
        data['messages'] = [
            {
                'id': m.id,
                'role': m.role,
                'content': m.content,
                'created_at': m.created_at.isoformat() if m.created_at else None,
            }
            for m in session.messages.all()
        ]
    return data


def serialize_proposal(p: CopilotActionProposal) -> dict[str, Any]:
    return {
        'id': p.id,
        'project_slug': p.project_slug,
        'scan_id': p.scan_id,
        'assessment_id': p.assessment_id,
        'vulnerability_id': p.vulnerability_id,
        'session_id': p.session_id,
        'action_type': p.action_type,
        'status': p.status,
        'summary': p.summary,
        'rationale': p.rationale,
        'payload': p.payload or {},
        'safe_poc_attempt_id': p.safe_poc_attempt_id,
        'followup_plan_id': p.followup_plan_id,
        'result': p.result or {},
        'created_at': p.created_at.isoformat() if p.created_at else None,
        'decided_at': p.decided_at.isoformat() if p.decided_at else None,
    }


def service_status(project_slug: str | None = None) -> dict[str, Any]:
    health = copilot_health()
    cfg = None
    if project_slug:
        cfg = serialize_settings(get_or_create_settings(project_slug))
    pending = 0
    if project_slug:
        pending = CopilotActionProposal.objects.filter(
            project_slug=project_slug,
            status=CopilotActionProposal.STATUS_PENDING,
        ).count()
    return {
        'health': health,
        'settings': cfg,
        'pending_proposals': pending,
    }


def chat(
    *,
    session: CopilotSession,
    content: str,
    user=None,
) -> dict[str, Any]:
    cfg = get_or_create_settings(session.project_slug)
    if not cfg.enabled:
        raise CopilotError('Assessment Copilot is disabled for this project', 403)

    CopilotMessage.objects.create(
        session=session,
        role=CopilotMessage.ROLE_USER,
        content=content,
    )
    history = list(
        session.messages.order_by('created_at').values('role', 'content')[:40]
    )
    try:
        result = copilot_chat(
            history,
            model=cfg.model_id or None,
            scope=cfg.memory_scope,
            project_id=session.project_slug,
            org_id=cfg.org_id or None,
        )
    except CopilotClientError as exc:
        raise CopilotError(str(exc), status=exc.status) from exc

    assistant = ((result.get('message') or {}).get('content')) or ''
    CopilotMessage.objects.create(
        session=session,
        role=CopilotMessage.ROLE_ASSISTANT,
        content=assistant,
    )
    if session.title in ('', 'New conversation') and content.strip():
        session.title = content.strip()[:80]
    session.save(update_fields=['title', 'updated_at'])

    created_proposals = _extract_and_store_proposals(
        session=session,
        assistant_text=assistant,
        user=user,
    )
    return {
        'session': serialize_session(session, include_messages=True),
        'reply': assistant,
        'memory_hits': result.get('memory_hits'),
        'model': result.get('model'),
        'proposals': [serialize_proposal(p) for p in created_proposals],
    }


def _extract_and_store_proposals(
    *,
    session: CopilotSession,
    assistant_text: str,
    user=None,
) -> list[CopilotActionProposal]:
    created: list[CopilotActionProposal] = []
    for match in _PROPOSAL_RE.finditer(assistant_text or ''):
        raw = match.group(1)
        try:
            import json
            data = json.loads(raw)
        except Exception:
            continue
        if not isinstance(data, dict):
            continue
        action_type = str(data.get('type') or '').strip().lower()
        if action_type not in {
            CopilotActionProposal.TYPE_VALIDATE,
            CopilotActionProposal.TYPE_SAFE_POC,
            CopilotActionProposal.TYPE_FOLLOWUP,
            CopilotActionProposal.TYPE_REMEDIATION,
        }:
            continue
        details = data.get('details') if isinstance(data.get('details'), dict) else {}
        vuln_id = details.get('vulnerability_id') or data.get('vulnerability_id')
        try:
            vuln_id = int(vuln_id) if vuln_id is not None else None
        except (TypeError, ValueError):
            vuln_id = None
        proposal = CopilotActionProposal.objects.create(
            project_slug=session.project_slug,
            scan_id=session.scan_id,
            assessment_id=session.assessment_id,
            vulnerability_id=vuln_id,
            session=session,
            action_type=action_type,
            summary=(data.get('summary') or action_type)[:512],
            rationale=str(data.get('rationale') or details.get('rationale') or '')[:4000],
            payload=details,
            created_by=user if getattr(user, 'is_authenticated', False) else None,
        )
        created.append(proposal)
    return created


def create_proposal(
    *,
    project_slug: str,
    action_type: str,
    summary: str = '',
    rationale: str = '',
    payload: dict | None = None,
    vulnerability_id: int | None = None,
    scan_id: int | None = None,
    assessment_id: int | None = None,
    session_id: int | None = None,
    user=None,
) -> CopilotActionProposal:
    if action_type not in {
        CopilotActionProposal.TYPE_VALIDATE,
        CopilotActionProposal.TYPE_SAFE_POC,
        CopilotActionProposal.TYPE_FOLLOWUP,
        CopilotActionProposal.TYPE_REMEDIATION,
    }:
        raise CopilotError(f'invalid action_type: {action_type}')
    session = None
    if session_id:
        session = CopilotSession.objects.filter(pk=session_id, project_slug=project_slug).first()
    return CopilotActionProposal.objects.create(
        project_slug=project_slug,
        scan_id=scan_id,
        assessment_id=assessment_id,
        vulnerability_id=vulnerability_id,
        session=session,
        action_type=action_type,
        summary=(summary or action_type)[:512],
        rationale=(rationale or '')[:4000],
        payload=payload or {},
        created_by=user if getattr(user, 'is_authenticated', False) else None,
    )


@transaction.atomic
def reject_proposal(proposal: CopilotActionProposal, *, user=None) -> CopilotActionProposal:
    locked = (
        CopilotActionProposal.objects
        .select_for_update()
        .filter(pk=proposal.pk)
        .first()
    )
    if not locked:
        raise CopilotError('proposal not found', 404)
    proposal = locked
    if proposal.status != CopilotActionProposal.STATUS_PENDING:
        raise CopilotError(f'proposal not pending (status={proposal.status})', 409)
    proposal.status = CopilotActionProposal.STATUS_REJECTED
    proposal.decided_at = timezone.now()
    proposal.decided_by = user if getattr(user, 'is_authenticated', False) else None
    proposal.save(update_fields=['status', 'decided_at', 'decided_by', 'updated_at'])
    return proposal


def _vuln_for_project(vuln_id: int, project_slug: str) -> Vulnerability:
    """Load a vulnerability and enforce it belongs to the proposal's project."""
    vuln = (
        Vulnerability.objects
        .select_related('scan_history', 'scan_history__domain', 'scan_history__domain__project',
                        'target_domain', 'target_domain__project')
        .filter(pk=int(vuln_id))
        .first()
    )
    if not vuln:
        raise CopilotError('vulnerability not found', 404)
    domain = vuln.target_domain or (vuln.scan_history.domain if vuln.scan_history_id else None)
    project = getattr(domain, 'project', None) if domain is not None else None
    slug = getattr(project, 'slug', None)
    if not slug or slug != project_slug:
        raise CopilotError('vulnerability does not belong to this project', 403)
    return vuln


@transaction.atomic
def approve_proposal(proposal: CopilotActionProposal, *, user=None) -> CopilotActionProposal:
    """Delegate to existing Safe PoC / follow-up / enrich paths — no parallel executor."""
    # Row lock prevents concurrent double-approve / double Temporal starts.
    locked = (
        CopilotActionProposal.objects
        .select_for_update()
        .filter(pk=proposal.pk)
        .first()
    )
    if not locked:
        raise CopilotError('proposal not found', 404)
    proposal = locked
    if proposal.status != CopilotActionProposal.STATUS_PENDING:
        raise CopilotError(f'proposal not pending (status={proposal.status})', 409)

    try:
        if proposal.action_type == CopilotActionProposal.TYPE_SAFE_POC:
            result = _approve_safe_poc(proposal, user=user)
        elif proposal.action_type == CopilotActionProposal.TYPE_FOLLOWUP:
            result = _approve_followup(proposal, user=user)
        elif proposal.action_type == CopilotActionProposal.TYPE_VALIDATE:
            result = _approve_validate(proposal, user=user)
        elif proposal.action_type == CopilotActionProposal.TYPE_REMEDIATION:
            result = _approve_remediation(proposal, user=user)
        else:
            raise CopilotError(f'unsupported action_type: {proposal.action_type}')
    except CopilotError:
        raise
    except Exception as exc:
        logger.exception('copilot approve failed proposal_id=%s', proposal.id)
        proposal.status = CopilotActionProposal.STATUS_FAILED
        proposal.result = {'error': str(exc)}
        proposal.decided_at = timezone.now()
        proposal.decided_by = user if getattr(user, 'is_authenticated', False) else None
        proposal.save(update_fields=['status', 'result', 'decided_at', 'decided_by', 'updated_at'])
        raise CopilotError(str(exc), status=400) from exc

    proposal.status = CopilotActionProposal.STATUS_APPROVED
    proposal.result = result
    proposal.decided_at = timezone.now()
    proposal.decided_by = user if getattr(user, 'is_authenticated', False) else None
    proposal.save(
        update_fields=[
            'status', 'result', 'decided_at', 'decided_by', 'updated_at',
            'safe_poc_attempt_id', 'followup_plan_id',
        ]
    )
    return proposal


def _approve_safe_poc(proposal: CopilotActionProposal, *, user=None) -> dict[str, Any]:
    from mcp.safe_poc import SafePocError, approve_attempt, propose_attempt

    payload = proposal.payload or {}
    vuln_id = proposal.vulnerability_id or payload.get('vulnerability_id')
    template_id = payload.get('template_id')
    params = payload.get('params') or {}
    if not vuln_id or not template_id:
        raise CopilotError('safe_poc requires vulnerability_id and template_id')
    try:
        attempt = propose_attempt(
            vulnerability_id=int(vuln_id),
            template_id=str(template_id),
            params=params if isinstance(params, dict) else {},
            rationale=proposal.rationale or proposal.summary,
            project_slug=proposal.project_slug,
            agent_id='assessment-copilot',
            user=user,
        )
        attempt = approve_attempt(attempt, user=user)
    except SafePocError as exc:
        raise CopilotError(str(exc), status=exc.status) from exc
    proposal.safe_poc_attempt_id = attempt.id
    return {
        'safe_poc_attempt_id': attempt.id,
        'status': attempt.status,
        'template_id': attempt.template_id,
    }


def _approve_followup(proposal: CopilotActionProposal, *, user=None) -> dict[str, Any]:
    from mcp.followups import FollowupError, approve_plan, propose_plan

    payload = proposal.payload or {}
    steps = payload.get('steps')
    if not isinstance(steps, list) or not steps:
        raise CopilotError('followup requires non-empty steps')
    try:
        plan = propose_plan(
            project_slug=proposal.project_slug,
            steps=steps,
            rationale=proposal.rationale or proposal.summary,
            scan_id=proposal.scan_id or payload.get('scan_id'),
            assessment_id=proposal.assessment_id or payload.get('assessment_id'),
            user=user,
        )
        plan = approve_plan(plan, user=user)
    except FollowupError as exc:
        raise CopilotError(str(exc), status=getattr(exc, 'status', 400)) from exc
    proposal.followup_plan_id = plan.id
    return {
        'followup_plan_id': plan.id,
        'status': plan.status,
        'steps': plan.steps,
    }


def _approve_validate(proposal: CopilotActionProposal, *, user=None) -> dict[str, Any]:
    payload = proposal.payload or {}
    vuln_id = proposal.vulnerability_id or payload.get('vulnerability_id')
    if not vuln_id:
        raise CopilotError('validate requires vulnerability_id')
    vuln = _vuln_for_project(int(vuln_id), proposal.project_slug)

    enrichment = dict(vuln.agent_enrichment or {})
    if payload.get('validation_verdict'):
        enrichment['validation_verdict'] = str(payload['validation_verdict'])[:32]
    if payload.get('confidence') is not None:
        try:
            enrichment['confidence'] = max(0.0, min(1.0, float(payload['confidence'])))
        except (TypeError, ValueError):
            pass
    if payload.get('impact_classes'):
        enrichment['impact_classes'] = payload['impact_classes']
    enrichment['rationale'] = (proposal.rationale or payload.get('rationale') or '')[:4000]
    enrichment['agent_id'] = 'assessment-copilot'
    enrichment['enriched_at'] = timezone.now().isoformat()
    vuln.agent_enrichment = enrichment

    status_val = payload.get('validation_status') or 'needs_review'
    # Hard gate: never auto-set verified from co-pilot alone
    if status_val == 'verified':
        status_val = 'needs_review'
    vuln.validation_status = status_val
    if payload.get('confidence') is not None:
        try:
            vuln.validation_confidence = max(0.0, min(1.0, float(payload['confidence'])))
        except (TypeError, ValueError):
            pass
    vuln.validation_reason = (proposal.rationale or '')[:2000]
    vuln.save(
        update_fields=[
            'agent_enrichment',
            'validation_status',
            'validation_confidence',
            'validation_reason',
        ]
    )
    return {
        'vulnerability_id': vuln.id,
        'validation_status': vuln.validation_status,
        'agent_enrichment': vuln.agent_enrichment,
    }


def _approve_remediation(proposal: CopilotActionProposal, *, user=None) -> dict[str, Any]:
    payload = proposal.payload or {}
    vuln_id = proposal.vulnerability_id or payload.get('vulnerability_id')
    if not vuln_id:
        raise CopilotError('remediation requires vulnerability_id')
    vuln = _vuln_for_project(int(vuln_id), proposal.project_slug)

    short = str(payload.get('short') or payload.get('short_term') or '').strip()
    long_term = str(payload.get('long') or payload.get('long_term') or '').strip()
    if not short and not long_term:
        raise CopilotError('remediation requires short and/or long text')

    enrichment = dict(vuln.agent_enrichment or {})
    enrichment['remediation'] = {
        'short': short,
        'long': long_term,
        'agent_id': 'assessment-copilot',
        'updated_at': timezone.now().isoformat(),
    }
    vuln.agent_enrichment = enrichment
    summary = short or long_term
    if summary:
        vuln.remediation = summary[:5000]
    vuln.save(update_fields=['agent_enrichment', 'remediation'])
    return {
        'vulnerability_id': vuln.id,
        'remediation': enrichment['remediation'],
    }
