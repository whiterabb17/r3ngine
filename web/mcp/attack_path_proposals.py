"""Attack-path proposal service — propose, edit, approve (apply), abort.

All path-domain mutations go through proposals. Propose never mutates live rows.
"""
from __future__ import annotations

import re
import asyncio
import logging
import uuid
from datetime import timezone as dt_timezone
from typing import Any, Optional

from django.utils import timezone

from mcp.models import AttackPathProposal
from startScan.models import ImpactAssessment, ScanHistory, Subdomain, Vulnerability

logger = logging.getLogger(__name__)

MAX_STEPS = 40
MAX_STRING = 500
MAX_RATIONALE = 4000
MAX_IMPACT = 8000
PATH_FEASIBILITY = frozenset({'plausible', 'stretched', 'fantasy'})
IMPACT_CLASSES = frozenset({
    'remote_code_execution',
    'remote_access',
    'privilege_escalation',
    'data_leakage',
    'auth_bypass',
    'denial_of_service',
    'lateral_movement',
    'recon_only',
})
_FORBIDDEN_KEY_RE = re.compile(
    r'(payload|exploit_code|exploit_body|shellcode|metasploit|msfvenom|'
    r'reverse_shell|bind_shell|weaponiz)',
    re.I,
)

OPERATIONS = frozenset({
    AttackPathProposal.OP_ENRICH,
    AttackPathProposal.OP_CREATE,
    AttackPathProposal.OP_UPDATE,
    AttackPathProposal.OP_DISMISS,
    AttackPathProposal.OP_TRIGGER_APME,
    AttackPathProposal.OP_RECALCULATE_APME,
})

PROPOSE_APPROVE_MSG = (
    'Attack-path mutations require propose → operator approve. '
    'Use r3ngine_propose_attack_path with the matching operation.'
)


class AttackPathProposalError(Exception):
    def __init__(self, message: str, status: int = 400):
        super().__init__(message)
        self.status = status


def _utc_now_iso() -> str:
    return timezone.now().astimezone(dt_timezone.utc).isoformat()


def _reject_forbidden_keys(obj: Any, path: str = '') -> str | None:
    if isinstance(obj, dict):
        for key, value in obj.items():
            key_s = str(key)
            if _FORBIDDEN_KEY_RE.search(key_s):
                return f'forbidden field: {path + key_s}'
            err = _reject_forbidden_keys(value, path + key_s + '.')
            if err:
                return err
    elif isinstance(obj, list):
        for i, item in enumerate(obj):
            err = _reject_forbidden_keys(item, f'{path}{i}.')
            if err:
                return err
    return None


def _clamp_confidence(raw) -> float | None:
    if raw is None or raw == '':
        return None
    try:
        val = float(raw)
    except (TypeError, ValueError):
        return None
    return max(0.0, min(1.0, val))


def _normalize_impact_classes(raw) -> list[str] | None:
    if raw is None:
        return None
    if not isinstance(raw, list):
        return None
    out = []
    for item in raw:
        key = str(item).strip().lower().replace(' ', '_').replace('-', '_')
        if key not in IMPACT_CLASSES:
            continue
        if key not in out:
            out.append(key)
    return out


def _path_summary(assessment: ImpactAssessment) -> dict[str, Any]:
    from mcp.views.validation import serialize_path_summary
    return serialize_path_summary(assessment)


def find_assessment_by_path_key(path_key: str) -> Optional[ImpactAssessment]:
    path_key = str(path_key or '').strip()
    if not path_key:
        return None
    assessment = None
    if path_key.isdigit():
        assessment = ImpactAssessment.objects.filter(pk=int(path_key)).first()
    if assessment is not None:
        return assessment
    candidates = (
        ImpactAssessment.objects
        .exclude(potential_attack_chain__isnull=True)
        .exclude(potential_attack_chain={})
        .order_by('-id')
    )
    for row in candidates.iterator(chunk_size=200):
        chain = row.potential_attack_chain or {}
        if str(chain.get('apme_path_id') or '') == path_key:
            return row
    return None


def _new_agent_path_id() -> str:
    return f'APT-AGENT-{uuid.uuid4().hex[:10].upper()}'


def _sanitize_step(raw: Any, index: int) -> dict:
    if not isinstance(raw, dict):
        raise AttackPathProposalError(f'steps[{index}] must be an object')
    forbidden = _reject_forbidden_keys(raw)
    if forbidden:
        raise AttackPathProposalError(forbidden)
    step: dict[str, Any] = {}
    for key in ('from', 'to', 'action', 'status', 'confidence'):
        if key in raw and raw[key] is not None:
            if key == 'confidence':
                conf = _clamp_confidence(raw[key])
                if conf is None:
                    raise AttackPathProposalError(f'steps[{index}].confidence must be a number')
                step['confidence'] = conf
            else:
                step[key] = str(raw[key])[:MAX_STRING]
    for node_key in ('from_node', 'to_node'):
        node = raw.get(node_key)
        if isinstance(node, dict):
            name = node.get('name') or node.get('id') or ''
            step[node_key] = {'name': str(name)[:MAX_STRING]}
    techniques = raw.get('attck_techniques') or raw.get('techniques')
    if techniques is not None:
        if not isinstance(techniques, list):
            raise AttackPathProposalError(f'steps[{index}].attck_techniques must be a list')
        step['attck_techniques'] = [
            str(t)[:64] for t in techniques[:20] if str(t).strip()
        ]
    return step


def _sanitize_chain(raw: Any) -> dict:
    if raw is None:
        return {}
    if not isinstance(raw, dict):
        raise AttackPathProposalError('payload.chain must be an object')
    forbidden = _reject_forbidden_keys(raw)
    if forbidden:
        raise AttackPathProposalError(forbidden)
    chain: dict[str, Any] = {}
    if 'risk' in raw and raw['risk'] is not None:
        chain['risk'] = str(raw['risk'])[:64]
    if 'score' in raw and raw['score'] is not None:
        try:
            chain['score'] = float(raw['score'])
        except (TypeError, ValueError) as exc:
            raise AttackPathProposalError('payload.chain.score must be a number') from exc
    if 'summary' in raw and raw['summary'] is not None:
        chain['summary'] = str(raw['summary'])[:MAX_RATIONALE]
    steps = raw.get('steps')
    if steps is not None:
        if not isinstance(steps, list):
            raise AttackPathProposalError('payload.chain.steps must be a list')
        if len(steps) > MAX_STEPS:
            raise AttackPathProposalError(f'max {MAX_STEPS} steps')
        chain['steps'] = [_sanitize_step(s, i) for i, s in enumerate(steps)]
    return chain


def _sanitize_enrich_fields(payload: dict) -> dict:
    out: dict[str, Any] = {}
    feasibility = payload.get('feasibility')
    if feasibility is not None:
        feasibility = str(feasibility).strip().lower()
        if feasibility not in PATH_FEASIBILITY:
            raise AttackPathProposalError(
                f'feasibility must be one of {sorted(PATH_FEASIBILITY)}'
            )
        out['feasibility'] = feasibility
    if payload.get('confidence') is not None:
        conf = _clamp_confidence(payload.get('confidence'))
        if conf is None:
            raise AttackPathProposalError('confidence must be a number')
        out['confidence'] = conf
    if 'blocked_reasons' in payload:
        reasons = payload.get('blocked_reasons') or []
        if not isinstance(reasons, list):
            raise AttackPathProposalError('blocked_reasons must be a list')
        out['blocked_reasons'] = [str(r)[:MAX_STRING] for r in reasons[:40]]
    if 'missing_prereqs' in payload:
        prereqs = payload.get('missing_prereqs') or []
        if not isinstance(prereqs, list):
            raise AttackPathProposalError('missing_prereqs must be a list')
        out['missing_prereqs'] = [str(r)[:MAX_STRING] for r in prereqs[:40]]
    if 'impact_classes' in payload:
        classes = _normalize_impact_classes(payload.get('impact_classes'))
        if classes is None:
            raise AttackPathProposalError(
                f'impact_classes must be a list of {sorted(IMPACT_CLASSES)}'
            )
        out['impact_classes'] = classes
    if 'rationale' in payload:
        out['rationale'] = str(payload.get('rationale') or '')[:MAX_RATIONALE]
    if 'potential_impact' in payload and payload.get('potential_impact') is not None:
        out['potential_impact'] = str(payload.get('potential_impact'))[:MAX_IMPACT]
    return out


def normalize_payload(operation: str, payload: Any) -> dict:
    if payload is None:
        payload = {}
    if not isinstance(payload, dict):
        raise AttackPathProposalError('payload must be an object')
    forbidden = _reject_forbidden_keys(payload)
    if forbidden:
        raise AttackPathProposalError(forbidden)

    if operation in (
        AttackPathProposal.OP_TRIGGER_APME,
        AttackPathProposal.OP_RECALCULATE_APME,
    ):
        return {}

    out: dict[str, Any] = {}
    if operation == AttackPathProposal.OP_ENRICH:
        out.update(_sanitize_enrich_fields(payload))
        if not out:
            raise AttackPathProposalError('enrich payload must include at least one field')
        return out

    if operation == AttackPathProposal.OP_DISMISS:
        reason = payload.get('dismiss_reason') or payload.get('reason') or ''
        out['dismiss_reason'] = str(reason)[:MAX_RATIONALE]
        return out

    if operation in (AttackPathProposal.OP_CREATE, AttackPathProposal.OP_UPDATE):
        if 'chain' in payload:
            out['chain'] = _sanitize_chain(payload.get('chain'))
        enrich = _sanitize_enrich_fields(payload)
        if enrich:
            out['review'] = enrich
        if operation == AttackPathProposal.OP_CREATE:
            if not out.get('chain') and not out.get('review'):
                raise AttackPathProposalError('create requires chain and/or review fields')
            for key in ('vulnerability_id', 'subdomain_id'):
                if payload.get(key) is not None:
                    try:
                        out[key] = int(payload[key])
                    except (TypeError, ValueError) as exc:
                        raise AttackPathProposalError(f'{key} must be an integer') from exc
            if payload.get('potential_impact') is not None:
                out['potential_impact'] = str(payload.get('potential_impact'))[:MAX_IMPACT]
            if payload.get('remediation_priority') is not None:
                try:
                    out['remediation_priority'] = int(payload['remediation_priority'])
                except (TypeError, ValueError) as exc:
                    raise AttackPathProposalError(
                        'remediation_priority must be an integer'
                    ) from exc
        elif operation == AttackPathProposal.OP_UPDATE:
            if not out.get('chain') and not out.get('review') and 'potential_impact' not in payload:
                raise AttackPathProposalError(
                    'update requires chain, review fields, and/or potential_impact'
                )
            if payload.get('potential_impact') is not None:
                out['potential_impact'] = str(payload.get('potential_impact'))[:MAX_IMPACT]
        return out

    raise AttackPathProposalError(f'unknown operation {operation}')


def serialize_proposal(proposal: AttackPathProposal) -> dict[str, Any]:
    return {
        'id': proposal.id,
        'project_slug': proposal.project_slug,
        'scan_id': proposal.scan_id,
        'target_path_id': proposal.target_path_id or None,
        'impact_assessment_id': proposal.impact_assessment_id,
        'status': proposal.status,
        'operation': proposal.operation,
        'payload': proposal.payload or {},
        'rationale': proposal.rationale,
        'agent_id': proposal.agent_id or None,
        'result': proposal.result,
        'operator_edited': proposal.operator_edited,
        'created_by_id': proposal.created_by_id,
        'updated_by_id': proposal.updated_by_id,
        'created_at': proposal.created_at.isoformat() if proposal.created_at else None,
        'updated_at': proposal.updated_at.isoformat() if proposal.updated_at else None,
        'approved_at': proposal.approved_at.isoformat() if proposal.approved_at else None,
        'applied_at': proposal.applied_at.isoformat() if proposal.applied_at else None,
    }


def _require_project(project_slug: str) -> None:
    from dashboard.models import Project
    if not project_slug:
        raise AttackPathProposalError('project_slug is required')
    if not Project.objects.filter(slug=project_slug).exists():
        raise AttackPathProposalError('project_slug not found', 404)


def _require_scan_in_project(scan_id: Optional[int], project_slug: str) -> Optional[ScanHistory]:
    if scan_id is None:
        return None
    try:
        scan_id = int(scan_id)
    except (TypeError, ValueError) as exc:
        raise AttackPathProposalError('scan_id must be an integer') from exc
    scan = ScanHistory.objects.filter(pk=scan_id).select_related('domain__project').first()
    if not scan:
        raise AttackPathProposalError('scan_id not found', 404)
    slug = getattr(getattr(getattr(scan, 'domain', None), 'project', None), 'slug', None)
    if slug and slug != project_slug:
        raise AttackPathProposalError('scan_id is outside project_slug', 403)
    return scan


def _assessment_project_slug(assessment: ImpactAssessment) -> Optional[str]:
    scan = assessment.scan_history
    if scan is None and assessment.scan_history_id:
        scan = ScanHistory.objects.filter(pk=assessment.scan_history_id).select_related(
            'domain__project'
        ).first()
    elif scan is not None and not hasattr(getattr(scan, 'domain', None), 'project'):
        scan = ScanHistory.objects.filter(pk=scan.pk).select_related('domain__project').first()
    return getattr(getattr(getattr(scan, 'domain', None), 'project', None), 'slug', None)


def _require_assessment_in_project(
    assessment: ImpactAssessment,
    project_slug: str,
) -> ImpactAssessment:
    slug = _assessment_project_slug(assessment)
    if slug and slug != project_slug:
        raise AttackPathProposalError('Attack path is outside project_slug', 403)
    return assessment


def propose_attack_path(
    *,
    project_slug: str,
    operation: str,
    payload: Any = None,
    rationale: str = '',
    scan_id: Optional[int] = None,
    target_path_id: str = '',
    impact_assessment_id: Optional[int] = None,
    agent_id: str = '',
    user=None,
) -> AttackPathProposal:
    _require_project(project_slug)
    operation = str(operation or '').strip().lower()
    if operation not in OPERATIONS:
        raise AttackPathProposalError(f'operation must be one of {sorted(OPERATIONS)}')
    scan = _require_scan_in_project(scan_id, project_slug)
    if operation in (
        AttackPathProposal.OP_TRIGGER_APME,
        AttackPathProposal.OP_RECALCULATE_APME,
    ) and not scan:
        raise AttackPathProposalError('scan_id is required for APME queue operations')

    target_path_id = str(target_path_id or '').strip()
    if operation in (
        AttackPathProposal.OP_ENRICH,
        AttackPathProposal.OP_UPDATE,
        AttackPathProposal.OP_DISMISS,
    ):
        if not target_path_id and impact_assessment_id is None:
            raise AttackPathProposalError(
                'target_path_id or impact_assessment_id required for this operation'
            )
        assessment = None
        if impact_assessment_id is not None:
            assessment = ImpactAssessment.objects.filter(pk=int(impact_assessment_id)).first()
        if assessment is None and target_path_id:
            assessment = find_assessment_by_path_key(target_path_id)
        if assessment is None:
            raise AttackPathProposalError('Attack path not found', 404)
        _require_assessment_in_project(assessment, project_slug)
        impact_assessment_id = assessment.id
        chain = assessment.potential_attack_chain or {}
        if not target_path_id:
            target_path_id = str(chain.get('apme_path_id') or assessment.id)
        if scan is None and assessment.scan_history_id:
            scan = _require_scan_in_project(assessment.scan_history_id, project_slug)

    normalized = normalize_payload(operation, payload)
    return AttackPathProposal.objects.create(
        project_slug=project_slug,
        scan_id=scan.id if scan else (int(scan_id) if scan_id else None),
        target_path_id=target_path_id,
        impact_assessment_id=impact_assessment_id,
        status=AttackPathProposal.STATUS_PROPOSED,
        operation=operation,
        payload=normalized,
        rationale=(rationale or '')[:2000],
        agent_id=str(agent_id or '')[:128],
        created_by=user if getattr(user, 'pk', None) else None,
        updated_by=user if getattr(user, 'pk', None) else None,
    )


def update_proposal(
    proposal: AttackPathProposal,
    *,
    payload: Any = None,
    rationale: Optional[str] = None,
    user=None,
    is_operator: bool = False,
) -> AttackPathProposal:
    if proposal.status != AttackPathProposal.STATUS_PROPOSED:
        raise AttackPathProposalError('only proposed proposals can be edited')
    if proposal.operator_edited and not is_operator:
        raise AttackPathProposalError(
            'proposal was edited by an operator; agent cannot overwrite',
            403,
        )
    fields = ['updated_at', 'updated_by', 'operator_edited']
    if payload is not None:
        proposal.payload = normalize_payload(proposal.operation, payload)
        fields.append('payload')
    if rationale is not None:
        proposal.rationale = str(rationale)[:2000]
        fields.append('rationale')
    if is_operator:
        proposal.operator_edited = True
    if user and getattr(user, 'pk', None):
        proposal.updated_by = user
    proposal.save(update_fields=fields)
    return proposal


def abort_proposal(proposal: AttackPathProposal, *, user=None) -> AttackPathProposal:
    if proposal.status not in (
        AttackPathProposal.STATUS_PROPOSED,
        AttackPathProposal.STATUS_APPROVED,
    ):
        raise AttackPathProposalError(f'cannot abort proposal in status {proposal.status}')
    proposal.status = AttackPathProposal.STATUS_ABORTED
    if user and getattr(user, 'pk', None):
        proposal.updated_by = user
    proposal.save(update_fields=['status', 'updated_by', 'updated_at'])
    return proposal


def _apply_enrich(assessment: ImpactAssessment, payload: dict, agent_id: str) -> dict:
    chain = dict(assessment.potential_attack_chain or {})
    review = dict(chain.get('agent_path_review') or {})
    for key in (
        'feasibility', 'confidence', 'blocked_reasons', 'missing_prereqs',
        'impact_classes', 'rationale',
    ):
        if key in payload:
            review[key] = payload[key]
    review['enriched_at'] = _utc_now_iso()
    if agent_id:
        review['agent_id'] = agent_id[:128]
    chain['agent_path_review'] = review
    assessment.potential_attack_chain = chain
    update_fields = ['potential_attack_chain', 'updated_at']
    if 'potential_impact' in payload:
        assessment.potential_impact = payload['potential_impact']
        update_fields.append('potential_impact')
    assessment.save(update_fields=update_fields)
    return _path_summary(assessment)


def _apply_update(assessment: ImpactAssessment, payload: dict, agent_id: str) -> dict:
    chain = dict(assessment.potential_attack_chain or {})
    if 'chain' in payload:
        for key, value in (payload['chain'] or {}).items():
            chain[key] = value
    chain['source'] = 'agent'
    if 'review' in payload:
        review = dict(chain.get('agent_path_review') or {})
        review.update(payload['review'])
        review['enriched_at'] = _utc_now_iso()
        if agent_id:
            review['agent_id'] = agent_id[:128]
        chain['agent_path_review'] = review
    assessment.potential_attack_chain = chain
    update_fields = ['potential_attack_chain', 'updated_at']
    if 'potential_impact' in payload:
        assessment.potential_impact = payload['potential_impact']
        update_fields.append('potential_impact')
    assessment.save(update_fields=update_fields)
    return _path_summary(assessment)


def _apply_create(
    *,
    scan_id: Optional[int],
    payload: dict,
    agent_id: str,
) -> dict:
    if not scan_id:
        raise AttackPathProposalError('scan_id is required to create a path')
    scan = ScanHistory.objects.filter(pk=scan_id).first()
    if not scan:
        raise AttackPathProposalError('scan_id not found', 404)

    vuln = None
    subdomain = None
    vuln_id = payload.get('vulnerability_id')
    if vuln_id is not None:
        vuln = Vulnerability.objects.filter(pk=vuln_id, scan_history_id=scan_id).first()
        if not vuln:
            raise AttackPathProposalError('vulnerability_id not found on scan', 404)
        if ImpactAssessment.objects.filter(vulnerability=vuln).exists():
            raise AttackPathProposalError(
                'ImpactAssessment already exists for this vulnerability; use update',
                409,
            )
    subdomain_id = payload.get('subdomain_id')
    if subdomain_id is not None:
        subdomain = Subdomain.objects.filter(pk=subdomain_id, scan_history_id=scan_id).first()
        if not subdomain:
            raise AttackPathProposalError('subdomain_id not found on scan', 404)

    path_id = _new_agent_path_id()
    chain = dict(payload.get('chain') or {})
    chain['apme_path_id'] = path_id
    chain['source'] = 'agent'
    if 'steps' not in chain:
        chain['steps'] = []
    review_src = payload.get('review') or {}
    if review_src:
        review = dict(review_src)
        review['enriched_at'] = _utc_now_iso()
        if agent_id:
            review['agent_id'] = agent_id[:128]
        chain['agent_path_review'] = review

    assessment = ImpactAssessment.objects.create(
        scan_history=scan,
        vulnerability=vuln,
        subdomain=subdomain,
        potential_attack_chain=chain,
        potential_impact=payload.get('potential_impact') or '',
        remediation_priority=int(payload.get('remediation_priority') or 1),
        is_ai_generated=True,
    )
    return _path_summary(assessment)


def _apply_dismiss(assessment: ImpactAssessment, payload: dict) -> dict:
    assessment.dismissed = True
    assessment.dismiss_reason = payload.get('dismiss_reason') or ''
    assessment.save(update_fields=['dismissed', 'dismiss_reason', 'updated_at'])
    return {
        'status': 'dismissed',
        'path_id': (assessment.potential_attack_chain or {}).get('apme_path_id'),
        'impact_assessment_id': assessment.id,
        'dismiss_reason': assessment.dismiss_reason,
    }


def _queue_apme(scan_id: int, *, recalculate: bool) -> dict:
    from reNgine.job_tracker import create_job, update_job
    from reNgine.temporal_client import TemporalClientProvider

    if not ScanHistory.objects.filter(pk=scan_id).exists():
        raise AttackPathProposalError('scan_id not found', 404)

    job_id = create_job()
    workflow = 'RecalculateApmeWorkflow' if recalculate else 'ApmeTaskWorkflow'
    wf_id = (
        f"apme-recalculate-{scan_id}-{job_id}"
        if recalculate
        else f"apme-modeling-{scan_id}-{job_id}"
    )

    async def _start():
        client = await TemporalClientProvider.get_client()
        await client.start_workflow(
            workflow,
            args=[scan_id, job_id],
            id=wf_id,
            task_queue='python-orchestrator-queue',
        )

    loop = asyncio.new_event_loop()
    try:
        loop.run_until_complete(_start())
    except Exception as exc:
        logger.exception('Failed to start APME workflow from proposal')
        update_job(job_id, 'FAILED', 100, f'Failed to start workflow: {exc}')
        raise AttackPathProposalError(f'Failed to start APME workflow: {exc}', 500) from exc
    finally:
        loop.close()

    return {
        'status': 'triggered',
        'task_id': job_id,
        'workflow_id': wf_id,
        'recalculate': recalculate,
    }


def approve_proposal(proposal: AttackPathProposal, *, user=None) -> AttackPathProposal:
    if proposal.status != AttackPathProposal.STATUS_PROPOSED:
        raise AttackPathProposalError(
            f'only proposed proposals can be approved (got {proposal.status})'
        )

    proposal.status = AttackPathProposal.STATUS_APPROVED
    proposal.approved_at = timezone.now()
    if user and getattr(user, 'pk', None):
        proposal.updated_by = user
    proposal.save(update_fields=['status', 'approved_at', 'updated_by', 'updated_at'])

    payload = proposal.payload or {}
    agent_id = proposal.agent_id or ''
    result: dict[str, Any]

    def _rollback_to_proposed() -> None:
        proposal.status = AttackPathProposal.STATUS_PROPOSED
        proposal.approved_at = None
        proposal.save(update_fields=['status', 'approved_at', 'updated_at'])

    try:
        if proposal.operation == AttackPathProposal.OP_TRIGGER_APME:
            result = _queue_apme(int(proposal.scan_id), recalculate=False)
        elif proposal.operation == AttackPathProposal.OP_RECALCULATE_APME:
            result = _queue_apme(int(proposal.scan_id), recalculate=True)
        else:
            assessment = None
            if proposal.impact_assessment_id:
                assessment = ImpactAssessment.objects.filter(
                    pk=proposal.impact_assessment_id
                ).first()
            if assessment is None and proposal.target_path_id:
                assessment = find_assessment_by_path_key(proposal.target_path_id)

            if proposal.operation == AttackPathProposal.OP_CREATE:
                result = _apply_create(
                    scan_id=proposal.scan_id,
                    payload=payload,
                    agent_id=agent_id,
                )
            else:
                if assessment is None:
                    raise AttackPathProposalError('Attack path not found', 404)
                _require_assessment_in_project(assessment, proposal.project_slug)
                if proposal.operation == AttackPathProposal.OP_ENRICH:
                    result = _apply_enrich(assessment, payload, agent_id)
                elif proposal.operation == AttackPathProposal.OP_UPDATE:
                    result = _apply_update(assessment, payload, agent_id)
                elif proposal.operation == AttackPathProposal.OP_DISMISS:
                    result = _apply_dismiss(assessment, payload)
                else:
                    raise AttackPathProposalError(f'unsupported operation {proposal.operation}')
    except AttackPathProposalError:
        _rollback_to_proposed()
        raise
    except Exception as exc:
        logger.exception('Unexpected failure applying attack-path proposal %s', proposal.id)
        _rollback_to_proposed()
        raise AttackPathProposalError(
            f'Failed to apply proposal: {exc}',
            500,
        ) from exc

    proposal.status = AttackPathProposal.STATUS_APPLIED
    proposal.applied_at = timezone.now()
    proposal.result = result
    if result.get('impact_assessment_id'):
        proposal.impact_assessment_id = result['impact_assessment_id']
    if result.get('path_id'):
        proposal.target_path_id = str(result['path_id'])[:128]
    proposal.save(update_fields=[
        'status', 'applied_at', 'result', 'impact_assessment_id',
        'target_path_id', 'updated_at',
    ])
    return proposal


def list_proposals(
    *,
    project_slug: Optional[str] = None,
    scan_id: Optional[int] = None,
    status: Optional[str] = None,
    limit: int = 50,
) -> list[AttackPathProposal]:
    qs = AttackPathProposal.objects.all().order_by('-created_at')
    if project_slug:
        qs = qs.filter(project_slug=project_slug)
    if scan_id is not None:
        qs = qs.filter(scan_id=scan_id)
    if status:
        qs = qs.filter(status=status)
    return list(qs[: max(1, min(int(limit or 50), 100))])
