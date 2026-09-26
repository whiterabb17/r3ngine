"""SAFE vulnerability / attack-path enrichment and validation for MCP agents.

Never accepts exploit payloads or execution recipes. Writes reviewable metadata only.
"""
from __future__ import annotations

import re
from datetime import timezone as dt_timezone
from typing import Any

from django.db.models import Q
from django.utils import timezone
from rest_framework.response import Response

from api.permissions import IsPenetrationTester
from mcp.views.base import McpDataView
from mcp.views.detail import serialize_vulnerability_detail
from mcp.views.read import serialize_vulnerability
from startScan.models import ImpactAssessment, Vulnerability


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
VALIDATION_VERDICTS = frozenset({'likely_tp', 'likely_fp', 'uncertain'})
PATH_FEASIBILITY = frozenset({'plausible', 'stretched', 'fantasy'})
ALLOWED_STATUSES = frozenset({
    'new', 'verified', 'needs_review', 'false_positive', 'accepted_risk', 'resolved',
})
# Agent may freely set these; verified requires confirm_verified + confidence gate.
AGENT_FREE_STATUSES = frozenset({'needs_review', 'false_positive', 'new'})
VERIFIED_MIN_CONFIDENCE = 0.8

_FORBIDDEN_KEY_RE = re.compile(
    r'(payload|exploit_code|exploit_body|shellcode|metasploit|msfvenom|'
    r'reverse_shell|bind_shell|weaponiz)',
    re.I,
)
_RELATED_CAP = 20


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


def serialize_cve_signal(cve) -> dict[str, Any]:
    """Public-exploit *existence* metadata only — never exploit body/content."""
    public = cve.public_exploits if isinstance(cve.public_exploits, list) else []
    sources = []
    for entry in public[:20]:
        if not isinstance(entry, dict):
            continue
        sources.append({
            'name': (entry.get('name') or entry.get('title') or '')[:200],
            'source': (entry.get('source') or entry.get('type') or '')[:100],
            'url': (entry.get('url') or entry.get('html_url') or '')[:500] or None,
        })
    return {
        'cve': cve.name,
        'is_cisa_kev': bool(cve.is_cisa_kev),
        'cvss_v31_base_score': cve.cvss_v31_base_score,
        'attack_vector': cve.attack_vector,
        'attack_complexity': cve.attack_complexity,
        'privileges_required': cve.privileges_required,
        'user_interaction': cve.user_interaction,
        'confidentiality_impact': cve.confidentiality_impact,
        'integrity_impact': cve.integrity_impact,
        'availability_impact': cve.availability_impact,
        'epss_score': cve.epss_score,
        'epss_percentile': cve.epss_percentile,
        'is_poc': bool(cve.is_poc),
        'public_exploit_count': len(public),
        'public_exploit_sources': sources,
        'patching_priority': cve.patching_priority,
    }


def serialize_path_summary(assessment: ImpactAssessment) -> dict[str, Any]:
    chain = assessment.potential_attack_chain or {}
    return {
        'path_id': chain.get('apme_path_id'),
        'impact_assessment_id': assessment.id,
        'risk': chain.get('risk', 'unknown'),
        'score': chain.get('score', 0.0),
        'step_count': len(chain.get('steps') or []),
        'steps': chain.get('steps') or [],
        'potential_impact': assessment.potential_impact,
        'remediation_priority': assessment.remediation_priority,
        'vulnerability_id': assessment.vulnerability_id,
        'agent_path_review': chain.get('agent_path_review') or None,
        'dismissed': bool(assessment.dismissed),
    }


def build_analyze_context(vuln: Vulnerability) -> dict[str, Any]:
    detail = serialize_vulnerability_detail(vuln)
    cves = list(vuln.cve_ids.all())
    cve_signals = [serialize_cve_signal(c) for c in cves]

    related_qs = Vulnerability.objects.filter(scan_history_id=vuln.scan_history_id)
    if vuln.subdomain_id and vuln.endpoint_id:
        related_qs = related_qs.filter(
            Q(subdomain_id=vuln.subdomain_id) | Q(endpoint_id=vuln.endpoint_id)
        )
    elif vuln.subdomain_id:
        related_qs = related_qs.filter(subdomain_id=vuln.subdomain_id)
    elif vuln.endpoint_id:
        related_qs = related_qs.filter(endpoint_id=vuln.endpoint_id)
    related_qs = related_qs.exclude(pk=vuln.pk).order_by('-severity', '-id')[:_RELATED_CAP]
    related = [serialize_vulnerability(r) for r in related_qs]

    paths = []
    path_q = Q(vulnerability_id=vuln.pk)
    if vuln.subdomain_id:
        path_q |= Q(subdomain_id=vuln.subdomain_id)
    assessments = (
        ImpactAssessment.objects
        .filter(scan_history_id=vuln.scan_history_id)
        .filter(path_q)
        .exclude(potential_attack_chain__isnull=True)
        .exclude(potential_attack_chain={})
        .order_by('-remediation_priority', '-id')[:_RELATED_CAP]
    )
    for assessment in assessments:
        chain = assessment.potential_attack_chain or {}
        if not chain.get('apme_path_id') and assessment.vulnerability_id != vuln.pk:
            continue
        paths.append(serialize_path_summary(assessment))

    return {
        'vulnerability': {
            **detail,
            'agent_enrichment': vuln.agent_enrichment or {},
            'validation_status': vuln.validation_status,
            'validation_confidence': vuln.validation_confidence,
            'validation_reason': vuln.validation_reason,
        },
        'cve_signals': cve_signals,
        'related_vulnerabilities': related,
        'linked_attack_paths': paths,
        'safety': {
            'mode': 'interpret_enrich_only',
            'forbids': [
                'payload_craft',
                'exploit_execution',
                'offensive_command_recipes',
            ],
        },
    }


class McpAnalyzeVulnerabilityView(McpDataView):
    """Packaged SAFE analysis context for one vulnerability."""

    def get(self, request, pk):
        row = (
            Vulnerability.objects
            .select_related('subdomain', 'endpoint', 'target_domain', 'scan_history')
            .prefetch_related('cve_ids', 'cwe_ids', 'tags', 'references')
            .filter(pk=pk)
            .first()
        )
        if not row:
            return Response({'error': 'Not found'}, status=404)
        return Response(build_analyze_context(row))


class McpEnrichVulnerabilityView(McpDataView):
    http_method_names = ['patch', 'options']
    permission_classes = [IsPenetrationTester]

    def patch(self, request, pk):
        row = Vulnerability.objects.filter(pk=pk).first()
        if not row:
            return Response({'error': 'Not found'}, status=404)

        forbidden = _reject_forbidden_keys(request.data)
        if forbidden:
            return Response({'error': forbidden}, status=400)

        data = request.data or {}
        enrichment = dict(row.agent_enrichment or {})

        classes = _normalize_impact_classes(data.get('impact_classes'))
        if data.get('impact_classes') is not None and classes is None:
            return Response({'error': 'impact_classes must be a list of known class names'}, status=400)
        if classes is not None:
            enrichment['impact_classes'] = classes

        verdict = data.get('validation_verdict')
        if verdict is not None:
            verdict = str(verdict).strip().lower()
            if verdict not in VALIDATION_VERDICTS:
                return Response({'error': f'validation_verdict must be one of {sorted(VALIDATION_VERDICTS)}'}, status=400)
            enrichment['validation_verdict'] = verdict

        confidence = _clamp_confidence(data.get('confidence'))
        if data.get('confidence') is not None and confidence is None:
            return Response({'error': 'confidence must be a number'}, status=400)
        if confidence is not None:
            enrichment['confidence'] = confidence

        if 'rationale' in data:
            enrichment['rationale'] = str(data.get('rationale') or '')[:4000]

        if 'related_vuln_ids' in data:
            raw_ids = data.get('related_vuln_ids') or []
            if not isinstance(raw_ids, list):
                return Response({'error': 'related_vuln_ids must be a list'}, status=400)
            ids = []
            for item in raw_ids[:50]:
                try:
                    ids.append(int(item))
                except (TypeError, ValueError):
                    return Response({'error': 'related_vuln_ids must be integers'}, status=400)
            enrichment['related_vuln_ids'] = ids

        if 'cve_signals' in data:
            signals = data.get('cve_signals')
            if signals is not None and not isinstance(signals, (dict, list)):
                return Response({'error': 'cve_signals must be an object or list'}, status=400)
            enrichment['cve_signals'] = signals

        if 'attck_techniques' in data:
            techs = data.get('attck_techniques') or []
            if not isinstance(techs, list):
                return Response({'error': 'attck_techniques must be a list'}, status=400)
            enrichment['attck_techniques'] = [str(t)[:64] for t in techs[:40]]

        enrichment['enriched_at'] = _utc_now_iso()
        if data.get('agent_id'):
            enrichment['agent_id'] = str(data.get('agent_id'))[:128]

        row.agent_enrichment = enrichment
        row.save(update_fields=['agent_enrichment'])
        return Response({
            'id': row.id,
            'agent_enrichment': row.agent_enrichment,
        })


class McpValidateVulnerabilityView(McpDataView):
    http_method_names = ['patch', 'options']
    permission_classes = [IsPenetrationTester]

    def patch(self, request, pk):
        row = Vulnerability.objects.filter(pk=pk).first()
        if not row:
            return Response({'error': 'Not found'}, status=404)

        forbidden = _reject_forbidden_keys(request.data)
        if forbidden:
            return Response({'error': forbidden}, status=400)

        data = request.data or {}
        status_raw = data.get('validation_status')
        if not status_raw:
            return Response({'error': 'validation_status is required'}, status=400)
        status_val = str(status_raw).strip().lower()
        if status_val not in ALLOWED_STATUSES:
            return Response({'error': f'validation_status must be one of {sorted(ALLOWED_STATUSES)}'}, status=400)

        confidence = _clamp_confidence(data.get('validation_confidence', data.get('confidence')))
        confirm_verified = bool(data.get('confirm_verified'))

        if status_val == 'verified':
            if not confirm_verified:
                return Response({
                    'error': 'verified requires confirm_verified=true',
                }, status=400)
            if confidence is None or confidence < VERIFIED_MIN_CONFIDENCE:
                return Response({
                    'error': f'verified requires validation_confidence >= {VERIFIED_MIN_CONFIDENCE}',
                }, status=400)
        elif status_val not in AGENT_FREE_STATUSES and status_val not in ('accepted_risk', 'resolved'):
            return Response({'error': f'status {status_val} is not writable via MCP'}, status=400)

        reason = data.get('validation_reason')
        if reason is not None:
            row.validation_reason = str(reason)[:4000]
        row.validation_status = status_val
        if confidence is not None:
            row.validation_confidence = confidence
        row.save(update_fields=['validation_status', 'validation_confidence', 'validation_reason'])

        return Response({
            'id': row.id,
            'validation_status': row.validation_status,
            'validation_confidence': row.validation_confidence,
            'validation_reason': row.validation_reason,
        })


class McpEnrichAttackPathView(McpDataView):
    http_method_names = ['patch', 'options']
    permission_classes = [IsPenetrationTester]

    def patch(self, request, path_id):
        forbidden = _reject_forbidden_keys(request.data)
        if forbidden:
            return Response({'error': forbidden}, status=400)

        path_key = str(path_id).strip()
        if not path_key:
            return Response({'error': 'path_id is required'}, status=400)

        assessment = None
        candidates = (
            ImpactAssessment.objects
            .exclude(potential_attack_chain__isnull=True)
            .exclude(potential_attack_chain={})
            .order_by('-id')
        )
        # Prefer exact apme_path_id match; also allow ImpactAssessment pk.
        if path_key.isdigit():
            assessment = ImpactAssessment.objects.filter(pk=int(path_key)).first()
        if assessment is None:
            for row in candidates.iterator(chunk_size=200):
                chain = row.potential_attack_chain or {}
                if str(chain.get('apme_path_id') or '') == path_key:
                    assessment = row
                    break
        if assessment is None:
            return Response({'error': 'Attack path not found'}, status=404)

        data = request.data or {}
        chain = dict(assessment.potential_attack_chain or {})
        review = dict(chain.get('agent_path_review') or {})

        feasibility = data.get('feasibility')
        if feasibility is not None:
            feasibility = str(feasibility).strip().lower()
            if feasibility not in PATH_FEASIBILITY:
                return Response({
                    'error': f'feasibility must be one of {sorted(PATH_FEASIBILITY)}',
                }, status=400)
            review['feasibility'] = feasibility

        confidence = _clamp_confidence(data.get('confidence'))
        if data.get('confidence') is not None and confidence is None:
            return Response({'error': 'confidence must be a number'}, status=400)
        if confidence is not None:
            review['confidence'] = confidence

        if 'blocked_reasons' in data:
            reasons = data.get('blocked_reasons') or []
            if not isinstance(reasons, list):
                return Response({'error': 'blocked_reasons must be a list'}, status=400)
            review['blocked_reasons'] = [str(r)[:500] for r in reasons[:40]]

        if 'missing_prereqs' in data:
            prereqs = data.get('missing_prereqs') or []
            if not isinstance(prereqs, list):
                return Response({'error': 'missing_prereqs must be a list'}, status=400)
            review['missing_prereqs'] = [str(r)[:500] for r in prereqs[:40]]

        classes = _normalize_impact_classes(data.get('impact_classes'))
        if data.get('impact_classes') is not None and classes is None:
            return Response({'error': 'impact_classes must be a list of known class names'}, status=400)
        if classes is not None:
            review['impact_classes'] = classes

        if 'rationale' in data:
            review['rationale'] = str(data.get('rationale') or '')[:4000]

        review['enriched_at'] = _utc_now_iso()
        if data.get('agent_id'):
            review['agent_id'] = str(data.get('agent_id'))[:128]

        chain['agent_path_review'] = review
        assessment.potential_attack_chain = chain
        update_fields = ['potential_attack_chain', 'updated_at']
        if 'potential_impact' in data and data.get('potential_impact') is not None:
            assessment.potential_impact = str(data.get('potential_impact'))[:8000]
            update_fields.append('potential_impact')
        assessment.save(update_fields=update_fields)

        return Response(serialize_path_summary(assessment))
