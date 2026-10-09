"""MCP views for attack-path proposals and path detail (propose → approve)."""
from __future__ import annotations

import logging

from rest_framework.response import Response

from api.permissions import IsPenetrationTester
from mcp.attack_path_proposals import (
    AttackPathProposalError,
    abort_proposal,
    approve_proposal,
    find_assessment_by_path_key,
    list_proposals,
    propose_attack_path,
    serialize_proposal,
    update_proposal,
)
from mcp.models import AttackPathProposal
from mcp.operator_gate import resolve_is_operator
from mcp.views.base import McpDataView
from mcp.views.validation import serialize_path_summary
from startScan.models import Vulnerability

logger = logging.getLogger(__name__)


class McpGetAttackPathView(McpDataView):
    """GET /api/mcp/attack-paths/<path_id>/ — full chain + linked vuln summary."""

    def get(self, request, path_id):
        assessment = find_assessment_by_path_key(path_id)
        if assessment is None:
            return Response({'error': 'Attack path not found'}, status=404)
        body = serialize_path_summary(assessment)
        chain = assessment.potential_attack_chain or {}
        body['chain'] = chain
        body['scan_id'] = assessment.scan_history_id
        body['subdomain_id'] = assessment.subdomain_id
        body['dismiss_reason'] = assessment.dismiss_reason
        body['is_ai_generated'] = bool(assessment.is_ai_generated)
        body['updated_at'] = (
            assessment.updated_at.isoformat() if assessment.updated_at else None
        )
        vuln = None
        if assessment.vulnerability_id:
            vuln = Vulnerability.objects.filter(pk=assessment.vulnerability_id).first()
        if vuln:
            body['vulnerability'] = {
                'id': vuln.id,
                'name': vuln.name,
                'severity': vuln.severity,
                'http_url': vuln.http_url,
                'validation_status': getattr(vuln, 'validation_status', None),
            }
        else:
            body['vulnerability'] = None
        return Response(body)


class McpProposeAttackPathView(McpDataView):
    http_method_names = ['post', 'options']
    permission_classes = [IsPenetrationTester]

    def post(self, request):
        data = request.data or {}
        try:
            proposal = propose_attack_path(
                project_slug=data.get('project_slug') or '',
                operation=data.get('operation') or '',
                payload=data.get('payload'),
                rationale=data.get('rationale') or '',
                scan_id=data.get('scan_id'),
                target_path_id=data.get('target_path_id') or data.get('path_id') or '',
                impact_assessment_id=data.get('impact_assessment_id'),
                agent_id=data.get('agent_id') or '',
                user=request.user,
            )
        except AttackPathProposalError as exc:
            return Response({'error': str(exc)}, status=exc.status)
        return Response(serialize_proposal(proposal), status=201)


class McpListAttackPathProposalsView(McpDataView):
    def get(self, request):
        project_slug = request.query_params.get('project_slug') or request.query_params.get('project')
        status = request.query_params.get('status')
        scan_id = request.query_params.get('scan_id')
        limit = request.query_params.get('limit') or 50
        try:
            scan_id_int = int(scan_id) if scan_id is not None and scan_id != '' else None
            limit_int = int(limit)
        except (TypeError, ValueError):
            return Response({'error': 'scan_id and limit must be integers'}, status=400)
        rows = list_proposals(
            project_slug=project_slug,
            scan_id=scan_id_int,
            status=status,
            limit=limit_int,
        )
        return Response({
            'count': len(rows),
            'proposals': [serialize_proposal(p) for p in rows],
        })


class McpGetAttackPathProposalView(McpDataView):
    def get(self, request, pk):
        proposal = AttackPathProposal.objects.filter(pk=pk).first()
        if not proposal:
            return Response({'error': 'Not found'}, status=404)
        return Response(serialize_proposal(proposal))


class McpUpdateAttackPathProposalView(McpDataView):
    http_method_names = ['post', 'options']
    permission_classes = [IsPenetrationTester]

    def post(self, request, pk):
        proposal = AttackPathProposal.objects.filter(pk=pk).first()
        if not proposal:
            return Response({'error': 'Not found'}, status=404)
        data = request.data or {}
        # MCP agents cannot claim operator via body; JWT/UI only.
        is_operator = resolve_is_operator(request)
        try:
            updated = update_proposal(
                proposal,
                payload=data['payload'] if 'payload' in data else None,
                rationale=data['rationale'] if 'rationale' in data else None,
                user=request.user,
                is_operator=is_operator,
            )
        except AttackPathProposalError as exc:
            logger.warning(
                'attack_path proposal update failed id=%s status=%s err=%s is_operator=%s',
                pk,
                exc.status,
                exc,
                is_operator,
            )
            return Response({'error': str(exc)}, status=exc.status)
        logger.info(
            'attack_path proposal updated id=%s is_operator=%s operator_edited=%s',
            updated.id,
            is_operator,
            updated.operator_edited,
        )
        return Response(serialize_proposal(updated))


class McpApproveAttackPathProposalView(McpDataView):
    http_method_names = ['post', 'options']
    permission_classes = [IsPenetrationTester]

    def post(self, request, pk):
        proposal = AttackPathProposal.objects.filter(pk=pk).first()
        if not proposal:
            return Response({'error': 'Not found'}, status=404)
        try:
            applied = approve_proposal(proposal, user=request.user)
        except AttackPathProposalError as exc:
            return Response({'error': str(exc)}, status=exc.status)
        return Response(serialize_proposal(applied))


class McpAbortAttackPathProposalView(McpDataView):
    http_method_names = ['post', 'options']
    permission_classes = [IsPenetrationTester]

    def post(self, request, pk):
        proposal = AttackPathProposal.objects.filter(pk=pk).first()
        if not proposal:
            return Response({'error': 'Not found'}, status=404)
        try:
            aborted = abort_proposal(proposal, user=request.user)
        except AttackPathProposalError as exc:
            return Response({'error': str(exc)}, status=exc.status)
        return Response(serialize_proposal(aborted))
