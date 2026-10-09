"""MCP views for SAFE PoC attempts (propose → approve → execute)."""
from __future__ import annotations

import logging

from rest_framework.response import Response

from api.permissions import IsPenetrationTester
from mcp.models import SafePocAttempt
from mcp.operator_gate import resolve_is_operator
from mcp.safe_poc import (
    PROPOSE_APPROVE_MSG,
    SafePocError,
    abort_attempt,
    approve_attempt,
    list_attempts,
    propose_attempt,
    serialize_attempt,
    update_attempt,
)
from mcp.views.base import McpDataView

logger = logging.getLogger(__name__)


class McpProposeSafePocView(McpDataView):
    http_method_names = ['post', 'options']
    permission_classes = [IsPenetrationTester]

    def post(self, request):
        data = request.data or {}
        try:
            attempt = propose_attempt(
                vulnerability_id=data.get('vulnerability_id'),
                template_id=data.get('template_id') or '',
                params=data.get('params'),
                rationale=data.get('rationale') or '',
                project_slug=data.get('project_slug') or '',
                scan_id=data.get('scan_id'),
                agent_id=data.get('agent_id') or '',
                user=request.user,
            )
        except (SafePocError, TypeError, ValueError) as exc:
            status = getattr(exc, 'status', 400)
            logger.warning(
                'safe_poc propose failed status=%s err=%s vuln=%s template=%s',
                status,
                exc,
                data.get('vulnerability_id'),
                data.get('template_id'),
            )
            return Response({'error': str(exc)}, status=status)
        logger.info(
            'safe_poc proposed id=%s vuln=%s template=%s user=%s',
            attempt.id,
            attempt.vulnerability_id,
            attempt.template_id,
            getattr(request.user, 'pk', None),
        )
        return Response(serialize_attempt(attempt), status=201)


class McpListSafePocsView(McpDataView):
    permission_classes = [IsPenetrationTester]

    def get(self, request):
        project_slug = request.query_params.get('project_slug') or request.query_params.get('project')
        status = request.query_params.get('status')
        scan_id = request.query_params.get('scan_id')
        vulnerability_id = request.query_params.get('vulnerability_id')
        limit = request.query_params.get('limit') or 50
        try:
            scan_id_int = int(scan_id) if scan_id not in (None, '') else None
            vuln_id_int = (
                int(vulnerability_id) if vulnerability_id not in (None, '') else None
            )
            limit_int = int(limit)
        except (TypeError, ValueError):
            return Response(
                {'error': 'scan_id, vulnerability_id, and limit must be integers'},
                status=400,
            )
        rows = list_attempts(
            project_slug=project_slug,
            scan_id=scan_id_int,
            vulnerability_id=vuln_id_int,
            status=status,
            limit=limit_int,
        )
        return Response({
            'count': len(rows),
            'attempts': [serialize_attempt(a) for a in rows],
        })


class McpGetSafePocView(McpDataView):
    permission_classes = [IsPenetrationTester]

    def get(self, request, pk):
        attempt = SafePocAttempt.objects.filter(pk=pk).first()
        if not attempt:
            return Response({'error': 'Not found'}, status=404)
        return Response(serialize_attempt(attempt))


class McpUpdateSafePocView(McpDataView):
    http_method_names = ['post', 'options']
    permission_classes = [IsPenetrationTester]

    def post(self, request, pk):
        attempt = SafePocAttempt.objects.filter(pk=pk).first()
        if not attempt:
            return Response({'error': 'Not found'}, status=404)
        data = request.data or {}
        # MCP agents cannot claim operator via body; JWT/UI only.
        is_operator = resolve_is_operator(request)
        try:
            updated = update_attempt(
                attempt,
                template_id=data.get('template_id'),
                params=data['params'] if 'params' in data else None,
                rationale=data['rationale'] if 'rationale' in data else None,
                user=request.user,
                is_operator=is_operator,
            )
        except SafePocError as exc:
            logger.warning(
                'safe_poc update failed id=%s status=%s err=%s is_operator=%s',
                pk,
                exc.status,
                exc,
                is_operator,
            )
            return Response({'error': str(exc)}, status=exc.status)
        logger.info(
            'safe_poc updated id=%s is_operator=%s operator_edited=%s',
            updated.id,
            is_operator,
            updated.operator_edited,
        )
        return Response(serialize_attempt(updated))


class McpApproveSafePocView(McpDataView):
    http_method_names = ['post', 'options']
    permission_classes = [IsPenetrationTester]

    def post(self, request, pk):
        attempt = SafePocAttempt.objects.filter(pk=pk).first()
        if not attempt:
            return Response({'error': 'Not found'}, status=404)
        try:
            approved = approve_attempt(attempt, user=request.user)
        except SafePocError as exc:
            logger.warning(
                'safe_poc approve failed id=%s status=%s err=%s',
                pk,
                exc.status,
                exc,
            )
            return Response({'error': str(exc)}, status=exc.status)
        logger.info(
            'safe_poc approved id=%s status=%s workflow=%s user=%s',
            approved.id,
            approved.status,
            approved.temporal_workflow_id,
            getattr(request.user, 'pk', None),
        )
        return Response(serialize_attempt(approved))


class McpAbortSafePocView(McpDataView):
    http_method_names = ['post', 'options']
    permission_classes = [IsPenetrationTester]

    def post(self, request, pk):
        attempt = SafePocAttempt.objects.filter(pk=pk).first()
        if not attempt:
            return Response({'error': 'Not found'}, status=404)
        try:
            aborted = abort_attempt(attempt, user=request.user)
        except SafePocError as exc:
            logger.warning(
                'safe_poc abort failed id=%s status=%s err=%s',
                pk,
                exc.status,
                exc,
            )
            return Response({'error': str(exc)}, status=exc.status)
        logger.info(
            'safe_poc aborted id=%s user=%s',
            aborted.id,
            getattr(request.user, 'pk', None),
        )
        return Response(serialize_attempt(aborted))


class McpRunSafePocDirectView(McpDataView):
    """Direct execute is forbidden — returns 410 with propose→approve hint."""

    http_method_names = ['post', 'options']
    permission_classes = [IsPenetrationTester]

    def post(self, request):
        logger.warning(
            'safe_poc direct run rejected (410) user=%s',
            getattr(request.user, 'pk', None),
        )
        return Response(
            {
                'error': PROPOSE_APPROVE_MSG,
                'tool': 'r3ngine_propose_safe_poc',
            },
            status=410,
        )
