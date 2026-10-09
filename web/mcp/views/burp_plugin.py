"""MCP wrappers for Burp Suite Integration (gated)."""
from __future__ import annotations

import logging

from rest_framework import status
from rest_framework.response import Response

from mcp.plugins_gate import gate_plugin
from mcp.views.base import McpDataView
from mcp.views.dispatch import McpIntelDispatchView

logger = logging.getLogger(__name__)

SLUG = 'burpsuite_integration'
BACKEND = 'plugins_data.burpsuite_integration.backend'


class McpBurpListIssuesView(McpDataView):
    def get(self, request):
        err = gate_plugin(SLUG, backend_module=BACKEND)
        if err:
            return err
        from plugins_data.burpsuite_integration.backend.models import BurpIssue
        from plugins_data.burpsuite_integration.backend.serializers import BurpIssueSerializer

        qs = BurpIssue.objects.all().order_by('-id')
        unmatched = (request.query_params.get('unmatched') or '').lower()
        if unmatched == 'true':
            qs = qs.filter(is_correlated=True, linked_vulnerability_id__isnull=True)
        severity = request.query_params.get('severity')
        if severity is not None:
            try:
                qs = qs.filter(severity=int(severity))
            except (TypeError, ValueError):
                return Response(
                    {'error': 'severity must be an integer 0-4'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        q = (request.query_params.get('q') or '').strip()
        if q:
            from django.db.models import Q
            qs = qs.filter(Q(name__icontains=q) | Q(host__icontains=q))

        try:
            limit = min(int(request.query_params.get('limit', 50)), 200)
        except (TypeError, ValueError):
            limit = 50
        try:
            offset = max(int(request.query_params.get('offset', 0)), 0)
        except (TypeError, ValueError):
            offset = 0
        total = qs.count()
        page = qs[offset:offset + limit]
        return Response({
            'count': total,
            'results': BurpIssueSerializer(page, many=True).data,
        })


class McpBurpGetIssueView(McpDataView):
    def get(self, request, pk):
        err = gate_plugin(SLUG, backend_module=BACKEND)
        if err:
            return err
        from plugins_data.burpsuite_integration.backend.models import BurpIssue
        from plugins_data.burpsuite_integration.backend.serializers import BurpIssueSerializer

        try:
            issue = BurpIssue.objects.get(pk=pk)
        except BurpIssue.DoesNotExist:
            return Response({'error': f'Burp issue {pk} not found.'}, status=404)
        return Response(BurpIssueSerializer(issue).data)


class McpBurpMetricsView(McpDataView):
    def get(self, request):
        err = gate_plugin(SLUG, backend_module=BACKEND)
        if err:
            return err
        from plugins_data.burpsuite_integration.backend.views import BurpIssueViewSet

        viewset = BurpIssueViewSet()
        viewset.request = request
        viewset.format_kwarg = None
        viewset.action = 'metrics'
        return viewset.metrics(request)


class McpBurpListSyncLogsView(McpDataView):
    def get(self, request):
        err = gate_plugin(SLUG, backend_module=BACKEND)
        if err:
            return err
        from plugins_data.burpsuite_integration.backend.models import BurpSyncLog
        from plugins_data.burpsuite_integration.backend.serializers import BurpSyncLogSerializer

        qs = BurpSyncLog.objects.all().order_by('-id')
        try:
            limit = min(int(request.query_params.get('limit', 50)), 200)
        except (TypeError, ValueError):
            limit = 50
        try:
            offset = max(int(request.query_params.get('offset', 0)), 0)
        except (TypeError, ValueError):
            offset = 0
        total = qs.count()
        page = qs[offset:offset + limit]
        return Response({
            'count': total,
            'results': BurpSyncLogSerializer(page, many=True).data,
        })


class McpBurpHealthView(McpDataView):
    def get(self, request):
        err = gate_plugin(SLUG, backend_module=BACKEND)
        if err:
            return err
        from plugins_data.burpsuite_integration.backend.views import BurpHealthView

        view = BurpHealthView()
        view.request = request
        view.format_kwarg = None
        return view.get(request)


class McpBurpSyncImportView(McpIntelDispatchView):
    def post(self, request):
        err = gate_plugin(SLUG, backend_module=BACKEND)
        if err:
            return err
        from plugins_data.burpsuite_integration.backend.views import BurpManualSyncView

        view = BurpManualSyncView()
        view.request = request
        view.format_kwarg = None
        return view.post(request)
