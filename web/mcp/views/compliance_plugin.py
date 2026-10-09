"""MCP wrappers for Compliance Assessment (gated)."""
from __future__ import annotations

import json
import logging
import os

from rest_framework import status
from rest_framework.response import Response

from mcp.plugins_gate import gate_plugin
from mcp.views.base import McpDataView
from mcp.views.dispatch import McpIntelDispatchView
from reNgine.definitions import INTERNAL_ERROR_MESSAGE

logger = logging.getLogger(__name__)

SLUG = 'compliance_assessment'
BACKEND = 'plugins_data.compliance_assessment.backend'


class McpComplianceListAssessmentsView(McpDataView):
    def get(self, request):
        err = gate_plugin(SLUG, backend_module=BACKEND)
        if err:
            return err
        from plugins_data.compliance_assessment.backend.models import ComplianceAssessment
        from plugins_data.compliance_assessment.backend.serializers import (
            ComplianceAssessmentListSerializer,
        )

        qs = ComplianceAssessment.objects.select_related('scan_history__domain').order_by(
            '-created_at',
        )
        scan_id = request.query_params.get('scan_id')
        framework = request.query_params.get('framework')
        if scan_id:
            qs = qs.filter(scan_history_id=scan_id)
        if framework:
            qs = qs.filter(framework=framework)
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
            'results': ComplianceAssessmentListSerializer(page, many=True).data,
        })


class McpComplianceGetAssessmentView(McpDataView):
    def get(self, request, pk):
        err = gate_plugin(SLUG, backend_module=BACKEND)
        if err:
            return err
        from plugins_data.compliance_assessment.backend.models import ComplianceAssessment
        from plugins_data.compliance_assessment.backend.serializers import (
            ComplianceAssessmentSerializer,
        )

        try:
            assessment = ComplianceAssessment.objects.prefetch_related(
                'controls__evidence',
            ).get(pk=pk)
        except ComplianceAssessment.DoesNotExist:
            return Response({'error': f'Compliance assessment {pk} not found.'}, status=404)
        return Response(ComplianceAssessmentSerializer(assessment).data)


class McpComplianceListControlsView(McpDataView):
    def get(self, request):
        err = gate_plugin(SLUG, backend_module=BACKEND)
        if err:
            return err
        from plugins_data.compliance_assessment.backend.models import ControlResult
        from plugins_data.compliance_assessment.backend.serializers import (
            ControlResultSerializer,
        )

        assessment_id = request.query_params.get('assessment_id')
        if not assessment_id:
            return Response(
                {'error': 'assessment_id query param is required.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        qs = ControlResult.objects.prefetch_related('evidence').filter(
            assessment_id=assessment_id,
        ).order_by('section', 'control_id')
        result_f = request.query_params.get('result')
        if result_f:
            qs = qs.filter(result=result_f)
        try:
            limit = min(int(request.query_params.get('limit', 100)), 500)
        except (TypeError, ValueError):
            limit = 100
        try:
            offset = max(int(request.query_params.get('offset', 0)), 0)
        except (TypeError, ValueError):
            offset = 0
        total = qs.count()
        page = qs[offset:offset + limit]
        return Response({
            'count': total,
            'results': ControlResultSerializer(page, many=True).data,
        })


class McpComplianceGetReportView(McpDataView):
    """Return attestation JSON when available (agent-friendly); note HTML/PDF paths."""

    def get(self, request, pk):
        err = gate_plugin(SLUG, backend_module=BACKEND)
        if err:
            return err
        from plugins_data.compliance_assessment.backend.models import ComplianceAssessment
        from plugins_data.compliance_assessment.backend.serializers import (
            ComplianceAssessmentListSerializer,
        )

        try:
            assessment = ComplianceAssessment.objects.get(pk=pk)
        except ComplianceAssessment.DoesNotExist:
            return Response({'error': f'Compliance assessment {pk} not found.'}, status=404)

        attestation = None
        path = assessment.attestation_path
        if path and os.path.exists(path):
            try:
                with open(path, 'r', encoding='utf-8') as fh:
                    attestation = json.load(fh)
            except Exception as exc:
                logger.warning('Failed to read attestation for %s: %s', pk, exc)
                attestation = {'error': INTERNAL_ERROR_MESSAGE}

        meta = ComplianceAssessmentListSerializer(assessment).data
        return Response({
            'assessment': meta,
            'attestation': attestation,
            'html_report_available': bool(
                assessment.html_report_path and os.path.exists(assessment.html_report_path or ''),
            ),
            'pdf_report_available': bool(
                assessment.pdf_report_path and os.path.exists(assessment.pdf_report_path or ''),
            ),
            'note': 'HTML/PDF downloads remain in the UI; MCP returns attestation JSON when present.',
        })


class McpComplianceEnrichControlView(McpIntelDispatchView):
    def post(self, request, pk):
        err = gate_plugin(SLUG, backend_module=BACKEND)
        if err:
            return err
        from plugins_data.compliance_assessment.backend.models import ControlResult
        from plugins_data.compliance_assessment.backend.views import ControlResultViewSet

        try:
            ControlResult.objects.get(pk=pk)
        except ControlResult.DoesNotExist:
            return Response({'error': f'Control result {pk} not found.'}, status=404)

        viewset = ControlResultViewSet()
        viewset.request = request
        viewset.format_kwarg = None
        viewset.kwargs = {'pk': pk}
        viewset.action = 'enrich'
        return viewset.enrich(request, pk=pk)
