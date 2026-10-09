"""MCP wrappers for the Active Directory Intelligence plugin (gated)."""
from __future__ import annotations

import base64
import json
import logging
import os
import tempfile

from rest_framework import status
from rest_framework.response import Response

from mcp.plugins_gate import McpPluginUnavailable, require_plugin
from mcp.views.base import McpDataView
from mcp.views.dispatch import McpIntelDispatchView
from reNgine.definitions import INTERNAL_ERROR_MESSAGE

logger = logging.getLogger(__name__)

AD_SLUG = 'active_directory'


def _require_ad():
    return require_plugin(AD_SLUG, backend_module='plugins_data.active_directory.backend')


def _assessment_qs(request):
    from django.db import models
    from plugins_data.active_directory.backend.models import ADAssessment

    user = request.user
    if user.is_staff or user.is_superuser:
        return ADAssessment.objects.all()
    return ADAssessment.objects.filter(
        models.Q(created_by=user) | models.Q(created_by__isnull=True)
    )


class AdAssessmentNotFound(Exception):
    def __init__(self, pk):
        self.pk = pk
        self.detail = {'error': f'AD assessment {pk} not found.'}


def _get_assessment(request, pk):
    from plugins_data.active_directory.backend.models import ADAssessment

    try:
        return _assessment_qs(request).get(pk=pk)
    except ADAssessment.DoesNotExist as exc:
        raise AdAssessmentNotFound(pk) from exc


def _ad_gate_or_404(request, pk=None):
    """Return (assessment_or_None, error_response_or_None)."""
    try:
        _require_ad()
        if pk is None:
            return None, None
        return _get_assessment(request, pk), None
    except McpPluginUnavailable as exc:
        return None, Response(exc.detail, status=404)
    except AdAssessmentNotFound as exc:
        return None, Response(exc.detail, status=404)


class McpAdListAssessmentsView(McpDataView):
    def get(self, request):
        _, err = _ad_gate_or_404(request)
        if err:
            return err

        from plugins_data.active_directory.backend.serializers import (
            ADAssessmentListSerializer,
        )

        qs = _assessment_qs(request).order_by('-created_at')
        domain = request.query_params.get('target_domain') or request.query_params.get('domain')
        status_filter = request.query_params.get('status')
        if domain:
            qs = qs.filter(target_domain__icontains=domain)
        if status_filter:
            qs = qs.filter(status=status_filter.upper())
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
            'results': ADAssessmentListSerializer(page, many=True).data,
        })


class McpAdGetAssessmentView(McpDataView):
    def get(self, request, pk):
        assessment, err = _ad_gate_or_404(request, pk)
        if err:
            return err

        from plugins_data.active_directory.backend.serializers import (
            ADAssessmentDetailSerializer,
        )

        return Response(ADAssessmentDetailSerializer(assessment).data)


class McpAdStartAssessmentView(McpIntelDispatchView):
    """Create an AD assessment and optionally start its Temporal workflow."""

    def post(self, request):
        _, err = _ad_gate_or_404(request)
        if err:
            return err

        from plugins_data.active_directory.backend.api import ADAssessmentViewSet
        from plugins_data.active_directory.backend.serializers import (
            ADAssessmentCreateSerializer,
            ADAssessmentDetailSerializer,
        )

        name = request.data.get('name')
        target_domain = request.data.get('target_domain') or request.data.get('domain')
        if not target_domain:
            return Response(
                {'error': 'target_domain is required.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if not name:
            name = f'AD Assessment — {target_domain}'

        config = request.data.get('config')
        if config is None:
            config = {}
        if not isinstance(config, dict):
            return Response(
                {'error': 'config must be an object.'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        serializer = ADAssessmentCreateSerializer(data={
            'name': name,
            'target_domain': target_domain,
            'config': config,
        })
        serializer.is_valid(raise_exception=True)
        assessment = serializer.save(created_by=request.user)

        auto_start = request.data.get('auto_start', True)
        if isinstance(auto_start, str):
            auto_start = auto_start.lower() not in ('0', 'false', 'no')

        started = None
        if auto_start:
            viewset = ADAssessmentViewSet()
            viewset.request = request
            viewset.format_kwarg = None
            viewset.kwargs = {'pk': assessment.pk}
            start_response = viewset.start(request, pk=assessment.pk)
            if start_response.status_code >= 400:
                assessment.refresh_from_db()
                return Response({
                    'assessment': ADAssessmentDetailSerializer(assessment).data,
                    'start_error': start_response.data,
                }, status=start_response.status_code)
            started = start_response.data
            assessment.refresh_from_db()

        return Response({
            'assessment': ADAssessmentDetailSerializer(assessment).data,
            'started': started,
        }, status=status.HTTP_201_CREATED)


class McpAdIngestView(McpIntelDispatchView):
    """Ingest BloodHound / LDAP export data into an assessment (no SharpHound run)."""

    def post(self, request, pk):
        assessment, err = _ad_gate_or_404(request, pk)
        if err:
            return err

        from plugins_data.active_directory.backend.api import ADAssessmentViewSet

        ingest_type = (request.data.get('type') or 'auto').lower()
        filename = request.data.get('filename') or 'upload.bin'
        # Reject path traversal in the provided filename.
        filename = os.path.basename(str(filename)) or 'upload.bin'

        tmp_path = None
        try:
            if 'file' in request.FILES:
                uploaded = request.FILES['file']
                filename = os.path.basename(uploaded.name) or filename
                suffix = os.path.splitext(filename)[1] or '.bin'
                with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                    for chunk in uploaded.chunks():
                        tmp.write(chunk)
                    tmp_path = tmp.name
            elif request.data.get('content_base64'):
                try:
                    raw = base64.b64decode(request.data['content_base64'], validate=True)
                except Exception:
                    return Response(
                        {'error': 'content_base64 is not valid base64.'},
                        status=status.HTTP_400_BAD_REQUEST,
                    )
                suffix = os.path.splitext(filename)[1] or '.bin'
                with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                    tmp.write(raw)
                    tmp_path = tmp.name
            elif request.data.get('content') is not None:
                content = request.data['content']
                if isinstance(content, (dict, list)):
                    raw = json.dumps(content).encode('utf-8')
                    if not filename.endswith('.json'):
                        filename = f'{os.path.splitext(filename)[0] or "bloodhound"}.json'
                else:
                    raw = str(content).encode('utf-8')
                suffix = os.path.splitext(filename)[1] or '.json'
                with tempfile.NamedTemporaryFile(delete=False, suffix=suffix) as tmp:
                    tmp.write(raw)
                    tmp_path = tmp.name
            else:
                return Response(
                    {
                        'error': (
                            'Provide file upload, content_base64, or content '
                            '(BloodHound/SharpHound JSON or LDAP export).'
                        ),
                    },
                    status=status.HTTP_400_BAD_REQUEST,
                )

            # Single JSON file: put in a temp dir so bloodhound_parser can scan directory.
            work_path = tmp_path
            extract_dir = None
            try:
                if tmp_path.endswith('.json') and not tmp_path.endswith('.zip'):
                    extract_dir = tempfile.mkdtemp()
                    dest = os.path.join(extract_dir, filename)
                    os.replace(tmp_path, dest)
                    tmp_path = dest
                    work_path = extract_dir

                summary = ADAssessmentViewSet._run_ingestion(
                    ingest_type, work_path, assessment.id,
                )
            finally:
                if extract_dir and os.path.isdir(extract_dir):
                    import shutil
                    shutil.rmtree(extract_dir, ignore_errors=True)
                    tmp_path = None
        except Exception as exc:
            logger.error('[MCP AD Ingest] Failed: %s', exc, exc_info=True)
            return Response(
                {'error': INTERNAL_ERROR_MESSAGE},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )
        finally:
            if tmp_path and os.path.exists(tmp_path):
                try:
                    os.remove(tmp_path)
                except OSError:
                    pass

        ADAssessmentViewSet._log_analyst_action(
            assessment, request, 'ingest_data',
            {
                'file': filename,
                'type': ingest_type,
                'via': 'mcp',
                'success': isinstance(summary, dict) and 'error' not in summary,
            },
        )
        return Response({
            'status': 'completed',
            'file': filename,
            'type': ingest_type,
            'summary': summary,
            'assessment_id': assessment.id,
        })


class McpAdFindingsView(McpDataView):
    def get(self, request, pk):
        assessment, err = _ad_gate_or_404(request, pk)
        if err:
            return err

        from plugins_data.active_directory.backend.serializers import (
            ADExposureSerializer,
            ADFindingSerializer,
            ADTrustSerializer,
        )

        severity = request.query_params.get('severity')
        findings_qs = assessment.findings.all()
        if severity:
            findings_qs = findings_qs.filter(severity=severity.upper())

        include = (request.query_params.get('include') or 'findings').lower()
        payload = {
            'assessment_id': assessment.id,
            'target_domain': assessment.target_domain,
            'status': assessment.status,
        }
        if 'findings' in include or include == 'all':
            payload['findings'] = ADFindingSerializer(findings_qs[:200], many=True).data
            payload['finding_count'] = findings_qs.count()
        if 'trusts' in include or include == 'all':
            payload['trusts'] = ADTrustSerializer(assessment.trusts.all()[:200], many=True).data
        if 'exposures' in include or include == 'all':
            payload['exposures'] = ADExposureSerializer(
                assessment.exposures.all()[:200], many=True,
            ).data
        return Response(payload)


class McpAdAttackPathsView(McpDataView):
    def get(self, request, pk):
        assessment, err = _ad_gate_or_404(request, pk)
        if err:
            return err

        category = request.query_params.get('category')
        valid = {
            'da_paths', 'kerberoastable', 'asreproastable',
            'unconstrained_delegation', 'acl_abuse',
        }
        if category not in valid:
            return Response(
                {'error': f'category must be one of {sorted(valid)}'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        method_map = {
            'da_paths': 'find_da_paths',
            'kerberoastable': 'find_kerberoastable',
            'asreproastable': 'find_asreproastable',
            'unconstrained_delegation': 'find_unconstrained_delegation',
            'acl_abuse': 'find_acl_abuse',
        }
        try:
            from plugins_data.active_directory.backend.graph.manager import ADGraphManager
            from plugins_data.active_directory.backend.models import ADPluginConfig

            max_hops = int(ADPluginConfig.get_setting('max_path_length', 10))
            kwargs = {'max_hops': max_hops} if category == 'da_paths' else {}
            with ADGraphManager() as mgr:
                results = getattr(mgr, method_map[category])(assessment.id, **kwargs)
            return Response({
                'assessment_id': assessment.id,
                'category': category,
                'results': results,
                'count': len(results),
                'note': (
                    'AD graph attack paths from the Active Directory plugin '
                    '(not APME web-recon paths).'
                ),
            })
        except Exception as exc:
            logger.error('[MCP AD] attack_paths failed: %s', exc, exc_info=True)
            return Response({
                'assessment_id': assessment.id,
                'category': category,
                'results': [],
                'error': INTERNAL_ERROR_MESSAGE,
                'count': 0,
            })


class McpAdReportView(McpDataView):
    def get(self, request, pk):
        assessment, err = _ad_gate_or_404(request, pk)
        if err:
            return err

        from plugins_data.active_directory.backend.api import ADAssessmentViewSet
        from plugins_data.active_directory.backend.reporting.engine import ReportingEngine

        try:
            compiled = ReportingEngine.compile(assessment.id)
        except Exception as exc:
            logger.error('[MCP AD Report] compile failed: %s', exc, exc_info=True)
            return Response(
                {'error': INTERNAL_ERROR_MESSAGE},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

        ADAssessmentViewSet._log_analyst_action(
            assessment, request, 'generate_report',
            {'format': 'json', 'via': 'mcp'},
        )
        return Response({
            'assessment_id': assessment.id,
            'target_domain': assessment.target_domain,
            'report': compiled,
        })
