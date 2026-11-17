"""REST API for Assessment Copilot gateway."""
from __future__ import annotations

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from api.permissions import IsPenetrationTester
from copilot import service
from copilot.client import CopilotClientError, copilot_models
from copilot.models import CopilotActionProposal, CopilotSession, CopilotTraceEvent, MsfAuxAttempt
from copilot.trace import list_trace_events, serialize_trace_event
from mcp.operator_gate import resolve_is_operator


class CopilotStatusAPIView(APIView):
    permission_classes = [IsPenetrationTester]

    def get(self, request):
        project_slug = request.query_params.get('project_slug') or ''
        return Response(service.service_status(project_slug or None))


class CopilotSettingsAPIView(APIView):
    permission_classes = [IsPenetrationTester]

    def get(self, request):
        project_slug = request.query_params.get('project_slug')
        if not project_slug:
            return Response({'error': 'project_slug is required'}, status=400)
        cfg = service.get_or_create_settings(project_slug)
        return Response(service.serialize_settings(cfg))

    def patch(self, request):
        if not resolve_is_operator(request):
            return Response({'error': 'operator only'}, status=403)
        data = request.data or {}
        project_slug = data.get('project_slug') or request.query_params.get('project_slug')
        if not project_slug:
            return Response({'error': 'project_slug is required'}, status=400)
        cfg = service.get_or_create_settings(project_slug)
        if 'enabled' in data:
            cfg.enabled = bool(data['enabled'])
        if 'memory_scope' in data:
            scope = str(data['memory_scope'])
            allowed = {c[0] for c in cfg.SCOPE_CHOICES}
            if scope not in allowed:
                return Response({'error': f'memory_scope must be one of {sorted(allowed)}'}, status=400)
            cfg.memory_scope = scope
        if 'model_id' in data:
            cfg.model_id = str(data['model_id'] or '')[:255]
        if 'org_id' in data:
            cfg.org_id = str(data['org_id'] or '')[:255]
        if getattr(request.user, 'is_authenticated', False):
            cfg.updated_by = request.user
        cfg.save()
        return Response(service.serialize_settings(cfg))


class CopilotModelsAPIView(APIView):
    permission_classes = [IsPenetrationTester]

    def get(self, request):
        try:
            return Response(copilot_models())
        except CopilotClientError as exc:
            return Response({'error': str(exc)}, status=exc.status)


class CopilotSessionListCreateAPIView(APIView):
    permission_classes = [IsPenetrationTester]

    def get(self, request):
        project_slug = request.query_params.get('project_slug')
        if not project_slug:
            return Response({'error': 'project_slug is required'}, status=400)
        qs = CopilotSession.objects.filter(project_slug=project_slug).order_by('-updated_at')[:100]
        return Response({'sessions': [service.serialize_session(s) for s in qs]})

    def post(self, request):
        data = request.data or {}
        project_slug = data.get('project_slug')
        if not project_slug:
            return Response({'error': 'project_slug is required'}, status=400)
        session = CopilotSession.objects.create(
            project_slug=project_slug,
            scan_id=data.get('scan_id'),
            assessment_id=data.get('assessment_id'),
            title=(data.get('title') or 'New conversation')[:255],
            created_by=request.user if getattr(request.user, 'is_authenticated', False) else None,
        )
        return Response(service.serialize_session(session, include_messages=True), status=201)


def _session_for_project(pk, project_slug: str):
    if not project_slug:
        return None, Response({'error': 'project_slug is required'}, status=400)
    session = CopilotSession.objects.filter(pk=pk, project_slug=project_slug).first()
    if not session:
        return None, Response({'error': 'not found'}, status=404)
    return session, None


class CopilotSessionDetailAPIView(APIView):
    permission_classes = [IsPenetrationTester]

    def get(self, request, pk):
        project_slug = request.query_params.get('project_slug') or ''
        session, err = _session_for_project(pk, project_slug)
        if err:
            return err
        return Response(service.serialize_session(session, include_messages=True))

    def patch(self, request, pk):
        data = request.data or {}
        project_slug = data.get('project_slug') or request.query_params.get('project_slug') or ''
        session, err = _session_for_project(pk, project_slug)
        if err:
            return err
        title = data.get('title')
        if title is not None:
            session.title = str(title)[:255]
            session.save(update_fields=['title', 'updated_at'])
        return Response(service.serialize_session(session, include_messages=True))

    def delete(self, request, pk):
        project_slug = request.query_params.get('project_slug') or (request.data or {}).get('project_slug') or ''
        session, err = _session_for_project(pk, project_slug)
        if err:
            return err
        session.delete()
        return Response(status=204)


class CopilotChatAPIView(APIView):
    permission_classes = [IsPenetrationTester]

    def post(self, request):
        data = request.data or {}
        session_id = data.get('session_id')
        project_slug = data.get('project_slug') or ''
        content = (data.get('content') or data.get('message') or '').strip()
        if not session_id:
            return Response({'error': 'session_id is required'}, status=400)
        if not content:
            return Response({'error': 'content is required'}, status=400)
        session, err = _session_for_project(session_id, project_slug)
        if err:
            return err
        try:
            result = service.chat(session=session, content=content, user=request.user)
        except service.CopilotError as exc:
            return Response({'error': str(exc)}, status=exc.status)
        return Response(result)


class CopilotProposalListCreateAPIView(APIView):
    permission_classes = [IsPenetrationTester]

    def get(self, request):
        project_slug = request.query_params.get('project_slug')
        if not project_slug:
            return Response({'error': 'project_slug is required'}, status=400)
        status_filter = request.query_params.get('status') or CopilotActionProposal.STATUS_PENDING
        qs = CopilotActionProposal.objects.filter(project_slug=project_slug)
        if status_filter != 'all':
            qs = qs.filter(status=status_filter)
        qs = qs.order_by('-created_at')[:200]
        return Response({'proposals': [service.serialize_proposal(p) for p in qs]})

    def post(self, request):
        data = request.data or {}
        project_slug = data.get('project_slug')
        action_type = data.get('action_type')
        if not project_slug or not action_type:
            return Response({'error': 'project_slug and action_type are required'}, status=400)
        try:
            proposal = service.create_proposal(
                project_slug=project_slug,
                action_type=action_type,
                summary=data.get('summary') or '',
                rationale=data.get('rationale') or '',
                payload=data.get('payload') if isinstance(data.get('payload'), dict) else {},
                vulnerability_id=data.get('vulnerability_id'),
                scan_id=data.get('scan_id'),
                assessment_id=data.get('assessment_id'),
                session_id=data.get('session_id'),
                user=request.user,
            )
        except service.CopilotError as exc:
            return Response({'error': str(exc)}, status=exc.status)
        return Response(service.serialize_proposal(proposal), status=201)


class CopilotProposalApproveAPIView(APIView):
    permission_classes = [IsPenetrationTester]

    def post(self, request, pk):
        if not resolve_is_operator(request):
            return Response({'error': 'operator approve required'}, status=403)
        proposal = CopilotActionProposal.objects.filter(pk=pk).first()
        if not proposal:
            return Response({'error': 'not found'}, status=404)
        try:
            proposal = service.approve_proposal(proposal, user=request.user)
        except service.CopilotError as exc:
            return Response({'error': str(exc), 'proposal': service.serialize_proposal(proposal)}, status=exc.status)
        return Response(service.serialize_proposal(proposal))


class CopilotProposalRejectAPIView(APIView):
    permission_classes = [IsPenetrationTester]

    def post(self, request, pk):
        if not resolve_is_operator(request):
            return Response({'error': 'operator reject required'}, status=403)
        proposal = CopilotActionProposal.objects.filter(pk=pk).first()
        if not proposal:
            return Response({'error': 'not found'}, status=404)
        try:
            proposal = service.reject_proposal(proposal, user=request.user)
        except service.CopilotError as exc:
            return Response({'error': str(exc)}, status=exc.status)
        return Response(service.serialize_proposal(proposal))


class CopilotTraceListAPIView(APIView):
    permission_classes = [IsPenetrationTester]

    def get(self, request):
        if not resolve_is_operator(request):
            return Response({'error': 'operator only'}, status=403)
        project_slug = request.query_params.get('project_slug') or ''
        if not project_slug:
            return Response({'error': 'project_slug is required'}, status=400)
        session_id = request.query_params.get('session_id')
        turn_id = request.query_params.get('turn_id') or None
        try:
            limit = int(request.query_params.get('limit') or 100)
        except (TypeError, ValueError):
            limit = 100
        sid = None
        if session_id:
            try:
                sid = int(session_id)
            except (TypeError, ValueError):
                return Response({'error': 'invalid session_id'}, status=400)
        events = list_trace_events(
            project_slug=project_slug,
            session_id=sid,
            turn_id=turn_id,
            limit=limit,
        )
        return Response({'events': [serialize_trace_event(e) for e in events]})


class CopilotTraceDetailAPIView(APIView):
    permission_classes = [IsPenetrationTester]

    def get(self, request, pk):
        if not resolve_is_operator(request):
            return Response({'error': 'operator only'}, status=403)
        project_slug = request.query_params.get('project_slug') or ''
        qs = CopilotTraceEvent.objects.filter(pk=pk)
        if project_slug:
            qs = qs.filter(project_slug=project_slug)
        ev = qs.first()
        if not ev:
            return Response({'error': 'not found'}, status=404)
        return Response(serialize_trace_event(ev))


def _serialize_msf_attempt(a: MsfAuxAttempt) -> dict:
    return {
        'id': a.id,
        'project_slug': a.project_slug,
        'scan_id': a.scan_id,
        'vulnerability_id': a.vulnerability_id,
        'status': a.status,
        'module': a.module,
        'options': a.options or {},
        'rationale': a.rationale,
        'result': a.result,
        'error': a.error,
        'temporal_workflow_id': a.temporal_workflow_id,
        'created_at': a.created_at.isoformat() if a.created_at else None,
        'approved_at': a.approved_at.isoformat() if a.approved_at else None,
        'completed_at': a.completed_at.isoformat() if a.completed_at else None,
    }


class MsfAuxListAPIView(APIView):
    permission_classes = [IsPenetrationTester]

    def get(self, request):
        if not resolve_is_operator(request):
            return Response({'error': 'operator only'}, status=403)
        project_slug = request.query_params.get('project_slug') or ''
        if not project_slug:
            return Response({'error': 'project_slug is required'}, status=400)
        qs = MsfAuxAttempt.objects.filter(project_slug=project_slug).order_by('-created_at')[:100]
        return Response({'attempts': [_serialize_msf_attempt(a) for a in qs]})


class MsfAuxDetailAPIView(APIView):
    permission_classes = [IsPenetrationTester]

    def get(self, request, pk):
        if not resolve_is_operator(request):
            return Response({'error': 'operator only'}, status=403)
        project_slug = request.query_params.get('project_slug') or ''
        qs = MsfAuxAttempt.objects.filter(pk=pk)
        if project_slug:
            qs = qs.filter(project_slug=project_slug)
        attempt = qs.first()
        if not attempt:
            return Response({'error': 'not found'}, status=404)
        return Response(_serialize_msf_attempt(attempt))


class MsfAuxAbortAPIView(APIView):
    permission_classes = [IsPenetrationTester]

    def post(self, request, pk):
        if not resolve_is_operator(request):
            return Response({'error': 'operator only'}, status=403)
        from copilot.msf_aux import MsfAuxError, abort_attempt

        attempt = MsfAuxAttempt.objects.filter(pk=pk).first()
        if not attempt:
            return Response({'error': 'not found'}, status=404)
        try:
            attempt = abort_attempt(attempt, user=request.user)
        except MsfAuxError as exc:
            return Response({'error': str(exc)}, status=exc.status)
        return Response(_serialize_msf_attempt(attempt))
