"""API views for singular tool runs and follow-up plans."""
from __future__ import annotations

from rest_framework import status
from rest_framework.response import Response
from rest_framework.views import APIView

from api.permissions import HasPermission, IsPenetrationTester
from api.tool_run import ToolRunError, start_pipeline_tool_run, start_workflow_tool_run
from mcp.followups import (
    FollowupError,
    abort_plan,
    approve_plan,
    followup_metrics,
    propose_plan,
    retry_plan,
    serialize_plan,
    update_plan_steps,
)
from mcp.models import FollowupPlan
from reNgine.capabilities import list_capabilities, serialize_engine_detail
from reNgine.definitions import PERM_INITATE_SCANS_SUBSCANS
from scanEngine.models import EngineType


class ListCapabilitiesAPIView(APIView):
    permission_classes = [IsPenetrationTester]

    def get(self, request):
        return Response(list_capabilities())


class EngineDetailAPIView(APIView):
    permission_classes = [IsPenetrationTester]

    def get(self, request, pk):
        engine = EngineType.objects.filter(pk=pk).first()
        if not engine:
            return Response({'error': 'Not found'}, status=404)
        return Response(serialize_engine_detail(engine))


class ToolRunAPIView(APIView):
    permission_classes = [HasPermission]
    permission_required = PERM_INITATE_SCANS_SUBSCANS

    def post(self, request):
        data = request.data or {}
        tool = data.get('tool')
        asset_type = data.get('asset_type')
        if not tool or not asset_type:
            return Response(
                {'status': False, 'message': 'tool and asset_type are required'},
                status=400,
            )
        from reNgine.capabilities import get_pipeline_tool, get_workflow_tool

        try:
            if get_pipeline_tool(tool):
                scan_id = data.get('scan_history_id') or data.get('scan_id')
                if not scan_id:
                    return Response(
                        {'status': False, 'message': 'scan_history_id is required'},
                        status=400,
                    )
                result = start_pipeline_tool_run(
                    tool=tool,
                    asset_type=asset_type,
                    scan_id=int(scan_id),
                    asset_id=data.get('asset_id'),
                    url=data.get('url'),
                    tool_args=data.get('tool_args'),
                    user=request.user,
                )
            elif get_workflow_tool(tool):
                result = start_workflow_tool_run(
                    workflow_slug=tool,
                    scan_id=data.get('scan_history_id') or data.get('scan_id'),
                    url=data.get('url'),
                    asset_id=data.get('asset_id'),
                    user=request.user,
                )
            else:
                return Response(
                    {'status': False, 'message': f'Unknown tool: {tool}'},
                    status=400,
                )
        except ToolRunError as exc:
            return Response(
                {'status': False, 'message': str(exc)},
                status=exc.status,
            )
        return Response({'status': True, **result})


class ToolArgsAPIView(APIView):
    """Return cached CLI/schema args for a pipeline tool (from installed binary help)."""

    permission_classes = [IsPenetrationTester]

    def get(self, request, tool: str):
        from reNgine.tool_args import ToolArgsError, get_or_refresh_schema

        force = str(request.query_params.get('refresh') or '').lower() in ('1', 'true', 'yes')
        try:
            payload = get_or_refresh_schema(tool, force=force, sync_first=False)
        except ToolArgsError as exc:
            return Response({'error': str(exc)}, status=exc.status)
        return Response(payload)

def _followup_error_response(exc: FollowupError):
    return Response({'status': False, 'error': str(exc)}, status=exc.status)


class FollowupProposeAPIView(APIView):
    permission_classes = [HasPermission]
    permission_required = PERM_INITATE_SCANS_SUBSCANS

    def post(self, request):
        data = request.data or {}
        try:
            plan = propose_plan(
                project_slug=data.get('project_slug') or '',
                steps=data.get('steps') or [],
                rationale=data.get('rationale') or '',
                scan_id=data.get('scan_id'),
                assessment_id=data.get('assessment_id'),
                user=request.user,
            )
        except FollowupError as exc:
            return _followup_error_response(exc)
        return Response({'status': True, 'plan': serialize_plan(plan)}, status=201)


class FollowupPlanDetailAPIView(APIView):
    permission_classes = [IsPenetrationTester]

    def get(self, request, pk):
        plan = FollowupPlan.objects.filter(pk=pk).first()
        if not plan:
            return Response({'error': 'Not found'}, status=404)
        return Response(serialize_plan(plan))


class FollowupUpdateAPIView(APIView):
    """Operator (or agent until first operator edit) updates proposed steps."""

    permission_classes = [HasPermission]
    permission_required = PERM_INITATE_SCANS_SUBSCANS

    def post(self, request, pk):
        plan = FollowupPlan.objects.filter(pk=pk).first()
        if not plan:
            return Response({'error': 'Not found'}, status=404)
        data = request.data or {}
        # Treat JWT/UI and MCP pentester as operator; agent identity uses mcp_key
        is_operator = not getattr(request, 'mcp_key', None) or bool(
            getattr(request, 'mcp_operator', False)
        )
        # MCP agent keys are not operators unless marked; default agent = False
        if getattr(request, 'mcp_key', None) and not request.data.get('_operator'):
            is_operator = False
            # Operator-facing MCP tools set operator=true in body
            if data.get('operator') is True:
                is_operator = True
        try:
            plan = update_plan_steps(
                plan,
                data.get('steps') or [],
                user=request.user,
                is_operator=is_operator,
            )
        except FollowupError as exc:
            return _followup_error_response(exc)
        return Response({'status': True, 'plan': serialize_plan(plan)})


class FollowupApproveAPIView(APIView):
    permission_classes = [HasPermission]
    permission_required = PERM_INITATE_SCANS_SUBSCANS

    def post(self, request, pk):
        plan = FollowupPlan.objects.filter(pk=pk).first()
        if not plan:
            return Response({'error': 'Not found'}, status=404)
        data = request.data or {}
        try:
            plan = approve_plan(
                plan,
                steps=data.get('steps'),
                user=request.user,
            )
        except FollowupError as exc:
            return _followup_error_response(exc)
        return Response({'status': True, 'plan': serialize_plan(plan)})


class FollowupAbortAPIView(APIView):
    permission_classes = [HasPermission]
    permission_required = PERM_INITATE_SCANS_SUBSCANS

    def post(self, request, pk):
        plan = FollowupPlan.objects.filter(pk=pk).first()
        if not plan:
            return Response({'error': 'Not found'}, status=404)
        try:
            plan = abort_plan(plan, user=request.user)
        except FollowupError as exc:
            return _followup_error_response(exc)
        return Response({'status': True, 'plan': serialize_plan(plan)})


class FollowupRetryAPIView(APIView):
    permission_classes = [HasPermission]
    permission_required = PERM_INITATE_SCANS_SUBSCANS

    def post(self, request, pk):
        plan = FollowupPlan.objects.filter(pk=pk).first()
        if not plan:
            return Response({'error': 'Not found'}, status=404)
        data = request.data or {}
        try:
            plan = retry_plan(
                plan,
                step_ids=data.get('step_ids'),
                include_succeeded=bool(data.get('include_succeeded')),
                user=request.user,
            )
        except FollowupError as exc:
            return _followup_error_response(exc)
        return Response({'status': True, 'plan': serialize_plan(plan)})


class FollowupListAPIView(APIView):
    permission_classes = [IsPenetrationTester]

    def get(self, request):
        qs = FollowupPlan.objects.all().order_by('-created_at')
        slug = request.query_params.get('project_slug')
        if slug:
            qs = qs.filter(project_slug=slug)
        st = request.query_params.get('status')
        if st:
            qs = qs.filter(status=st)
        scan_id = request.query_params.get('scan_id')
        if scan_id:
            qs = qs.filter(scan_id=scan_id)
        assessment_id = request.query_params.get('assessment_id')
        if assessment_id:
            qs = qs.filter(assessment_id=assessment_id)
        limit = min(int(request.query_params.get('limit') or 50), 100)
        rows = [serialize_plan(p) for p in qs[:limit]]
        return Response({'results': rows, 'count': qs.count()})


class FollowupMetricsAPIView(APIView):
    permission_classes = [IsPenetrationTester]

    def get(self, request):
        return Response(followup_metrics())
