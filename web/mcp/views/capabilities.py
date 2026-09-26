"""MCP wrappers for capabilities, singular tool run, and follow-up plans."""
from rest_framework.response import Response

from api.views.followups import (
    EngineDetailAPIView,
    FollowupAbortAPIView,
    FollowupApproveAPIView,
    FollowupListAPIView,
    FollowupMetricsAPIView,
    FollowupPlanDetailAPIView,
    FollowupProposeAPIView,
    FollowupRetryAPIView,
    FollowupUpdateAPIView,
    ListCapabilitiesAPIView,
    ToolArgsAPIView,
    ToolRunAPIView,
)
from mcp.views.base import McpDataView
from mcp.views.dispatch import McpScanDispatchView, _delegate_post


class McpListCapabilitiesView(McpDataView):
    def get(self, request):
        return ListCapabilitiesAPIView().get(request)


class McpGetEngineDetailView(McpDataView):
    def get(self, request, pk):
        return EngineDetailAPIView().get(request, pk)


class McpGetToolArgsView(McpDataView):
    def get(self, request, tool):
        return ToolArgsAPIView().get(request, tool)


class McpRunToolView(McpScanDispatchView):
    def post(self, request):
        return _delegate_post(ToolRunAPIView, request)


class McpProposeFollowupsView(McpScanDispatchView):
    def post(self, request):
        return _delegate_post(FollowupProposeAPIView, request)


class McpGetFollowupPlanView(McpDataView):
    def get(self, request, pk):
        return FollowupPlanDetailAPIView().get(request, pk)


class McpListFollowupsView(McpDataView):
    def get(self, request):
        return FollowupListAPIView().get(request)


class McpUpdateFollowupsView(McpScanDispatchView):
    def post(self, request, pk):
        # Operator edit from IDE: mark operator so agent lock applies after
        data = request.data
        try:
            data['operator'] = True
        except (TypeError, AttributeError):
            request._full_data = {**dict(data), 'operator': True}
        return _delegate_post(FollowupUpdateAPIView, request, pk=pk)


class McpApproveFollowupsView(McpScanDispatchView):
    def post(self, request, pk):
        return _delegate_post(FollowupApproveAPIView, request, pk=pk)


class McpAbortFollowupsView(McpScanDispatchView):
    def post(self, request, pk):
        return _delegate_post(FollowupAbortAPIView, request, pk=pk)


class McpRetryFollowupsView(McpScanDispatchView):
    def post(self, request, pk):
        return _delegate_post(FollowupRetryAPIView, request, pk=pk)


class McpFollowupMetricsView(McpDataView):
    def get(self, request):
        return FollowupMetricsAPIView().get(request)
