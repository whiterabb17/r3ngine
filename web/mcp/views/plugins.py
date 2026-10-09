"""MCP discovery for installed/enabled plugins."""
from rest_framework.response import Response

from mcp.plugins_gate import (
    get_enabled_plugin,
    list_enabled_plugins,
    serialize_plugin,
)
from mcp.views.base import McpDataView


class McpListPluginsView(McpDataView):
    def get(self, request):
        return Response({'results': list_enabled_plugins()})


class McpGetPluginView(McpDataView):
    def get(self, request, slug):
        plugin = get_enabled_plugin(slug)
        return Response(serialize_plugin(plugin))
