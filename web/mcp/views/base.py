from rest_framework.exceptions import AuthenticationFailed
from rest_framework.permissions import IsAuthenticated

from mcp.authentication import McpApiKeyAuthentication
from mcp.views.audit import McpAuditedAPIView


class McpDataView(McpAuditedAPIView):
    authentication_classes = [McpApiKeyAuthentication]
    permission_classes = [IsAuthenticated]
    http_method_names = ['get', 'head', 'options']

    def initial(self, request, *args, **kwargs):
        super().initial(request, *args, **kwargs)
        if getattr(request, 'mcp_key', None) and not getattr(request, 'mcp_session', None):
            raise AuthenticationFailed(
                'MCP session invalid or revoked. Reconnect or use a new session; the API key may still be valid.'
            )
