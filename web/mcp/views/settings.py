from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status
from rest_framework_simplejwt.authentication import JWTAuthentication

from api.permissions import IsSysAdmin
from mcp.authentication import McpApiKeyAuthentication
from mcp.models import McpInstanceSettings


VALID_MODES = {
    McpInstanceSettings.TRANSPORT_STDIO,
    McpInstanceSettings.TRANSPORT_HTTP,
    McpInstanceSettings.TRANSPORT_BOTH,
}


class McpSettingsView(APIView):
    permission_classes = [IsAuthenticated]
    http_method_names = ['get', 'patch', 'head', 'options']

    def get_authenticators(self):
        if getattr(self, 'request', None) is not None and self.request.method == 'PATCH':
            return [JWTAuthentication(), SessionAuthentication()]
        return [
            McpApiKeyAuthentication(),
            JWTAuthentication(),
            SessionAuthentication(),
        ]

    def get_permissions(self):
        if self.request.method == 'PATCH':
            return [IsSysAdmin()]
        return [IsAuthenticated()]

    def get(self, request):
        settings_row = McpInstanceSettings.get_solo()
        return Response({'transport_mode': settings_row.transport_mode})

    def patch(self, request):
        mode = request.data.get('transport_mode')
        if mode not in VALID_MODES:
            return Response(
                {'error': 'transport_mode must be stdio, http, or both'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        settings_row = McpInstanceSettings.get_solo()
        settings_row.transport_mode = mode
        settings_row.updated_by = request.user
        settings_row.save(update_fields=['transport_mode', 'updated_at', 'updated_by'])
        return Response({'transport_mode': settings_row.transport_mode})
