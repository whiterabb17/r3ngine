from django.utils import timezone
from rest_framework.authentication import BaseAuthentication
from rest_framework.exceptions import AuthenticationFailed

from mcp.identity import BANNED_MESSAGE, agent_is_banned
from mcp.keys import MCP_KEY_PREFIX, hash_mcp_secret, secrets_match
from mcp.models import McpApiKey, McpSession

SESSION_HEADER = 'HTTP_X_MCP_SESSION_ID'


class McpApiKeyAuthentication(BaseAuthentication):
    def authenticate(self, request):
        header = request.META.get('HTTP_AUTHORIZATION', '')
        if not header.startswith('Bearer '):
            return None
        token = header[7:].strip()
        if not token.startswith(MCP_KEY_PREFIX):
            return None
        digest = hash_mcp_secret(token)
        try:
            key = McpApiKey.objects.select_related('user').get(key_hash=digest)
        except McpApiKey.DoesNotExist:
            raise AuthenticationFailed(
                'API key invalid or revoked. Generate a new key in Settings → MCP Access.'
            )
        if key.revoked_at is not None:
            raise AuthenticationFailed(
                'API key invalid or revoked. Generate a new key in Settings → MCP Access.'
            )
        if not secrets_match(token, key.key_hash):
            raise AuthenticationFailed(
                'API key invalid or revoked. Generate a new key in Settings → MCP Access.'
            )
        McpApiKey.objects.filter(pk=key.pk).update(last_used_at=timezone.now())
        request.mcp_key = key
        session_id = request.META.get(SESSION_HEADER)
        request.mcp_session = None
        if session_id:
            try:
                session = McpSession.objects.get(pk=session_id, key=key)
            except (McpSession.DoesNotExist, ValueError, TypeError):
                raise AuthenticationFailed(
                    'MCP session invalid or revoked. Reconnect or use a new session; the API key may still be valid.'
                )
            if session.revoked_at is not None or session.ended_at is not None:
                raise AuthenticationFailed(
                    'MCP session invalid or revoked. Reconnect or use a new session; the API key may still be valid.'
                )
            if agent_is_banned(session.agent_id):
                raise AuthenticationFailed(BANNED_MESSAGE)
            McpSession.objects.filter(pk=session.pk).update(last_seen_at=timezone.now())
            request.mcp_session = session
        return (key.user, None)

    def authenticate_header(self, request):
        return 'Bearer realm="r3ngine-mcp"'
