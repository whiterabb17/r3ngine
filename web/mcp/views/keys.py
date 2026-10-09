from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rolepermissions.checkers import has_role

from mcp.keys import display_prefix, generate_mcp_secret, hash_mcp_secret
from mcp.models import McpApiKey, McpSession


def _serialize_key(row, secret=None):
    agents = [
        {
            'agent_id': agent.id,
            'provider': agent.provider,
            'ide': agent.ide,
            'hostname': agent.hostname,
            'os_name': agent.os_name,
            'username': agent.username,
            'banned': bool(agent.banned_at),
            'last_seen_at': agent.last_seen_at.isoformat() if agent.last_seen_at else None,
        }
        for agent in row.agents.all().order_by('-last_seen_at')[:12]
    ]
    payload = {
        'id': row.id,
        'name': row.name,
        'prefix': row.prefix,
        'created_at': row.created_at.isoformat() if row.created_at else None,
        'last_used_at': row.last_used_at.isoformat() if row.last_used_at else None,
        'revoked_at': row.revoked_at.isoformat() if row.revoked_at else None,
        'status': 'revoked' if row.revoked_at else 'active',
        'agents': agents,
        'agent_count': len(agents),
    }
    if secret is not None:
        payload['secret'] = secret
    return payload


def _key_queryset(request):
    qs = McpApiKey.objects.prefetch_related('agents').all().order_by('-created_at')
    want_all = request.query_params.get('all') == '1'
    is_admin = request.user.is_superuser or has_role(request.user, 'sys_admin')
    if want_all and is_admin:
        return qs
    return qs.filter(user=request.user)


def _get_owned_or_admin_key(request, pk):
    key = get_object_or_404(McpApiKey, pk=pk)
    is_admin = request.user.is_superuser or has_role(request.user, 'sys_admin')
    if key.user_id != request.user.id and not is_admin:
        return None
    return key


class McpKeyListCreateView(APIView):
    permission_classes = [IsAuthenticated]
    http_method_names = ['get', 'post', 'head', 'options']

    def get(self, request):
        items = [_serialize_key(row) for row in _key_queryset(request)]
        return Response({'items': items, 'count': len(items)})

    def post(self, request):
        name = (request.data.get('name') or '').strip()
        if not name:
            return Response({'error': 'name is required'}, status=status.HTTP_400_BAD_REQUEST)
        if McpApiKey.objects.filter(user=request.user, name=name).exists():
            return Response(
                {'error': 'A key with that name already exists'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        secret = generate_mcp_secret()
        row = McpApiKey.objects.create(
            user=request.user,
            name=name,
            prefix=display_prefix(secret),
            key_hash=hash_mcp_secret(secret),
        )
        return Response(_serialize_key(row, secret=secret), status=status.HTTP_201_CREATED)


class McpKeyRegenerateView(APIView):
    permission_classes = [IsAuthenticated]
    http_method_names = ['post', 'options']

    def post(self, request, pk):
        key = _get_owned_or_admin_key(request, pk)
        if key is None:
            return Response({'error': 'Not found'}, status=status.HTTP_404_NOT_FOUND)
        secret = generate_mcp_secret()
        key.prefix = display_prefix(secret)
        key.key_hash = hash_mcp_secret(secret)
        key.revoked_at = None
        key.save(update_fields=['prefix', 'key_hash', 'revoked_at'])
        now = timezone.now()
        McpSession.objects.filter(key=key, revoked_at__isnull=True).update(revoked_at=now)
        return Response(_serialize_key(key, secret=secret))


class McpKeyRevokeView(APIView):
    permission_classes = [IsAuthenticated]
    http_method_names = ['post', 'options']

    def post(self, request, pk):
        key = _get_owned_or_admin_key(request, pk)
        if key is None:
            return Response({'error': 'Not found'}, status=status.HTTP_404_NOT_FOUND)
        now = timezone.now()
        key.revoked_at = now
        key.save(update_fields=['revoked_at'])
        McpSession.objects.filter(key=key, revoked_at__isnull=True).update(revoked_at=now)
        return Response(_serialize_key(key))
