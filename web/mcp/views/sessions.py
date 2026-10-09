from datetime import timedelta

from django.db.models import Count
from django.shortcuts import get_object_or_404
from django.utils import timezone
from rest_framework import status
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rolepermissions.checkers import has_role

from mcp.authentication import McpApiKeyAuthentication
from mcp.identity import (
    BANNED_MESSAGE,
    agent_is_banned,
    ban_agent,
    parse_agent_id,
    unban_agent_id,
)
from mcp.models import McpAgent, McpAuditEvent, McpSession


def _is_admin(user):
    return bool(user and (user.is_superuser or has_role(user, 'sys_admin')))


def _session_status(row):
    if row.revoked_at:
        return 'revoked'
    if row.ended_at:
        return 'ended'
    if row.is_connected():
        return 'connected'
    return 'idle'


def _serialize_session(row, request_count=None):
    agent = row.agent
    payload = {
        'id': str(row.id),
        'session_id': str(row.id),
        'agent_id': row.agent_id or (agent.id if agent else ''),
        'key_id': row.key_id,
        'key_name': row.key.name,
        'key_prefix': row.key.prefix,
        'user_id': row.user_id,
        'username': row.user.username,
        'transport': row.transport,
        'client_name': row.client_name,
        'client_version': row.client_version,
        'provider': row.provider or (agent.provider if agent else ''),
        'ide': row.ide or (agent.ide if agent else ''),
        'device_id': row.device_id or (agent.device_id if agent else ''),
        'os_name': row.os_name or (agent.os_name if agent else ''),
        'hostname': row.hostname or (agent.hostname if agent else ''),
        'agent_username': row.agent_username or (agent.username if agent else ''),
        'user_agent': row.user_agent,
        'source_ip': row.source_ip,
        'connected_at': row.connected_at.isoformat() if row.connected_at else None,
        'last_seen_at': row.last_seen_at.isoformat() if row.last_seen_at else None,
        'revoked_at': row.revoked_at.isoformat() if row.revoked_at else None,
        'ended_at': row.ended_at.isoformat() if row.ended_at else None,
        'banned': bool(agent.banned_at) if agent else agent_is_banned(row.agent_id),
        'connected': row.is_connected(),
        'status': _session_status(row),
        'request_count': request_count,
    }
    return payload


def client_ip(request):
    """ASGI puts host:port in REMOTE_ADDR; PostgreSQL inet rejects the port."""
    forwarded = (request.META.get('HTTP_X_FORWARDED_FOR') or '').split(',')[0].strip()
    raw = forwarded or (request.META.get('REMOTE_ADDR') or '').strip()
    if not raw:
        return None
    if raw.startswith('[') and ']' in raw:
        return raw[1:raw.index(']')] or None
    if raw.count(':') == 1:
        host, port = raw.rsplit(':', 1)
        if port.isdigit():
            raw = host
    return raw or None


def _owned_or_admin_session(request, pk):
    session = get_object_or_404(McpSession, pk=pk)
    if session.user_id != request.user.id and not _is_admin(request.user):
        return None
    return session


def _upsert_agent(key, user, identity, now):
    agent, created = McpAgent.objects.get_or_create(
        pk=identity['agent_id'],
        defaults={
            'key': key,
            'user': user,
            'provider': identity['provider'],
            'ide': identity['ide'],
            'device_id': identity['device_id'],
            'os_name': identity['os_name'],
            'hostname': identity['hostname'],
            'username': identity['username'],
            'last_seen_at': now,
        },
    )
    updates = {
        'key': key,
        'user': user,
        'provider': identity['provider'],
        'ide': identity['ide'],
        'device_id': identity['device_id'],
        'os_name': identity['os_name'],
        'hostname': identity['hostname'],
        'username': identity['username'],
        'last_seen_at': now,
    }
    for field, value in updates.items():
        setattr(agent, field, value)
    agent.save(update_fields=list(updates.keys()))
    return agent, created


class McpSessionListCreateView(APIView):
    permission_classes = [IsAuthenticated]
    http_method_names = ['get', 'post', 'head', 'options']

    def get_authenticators(self):
        if getattr(self, 'request', None) is not None and self.request.method == 'POST':
            return [McpApiKeyAuthentication()]
        return [JWTAuthentication(), SessionAuthentication()]

    def get(self, request):
        qs = McpSession.objects.select_related('key', 'user', 'agent').order_by('-last_seen_at')
        if not (request.query_params.get('all') == '1' and _is_admin(request.user)):
            qs = qs.filter(user=request.user)
        if request.query_params.get('status') == 'connected':
            cutoff = timezone.now() - timedelta(seconds=McpSession.CONNECTED_WINDOW_SECONDS)
            qs = qs.filter(
                revoked_at__isnull=True,
                ended_at__isnull=True,
                last_seen_at__gte=cutoff,
            )
        seen = set()
        latest_rows = []
        for row in qs:
            identity = (row.user_id, row.agent_id or str(row.id))
            if identity in seen:
                continue
            seen.add(identity)
            latest_rows.append(row)
        agent_ids = [row.agent_id for row in latest_rows if row.agent_id]
        count_map = {}
        if agent_ids:
            event_qs = McpAuditEvent.objects.filter(session__agent_id__in=agent_ids)
            if not (request.query_params.get('all') == '1' and _is_admin(request.user)):
                event_qs = event_qs.filter(session__user=request.user)
            for item in event_qs.values('session__agent_id', 'session__user_id').annotate(n=Count('id')):
                count_map[(item['session__user_id'], item['session__agent_id'])] = item['n']
        items = [
            _serialize_session(
                row,
                request_count=count_map.get((row.user_id, row.agent_id), 0),
            )
            for row in latest_rows
        ]
        return Response({'items': items, 'count': len(items)})

    def post(self, request):
        transport = request.data.get('transport') or 'stdio'
        if transport not in ('stdio', 'http'):
            return Response(
                {'error': 'transport must be stdio or http'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        key = getattr(request, 'mcp_key', None)
        if key is None:
            return Response({'error': 'MCP API key required'}, status=status.HTTP_401_UNAUTHORIZED)
        agent_id = parse_agent_id(request.data.get('agent_id'))
        if not agent_id:
            return Response(
                {'error': 'agent_id is required (64-char provider+device fingerprint)'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if agent_is_banned(agent_id):
            return Response({'error': BANNED_MESSAGE}, status=status.HTTP_403_FORBIDDEN)
        now = timezone.now()
        identity = {
            'agent_id': agent_id,
            'provider': (request.data.get('provider') or '')[:80],
            'ide': (request.data.get('ide') or '')[:80],
            'device_id': (request.data.get('device_id') or '')[:128],
            'os_name': (request.data.get('os') or request.data.get('os_name') or '')[:80],
            'hostname': (request.data.get('hostname') or '')[:200],
            'username': (request.data.get('username') or '')[:200],
        }
        agent, _created = _upsert_agent(key, request.user, identity, now)
        if agent.banned_at:
            return Response({'error': BANNED_MESSAGE}, status=status.HTTP_403_FORBIDDEN)
        live = (
            McpSession.objects.filter(
                agent=agent,
                key=key,
                revoked_at__isnull=True,
                ended_at__isnull=True,
            )
            .order_by('-last_seen_at')
            .first()
        )
        fields = {
            'transport': transport,
            'client_name': request.data.get('client_name') or '',
            'client_version': request.data.get('client_version') or '',
            'user_agent': request.META.get('HTTP_USER_AGENT', '')[:300],
            'source_ip': client_ip(request),
            'agent': agent,
            'provider': identity['provider'],
            'ide': identity['ide'],
            'device_id': identity['device_id'],
            'os_name': identity['os_name'],
            'hostname': identity['hostname'],
            'agent_username': identity['username'],
            'last_seen_at': now,
        }
        if live:
            for name, value in fields.items():
                setattr(live, name, value)
            live.save(update_fields=list(fields.keys()))
            return Response({'session_id': str(live.id), 'agent_id': agent_id, 'reused': True})
        session = McpSession.objects.create(key=key, user=request.user, **fields)
        McpAuditEvent.objects.create(
            session=session,
            key=key,
            user=request.user,
            tool_name='session_open',
            method='POST',
            path='/api/mcp/sessions/',
            status_code=201,
            duration_ms=0,
            request_body={
                'transport': transport,
                'client_name': session.client_name,
                'agent_id': agent_id,
                'provider': identity['provider'],
                'key_name': key.name,
            },
            response_body={'session_id': str(session.id), 'agent_id': agent_id},
        )
        return Response(
            {'session_id': str(session.id), 'agent_id': agent_id, 'reused': False},
            status=status.HTTP_201_CREATED,
        )


class McpSessionHeartbeatView(APIView):
    authentication_classes = [McpApiKeyAuthentication]
    permission_classes = [IsAuthenticated]
    http_method_names = ['post', 'options']

    def post(self, request, pk):
        key = getattr(request, 'mcp_key', None)
        session = getattr(request, 'mcp_session', None)
        if key is None:
            return Response({'error': 'MCP API key required'}, status=status.HTTP_401_UNAUTHORIZED)
        if session is None or str(session.id) != str(pk):
            return Response(
                {'error': 'MCP session invalid or revoked. Reconnect or use a new session; the API key may still be valid.'},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        session.last_seen_at = timezone.now()
        session.save(update_fields=['last_seen_at'])
        if session.agent_id:
            McpAgent.objects.filter(pk=session.agent_id).update(last_seen_at=session.last_seen_at)
        return Response(status=status.HTTP_204_NO_CONTENT)


class McpSessionEndView(APIView):
    authentication_classes = [McpApiKeyAuthentication]
    permission_classes = [IsAuthenticated]
    http_method_names = ['post', 'options']

    def post(self, request, pk):
        session = getattr(request, 'mcp_session', None)
        if session is None or str(session.id) != str(pk):
            return Response(
                {'error': 'MCP session invalid or revoked. Reconnect or use a new session; the API key may still be valid.'},
                status=status.HTTP_401_UNAUTHORIZED,
            )
        session.ended_at = timezone.now()
        session.save(update_fields=['ended_at'])
        McpAuditEvent.objects.create(
            session=session,
            key=session.key,
            user=request.user,
            tool_name='session_end',
            method='POST',
            path=request.path,
            status_code=200,
            duration_ms=0,
            request_body={},
            response_body={'status': 'ended'},
        )
        return Response({'status': 'ended'})


class McpSessionRevokeView(APIView):
    authentication_classes = [JWTAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    http_method_names = ['post', 'options']

    def post(self, request, pk):
        session = _owned_or_admin_session(request, pk)
        if session is None:
            return Response({'error': 'Not found'}, status=status.HTTP_404_NOT_FOUND)
        if session.agent:
            ban_agent(session.agent, user=request.user, revoke_sessions=True)
            session.refresh_from_db()
        else:
            session.revoked_at = timezone.now()
            session.save(update_fields=['revoked_at'])
        return Response(_serialize_session(session))


class McpAgentDeleteView(APIView):
    authentication_classes = [JWTAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    http_method_names = ['delete', 'options']

    def delete(self, request, agent_id):
        if not _is_admin(request.user):
            return Response({'error': 'Only a sys-admin can delete MCP agents.'}, status=status.HTTP_403_FORBIDDEN)
        parsed = parse_agent_id(agent_id)
        if not parsed:
            return Response({'error': 'Invalid agent_id'}, status=status.HTTP_400_BAD_REQUEST)
        persist_ban = request.data.get('persist_ban')
        if persist_ban is None:
            persist_ban = request.query_params.get('persist_ban')
        if isinstance(persist_ban, str):
            persist_ban = persist_ban.lower() in ('1', 'true', 'yes')
        if persist_ban is None:
            return Response(
                {'error': 'persist_ban is required (true keeps the ban, false unbans).'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        agent = McpAgent.objects.filter(pk=parsed).first()
        sessions = McpSession.objects.filter(agent_id=parsed)
        live = [
            row for row in sessions
            if row.revoked_at is None and row.ended_at is None and row.is_connected()
        ]
        McpAuditEvent.objects.filter(session__agent_id=parsed).delete()
        if persist_ban:
            if agent:
                ban_agent(agent, user=request.user, revoke_sessions=True)
            else:
                from mcp.models import McpAgentBan
                McpAgentBan.objects.update_or_create(
                    agent_id=parsed,
                    defaults={'banned_by': request.user, 'user': request.user},
                )
            McpSession.objects.filter(agent_id=parsed).delete()
            McpAgent.objects.filter(pk=parsed).delete()
            return Response({
                'deleted': True,
                'persist_ban': True,
                'unbanned': False,
                'audit_logs_removed': True,
            })
        unban_agent_id(parsed)
        live_ids = {row.id for row in live}
        McpSession.objects.filter(agent_id=parsed).exclude(id__in=live_ids).delete()
        if not live_ids:
            McpAgent.objects.filter(pk=parsed).delete()
        return Response({
            'deleted': True,
            'persist_ban': False,
            'unbanned': True,
            'audit_logs_removed': True,
            'live_sessions_kept': len(live_ids),
        })
