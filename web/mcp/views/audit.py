import logging
import time

from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework_simplejwt.authentication import JWTAuthentication
from rolepermissions.checkers import has_role

from mcp.audit import write_audit_event
from mcp.models import McpAuditEvent, McpSession
from mcp.pagination import page_queryset

logger = logging.getLogger(__name__)


def _is_admin(user):
    return bool(user and (user.is_superuser or has_role(user, 'sys_admin')))


def _event_queryset():
    return McpAuditEvent.objects.select_related(
        'user', 'key', 'session', 'session__agent', 'session__key',
    )


def _serialize_event(row):
    session = row.session
    agent = session.agent if session is not None else None
    key = row.key or (session.key if session is not None else None)
    agent_id = ''
    if session is not None and session.agent_id:
        agent_id = session.agent_id
    elif agent is not None:
        agent_id = agent.id
    return {
        'id': row.id,
        'session_id': str(row.session_id) if row.session_id else None,
        'created_at': row.created_at.isoformat() if row.created_at else None,
        'tool_name': row.tool_name,
        'method': row.method,
        'path': row.path,
        'status_code': row.status_code,
        'duration_ms': row.duration_ms,
        'request_body': row.request_body,
        'response_body': row.response_body,
        'truncated': row.truncated,
        'error_message': row.error_message,
        'username': row.user.username if row.user_id else None,
        'agent_id': agent_id or None,
        'provider': ((session.provider if session else '') or (agent.provider if agent else '')),
        'ide': ((session.ide if session else '') or (agent.ide if agent else '')),
        'hostname': ((session.hostname if session else '') or (agent.hostname if agent else '')),
        'os_name': ((session.os_name if session else '') or (agent.os_name if agent else '')),
        'agent_username': (
            (session.agent_username if session else '') or (agent.username if agent else '')
        ),
        'key_id': key.id if key else None,
        'key_name': key.name if key else '',
        'key_prefix': key.prefix if key else '',
        'transport': session.transport if session else '',
        'client_name': session.client_name if session else '',
    }


class McpAuditedAPIView(APIView):
    def dispatch(self, request, *args, **kwargs):
        started = time.monotonic()
        response = super().dispatch(request, *args, **kwargs)
        duration_ms = int((time.monotonic() - started) * 1000)
        audited = getattr(self, 'request', request)
        if getattr(audited, 'mcp_key', None) is None:
            return response
        request_body = getattr(audited, 'data', None)
        if hasattr(request_body, 'dict'):
            request_body = request_body.dict()
        response_body = getattr(response, 'data', None)
        error_message = ''
        if isinstance(response_body, dict):
            error_message = str(response_body.get('detail') or response_body.get('error') or '')
        try:
            write_audit_event(
                request=audited,
                status_code=getattr(response, 'status_code', 0),
                duration_ms=duration_ms,
                request_body=request_body if isinstance(request_body, (dict, list)) else None,
                response_body=response_body if isinstance(response_body, (dict, list)) else None,
                error_message=error_message,
            )
        except Exception:
            # The tool call already ran; losing its audit row must never go unnoticed.
            logger.exception(
                "MCP audit write failed for %s %s (key=%s)",
                audited.method, audited.path, getattr(audited.mcp_key, 'pk', None),
            )
        return response


class McpSessionEventsView(APIView):
    authentication_classes = [JWTAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    http_method_names = ['get', 'head', 'options']

    def get(self, request, pk):
        session = McpSession.objects.filter(pk=pk).first()
        if session is None:
            return Response({'error': 'Not found'}, status=404)
        if session.user_id != request.user.id and not _is_admin(request.user):
            return Response({'error': 'Not found'}, status=404)
        if session.agent_id:
            qs = _event_queryset().filter(
                session__agent_id=session.agent_id,
                session__user_id=session.user_id,
            ).order_by('created_at')
        else:
            qs = _event_queryset().filter(session=session).order_by('created_at')
        return Response(page_queryset(qs, request, _serialize_event))


class McpAuditListView(APIView):
    authentication_classes = [JWTAuthentication, SessionAuthentication]
    permission_classes = [IsAuthenticated]
    http_method_names = ['get', 'head', 'options']

    def get(self, request):
        qs = _event_queryset().order_by('-created_at')
        if not (request.query_params.get('all') == '1' and _is_admin(request.user)):
            qs = qs.filter(user=request.user)
        tool_name = request.query_params.get('tool_name')
        if tool_name:
            qs = qs.filter(tool_name=tool_name)
        session_id = request.query_params.get('session_id')
        if session_id:
            qs = qs.filter(session_id=session_id)
        status_code = request.query_params.get('status_code')
        if status_code:
            try:
                qs = qs.filter(status_code=int(status_code))
            except (TypeError, ValueError):
                pass
        since = request.query_params.get('from')
        until = request.query_params.get('to')
        if since:
            qs = qs.filter(created_at__gte=since)
        if until:
            qs = qs.filter(created_at__lte=until)
        return Response(page_queryset(qs, request, _serialize_event))
