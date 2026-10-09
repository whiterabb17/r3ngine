from mcp.models import McpAuditEvent
from mcp.redact import redact_payload
from mcp.tool_map import tool_name_for


def should_skip_audit(path: str) -> bool:
    normalized = path.rstrip('/')
    return normalized.endswith('/heartbeat')


def write_audit_event(
    *,
    request,
    status_code,
    duration_ms,
    request_body,
    response_body,
    tool_name=None,
    error_message='',
):
    if should_skip_audit(request.path):
        return
    req, truncated_req = redact_payload(request_body)
    res, truncated_res = redact_payload(response_body)
    user = getattr(request, 'user', None)
    if user is not None and not getattr(user, 'is_authenticated', False):
        user = None
    McpAuditEvent.objects.create(
        session=getattr(request, 'mcp_session', None),
        key=getattr(request, 'mcp_key', None),
        user=user,
        tool_name=tool_name or tool_name_for(request.method, request.path),
        method=request.method,
        path=request.path,
        status_code=status_code,
        duration_ms=duration_ms,
        request_body=req,
        response_body=res,
        truncated=truncated_req or truncated_res,
        error_message=error_message or '',
    )
