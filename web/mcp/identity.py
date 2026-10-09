import re

from django.utils import timezone

from mcp.models import McpAgent, McpAgentBan, McpSession

AGENT_ID_RE = re.compile(r'^[0-9a-f]{64}$')
BANNED_MESSAGE = (
    'This MCP agent is banned. The API key may still be valid. '
    'A sys-admin can delete the agent and unban it from Settings → MCP Access.'
)


def parse_agent_id(raw):
    value = str(raw or '').strip().lower()
    if not AGENT_ID_RE.fullmatch(value):
        return None
    return value


def agent_is_banned(agent_id):
    if not agent_id:
        return False
    if McpAgentBan.objects.filter(agent_id=agent_id).exists():
        return True
    return McpAgent.objects.filter(pk=agent_id, banned_at__isnull=False).exists()


def ban_agent(agent, *, user=None, revoke_sessions=True):
    now = timezone.now()
    McpAgentBan.objects.update_or_create(
        agent_id=agent.id,
        defaults={
            'key': agent.key,
            'user': agent.user,
            'provider': agent.provider,
            'ide': agent.ide,
            'device_id': agent.device_id,
            'hostname': agent.hostname,
            'banned_by': user,
        },
    )
    agent.banned_at = now
    agent.banned_by = user
    agent.save(update_fields=['banned_at', 'banned_by'])
    if revoke_sessions:
        McpSession.objects.filter(agent=agent, revoked_at__isnull=True).update(revoked_at=now)
    return agent


def unban_agent_id(agent_id):
    McpAgentBan.objects.filter(agent_id=agent_id).delete()
    McpAgent.objects.filter(pk=agent_id).update(banned_at=None, banned_by=None)
