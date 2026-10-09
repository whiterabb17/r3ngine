"""Request helpers shared by HTTP views."""
from typing import Optional

from django.http import HttpRequest


def client_ip(request: HttpRequest) -> Optional[str]:
    """Best-effort client address that a client cannot choose.

    The bundled nginx overwrites X-Real-IP with $remote_addr on every proxied
    location, so it carries the real peer. X-Forwarded-For is not used: nginx
    appends to whatever the client sent, so its left-most entry is spoofable.
    Without nginx in front (the app port is published on loopback only),
    REMOTE_ADDR is the peer.
    """
    raw = (request.META.get('HTTP_X_REAL_IP') or request.META.get('REMOTE_ADDR') or '').strip()
    if raw.startswith('[') and ']' in raw:
        return raw[1:raw.index(']')] or None
    # ASGI servers may put host:port in REMOTE_ADDR.
    if raw.count(':') == 1:
        host, port = raw.rsplit(':', 1)
        if port.isdigit():
            raw = host
    return raw or None
