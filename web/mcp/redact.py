import json
import copy

REDACT_KEYS = {
    'authorization',
    'r3ngine_mcp_api_key',
    'cookie',
    'cookie_value',
    'cookies',
    'secret',
    'api_key',
    'password',
    'token',
}
MAX_BODY_BYTES = 65536
REDACTED = '[REDACTED]'


def _redact_walk(value):
    if isinstance(value, dict):
        out = {}
        for key, item in value.items():
            if str(key).lower() in REDACT_KEYS:
                out[key] = REDACTED
            else:
                out[key] = _redact_walk(item)
        return out
    if isinstance(value, list):
        return [_redact_walk(item) for item in value]
    return value


def redact_payload(value):
    """Return (redacted_value, truncated)."""
    if value is None:
        return None, False
    redacted = _redact_walk(copy.deepcopy(value))
    encoded = json.dumps(redacted, default=str)
    if len(encoded.encode('utf-8')) <= MAX_BODY_BYTES:
        return redacted, False
    preview = encoded.encode('utf-8')[:MAX_BODY_BYTES].decode('utf-8', errors='ignore')
    return {'truncated': True, 'preview': preview}, True
