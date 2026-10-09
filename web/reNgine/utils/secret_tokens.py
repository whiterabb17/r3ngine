"""Bearer secrets that are shown once and stored only as a hash.

Used for MCP API keys and remote worker tokens. The secrets are 256-bit random
values, so a plain SHA-256 digest is enough; a slow password hash would only add
latency to every authenticated request.
"""
import hashlib
import hmac
import secrets


def generate_token(prefix: str = '') -> str:
    return prefix + secrets.token_urlsafe(32)


def hash_token(token: str) -> str:
    return hashlib.sha256(token.encode('utf-8')).hexdigest()


def token_matches(token: str, token_hash: str) -> bool:
    """Compare a presented token against a stored hash in constant time."""
    return hmac.compare_digest(hash_token(token), token_hash)
