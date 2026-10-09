from reNgine.utils.secret_tokens import generate_token, hash_token, token_matches

MCP_KEY_PREFIX = 'r3n_mcp_'


def generate_mcp_secret() -> str:
    return generate_token(MCP_KEY_PREFIX)


def hash_mcp_secret(secret: str) -> str:
    return hash_token(secret)


def display_prefix(secret: str) -> str:
    return secret[:16]


def secrets_match(secret: str, key_hash: str) -> bool:
    return token_matches(secret, key_hash)
