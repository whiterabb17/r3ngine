from django.contrib.auth import get_user_model
from django.test import TestCase

User = get_user_model()


class McpKeyCryptoTests(TestCase):
    def test_secret_has_prefix_and_is_long(self):
        from mcp.keys import generate_mcp_secret
        secret = generate_mcp_secret()
        self.assertTrue(secret.startswith('r3n_mcp_'))
        self.assertGreaterEqual(len(secret), 40)

    def test_hash_is_sha256_hex_and_not_plaintext(self):
        from mcp.keys import generate_mcp_secret, hash_mcp_secret
        secret = generate_mcp_secret()
        digest = hash_mcp_secret(secret)
        self.assertEqual(len(digest), 64)
        self.assertNotIn(secret, digest)

    def test_prefix_is_first_16_chars(self):
        from mcp.keys import display_prefix
        secret = 'r3n_mcp_ab12cd34RESTOFSECRET'
        self.assertEqual(display_prefix(secret), 'r3n_mcp_ab12cd34')

    def test_compare_is_true_for_match_false_for_mismatch(self):
        from mcp.keys import generate_mcp_secret, hash_mcp_secret, secrets_match
        secret = generate_mcp_secret()
        digest = hash_mcp_secret(secret)
        self.assertTrue(secrets_match(secret, digest))
        self.assertFalse(secrets_match(secret + 'x', digest))


class McpApiKeyModelTests(TestCase):
    def test_create_stores_hash_not_secret(self):
        from mcp.keys import generate_mcp_secret, hash_mcp_secret, display_prefix
        from mcp.models import McpApiKey
        user = User.objects.create_user(username='mcp-owner', password='x')
        secret = generate_mcp_secret()
        row = McpApiKey.objects.create(
            user=user,
            name='cursor',
            prefix=display_prefix(secret),
            key_hash=hash_mcp_secret(secret),
        )
        self.assertFalse(hasattr(row, 'key') and getattr(row, 'key') == secret)
        self.assertEqual(row.key_hash, hash_mcp_secret(secret))
        self.assertIsNone(row.revoked_at)
