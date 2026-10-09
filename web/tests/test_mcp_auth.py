from django.contrib.auth import get_user_model
from django.test import TestCase
from rest_framework.test import APIRequestFactory

from mcp.keys import generate_mcp_secret, hash_mcp_secret, display_prefix
from mcp.models import McpApiKey

User = get_user_model()


class McpAuthTests(TestCase):
    def setUp(self):
        self.factory = APIRequestFactory()
        self.user = User.objects.create_user(username='mcp-auth', password='x')
        self.secret = generate_mcp_secret()
        self.key = McpApiKey.objects.create(
            user=self.user,
            name='ide',
            prefix=display_prefix(self.secret),
            key_hash=hash_mcp_secret(self.secret),
        )

    def test_valid_key_authenticates(self):
        from mcp.authentication import McpApiKeyAuthentication
        request = self.factory.get('/api/mcp/health/', HTTP_AUTHORIZATION=f'Bearer {self.secret}')
        user, _ = McpApiKeyAuthentication().authenticate(request)
        self.assertEqual(user.username, 'mcp-auth')

    def test_revoked_key_fails(self):
        from django.utils import timezone
        from rest_framework.exceptions import AuthenticationFailed
        from mcp.authentication import McpApiKeyAuthentication
        self.key.revoked_at = timezone.now()
        self.key.save(update_fields=['revoked_at'])
        request = self.factory.get('/api/mcp/health/', HTTP_AUTHORIZATION=f'Bearer {self.secret}')
        with self.assertRaises(AuthenticationFailed):
            McpApiKeyAuthentication().authenticate(request)

    def test_jwt_shaped_bearer_is_skipped(self):
        from mcp.authentication import McpApiKeyAuthentication
        request = self.factory.get(
            '/api/mcp/health/',
            HTTP_AUTHORIZATION='Bearer eyJhbGciOiJIUzI1NiJ9.xx',
        )
        self.assertIsNone(McpApiKeyAuthentication().authenticate(request))
