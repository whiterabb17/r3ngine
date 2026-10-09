from django.test import TestCase
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role
from django.contrib.auth import get_user_model

from mcp.keys import display_prefix, generate_mcp_secret, hash_mcp_secret
from mcp.models import McpApiKey

User = get_user_model()

FORBIDDEN_METHODS = {'DELETE', 'PUT'}

# SAFE validation endpoints (interpret/enrich only), covered by test_mcp_validation.
PATCH_ENRICH_PATTERNS = {
    'vulnerabilities/<int:pk>/enrich/',
    'vulnerabilities/<int:pk>/validation/',
    'attack-paths/<str:path_id>/enrich/',
}


def mcp_client_with_session(user):
    secret = generate_mcp_secret()
    McpApiKey.objects.create(
        user=user,
        name='k',
        prefix=display_prefix(secret),
        key_hash=hash_mcp_secret(secret),
    )
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f'Bearer {secret}')
    sid = client.post('/api/mcp/sessions/', {
        'transport': 'stdio',
        'client_name': 'test',
        'client_version': '0',
        'agent_id': hash_mcp_secret(secret),
        'provider': 'test',
        'ide': 'test',
        'device_id': 'test-device',
        'hostname': 'test-host',
        'username': user.username,
    }, format='json').json()['session_id']
    client.credentials(
        HTTP_AUTHORIZATION=f'Bearer {secret}',
        HTTP_X_MCP_SESSION_ID=str(sid),
    )
    return client


class McpAllowlistTests(TestCase):
    def test_no_delete_or_put(self):
        from mcp import urls as mcp_urls
        for pattern in mcp_urls.urlpatterns:
            callback = getattr(pattern, 'callback', None)
            view = getattr(callback, 'view_class', None)
            if not view:
                continue
            methods = set(m.upper() for m in view.http_method_names) - {'OPTIONS', 'HEAD'}
            if 'DELETE' in methods:
                self.assertIn('agents', str(pattern.pattern))
                methods = methods - {'DELETE'}
            self.assertTrue(methods.isdisjoint(FORBIDDEN_METHODS), msg=str(pattern.pattern))
            if 'PATCH' in methods:
                pattern_s = str(pattern.pattern)
                self.assertTrue(
                    'settings' in pattern_s
                    or 'notes' in pattern_s
                    or pattern_s in PATCH_ENRICH_PATTERNS,
                    msg=pattern_s,
                )

    def test_mcp_key_cannot_delete_vulnerability(self):
        user = User.objects.create_user(username='allow', password='x')
        assign_role(user, 'penetration_tester')
        mcp_client = mcp_client_with_session(user)
        res = mcp_client.get('/api/action/vulnerability/delete/')
        self.assertIn(res.status_code, (401, 302, 403))
        res = mcp_client.post('/api/action/vulnerability/delete/', {'rows': [1]}, format='json')
        self.assertIn(res.status_code, (401, 302, 403))
