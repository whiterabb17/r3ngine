from django.test import RequestFactory, SimpleTestCase

from mcp.operator_gate import resolve_is_operator


class ResolveIsOperatorTests(SimpleTestCase):
    def setUp(self):
        self.factory = RequestFactory()

    def test_jwt_ui_is_operator(self):
        request = self.factory.post('/api/action/followups/1/update/')
        self.assertTrue(resolve_is_operator(request))

    def test_mcp_key_is_not_operator(self):
        request = self.factory.post('/api/mcp/safe-poc/1/update/')
        request.mcp_key = object()
        self.assertFalse(resolve_is_operator(request))

    def test_body_operator_flag_ignored_for_mcp(self):
        request = self.factory.post(
            '/api/mcp/safe-poc/1/update/',
            data='{"operator": true}',
            content_type='application/json',
        )
        request.mcp_key = object()
        # Even if middleware parsed operator=true, gate must ignore body.
        self.assertFalse(resolve_is_operator(request))

    def test_server_side_mcp_operator_marker(self):
        request = self.factory.post('/api/mcp/safe-poc/1/update/')
        request.mcp_key = object()
        request.mcp_operator = True
        self.assertTrue(resolve_is_operator(request))
