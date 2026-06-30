"""Tests for AddManualSubdomain API view behaviour."""
from django.test import TestCase


class AddManualSubdomainSizeCapTest(TestCase):
    """Posting more than 500 subdomains must be rejected with HTTP 400."""

    def test_too_many_subdomains_rejected(self):
        from api.views import AddManualSubdomain
        from rest_framework.test import APIRequestFactory
        from unittest.mock import patch, MagicMock

        factory = APIRequestFactory()
        big_input = '\n'.join(f'sub{i}.example.com' for i in range(501))
        request = factory.post(
            '/api/action/subdomain/add/',
            {'target_id': 1, 'subdomain_name': big_input},
            format='json',
        )

        with patch('api.views.targets.Domain') as mock_domain_cls:
            mock_domain = MagicMock()
            mock_domain.target_type = 'domain'
            mock_domain.name = 'example.com'
            mock_domain_cls.objects.filter.return_value.first.return_value = mock_domain

            view = AddManualSubdomain.as_view()
            # Bypass permission check for unit test
            with patch('api.views.AddManualSubdomain.permission_classes', []):
                response = view(request)

        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.data['status'])
        self.assertIn('500', response.data['message'])


class AddManualSubdomainStatusCodesTest(TestCase):
    """Error responses from AddManualSubdomain must use correct HTTP status codes."""

    def _make_request(self, body):
        from rest_framework.test import APIRequestFactory
        factory = APIRequestFactory()
        return factory.post('/api/action/subdomain/add/', body, format='json')

    def test_missing_subdomain_name_returns_400(self):
        from api.views import AddManualSubdomain
        from unittest.mock import patch
        request = self._make_request({'target_id': 1})
        view = AddManualSubdomain.as_view()
        with patch('api.views.AddManualSubdomain.permission_classes', []):
            response = view(request)
        self.assertEqual(response.status_code, 400)

    def test_domain_not_found_returns_404(self):
        from api.views import AddManualSubdomain
        from unittest.mock import patch, MagicMock
        request = self._make_request({'target_id': 99999, 'subdomain_name': 'sub.example.com'})
        view = AddManualSubdomain.as_view()
        with patch('api.views.AddManualSubdomain.permission_classes', []):
            with patch('api.views.targets.Domain') as mock_domain_cls:
                mock_domain_cls.objects.filter.return_value.first.return_value = None
                response = view(request)
        self.assertEqual(response.status_code, 404)
