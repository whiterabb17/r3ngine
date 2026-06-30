"""Regression tests for PR #66 merge fixes."""
from unittest.mock import patch, MagicMock
from django.test import TestCase
from rest_framework.test import APIRequestFactory


class SubdomainHasIpFilterTest(TestCase):
    """has_ip query parameter must filter the subdomain queryset."""

    def _get_queryset(self, has_ip_value):
        from api.views import SubdomainDatatableViewSet
        factory = APIRequestFactory()
        url = f'/api/subdomains/?project=test&has_ip={has_ip_value}'
        request = factory.get(url)
        request.query_params = request.GET

        view = SubdomainDatatableViewSet()
        view.request = request
        view.format_kwarg = None

        mock_qs = MagicMock()
        mock_qs.filter.return_value = mock_qs
        mock_qs.exclude.return_value = mock_qs
        mock_qs.distinct.return_value = mock_qs
        mock_qs.select_related.return_value = mock_qs
        mock_qs.prefetch_related.return_value = mock_qs
        mock_qs.order_by.return_value = mock_qs
        view.queryset = mock_qs

        with patch('api.views.Subdomain') as mock_subdomain_cls, \
             patch('api.views.SubdomainDatatableViewSet._latest_subdomain_rows_by_name', return_value=mock_qs):
            mock_subdomain_cls.objects.filter.return_value = mock_qs
            mock_subdomain_cls.objects.all.return_value = mock_qs
            view.get_queryset()

        return mock_qs

    def test_has_ip_true_applies_filter(self):
        qs = self._get_queryset('true')
        # filter(ip_addresses__isnull=False) must have been called
        found = any(
            kwargs.get('ip_addresses__isnull') is False
            for _, kwargs in [c for c in qs.filter.call_args_list]
        )
        self.assertTrue(found, "has_ip=true must add filter(ip_addresses__isnull=False)")

    def test_has_ip_false_applies_filter(self):
        qs = self._get_queryset('false')
        found = any(
            kwargs.get('ip_addresses__isnull') is True
            for _, kwargs in [c for c in qs.filter.call_args_list]
        )
        self.assertTrue(found, "has_ip=false must add filter(ip_addresses__isnull=True)")


class LoggerFstringTest(TestCase):
    """_run_single_subscan must not use f-string log calls (Rule 2.1)."""

    def test_no_fstring_in_run_single_subscan(self):
        import ast, inspect
        from api import views as api_views
        source = inspect.getsource(api_views)
        tree = ast.parse(source)

        violations = []
        for node in ast.walk(tree):
            # Find logger.info / logger.exception / logger.warning calls
            if not isinstance(node, ast.Call):
                continue
            if not (isinstance(node.func, ast.Attribute) and node.func.attr in ('info', 'exception', 'warning', 'error', 'debug')):
                continue
            if not (isinstance(node.func.value, ast.Name) and node.func.value.id == 'logger'):
                continue
            # Check if any argument is an f-string (JoinedStr)
            for arg in node.args:
                if isinstance(arg, ast.JoinedStr):
                    violations.append(ast.get_source_segment(source, node) or str(ast.dump(node)))

        self.assertEqual(
            violations, [],
            f"f-string logger calls found (violates Rule 2.1):\n" + "\n".join(violations[:5])
        )


class ProxyTimeoutConsistencyTest(TestCase):
    """get_random_proxy must call check_proxy_robust with PROXY_VALIDATION_TIMEOUT, not a hardcoded value."""

    def test_uses_constant_not_hardcoded_10(self):
        import ast, inspect
        from reNgine import common_func
        source = inspect.getsource(common_func)
        tree = ast.parse(source)

        # Find calls to check_proxy_robust that pass a literal integer for timeout
        hardcoded_timeouts = []
        for node in ast.walk(tree):
            if not isinstance(node, ast.Call):
                continue
            func = node.func
            name = (func.id if isinstance(func, ast.Name)
                    else func.attr if isinstance(func, ast.Attribute) else None)
            if name != 'check_proxy_robust':
                continue
            for kw in node.keywords:
                if kw.arg == 'timeout' and isinstance(kw.value, ast.Constant):
                    hardcoded_timeouts.append(kw.value.value)

        self.assertEqual(
            hardcoded_timeouts, [],
            f"check_proxy_robust called with hardcoded timeout value(s): {hardcoded_timeouts}. "
            "Use PROXY_VALIDATION_TIMEOUT instead."
        )
