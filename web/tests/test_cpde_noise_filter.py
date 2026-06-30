"""Tests for CPDE correlation_engine noise filter."""
from django.test import TestCase


def _finding(name, confidence=60, context='url_discovery:gau'):
    return {
        'name': name,
        'location': 'query_string',
        'data_type': None,
        'source_url': f'https://example.com/?{name}=val',
        'confidence': confidence,
        'context': context,
        'is_auth_related': False,
    }


class TestNoiseFilter(TestCase):

    def test_utm_params_filtered(self):
        from reNgine.cpde.correlation_engine import correlate
        findings = [
            _finding('utm_source'),
            _finding('utm_medium'),
            _finding('utm_campaign'),
            _finding('utm_term'),
            _finding('utm_content'),
        ]
        result = correlate(findings)
        names = {r['name'] for r in result}
        self.assertNotIn('utm_source', names)
        self.assertNotIn('utm_medium', names)
        self.assertNotIn('utm_campaign', names)

    def test_click_tracking_params_filtered(self):
        from reNgine.cpde.correlation_engine import correlate
        findings = [
            _finding('fbclid'),
            _finding('gclid'),
            _finding('msclkid'),
        ]
        result = correlate(findings)
        names = {r['name'] for r in result}
        self.assertNotIn('fbclid', names)
        self.assertNotIn('gclid', names)
        self.assertNotIn('msclkid', names)

    def test_ga_params_filtered(self):
        from reNgine.cpde.correlation_engine import correlate
        findings = [_finding('_ga'), _finding('_gl'), _finding('_gid')]
        result = correlate(findings)
        names = {r['name'] for r in result}
        self.assertNotIn('_ga', names)
        self.assertNotIn('_gl', names)

    def test_security_params_not_filtered(self):
        """Params useful for security testing must pass through."""
        from reNgine.cpde.correlation_engine import correlate
        findings = [
            _finding('id'),
            _finding('user_id'),
            _finding('token'),
            _finding('password'),
            _finding('redirect'),
            _finding('url'),
            _finding('file'),
            _finding('path'),
            _finding('cmd'),
            _finding('query'),
        ]
        result = correlate(findings)
        names = {r['name'] for r in result}
        for expected in ('id', 'userid', 'token', 'password', 'redirect', 'url', 'file', 'path', 'cmd', 'query'):
            # Allow for name normalization (user_id → userid in dedup key, canonical keeps original)
            self.assertTrue(
                any(expected in n.lower().replace('_', '') for n in names),
                f"Expected '{expected}' to pass noise filter but it was removed. Remaining: {names}",
            )

    def test_noise_filter_applies_even_at_high_confidence(self):
        """Noise params must be blocked regardless of confidence score."""
        from reNgine.cpde.correlation_engine import correlate
        findings = [_finding('fbclid', confidence=90, context='openapi:GET:/path')]
        result = correlate(findings)
        names = {r['name'] for r in result}
        self.assertNotIn('fbclid', names)

    def test_noise_filter_can_be_disabled(self):
        """apply_noise_filter=False must let blocked params through."""
        from reNgine.cpde.correlation_engine import correlate
        findings = [_finding('utm_source', confidence=90)]
        result = correlate(findings, apply_noise_filter=False)
        names = {r['name'] for r in result}
        self.assertIn('utm_source', names)

    def test_normalized_noise_param_filtered(self):
        """utm-source (hyphen variant) normalizes to same key as utm_source."""
        from reNgine.cpde.correlation_engine import correlate
        findings = [_finding('utm-source')]
        result = correlate(findings)
        names = {r['name'] for r in result}
        self.assertNotIn('utm-source', names)

    def test_cloudflare_param_filtered(self):
        from reNgine.cpde.correlation_engine import correlate
        findings = [_finding('__cf_chl_captcha_tk__')]
        result = correlate(findings)
        names = {r['name'] for r in result}
        self.assertNotIn('__cf_chl_captcha_tk__', names)

    def test_legitimate_params_with_noise_present(self):
        """Noise params filtered but legitimate params in same batch preserved."""
        from reNgine.cpde.correlation_engine import correlate
        findings = [
            _finding('utm_source'),
            _finding('id'),
            _finding('fbclid'),
            _finding('user_id'),
        ]
        result = correlate(findings)
        names = {r['name'] for r in result}
        self.assertNotIn('utm_source', names)
        self.assertNotIn('fbclid', names)
        self.assertTrue(any('id' in n for n in names))
