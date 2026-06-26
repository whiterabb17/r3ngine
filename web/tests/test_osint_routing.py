from django.test import TestCase
from reNgine.tasks.osint import _enrich_metadata


class TestEnrichMetadata(TestCase):

    def _event(self, osint_type, data, source_data='example.com', sf_type=''):
        return {
            'osint_type': osint_type,
            'data': data,
            'source_data': source_data,
            'type': sf_type,
        }

    def test_ssl_parses_subject_cn(self):
        event = self._event('SSL', "CN=api.example.com, O=Let's Encrypt, C=US", sf_type='SSL_CERTIFICATE_ISSUED_TO')
        base = {'sf_type': 'SSL_CERTIFICATE_ISSUED_TO', 'source_data': 'api.example.com'}
        result = _enrich_metadata(event, base)
        self.assertEqual(result['subject_cn'], 'api.example.com')
        self.assertEqual(result["issuer"], "Let's Encrypt")
        self.assertEqual(result['host'], 'api.example.com')

    def test_ssl_preserves_base_metadata(self):
        event = self._event('SSL', 'CN=x.com', sf_type='SSL_CERTIFICATE_ISSUED_TO')
        base = {'sf_type': 'SSL_CERTIFICATE_ISSUED_TO', 'iocs': {}}
        result = _enrich_metadata(event, base)
        self.assertIn('iocs', result)

    def test_dns_txt_record(self):
        event = self._event('DNS', 'v=spf1 ~all', source_data='example.com', sf_type='DNS_TXT_RECORD')
        result = _enrich_metadata(event, {})
        self.assertEqual(result['record_type'], 'TXT')
        self.assertEqual(result['hostname'], 'example.com')
        self.assertEqual(result['value'], 'v=spf1 ~all')

    def test_dns_mx_record(self):
        event = self._event('DNS', 'mail.example.com', source_data='example.com', sf_type='DNS_MX_RECORD')
        result = _enrich_metadata(event, {})
        self.assertEqual(result['record_type'], 'MX')

    def test_dns_ns_record(self):
        event = self._event('DNS', 'ns1.example.com', source_data='example.com', sf_type='DNS_NS_RECORD')
        result = _enrich_metadata(event, {})
        self.assertEqual(result['record_type'], 'NS')

    def test_phone_number(self):
        event = self._event('Phone', '+1-555-867-5309', source_data='https://example.com/contact')
        result = _enrich_metadata(event, {})
        self.assertEqual(result['phone_number'], '+1-555-867-5309')
        self.assertEqual(result['source_url'], 'https://example.com/contact')

    def test_social_linkedin(self):
        event = self._event('Social', 'https://linkedin.com/in/jdoe', source_data='example.com')
        result = _enrich_metadata(event, {})
        self.assertEqual(result['platform'], 'LinkedIn')
        self.assertEqual(result['profile_url'], 'https://linkedin.com/in/jdoe')

    def test_social_twitter(self):
        event = self._event('Social', 'https://x.com/jdoe')
        result = _enrich_metadata(event, {})
        self.assertEqual(result['platform'], 'Twitter/X')

    def test_social_unknown_platform(self):
        event = self._event('Social', 'https://mastodon.social/@jdoe')
        result = _enrich_metadata(event, {})
        self.assertEqual(result['platform'], 'Unknown')

    def test_os(self):
        event = self._event('OS', 'Ubuntu 22.04', source_data='192.0.2.1')
        result = _enrich_metadata(event, {})
        self.assertEqual(result['os_name'], 'Ubuntu 22.04')
        self.assertEqual(result['source_host'], '192.0.2.1')

    def test_crypto_btc(self):
        event = self._event('Crypto', '1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf')
        result = _enrich_metadata(event, {})
        self.assertEqual(result['address_type'], 'BTC')
        self.assertEqual(result['address'], '1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf')

    def test_crypto_eth(self):
        event = self._event('Crypto', '0xAbCdEf1234567890AbCdEf1234567890AbCdEf12')
        result = _enrich_metadata(event, {})
        self.assertEqual(result['address_type'], 'ETH')

    def test_hosting(self):
        event = self._event('Hosting', 'co-tenant.example.net')
        result = _enrich_metadata(event, {})
        self.assertEqual(result['co_hosted_domain'], 'co-tenant.example.net')

    def test_unknown_type_passthrough(self):
        event = self._event('Unknown', 'some-data')
        base = {'sf_type': 'SOME_TYPE', 'iocs': {}}
        result = _enrich_metadata(event, base)
        self.assertEqual(result, base)  # no extra keys added
