from django.test import TestCase
from django.utils import timezone
from unittest.mock import patch
from reNgine.tasks.osint import _enrich_metadata, persist_osint_item
from startScan.models import DnsRecord, CertificateIntelligence, Employee
from targetApp.models import Domain
from startScan.models import ScanHistory


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


class TestTypeRouterDispatch(TestCase):

    def setUp(self):
        from targetApp.models import Domain
        from startScan.models import ScanHistory
        from scanEngine.models import EngineType
        self.domain = Domain.objects.create(name='dispatch-test.com')
        self.engine = EngineType.objects.create(engine_name='Dispatch Test Engine')
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_status=0,
            start_scan_date=timezone.now(),
            scan_type=self.engine,
        )

    @patch('reNgine.tasks.osint.save_subdomain')
    def test_subdomain_dispatches(self, mock_save):
        persist_osint_item(
            self.scan, self.domain, 'Subdomain', 'sub.dispatch-test.com', 90,
        )
        mock_save.assert_called_once()

    @patch('reNgine.tasks.osint.save_email')
    def test_email_dispatches(self, mock_save):
        persist_osint_item(
            self.scan, self.domain, 'Email', 'user@dispatch-test.com', 90,
        )
        mock_save.assert_called_once()

    @patch('reNgine.tasks.osint.save_employee')
    def test_employee_dispatches(self, mock_save):
        persist_osint_item(
            self.scan, self.domain, 'Employee', 'Jane Doe', 90,
        )
        mock_save.assert_called_once()

    @patch('reNgine.tasks.osint.save_endpoint')
    def test_url_dispatches_valid_url(self, mock_save):
        persist_osint_item(
            self.scan, self.domain, 'URL', 'https://dispatch-test.com/path', 90,
        )
        mock_save.assert_called_once()

    @patch('reNgine.tasks.osint.save_endpoint')
    def test_url_skips_invalid_url(self, mock_save):
        persist_osint_item(
            self.scan, self.domain, 'URL', 'not-a-url', 90,
        )
        mock_save.assert_not_called()

    def test_unknown_type_does_not_raise(self):
        # Should log and return silently
        try:
            persist_osint_item(
                self.scan, self.domain, 'TOTALLY_UNKNOWN', 'data', 90,
            )
        except Exception as exc:
            self.fail(f"persist_osint_item raised unexpectedly: {exc}")


class TestHandleSsl(TestCase):

    def setUp(self):
        from targetApp.models import Domain
        from startScan.models import ScanHistory
        from scanEngine.models import EngineType
        self.domain = Domain.objects.create(name='ssl-test.com')
        engine = EngineType.objects.create(engine_name='SSL Test Engine')
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_status=0,
            start_scan_date=timezone.now(),
            scan_type=engine,
        )
        self.scan.results_dir = '/tmp/scan_results'

    @patch('reNgine.tasks.osint.run_certificate_intel')
    def test_ssl_with_host_and_results_dir_calls_cert_intel(self, mock_run):
        persist_osint_item(
            self.scan, self.domain, 'SSL',
            "CN=api.ssl-test.com, O=Let's Encrypt",
            70,
            source_data='api.ssl-test.com',
            metadata={
                'host': 'api.ssl-test.com',
                'subject_cn': 'api.ssl-test.com',
                'issuer': "Let's Encrypt",
            },
        )
        mock_run.assert_called_once_with(self.scan.id, '/tmp/scan_results')

    @patch('reNgine.tasks.osint.run_certificate_intel')
    def test_ssl_without_host_creates_partial_cert(self, mock_run):
        persist_osint_item(
            self.scan, self.domain, 'SSL',
            "CN=unknown-host.com",
            70,
            metadata={'host': '', 'subject_cn': 'unknown-host.com', 'issuer': None},
        )
        mock_run.assert_not_called()
        self.assertTrue(
            CertificateIntelligence.objects.filter(
                target_domain=self.domain,
                subject_cn='unknown-host.com',
            ).exists()
        )

    @patch('reNgine.tasks.osint.run_certificate_intel', side_effect=Exception('tlsx error'))
    def test_ssl_falls_back_to_partial_on_error(self, mock_run):
        self.scan.results_dir = '/tmp/scan_results'
        persist_osint_item(
            self.scan, self.domain, 'SSL',
            "CN=fallback.ssl-test.com, O=DigiCert",
            70,
            source_data='fallback.ssl-test.com',
            metadata={
                'host': 'fallback.ssl-test.com',
                'subject_cn': 'fallback.ssl-test.com',
                'issuer': 'DigiCert',
            },
        )
        self.assertTrue(
            CertificateIntelligence.objects.filter(
                target_domain=self.domain,
                host='fallback.ssl-test.com',
            ).exists()
        )


class TestHandleDns(TestCase):

    def setUp(self):
        from targetApp.models import Domain
        from startScan.models import ScanHistory
        from scanEngine.models import EngineType
        self.domain = Domain.objects.create(name='dns-test.com')
        engine = EngineType.objects.create(engine_name='DNS Test Engine')
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_status=0,
            start_scan_date=timezone.now(),
            scan_type=engine,
        )

    def test_dns_creates_txt_record(self):
        persist_osint_item(
            self.scan, self.domain, 'DNS',
            'v=spf1 include:_spf.dns-test.com ~all',
            65,
            source_data='dns-test.com',
            metadata={'record_type': 'TXT', 'hostname': 'dns-test.com', 'value': 'v=spf1 include:_spf.dns-test.com ~all'},
        )
        self.assertTrue(
            DnsRecord.objects.filter(
                scan_history=self.scan,
                record_type='TXT',
                value='v=spf1 include:_spf.dns-test.com ~all',
            ).exists()
        )

    def test_dns_links_subdomain_when_found(self):
        from startScan.models import Subdomain
        sub = Subdomain.objects.create(name='dns-test.com', scan_history=self.scan, target_domain=self.domain)
        persist_osint_item(
            self.scan, self.domain, 'DNS',
            'ns1.dns-test.com',
            60,
            source_data='dns-test.com',
            metadata={'record_type': 'NS', 'hostname': 'dns-test.com', 'value': 'ns1.dns-test.com'},
        )
        record = DnsRecord.objects.get(scan_history=self.scan, record_type='NS')
        self.assertEqual(record.subdomain, sub)

    def test_dns_idempotent_on_duplicate(self):
        for _ in range(2):
            persist_osint_item(
                self.scan, self.domain, 'DNS',
                'mail.dns-test.com',
                60,
                metadata={'record_type': 'MX', 'hostname': 'dns-test.com', 'value': 'mail.dns-test.com'},
            )
        self.assertEqual(
            DnsRecord.objects.filter(scan_history=self.scan, record_type='MX').count(), 1
        )


class TestHandlePhone(TestCase):

    def setUp(self):
        from scanEngine.models import EngineType
        self.domain = Domain.objects.create(name='phone-test.com')
        engine = EngineType.objects.create(engine_name='Phone Test Engine')
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_status=0,
            start_scan_date=timezone.now(),
            scan_type=engine,
        )

    def test_phone_creates_employee_with_metadata(self):
        persist_osint_item(
            self.scan, self.domain, 'Phone',
            '+1-555-867-5309', 75,
            source_data='https://phone-test.com/contact',
            metadata={'phone_number': '+1-555-867-5309', 'source_url': 'https://phone-test.com/contact'},
        )
        emp = Employee.objects.filter(metadata__type='phone').first()
        self.assertIsNotNone(emp)
        self.assertEqual(emp.metadata['phone'], '+1-555-867-5309')
        self.assertIn(emp, self.scan.employees.all())

    def test_phone_name_is_none(self):
        persist_osint_item(
            self.scan, self.domain, 'Phone',
            '+44-20-1234-5678', 75,
            metadata={'phone_number': '+44-20-1234-5678', 'source_url': ''},
        )
        emp = Employee.objects.filter(metadata__type='phone').first()
        self.assertIsNone(emp.name)


class TestHandleSocial(TestCase):

    def setUp(self):
        from scanEngine.models import EngineType
        self.domain = Domain.objects.create(name='social-test.com')
        engine = EngineType.objects.create(engine_name='Social Test Engine')
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_status=0,
            start_scan_date=timezone.now(),
            scan_type=engine,
        )

    def test_social_creates_employee_with_platform(self):
        persist_osint_item(
            self.scan, self.domain, 'Social',
            'https://linkedin.com/in/jane-doe', 75,
            metadata={'platform': 'LinkedIn', 'profile_url': 'https://linkedin.com/in/jane-doe'},
        )
        emp = Employee.objects.filter(metadata__type='social').first()
        self.assertIsNotNone(emp)
        self.assertEqual(emp.metadata['platform'], 'LinkedIn')
        self.assertIn(emp, self.scan.employees.all())


class TestHandleOs(TestCase):

    def setUp(self):
        from scanEngine.models import EngineType
        self.domain = Domain.objects.create(name='os-test.com')
        engine = EngineType.objects.create(engine_name='OS Test Engine')
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_status=0,
            start_scan_date=timezone.now(),
            scan_type=engine,
        )

    def test_os_creates_technology(self):
        from startScan.models import Technology
        persist_osint_item(
            self.scan, self.domain, 'OS',
            'Ubuntu 22.04', 80,
            source_data='192.0.2.1',
            metadata={'os_name': 'Ubuntu 22.04', 'source_host': '192.0.2.1'},
        )
        self.assertTrue(Technology.objects.filter(name='Ubuntu 22.04').exists())

    def test_os_links_technology_to_subdomain(self):
        from startScan.models import Technology, Subdomain
        sub = Subdomain.objects.create(name='192.0.2.1', scan_history=self.scan, target_domain=self.domain)
        persist_osint_item(
            self.scan, self.domain, 'OS',
            'CentOS 7', 80,
            source_data='192.0.2.1',
            metadata={'os_name': 'CentOS 7', 'source_host': '192.0.2.1'},
        )
        tech = Technology.objects.get(name='CentOS 7')
        self.assertIn(tech, sub.technologies.all())
