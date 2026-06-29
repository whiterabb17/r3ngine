from unittest.mock import patch, MagicMock
from django.test import TestCase
from django.utils import timezone

from startScan.models import OsintStaging, ScanHistory
from targetApp.models import Domain
from scanEngine.models import EngineType


class TestSpiderfootBatchEnrichment(TestCase):
    """Integration tests: _process_spiderfoot_batch → OsintStaging.metadata enrichment."""

    def setUp(self):
        self.domain = Domain.objects.create(name='parser-test.com')
        engine = EngineType.objects.create(engine_name='TestEngine')
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_status=0,
            start_scan_date=timezone.now(),
            scan_type=engine,
        )

    def _make_event(self, osint_type, data, source_data='parser-test.com', sf_type='', confidence=65):
        return {
            'osint_type': osint_type,
            'data': data,
            'source_data': source_data,
            'type': sf_type,
            'source': 'sfp_test',
            'confidence': confidence,
            'iocs': {},
        }

    def _run_batch(self, events):
        """Run a batch through _process_spiderfoot_batch with a minimal self-like context."""
        from reNgine.tasks.osint import _process_spiderfoot_batch

        class FakeSelf:
            scan = self.scan
            domain = self.domain
            scan_id = self.scan.id
            activity_id = None

        _process_spiderfoot_batch(FakeSelf(), events, {}, 'parser-test.com')

    def test_ssl_event_stores_enriched_metadata(self):
        events = [self._make_event(
            'SSL', "CN=api.parser-test.com, O=Let's Encrypt, C=US",
            source_data='api.parser-test.com',
            sf_type='SSL_CERTIFICATE_ISSUED_TO',
        )]
        self._run_batch(events)
        staging = OsintStaging.objects.filter(scan_history=self.scan, osint_type='SSL').first()
        self.assertIsNotNone(staging)
        self.assertIn('host', staging.metadata)
        self.assertIn('subject_cn', staging.metadata)
        self.assertEqual(staging.metadata['subject_cn'], 'api.parser-test.com')

    def test_dns_event_stores_record_type(self):
        events = [self._make_event(
            'DNS', 'v=spf1 ~all',
            source_data='parser-test.com',
            sf_type='DNS_TXT_RECORD',
        )]
        self._run_batch(events)
        staging = OsintStaging.objects.filter(scan_history=self.scan, osint_type='DNS').first()
        self.assertIsNotNone(staging)
        self.assertEqual(staging.metadata.get('record_type'), 'TXT')

    def test_phone_event_stores_phone_number(self):
        events = [self._make_event('Phone', '+1-555-000-0000', source_data='https://parser-test.com')]
        self._run_batch(events)
        staging = OsintStaging.objects.filter(scan_history=self.scan, osint_type='Phone').first()
        self.assertIsNotNone(staging)
        self.assertEqual(staging.metadata.get('phone_number'), '+1-555-000-0000')

    def test_social_event_stores_platform(self):
        events = [self._make_event('Social', 'https://linkedin.com/in/test-user')]
        self._run_batch(events)
        staging = OsintStaging.objects.filter(scan_history=self.scan, osint_type='Social').first()
        self.assertIsNotNone(staging)
        self.assertEqual(staging.metadata.get('platform'), 'LinkedIn')

    def test_os_event_stores_os_name(self):
        events = [self._make_event('OS', 'Ubuntu 22.04', source_data='192.0.2.1')]
        self._run_batch(events)
        staging = OsintStaging.objects.filter(scan_history=self.scan, osint_type='OS').first()
        self.assertIsNotNone(staging)
        self.assertEqual(staging.metadata.get('os_name'), 'Ubuntu 22.04')

    def test_crypto_event_stores_address(self):
        events = [self._make_event('Crypto', '1A1zP1eP5QGefi2DMPTfTL5SLmv7Divf')]
        self._run_batch(events)
        staging = OsintStaging.objects.filter(scan_history=self.scan, osint_type='Crypto').first()
        self.assertIsNotNone(staging)
        self.assertEqual(staging.metadata.get('address_type'), 'BTC')

    def test_hosting_event_stores_co_hosted_domain(self):
        events = [self._make_event('Hosting', 'co-tenant.example.net')]
        self._run_batch(events)
        staging = OsintStaging.objects.filter(scan_history=self.scan, osint_type='Hosting').first()
        self.assertIsNotNone(staging)
        self.assertEqual(staging.metadata.get('co_hosted_domain'), 'co-tenant.example.net')
