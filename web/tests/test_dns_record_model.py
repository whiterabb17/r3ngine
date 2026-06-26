from django.test import TestCase
from django.db import IntegrityError
from django.utils import timezone
from startScan.models import DnsRecord, ScanHistory
from targetApp.models import Domain
from scanEngine.models import EngineType


class TestDnsRecordModel(TestCase):
    def setUp(self):
        self.domain = Domain.objects.create(name='example.com')
        self.engine = EngineType.objects.create(engine_name='basic')
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=0,
            start_scan_date=timezone.now(),
        )

    def test_create_dns_record(self):
        record = DnsRecord.objects.create(
            scan_history=self.scan,
            target_domain=self.domain,
            record_type='TXT',
            value='v=spf1 include:_spf.example.com ~all',
            source='sfp_dns',
        )
        self.assertEqual(record.record_type, 'TXT')
        self.assertEqual(record.subdomain, None)

    def test_unique_together_enforced(self):
        DnsRecord.objects.create(
            scan_history=self.scan,
            target_domain=self.domain,
            record_type='MX',
            value='mail.example.com',
        )
        with self.assertRaises(IntegrityError):
            DnsRecord.objects.create(
                scan_history=self.scan,
                target_domain=self.domain,
                record_type='MX',
                value='mail.example.com',
            )

    def test_update_or_create_is_idempotent(self):
        DnsRecord.objects.update_or_create(
            scan_history=self.scan,
            record_type='NS',
            value='ns1.example.com',
            defaults={'target_domain': self.domain, 'source': 'sfp_dns'},
        )
        DnsRecord.objects.update_or_create(
            scan_history=self.scan,
            record_type='NS',
            value='ns1.example.com',
            defaults={'target_domain': self.domain, 'source': 'sfp_dns'},
        )
        self.assertEqual(
            DnsRecord.objects.filter(scan_history=self.scan, record_type='NS').count(), 1
        )
