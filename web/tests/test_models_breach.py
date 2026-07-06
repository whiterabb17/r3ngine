from django.test import TestCase
from django.utils import timezone
from startScan.models import EmailBreach, CredResult, ScanHistory
from targetApp.models import Domain
from scanEngine.models import EngineType


class TestEmailBreachSourceField(TestCase):
    def setUp(self):
        self.domain = Domain.objects.create(name='example.com')
        engine = EngineType.objects.create(engine_name='test', yaml_configuration='{}')
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=engine,
            scan_status=0,
            start_scan_date=timezone.now(),
        )

    def test_email_breach_source_defaults_to_hibp(self):
        breach = EmailBreach.objects.create(
            scan_history=self.scan,
            email_address='user@example.com',
            breach_name='TestBreach',
        )
        self.assertEqual(breach.source, 'hibp')

    def test_email_breach_source_can_be_whatbreach(self):
        breach = EmailBreach.objects.create(
            scan_history=self.scan,
            email_address='user@example.com',
            breach_name='TestBreach',
            source='whatbreach',
        )
        self.assertEqual(breach.source, 'whatbreach')

    def test_cred_result_creation(self):
        cred = CredResult.objects.create(
            scan_history=self.scan,
            email_address='user@corp.com',
            tool_name='credspy',
            account_exists=True,
            exposure_type='Password',
            has_password=True,
            domain_type='Managed',
        )
        self.assertEqual(cred.tool_name, 'credspy')
        self.assertTrue(cred.account_exists)
        self.assertEqual(str(cred), 'user@corp.com via credspy')
