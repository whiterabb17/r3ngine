from django.test import TestCase
from django.utils import timezone
from startScan.models import ScanHistory, EmailBreach, CredResult
from targetApp.models import Domain
from dashboard.models import Project
from scanEngine.models import EngineType
from itertools import groupby


def build_breach_groups(scan):
    """Replicate report.py grouping logic."""
    raw = EmailBreach.objects.filter(scan_history=scan).order_by('email_address', 'source', '-discovered_date')
    result = {}
    for addr, group in groupby(raw, key=lambda b: b.email_address):
        result[addr] = list(group)
    return result


def build_cred_groups(scan):
    raw = CredResult.objects.filter(scan_history=scan).order_by('email_address')
    result = {}
    for addr, group in groupby(raw, key=lambda c: c.email_address):
        result[addr] = list(group)
    return result


class TestBreachGrouping(TestCase):
    def setUp(self):
        engine = EngineType.objects.create(engine_name='test', yaml_configuration='{}')
        project = Project.objects.create(
            name='Test Project',
            slug='test-project',
            insert_date=timezone.now(),
        )
        domain = Domain.objects.create(name='corp.com', project=project)
        self.scan = ScanHistory.objects.create(
            scan_type=engine,
            scan_status=0,
            domain=domain,
            start_scan_date=timezone.now(),
        )
        EmailBreach.objects.create(scan_history=self.scan, email_address='alice@corp.com', breach_name='LinkedIn', source='hibp')
        EmailBreach.objects.create(scan_history=self.scan, email_address='alice@corp.com', breach_name='Dropbox', source='whatbreach')
        EmailBreach.objects.create(scan_history=self.scan, email_address='bob@corp.com', breach_name='Adobe', source='hibp')
        CredResult.objects.create(scan_history=self.scan, email_address='alice@corp.com', tool_name='credspy', account_exists=True)

    def test_breaches_grouped_by_user(self):
        groups = build_breach_groups(self.scan)
        self.assertIn('alice@corp.com', groups)
        self.assertIn('bob@corp.com', groups)
        self.assertEqual(len(groups['alice@corp.com']), 2)
        self.assertEqual(len(groups['bob@corp.com']), 1)

    def test_cred_results_grouped_by_user(self):
        groups = build_cred_groups(self.scan)
        self.assertIn('alice@corp.com', groups)
        self.assertNotIn('bob@corp.com', groups)

    def test_breach_sources_present(self):
        groups = build_breach_groups(self.scan)
        sources = {b.source for b in groups['alice@corp.com']}
        self.assertIn('hibp', sources)
        self.assertIn('whatbreach', sources)
