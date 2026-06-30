import logging
import os
import unittest

os.environ['RENGINE_SECRET_KEY'] = 'secret'
os.environ['CELERY_ALWAYS_EAGER'] = 'True'

from reNgine.settings import DEBUG
from reNgine.tasks import parse_nmap_results
import pathlib

logger = logging.getLogger(__name__)
DOMAIN_NAME = os.environ.get('DOMAIN_NAME', 'test.local')
FIXTURES_DIR = pathlib.Path().absolute() / 'fixtures' / 'nmap_xml'

if not DEBUG:
    logging.disable(logging.CRITICAL)


class TestNmapParsing(unittest.TestCase):
    def setUp(self):
        self.nmap_vuln_single_xml = FIXTURES_DIR / 'nmap_vuln_single.xml'
        self.nmap_vuln_multiple_xml = FIXTURES_DIR / 'nmap_vuln_multiple.xml'
        self.nmap_vulscan_single_xml = FIXTURES_DIR / 'nmap_vulscan_single.xml'
        self.nmap_vulscan_multiple_xml = FIXTURES_DIR / 'nmap_vulscan_multiple.xml'
        self.all_xml = [
            self.nmap_vuln_single_xml,
            self.nmap_vuln_multiple_xml,
            self.nmap_vulscan_single_xml,
            self.nmap_vulscan_multiple_xml
        ]

    def test_nmap_parse(self):
        for xml_file in self.all_xml:
            if os.path.exists(xml_file):
                vulns = parse_nmap_results(str(xml_file))
                self.assertIsNotNone(vulns)

    def test_nmap_vuln_single(self):
        pass

    def test_nmap_vuln_multiple(self):
        pass

    def test_nmap_vulscan_single(self):
        pass

    def test_nmap_vulscan_multiple(self):
        pass


from django.test import TestCase
from startScan.models import Vulnerability


class NmapTestCase(TestCase):
    def test_vulnerability_has_group_key_field(self):
        """Vulnerability model must have a group_key field backed by a DB column."""
        from startScan.models import Domain, ScanHistory
        from scanEngine.models import EngineType
        engine = EngineType.objects.create(
            engine_name='test-engine',
            yaml_configuration='subdomain_discovery:\n  - subfinder\n'
        )
        domain = Domain.objects.create(name='test-group-key.com')
        scan = ScanHistory.objects.create(
            domain=domain,
            scan_type=engine,
            scan_status=0,
            start_scan_date='2026-01-01T00:00:00Z'
        )
        v = Vulnerability.objects.create(
            scan_history=scan,
            target_domain=domain,
            name='Exim smtpd 4.99.2 (CVE-2026-45185)',
            severity=3,
            group_key='Exim smtpd 4.99.2'
        )
        v.refresh_from_db()
        self.assertEqual(v.group_key, 'Exim smtpd 4.99.2')

    def test_vulners_parser_sets_group_key(self):
        """parse_nmap_vulners_output must set group_key equal to service_title on each vuln."""
        from reNgine.tasks import parse_nmap_vulners_output
        script_output = (
            "E06430E8-210A-510A-A01B-011688E27E2F\t9.8\thttps://vulners.com/githubexploit/E06430E8\t*EXPLOIT*\n"
            "CVE-2026-45185\t9.8\thttps://vulners.com/cve/CVE-2026-45185\n"
        )
        results = parse_nmap_vulners_output(
            script_output, url='target.com:465', service_title='Exim smtpd 4.99.2'
        )
        self.assertTrue(len(results) > 0, "Parser must return at least one result")
        for vuln in results:
            self.assertEqual(
                vuln.get('group_key'), 'Exim smtpd 4.99.2',
                f"Expected group_key='Exim smtpd 4.99.2' but got {vuln.get('group_key')!r}"
            )

    def test_vulners_dedup_uses_subdomain_not_http_url(self):
        """Vulners dedup_fields must use subdomain not http_url (deduplicates across ports)."""
        import inspect
        from reNgine.tasks import nmap
        source = inspect.getsource(nmap)
        import re
        # Find the dedup_fields line in the nmap vulns save loop
        # Must NOT contain http_url in the dedup_fields for vulners
        # The pattern should be: ['name', 'subdomain', 'scan_history']
        nmap_dedup_pattern = r"dedup_fields=\['name',\s*'subdomain',\s*'scan_history'\]"
        self.assertRegex(
            source, nmap_dedup_pattern,
            "Vulners dedup_fields must be ['name', 'subdomain', 'scan_history']"
        )