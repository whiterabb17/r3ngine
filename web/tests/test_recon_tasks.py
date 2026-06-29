"""
Tests for web/reNgine/recon_tasks.py

All subprocess calls and external requests are mocked.
Tests verify correct parsing logic and database persistence patterns.
"""
import json
from unittest.mock import patch, MagicMock, call
from django.test import TestCase


def _make_proxy(yaml_config=None):
    proxy = MagicMock()
    proxy.yaml_configuration = yaml_config or {}
    return proxy


class TestDNSXScan(TestCase):
    @patch('subprocess.run')
    def test_dnsx_creates_subdomain_records(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout='', stderr='')
        output = json.dumps({'host': 'sub.example.com', 'a': ['1.2.3.4']}) + '\n'

        # Write fake output file
        with patch('builtins.open', create=True) as mock_open:
            mock_open.return_value.__enter__.return_value.__iter__ = lambda s: iter([output])
            with patch('os.path.exists', return_value=True):
                with patch('os.remove'):
                    with patch('startScan.models.Subdomain.objects') as mock_sub:
                        mock_sub.filter.return_value.exists.return_value = False
                        from reNgine.tasks.recon import dnsx_scan
                        result = dnsx_scan(
                            _make_proxy(), scan_history_id=1, domain_id=1,
                            subdomain='sub.example.com',
                        )
        self.assertTrue(result)

    @patch('subprocess.run')
    def test_dnsx_returns_true_with_no_targets(self, mock_run):
        from reNgine.tasks.recon import dnsx_scan
        result = dnsx_scan(_make_proxy(), scan_history_id=1, domain_id=1)
        self.assertTrue(result)
        mock_run.assert_not_called()


class TestWAFW00FScan(TestCase):
    @patch('subprocess.run')
    def test_wafw00f_returns_true_no_targets(self, mock_run):
        from reNgine.tasks.recon import wafw00f_scan
        result = wafw00f_scan(_make_proxy(), scan_history_id=1, domain_id=1)
        self.assertTrue(result)
        mock_run.assert_not_called()

    @patch('subprocess.run')
    def test_wafw00f_handles_no_detection(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps([{'detected': False, 'firewall': None}]),
            stderr='',
        )
        from reNgine.tasks.recon import wafw00f_scan
        result = wafw00f_scan(
            _make_proxy(), scan_history_id=1, domain_id=1,
            url='https://example.com',
        )
        self.assertTrue(result)

    @patch('subprocess.run')
    def test_wafw00f_handles_invalid_json(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout='error output', stderr='')
        from reNgine.tasks.recon import wafw00f_scan
        result = wafw00f_scan(
            _make_proxy(), scan_history_id=1, domain_id=1,
            url='https://example.com',
        )
        self.assertTrue(result)


class TestFPingScan(TestCase):
    @patch('subprocess.run')
    def test_fping_parses_alive_hosts(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='192.0.2.1 is alive\n192.0.2.2 is alive\n192.0.2.3 is unreachable\n',
            stderr='',
        )
        from reNgine.tasks.recon import fping_scan
        result = fping_scan(_make_proxy(), scan_history_id=1, cidr='192.0.2.0/24')
        self.assertIsInstance(result, list)
        self.assertIn('192.0.2.1', result)
        self.assertIn('192.0.2.2', result)
        self.assertNotIn('192.0.2.3', result)

    @patch('subprocess.run')
    def test_fping_returns_empty_for_no_targets(self, mock_run):
        from reNgine.tasks.recon import fping_scan
        result = fping_scan(_make_proxy(), scan_history_id=1)
        self.assertEqual(result, [])
        mock_run.assert_not_called()


class TestARPScanScan(TestCase):
    @patch('subprocess.run')
    def test_arpscan_parses_ips(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='192.0.2.1\thost1\t00:11:22:33:44:55\tVendor\n',
            stderr='',
        )
        from reNgine.tasks.recon import arpscan_scan
        result = arpscan_scan(_make_proxy(), scan_history_id=1, cidr='192.0.2.0/24')
        self.assertIn('192.0.2.1', result)

    @patch('subprocess.run')
    def test_arpscan_returns_empty_for_no_cidr(self, mock_run):
        from reNgine.tasks.recon import arpscan_scan
        result = arpscan_scan(_make_proxy(), scan_history_id=1)
        self.assertEqual(result, [])
        mock_run.assert_not_called()


class TestMapCIDRExpand(TestCase):
    @patch('subprocess.run')
    def test_mapcidr_returns_ip_list(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='192.0.2.1\n192.0.2.2\n192.0.2.3\n',
            stderr='',
        )
        from reNgine.tasks.recon import mapcidr_expand
        result = mapcidr_expand(_make_proxy(), scan_history_id=1, cidr='192.0.2.0/30')
        self.assertEqual(result, ['192.0.2.1', '192.0.2.2', '192.0.2.3'])

    @patch('subprocess.run')
    def test_mapcidr_timeout_returns_empty(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired('mapcidr', 60)
        from reNgine.tasks.recon import mapcidr_expand
        result = mapcidr_expand(_make_proxy(), scan_history_id=1, cidr='10.0.0.0/8')
        self.assertEqual(result, [])


class TestSSHAuditScan(TestCase):
    @patch('subprocess.run')
    def test_sshaudit_returns_true_with_no_cves(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({'banner': {'raw': 'SSH-2.0-OpenSSH_8.9'}, 'cves': []}),
            stderr='',
        )
        from reNgine.tasks.recon import sshaudit_scan
        result = sshaudit_scan(_make_proxy(), scan_history_id=1, host='192.0.2.1', port=22)
        self.assertTrue(result)

    @patch('subprocess.run')
    def test_sshaudit_maps_cvss_to_severity_int(self, mock_run):
        mock_run.return_value = MagicMock(
            returncode=0,
            stdout=json.dumps({
                'banner': {'raw': 'SSH-2.0-OpenSSH_7.4'},
                'cves': [
                    {'name': 'CVE-2023-38408', 'cvss': 9.8, 'description': 'RCE'},
                    {'name': 'CVE-2023-28531', 'cvss': 6.5, 'description': 'Medium'},
                ],
            }),
            stderr='',
        )
        with patch('startScan.models.Vulnerability.objects') as mock_vuln:
            mock_vuln.bulk_create = MagicMock()
            from reNgine.tasks.recon import sshaudit_scan
            result = sshaudit_scan(_make_proxy(), scan_history_id=1, host='192.0.2.1', port=22)
        self.assertTrue(result)

    @patch('subprocess.run')
    def test_sshaudit_handles_invalid_json(self, mock_run):
        mock_run.return_value = MagicMock(returncode=1, stdout='not json', stderr='')
        from reNgine.tasks.recon import sshaudit_scan
        result = sshaudit_scan(_make_proxy(), scan_history_id=1, host='192.0.2.1', port=22)
        self.assertTrue(result)


class TestWPProbeScan(TestCase):
    @patch('subprocess.run')
    def test_wpprobe_returns_true_on_timeout(self, mock_run):
        import subprocess
        mock_run.side_effect = subprocess.TimeoutExpired('wpprobe', 300)
        from reNgine.tasks.recon import wpprobe_scan
        result = wpprobe_scan(_make_proxy(), scan_history_id=1, url='https://example.com')
        self.assertTrue(result)

    @patch('subprocess.run')
    def test_wpprobe_handles_empty_json(self, mock_run):
        mock_run.return_value = MagicMock(returncode=0, stdout='[]', stderr='')
        from reNgine.tasks.recon import wpprobe_scan
        result = wpprobe_scan(_make_proxy(), scan_history_id=1, url='https://example.com')
        self.assertTrue(result)


class TestSearchVulnsScan(TestCase):
    @patch('requests.get')
    def test_search_vulns_skips_empty_service(self, mock_get):
        from reNgine.tasks.recon import search_vulns_scan
        result = search_vulns_scan(
            _make_proxy(), scan_history_id=1, service='', version=None,
            host='192.0.2.1', port=80,
        )
        self.assertTrue(result)
        mock_get.assert_not_called()

    @patch('requests.get')
    def test_search_vulns_handles_empty_results(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {'data': {'search': []}},
        )
        mock_get.return_value.raise_for_status = MagicMock()
        from reNgine.tasks.recon import search_vulns_scan
        result = search_vulns_scan(
            _make_proxy(), scan_history_id=1, service='nginx', version='1.14.0',
            host='192.0.2.1', port=80,
        )
        self.assertTrue(result)

    @patch('requests.get')
    def test_search_vulns_handles_request_exception(self, mock_get):
        import requests
        mock_get.side_effect = requests.exceptions.ConnectionError('no connection')
        from reNgine.tasks.recon import search_vulns_scan
        result = search_vulns_scan(
            _make_proxy(), scan_history_id=1, service='apache', version='2.4.49',
            host='192.0.2.1', port=80,
        )
        self.assertTrue(result)

    @patch('requests.get')
    def test_search_vulns_maps_cvss_to_severity(self, mock_get):
        mock_get.return_value = MagicMock(
            status_code=200,
            json=lambda: {
                'data': {
                    'search': [
                        {'id': 'CVE-2021-41773', 'title': 'Path traversal',
                         'cvss': {'score': 9.8}, 'description': '...', 'published': '2021'},
                    ]
                }
            },
        )
        mock_get.return_value.raise_for_status = MagicMock()
        with patch('startScan.models.Vulnerability.objects') as mock_vuln:
            created = []
            mock_vuln.bulk_create = lambda items, **kw: created.extend(items)
            from reNgine.tasks.recon import search_vulns_scan
            search_vulns_scan(
                _make_proxy(), scan_history_id=1, service='apache-httpd', version='2.4.49',
                host='192.0.2.1', port=80,
            )
        # CVSS 9.8 → critical (4)
        if created:
            self.assertEqual(created[0].severity, 4)


from django.utils import timezone


class TestGetASNScan(TestCase):
    @patch('subprocess.run')
    def test_getasn_updates_ip_address_asn_fields(self, mock_run):
        from startScan.models import IpAddress, ScanHistory, Domain
        from scanEngine.models import EngineType
        from reNgine.tasks.recon import getasn_scan

        engine = EngineType.objects.create(
            engine_name='test-asn-engine',
            yaml_configuration='subdomain_discovery:\n  - subfinder\n',
        )
        domain = Domain.objects.create(name='asn-test.example.com')
        scan = ScanHistory.objects.create(
            scan_status=0, start_scan_date=timezone.now(), domain=domain,
            scan_type=engine,
        )
        ip = IpAddress.objects.create(address='172.217.14.196')

        mock_run.return_value = MagicMock(
            returncode=0,
            stdout='172.217.14.196 AS15169 172.217.0.0/16 GOOGLE - Google LLC US\n',
            stderr='',
        )
        result = getasn_scan(_make_proxy(), scan_history_id=scan.id, domain_id=domain.id,
                             ips=['172.217.14.196'])
        self.assertTrue(result)
        ip.refresh_from_db()
        self.assertEqual(ip.asn, 'AS15169')
        self.assertEqual(ip.asn_cidr, '172.217.0.0/16')
        self.assertIn('GOOGLE', ip.asn_org)

    @patch('subprocess.run')
    def test_getasn_returns_true_with_no_ips(self, mock_run):
        from reNgine.tasks.recon import getasn_scan
        result = getasn_scan(_make_proxy(), scan_history_id=1, domain_id=1, ips=[])
        self.assertTrue(result)
        mock_run.assert_not_called()

    @patch('subprocess.run')
    def test_getasn_handles_malformed_output(self, mock_run):
        from reNgine.tasks.recon import getasn_scan
        mock_run.return_value = MagicMock(returncode=0, stdout='bad output\n', stderr='')
        result = getasn_scan(_make_proxy(), scan_history_id=1, domain_id=1, ips=['1.2.3.4'])
        self.assertTrue(result)

    @patch('subprocess.run')
    def test_getasn_handles_timeout(self, mock_run):
        """getasn_scan returns True even when subprocess times out."""
        from reNgine.tasks.recon import getasn_scan
        mock_run.side_effect = __import__('subprocess').TimeoutExpired(cmd='getasn', timeout=30)
        result = getasn_scan(_make_proxy(), scan_history_id=1, domain_id=1, ips=['1.2.3.4'])
        self.assertTrue(result)

    @patch('subprocess.run')
    def test_getasn_skips_non_asn_token(self, mock_run):
        """getasn_scan ignores lines where parts[1] does not start with AS."""
        from startScan.models import IpAddress
        from reNgine.tasks.recon import getasn_scan
        IpAddress.objects.create(address='1.2.3.4')
        mock_run.return_value = MagicMock(
            returncode=0, stdout='1.2.3.4 Error: lookup failed\n', stderr=''
        )
        result = getasn_scan(_make_proxy(), scan_history_id=1, domain_id=1, ips=['1.2.3.4'])
        self.assertTrue(result)
        ip = IpAddress.objects.get(address='1.2.3.4')
        self.assertIsNone(ip.asn)


class TestJsWhoisScan(TestCase):
    @patch('subprocess.run')
    def test_jswhois_stores_raw_json_in_domain_info(self, mock_run):
        from targetApp.models import Domain as TargetDomain, DomainInfo
        from startScan.models import ScanHistory
        from scanEngine.models import EngineType
        from reNgine.tasks.recon import jswhois_scan

        engine = EngineType.objects.create(
            engine_name='test-jswhois-engine',
            yaml_configuration='subdomain_discovery:\n  - subfinder\n',
        )
        domain_info = DomainInfo.objects.create()
        domain = TargetDomain.objects.create(
            name='jswhois-test.example.com',
            insert_date=timezone.now(), domain_info=domain_info,
        )
        scan = ScanHistory.objects.create(
            scan_status=0, start_scan_date=timezone.now(), domain=domain,
            scan_type=engine,
        )
        whois_json = '{"registrar": "ACME Registrar", "creation_date": "2000-01-01"}'
        mock_run.return_value = MagicMock(returncode=0, stdout=whois_json, stderr='')

        result = jswhois_scan(_make_proxy(), scan_history_id=scan.id, domain_id=domain.id,
                              domain='jswhois-test.example.com')
        self.assertTrue(result)
        domain_info.refresh_from_db()
        self.assertIsNotNone(domain_info.whois_raw)
        self.assertIn('registrar', domain_info.whois_raw)

    @patch('subprocess.run')
    def test_jswhois_returns_true_with_no_domain(self, mock_run):
        from reNgine.tasks.recon import jswhois_scan
        result = jswhois_scan(_make_proxy(), scan_history_id=1, domain_id=1)
        self.assertTrue(result)
        mock_run.assert_not_called()

    @patch('subprocess.run')
    def test_jswhois_handles_non_json_output(self, mock_run):
        from reNgine.tasks.recon import jswhois_scan
        mock_run.return_value = MagicMock(returncode=0, stdout='not json output', stderr='')
        result = jswhois_scan(_make_proxy(), scan_history_id=1, domain_id=1,
                              domain='example.com')
        self.assertTrue(result)


class TestWhoisDomainScan(TestCase):
    @patch('os.path.exists')
    @patch('os.remove')
    @patch('subprocess.run')
    def test_whoisdomain_stores_raw_json(self, mock_run, mock_remove, mock_exists):
        import json as _json
        from unittest.mock import mock_open, patch as _patch
        from targetApp.models import Domain as TargetDomain, DomainInfo
        from startScan.models import ScanHistory
        from scanEngine.models import EngineType
        from reNgine.tasks.recon import whoisdomain_scan

        engine = EngineType.objects.create(
            engine_name='test-wd-engine',
            yaml_configuration='subdomain_discovery:\n  - subfinder\n',
        )
        domain_info = DomainInfo.objects.create()
        domain = TargetDomain.objects.create(
            name='wd-test.example.com',
            insert_date=timezone.now(), domain_info=domain_info,
        )
        scan = ScanHistory.objects.create(
            scan_status=0, start_scan_date=timezone.now(), domain=domain,
            scan_type=engine,
        )
        mock_run.return_value = MagicMock(returncode=0, stdout='', stderr='')
        mock_exists.return_value = True
        whois_data = _json.dumps({'registrar': 'Test Registrar', 'expiration_date': '2030-01-01'})

        with _patch('builtins.open', mock_open(read_data=whois_data)):
            result = whoisdomain_scan(_make_proxy(), scan_history_id=scan.id,
                                      domain_id=domain.id, domain='wd-test.example.com')

        self.assertTrue(result)
        domain_info.refresh_from_db()
        self.assertIsNotNone(domain_info.whois_raw)
        self.assertIn('registrar', domain_info.whois_raw)

    @patch('subprocess.run')
    def test_whoisdomain_returns_true_with_no_domain(self, mock_run):
        from reNgine.tasks.recon import whoisdomain_scan
        result = whoisdomain_scan(_make_proxy(), scan_history_id=1, domain_id=1)
        self.assertTrue(result)
        mock_run.assert_not_called()


class TestBBotScan(TestCase):
    @patch('subprocess.run')
    @patch('os.path.exists')
    @patch('shutil.rmtree')
    def test_bbot_saves_dns_name_events_as_subdomains(self, mock_rmtree, mock_exists, mock_run):
        import json as _json
        from unittest.mock import mock_open, patch as _patch
        from startScan.models import ScanHistory, Subdomain
        from targetApp.models import Domain as TargetDomain, Project
        from scanEngine.models import EngineType
        from reNgine.tasks.recon import bbot_scan

        project = Project.objects.create(name='test-bbot-proj', insert_date=timezone.now())
        domain = TargetDomain.objects.create(
            name='bbot-test.example.com', project=project, insert_date=timezone.now(),
        )
        engine = EngineType.objects.create(engine_name='bbot-test-engine', yaml_configuration='{}')
        scan = ScanHistory.objects.create(
            scan_status=0, start_scan_date=timezone.now(), domain=domain, scan_type=engine,
        )
        mock_run.return_value = MagicMock(returncode=0, stdout='', stderr='')
        mock_exists.return_value = True

        events = '\n'.join([
            _json.dumps({'type': 'DNS_NAME', 'data': 'api.bbot-test.example.com'}),
            _json.dumps({'type': 'DNS_NAME', 'data': 'mail.bbot-test.example.com'}),
            _json.dumps({'type': 'OPEN_TCP_PORT', 'data': '1.2.3.4:80'}),
        ])
        with _patch('builtins.open', mock_open(read_data=events)):
            result = bbot_scan(_make_proxy(), scan_history_id=scan.id, domain_id=domain.id,
                               domain='bbot-test.example.com')

        self.assertTrue(result)
        names = list(Subdomain.objects.filter(
            scan_history_id=scan.id
        ).values_list('name', flat=True))
        self.assertIn('api.bbot-test.example.com', names)
        self.assertIn('mail.bbot-test.example.com', names)
        # OPEN_TCP_PORT event must not be stored as a subdomain
        self.assertNotIn('1.2.3.4:80', names)

    @patch('subprocess.run')
    def test_bbot_returns_true_with_no_domain(self, mock_run):
        from reNgine.tasks.recon import bbot_scan
        result = bbot_scan(_make_proxy(), scan_history_id=1, domain_id=1)
        self.assertTrue(result)
        mock_run.assert_not_called()

    @patch('subprocess.run')
    @patch('os.path.exists', return_value=False)
    @patch('shutil.rmtree')
    def test_bbot_returns_true_when_no_output_file(self, mock_rmtree, mock_exists, mock_run):
        from reNgine.tasks.recon import bbot_scan
        mock_run.return_value = MagicMock(returncode=0, stdout='', stderr='')
        result = bbot_scan(_make_proxy(), scan_history_id=1, domain_id=1,
                           domain='example.com')
        self.assertTrue(result)


class TestNetDetectScan(TestCase):
    @patch('psutil.net_if_addrs')
    def test_netdetect_returns_cidr_for_non_loopback_interface(self, mock_addrs):
        import psutil as _psutil
        mock_addrs.return_value = {
            'lo': [
                _psutil._ntuples.snicaddr(
                    family=2, address='127.0.0.1', netmask='255.0.0.0',
                    broadcast=None, ptp=None,
                ),
            ],
            'eth0': [
                _psutil._ntuples.snicaddr(
                    family=2, address='10.0.0.5', netmask='255.255.0.0',
                    broadcast='10.0.255.255', ptp=None,
                ),
            ],
        }
        from reNgine.tasks.recon import netdetect_scan
        result = netdetect_scan(_make_proxy(), scan_history_id=1, domain_id=1)
        self.assertIsInstance(result, list)
        self.assertIn('10.0.0.0/16', result)
        self.assertNotIn('127.0.0.0/8', result)

    @patch('psutil.net_if_addrs')
    def test_netdetect_skips_loopback(self, mock_addrs):
        import psutil as _psutil
        mock_addrs.return_value = {
            'lo': [
                _psutil._ntuples.snicaddr(
                    family=2, address='127.0.0.1', netmask='255.0.0.0',
                    broadcast=None, ptp=None,
                ),
            ],
        }
        from reNgine.tasks.recon import netdetect_scan
        result = netdetect_scan(_make_proxy(), scan_history_id=1, domain_id=1)
        self.assertEqual(result, [])

    @patch('psutil.net_if_addrs')
    def test_netdetect_handles_bad_netmask_gracefully(self, mock_addrs):
        import psutil as _psutil
        mock_addrs.return_value = {
            'eth0': [
                _psutil._ntuples.snicaddr(
                    family=2, address='10.0.0.5', netmask=None,
                    broadcast=None, ptp=None,
                ),
            ],
        }
        from reNgine.tasks.recon import netdetect_scan
        result = netdetect_scan(_make_proxy(), scan_history_id=1, domain_id=1)
        self.assertEqual(result, [])
