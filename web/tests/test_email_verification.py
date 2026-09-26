"""Tests for Reacher mailbox verification (replaces smtp-user-enum)."""
import json
import os
import tempfile
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone
from scanEngine.models import EngineType
from startScan.models import Email, Employee, ScanHistory
from targetApp.models import Domain


class TestIsInScopeEmail(TestCase):
    def test_same_domain_accepted(self):
        from reNgine.tasks.email_verification import is_in_scope_email
        self.assertTrue(is_in_scope_email('admin@example.com', 'example.com'))

    def test_case_insensitive_domain(self):
        from reNgine.tasks.email_verification import is_in_scope_email
        self.assertTrue(is_in_scope_email('Admin@Example.COM', 'example.com'))

    def test_other_domain_rejected(self):
        from reNgine.tasks.email_verification import is_in_scope_email
        self.assertFalse(is_in_scope_email('admin@other.com', 'example.com'))

    def test_mail_subdomain_rejected_when_target_is_apex(self):
        from reNgine.tasks.email_verification import is_in_scope_email
        self.assertFalse(is_in_scope_email('admin@mail.example.com', 'example.com'))

    def test_newline_rejected(self):
        from reNgine.tasks.email_verification import is_in_scope_email
        self.assertFalse(is_in_scope_email('admin@example.com\n', 'example.com'))
        self.assertFalse(is_in_scope_email('ad\nmin@example.com', 'example.com'))

    def test_semicolon_metachar_still_must_be_valid_email(self):
        from reNgine.tasks.email_verification import is_in_scope_email
        self.assertFalse(is_in_scope_email('admin;id@example.com', 'example.com'))

    def test_nul_rejected(self):
        from reNgine.tasks.email_verification import is_in_scope_email
        self.assertFalse(is_in_scope_email('ad\x00min@example.com', 'example.com'))

    def test_empty_rejected(self):
        from reNgine.tasks.email_verification import is_in_scope_email
        self.assertFalse(is_in_scope_email('', 'example.com'))
        self.assertFalse(is_in_scope_email('admin@example.com', ''))


class TestParseMailboxConfig(TestCase):
    def test_defaults_when_absent(self):
        from reNgine.tasks.email_verification import parse_mailbox_config
        cfg = parse_mailbox_config({})
        self.assertTrue(cfg['enabled'])
        self.assertEqual(cfg['http_url'], '')
        self.assertEqual(cfg['timeout'], 15)
        self.assertEqual(cfg['max_candidates'], 200)
        self.assertEqual(cfg['delay_ms'], 250)

    def test_enabled_false(self):
        from reNgine.tasks.email_verification import parse_mailbox_config
        cfg = parse_mailbox_config({
            'email_security': {'mailbox_verification': {'enabled': False}}
        })
        self.assertFalse(cfg['enabled'])

    def test_invalid_timeout_keeps_default(self):
        from reNgine.tasks.email_verification import parse_mailbox_config
        cfg = parse_mailbox_config({
            'email_security': {'mailbox_verification': {'timeout': 'nope'}}
        })
        self.assertEqual(cfg['timeout'], 15)

    def test_budget_clamps_max_candidates(self):
        from reNgine.tasks.email_verification import (
            parse_mailbox_config,
            ACTIVITY_BUDGET_SECONDS,
            CLI_TIMEOUT_PAD_SECONDS,
            SENTINEL_COUNT,
        )
        cfg = parse_mailbox_config({
            'email_security': {
                'mailbox_verification': {'timeout': 120, 'max_candidates': 1000, 'delay_ms': 0}
            }
        })
        per_check = cfg['timeout'] + CLI_TIMEOUT_PAD_SECONDS + (cfg['delay_ms'] / 1000.0)
        total = (cfg['max_candidates'] + SENTINEL_COUNT) * per_check
        self.assertLessEqual(total, ACTIVITY_BUDGET_SECONDS)
        self.assertLess(cfg['max_candidates'], 1000)

    def test_budget_leaves_shared_activity_reserve(self):
        from reNgine.tasks.email_verification import (
            parse_mailbox_config,
            ACTIVITY_START_TO_CLOSE_SECONDS,
            CLI_TIMEOUT_PAD_SECONDS,
            SENTINEL_COUNT,
            SHARED_WORK_RESERVE_SECONDS,
        )
        cfg = parse_mailbox_config({
            'email_security': {
                'mailbox_verification': {'timeout': 120, 'max_candidates': 1000, 'delay_ms': 0}
            }
        })
        per_check = cfg['timeout'] + CLI_TIMEOUT_PAD_SECONDS + (cfg['delay_ms'] / 1000.0)
        mailbox_seconds = (cfg['max_candidates'] + SENTINEL_COUNT) * per_check
        self.assertLessEqual(
            mailbox_seconds + SHARED_WORK_RESERVE_SECONDS,
            ACTIVITY_START_TO_CLOSE_SECONDS,
        )

    def test_remaining_seconds_clamps_below_static_budget(self):
        from reNgine.tasks.email_verification import (
            parse_mailbox_config,
            CLI_TIMEOUT_PAD_SECONDS,
            PERSIST_SLACK_SECONDS,
            SENTINEL_COUNT,
        )
        remaining = 10 * 60
        cfg = parse_mailbox_config(
            {
                'email_security': {
                    'mailbox_verification': {'timeout': 120, 'max_candidates': 1000, 'delay_ms': 0}
                }
            },
            remaining_seconds=remaining,
        )
        per_check = cfg['timeout'] + CLI_TIMEOUT_PAD_SECONDS
        total = (cfg['max_candidates'] + SENTINEL_COUNT) * per_check
        self.assertLessEqual(total + PERSIST_SLACK_SECONDS, remaining)
        self.assertLess(cfg['max_candidates'], 40)


class TestValidateReacherHttpUrl(TestCase):
    def test_https_origin(self):
        from reNgine.tasks.email_verification import validate_reacher_http_url
        self.assertEqual(
            validate_reacher_http_url('https://reacher.internal:8080/v0/other'),
            'https://reacher.internal:8080',
        )

    def test_file_rejected(self):
        from reNgine.tasks.email_verification import validate_reacher_http_url
        self.assertIsNone(validate_reacher_http_url('file:///etc/passwd'))

    def test_gopher_rejected(self):
        from reNgine.tasks.email_verification import validate_reacher_http_url
        self.assertIsNone(validate_reacher_http_url('gopher://example.com/1'))

    def test_metadata_ip_rejected(self):
        from reNgine.tasks.email_verification import validate_reacher_http_url
        self.assertIsNone(validate_reacher_http_url('http://169.254.169.254/latest/meta-data/'))

    def test_metadata_host_rejected(self):
        from reNgine.tasks.email_verification import validate_reacher_http_url
        self.assertIsNone(validate_reacher_http_url('http://metadata.google.internal/'))

    def test_userinfo_rejected(self):
        from reNgine.tasks.email_verification import validate_reacher_http_url
        self.assertIsNone(validate_reacher_http_url('http://user:pass@reacher:8080'))

    def test_docker_hostname_allowed(self):
        from reNgine.tasks.email_verification import validate_reacher_http_url
        self.assertEqual(
            validate_reacher_http_url('http://reacher:8080'),
            'http://reacher:8080',
        )


def _make_scan(domain_name='example.com'):
    engine = EngineType.objects.create(
        engine_name='mb-verify-%s' % domain_name,
        yaml_configuration='',
    )
    domain = Domain.objects.create(name=domain_name, insert_date=timezone.now())
    return ScanHistory.objects.create(
        domain=domain,
        scan_type=engine,
        scan_status=2,
        start_scan_date=timezone.now(),
    )


class TestBuildCandidates(TestCase):
    def test_wordlist_and_existing_and_patterns(self):
        from reNgine.tasks.email_verification import build_candidates
        scan = _make_scan('example.com')
        existing, _ = Email.objects.get_or_create(
            address='hunter@example.com',
            defaults={'source': Email.SOURCE_HUNTER},
        )
        scan.emails.add(existing)
        emp = Employee.objects.create(name='Jane Doe')
        scan.employees.add(emp)
        fd, path = tempfile.mkstemp(text=True)
        os.write(fd, b'admin\nsupport\n')
        os.close(fd)
        try:
            result = build_candidates('example.com', scan, path, max_candidates=50)
        finally:
            os.unlink(path)
        self.assertIn('admin@example.com', result)
        self.assertIn('support@example.com', result)
        self.assertIn('hunter@example.com', result)
        self.assertIn('jane.doe@example.com', result)
        self.assertIn('jdoe@example.com', result)

    def test_off_domain_existing_email_dropped(self):
        from reNgine.tasks.email_verification import build_candidates
        scan = _make_scan('example.com')
        other, _ = Email.objects.get_or_create(address='x@other.com')
        scan.emails.add(other)
        fd, path = tempfile.mkstemp(text=True)
        os.close(fd)
        try:
            result = build_candidates('example.com', scan, path, max_candidates=50)
        finally:
            os.unlink(path)
        self.assertNotIn('x@other.com', result)

    def test_max_candidates_cap(self):
        from reNgine.tasks.email_verification import build_candidates
        scan = _make_scan('example.com')
        fd, path = tempfile.mkstemp(text=True)
        os.write(fd, b'a\nb\nc\nd\n')
        os.close(fd)
        try:
            result = build_candidates('example.com', scan, path, max_candidates=2)
        finally:
            os.unlink(path)
        self.assertEqual(len(result), 2)

    def test_missing_wordlist_still_returns_osint(self):
        from reNgine.tasks.email_verification import build_candidates
        scan = _make_scan('example.com')
        existing, _ = Email.objects.get_or_create(address='osint@example.com')
        scan.emails.add(existing)
        result = build_candidates(
            'example.com', scan, '/no/such/wordlist.txt', max_candidates=50
        )
        self.assertEqual(result, ['osint@example.com'])

    def test_wordlist_does_not_starve_osint_when_capped(self):
        from reNgine.tasks.email_verification import build_candidates
        scan = _make_scan('example.com')
        existing, _ = Email.objects.get_or_create(address='hunter@example.com')
        scan.emails.add(existing)
        fd, path = tempfile.mkstemp(text=True)
        os.write(fd, b'a\nb\nc\nd\ne\n')
        os.close(fd)
        try:
            result = build_candidates('example.com', scan, path, max_candidates=3)
        finally:
            os.unlink(path)
        self.assertIn('hunter@example.com', result)
        self.assertEqual(len(result), 3)


class TestParseSocksProxy(TestCase):
    def test_socks5_with_auth(self):
        from reNgine.tasks.email_verification import parse_socks_proxy
        parsed = parse_socks_proxy('socks5://alice:secret@127.0.0.1:1080')
        self.assertEqual(parsed['host'], '127.0.0.1')
        self.assertEqual(parsed['port'], 1080)
        self.assertEqual(parsed['username'], 'alice')
        self.assertEqual(parsed['password'], 'secret')

    def test_socks5h_accepted(self):
        from reNgine.tasks.email_verification import parse_socks_proxy
        parsed = parse_socks_proxy('socks5h://127.0.0.1:9050')
        self.assertEqual(parsed['host'], '127.0.0.1')
        self.assertEqual(parsed['port'], 9050)

    def test_http_proxy_ignored(self):
        from reNgine.tasks.email_verification import parse_socks_proxy
        self.assertIsNone(parse_socks_proxy('http://127.0.0.1:8080'))

    def test_socks4_ignored(self):
        from reNgine.tasks.email_verification import parse_socks_proxy
        self.assertIsNone(parse_socks_proxy('socks4://127.0.0.1:1080'))
        self.assertIsNone(parse_socks_proxy('socks4a://127.0.0.1:1080'))

    def test_empty_ignored(self):
        from reNgine.tasks.email_verification import parse_socks_proxy
        self.assertIsNone(parse_socks_proxy(''))
        self.assertIsNone(parse_socks_proxy(None))


class TestVerifyAddressCli(TestCase):
    def test_cli_argv_list_no_shell_and_timeout(self):
        from reNgine.tasks.email_verification import verify_address
        payload = {
            'input': 'admin@example.com',
            'is_reachable': 'safe',
            'misc': {'is_role_account': True, 'is_disposable': False},
            'mx': {'accepts_mail': True},
            'smtp': {'is_catch_all': False},
        }
        captured = {}

        def fake_run(cmd, **kwargs):
            captured['cmd'] = cmd
            captured['kwargs'] = kwargs
            return 0, json.dumps(payload)

        with patch('reNgine.tasks.email_verification.run_command', side_effect=fake_run):
            result = verify_address('admin@example.com', {
                'timeout': 15, 'http_url': '', 'proxy_url': None, 'domain': 'example.com',
                'scan_id': 42, 'activity_id': 7,
            })
        self.assertEqual(captured['cmd'][0], 'check_if_email_exists')
        self.assertEqual(captured['cmd'][-1], 'admin@example.com')
        self.assertIsInstance(captured['cmd'], list)
        self.assertFalse(captured['kwargs'].get('shell'))
        self.assertEqual(captured['kwargs']['timeout'], 20)
        self.assertEqual(captured['kwargs']['scan_id'], 42)
        self.assertEqual(captured['kwargs']['activity_id'], 7)
        self.assertEqual(result['is_reachable'], 'safe')
        self.assertTrue(result['is_role_account'])

    def test_cli_passes_socks5_host_port_on_argv(self):
        from reNgine.tasks.email_verification import verify_address
        captured = {}

        def fake_run(cmd, **kwargs):
            captured['cmd'] = cmd
            captured['kwargs'] = kwargs
            return 0, json.dumps({
                'input': 'a@example.com', 'is_reachable': 'invalid',
                'misc': {}, 'mx': {}, 'smtp': {},
            })

        with patch('reNgine.tasks.email_verification.run_command', side_effect=fake_run):
            verify_address('a@example.com', {
                'timeout': 15,
                'http_url': '',
                'proxy_url': 'socks5://u:p@10.0.0.2:1080',
                'domain': 'example.com',
            })
        self.assertEqual(captured['cmd'][0], 'check_if_email_exists')
        self.assertEqual(captured['cmd'][-1], 'a@example.com')
        self.assertIn('--proxy-host=10.0.0.2', captured['cmd'])
        self.assertIn('--proxy-port=1080', captured['cmd'])
        self.assertIn('--proxy-username=u', captured['cmd'])
        self.assertNotIn('--proxy-password', captured['cmd'])
        self.assertNotIn('--proxy-password=p', captured['cmd'])
        self.assertNotIn('p', captured['cmd'])
        env = captured['kwargs'].get('env') or {}
        self.assertEqual(env.get('PROXY_HOST'), '10.0.0.2')
        self.assertEqual(env.get('PROXY_PORT'), '1080')
        self.assertEqual(env.get('PROXY_USERNAME'), 'u')
        self.assertEqual(env.get('PROXY_PASSWORD'), 'p')

    def test_off_domain_not_invoked(self):
        from reNgine.tasks.email_verification import verify_address
        with patch('reNgine.tasks.email_verification.run_command') as mock_rc:
            result = verify_address('x@other.com', {
                'timeout': 15, 'http_url': '', 'proxy_url': None, 'domain': 'example.com',
            })
        mock_rc.assert_not_called()
        self.assertEqual(result['is_reachable'], 'unknown')

    def test_bad_json_is_unknown(self):
        from reNgine.tasks.email_verification import verify_address
        with patch('reNgine.tasks.email_verification.run_command', return_value=(0, 'not-json')):
            result = verify_address('a@example.com', {
                'timeout': 15, 'http_url': '', 'proxy_url': None, 'domain': 'example.com',
            })
        self.assertEqual(result['is_reachable'], 'unknown')


class TestVerifyAddressHttp(TestCase):
    def test_posts_forced_path_no_redirects(self):
        from reNgine.tasks.email_verification import verify_address
        captured = {}

        class FakeResp:
            status_code = 200
            def iter_content(self, chunk_size=1024):
                yield json.dumps({
                    'input': 'a@example.com',
                    'is_reachable': 'safe',
                    'misc': {},
                    'mx': {'accepts_mail': True},
                    'smtp': {'is_catch_all': False},
                }).encode()

        def fake_post(url, **kwargs):
            captured['url'] = url
            captured['kwargs'] = kwargs
            return FakeResp()

        with patch('reNgine.tasks.email_verification.requests.post', side_effect=fake_post):
            result = verify_address('a@example.com', {
                'timeout': 15,
                'http_url': 'https://reacher.internal:8080/evil',
                'proxy_url': None,
                'domain': 'example.com',
            })
        self.assertEqual(captured['url'], 'https://reacher.internal:8080/v0/check_email')
        self.assertFalse(captured['kwargs']['allow_redirects'])
        self.assertEqual(captured['kwargs']['timeout'], 15)
        self.assertEqual(captured['kwargs']['json']['to_email'], 'a@example.com')
        self.assertEqual(result['is_reachable'], 'safe')

    def test_http_body_includes_socks5_proxy(self):
        from reNgine.tasks.email_verification import verify_address
        captured = {}

        class FakeResp:
            status_code = 200
            def iter_content(self, chunk_size=1024):
                yield json.dumps({
                    'input': 'a@example.com',
                    'is_reachable': 'safe',
                    'misc': {},
                    'mx': {'accepts_mail': True},
                    'smtp': {'is_catch_all': False},
                }).encode()

        def fake_post(url, **kwargs):
            captured['kwargs'] = kwargs
            return FakeResp()

        with patch('reNgine.tasks.email_verification.requests.post', side_effect=fake_post):
            verify_address('a@example.com', {
                'timeout': 15,
                'http_url': 'https://reacher.internal:8080',
                'proxy_url': 'socks5://u:secret@10.0.0.2:1080',
                'domain': 'example.com',
            })
        proxy_obj = captured['kwargs']['json'].get('proxy')
        self.assertEqual(proxy_obj['host'], '10.0.0.2')
        self.assertEqual(proxy_obj['port'], 1080)
        self.assertEqual(proxy_obj['username'], 'u')
        self.assertEqual(proxy_obj['password'], 'secret')

    def test_file_url_does_not_call_http_or_cli(self):
        from reNgine.tasks.email_verification import verify_address
        with patch('reNgine.tasks.email_verification.requests.post') as mock_post, \
             patch('reNgine.tasks.email_verification.run_command') as mock_rc:
            result = verify_address('a@example.com', {
                'timeout': 15,
                'http_url': 'file:///etc/passwd',
                'proxy_url': None,
                'domain': 'example.com',
            })
        mock_post.assert_not_called()
        mock_rc.assert_not_called()
        self.assertEqual(result['is_reachable'], 'unknown')
        self.assertEqual(result.get('error'), 'bad_http_url')


class TestVerifyDomainMailboxes(TestCase):
    def test_disabled_skips(self):
        from reNgine.tasks.email_verification import verify_domain_mailboxes
        scan = _make_scan()
        with patch('reNgine.tasks.email_verification.verify_address') as mock_v:
            result = verify_domain_mailboxes(
                'example.com', scan,
                {'email_security': {'mailbox_verification': {'enabled': False}}},
            )
        mock_v.assert_not_called()
        self.assertEqual(result['skipped_reason'], 'disabled')

    def test_catch_all_stops_without_save(self):
        from reNgine.tasks.email_verification import verify_domain_mailboxes
        scan = _make_scan()

        def fake_verify(address, options):
            return {
                'input': address,
                'is_reachable': 'safe',
                'is_catch_all': True,
                'is_role_account': False,
                'is_disposable': False,
                'mx_accepts_mail': True,
            }

        with patch('reNgine.tasks.email_verification.shutil.which', return_value='/usr/local/bin/check_if_email_exists'), \
             patch('reNgine.tasks.email_verification.build_candidates', return_value=['admin@example.com']), \
             patch('reNgine.tasks.email_verification.verify_address', side_effect=fake_verify) as mock_v, \
             patch('reNgine.tasks.email_verification.save_email') as mock_save, \
             patch('reNgine.tasks.email_verification.time.sleep'):
            result = verify_domain_mailboxes('example.com', scan, {})
        self.assertTrue(result['catch_all'])
        mock_save.assert_not_called()
        self.assertEqual(result['confirmed'], [])
        self.assertEqual(result['findings'][0]['name'], 'MX Catch-All Configured')
        self.assertEqual(result['findings'][0]['severity'], 0)
        self.assertLessEqual(mock_v.call_count, 3)

    def test_safe_persists_invalid_does_not(self):
        from reNgine.tasks.email_verification import verify_domain_mailboxes
        scan = _make_scan()

        def fake_verify(address, options):
            if address.startswith('r3n-nx-'):
                return {
                    'input': address, 'is_reachable': 'invalid', 'is_catch_all': False,
                    'is_role_account': False, 'is_disposable': False, 'mx_accepts_mail': True,
                }
            reachable = 'safe' if address.startswith('admin@') else 'invalid'
            return {
                'input': address, 'is_reachable': reachable, 'is_catch_all': False,
                'is_role_account': False, 'is_disposable': False, 'mx_accepts_mail': True,
            }

        with patch('reNgine.tasks.email_verification.shutil.which', return_value='/usr/local/bin/check_if_email_exists'), \
             patch('reNgine.tasks.email_verification.build_candidates',
                   return_value=['admin@example.com', 'nope@example.com']), \
             patch('reNgine.tasks.email_verification.verify_address', side_effect=fake_verify), \
             patch('reNgine.tasks.email_verification.time.sleep'), \
             patch('reNgine.utils.task.threading.Thread'):
            result = verify_domain_mailboxes('example.com', scan, {
                'email_security': {'mailbox_verification': {'delay_ms': 0}}
            })
        self.assertFalse(result['catch_all'])
        self.assertEqual(result['confirmed'], ['admin@example.com'])
        self.assertTrue(scan.emails.filter(address='admin@example.com').exists())
        self.assertFalse(scan.emails.filter(address='nope@example.com').exists())
        finding = result['findings'][0]
        self.assertEqual(finding['name'], 'Valid Mailboxes Confirmed')
        self.assertEqual(finding['severity'], 2)

    def test_existing_hunter_source_preserved(self):
        from reNgine.tasks.email_verification import verify_domain_mailboxes
        scan = _make_scan()
        email = Email.objects.create(
            address='hunter@example.com', source=Email.SOURCE_HUNTER, metadata={},
        )
        scan.emails.add(email)

        def fake_verify(address, options):
            if address.startswith('r3n-nx-'):
                return {
                    'input': address, 'is_reachable': 'invalid', 'is_catch_all': False,
                    'is_role_account': False, 'is_disposable': False, 'mx_accepts_mail': True,
                }
            return {
                'input': address, 'is_reachable': 'safe', 'is_catch_all': False,
                'is_role_account': True, 'is_disposable': False, 'mx_accepts_mail': True,
            }

        with patch('reNgine.tasks.email_verification.shutil.which', return_value='/usr/local/bin/check_if_email_exists'), \
             patch('reNgine.tasks.email_verification.build_candidates',
                   return_value=['hunter@example.com']), \
             patch('reNgine.tasks.email_verification.verify_address', side_effect=fake_verify), \
             patch('reNgine.tasks.email_verification.time.sleep'), \
             patch('reNgine.utils.task.threading.Thread'):
            verify_domain_mailboxes('example.com', scan, {
                'email_security': {'mailbox_verification': {'delay_ms': 0}}
            })
        email.refresh_from_db()
        self.assertEqual(email.source, Email.SOURCE_HUNTER)
        self.assertEqual(email.metadata.get('is_reachable'), 'safe')

    def test_safe_reuses_existing_email_ignoring_case(self):
        from reNgine.tasks.email_verification import verify_domain_mailboxes
        scan = _make_scan()
        email = Email.objects.create(
            address='Admin@example.com', source=Email.SOURCE_HUNTER, metadata={},
        )
        scan.emails.add(email)

        def fake_verify(address, options):
            if address.startswith('r3n-nx-'):
                return {
                    'input': address, 'is_reachable': 'invalid', 'is_catch_all': False,
                    'is_role_account': False, 'is_disposable': False, 'mx_accepts_mail': True,
                }
            return {
                'input': address, 'is_reachable': 'safe', 'is_catch_all': False,
                'is_role_account': False, 'is_disposable': False, 'mx_accepts_mail': True,
            }

        with patch('reNgine.tasks.email_verification.shutil.which', return_value='/usr/local/bin/check_if_email_exists'), \
             patch('reNgine.tasks.email_verification.build_candidates',
                   return_value=['admin@example.com']), \
             patch('reNgine.tasks.email_verification.verify_address', side_effect=fake_verify), \
             patch('reNgine.tasks.email_verification.time.sleep'), \
             patch('reNgine.utils.task.threading.Thread'):
            result = verify_domain_mailboxes('example.com', scan, {
                'email_security': {'mailbox_verification': {'delay_ms': 0}}
            })
        self.assertEqual(result['confirmed'], ['admin@example.com'])
        self.assertEqual(Email.objects.filter(address__iexact='admin@example.com').count(), 1)
        self.assertEqual(scan.emails.count(), 1)
        email.refresh_from_db()
        self.assertEqual(email.address, 'Admin@example.com')
        self.assertEqual(email.source, Email.SOURCE_HUNTER)
        self.assertEqual(email.metadata.get('is_reachable'), 'safe')

    def test_finding_caps_at_20_addresses(self):
        from reNgine.tasks.email_verification import verify_domain_mailboxes, FINDING_CONFIRMED_CAP
        scan = _make_scan()
        addrs = ['u%02d@example.com' % i for i in range(25)]

        def fake_verify(address, options):
            if address.startswith('r3n-nx-'):
                return {
                    'input': address, 'is_reachable': 'invalid', 'is_catch_all': False,
                    'is_role_account': False, 'is_disposable': False, 'mx_accepts_mail': True,
                }
            return {
                'input': address, 'is_reachable': 'safe', 'is_catch_all': False,
                'is_role_account': False, 'is_disposable': False, 'mx_accepts_mail': True,
            }

        with patch('reNgine.tasks.email_verification.shutil.which', return_value='/usr/local/bin/check_if_email_exists'), \
             patch('reNgine.tasks.email_verification.build_candidates', return_value=addrs), \
             patch('reNgine.tasks.email_verification.verify_address', side_effect=fake_verify), \
             patch('reNgine.tasks.email_verification.time.sleep'), \
             patch('reNgine.utils.task.threading.Thread'):
            result = verify_domain_mailboxes('example.com', scan, {
                'email_security': {'mailbox_verification': {'delay_ms': 0, 'max_candidates': 200}}
            })
        listed = [a for a in addrs if a in result['findings'][0]['description']]
        self.assertEqual(len(listed), FINDING_CONFIRMED_CAP)

    def test_missing_binary_skips(self):
        from reNgine.tasks.email_verification import verify_domain_mailboxes
        scan = _make_scan()
        with patch('reNgine.tasks.email_verification.shutil.which', return_value=None), \
             patch('reNgine.tasks.email_verification.verify_address') as mock_v:
            result = verify_domain_mailboxes('example.com', scan, {})
        mock_v.assert_not_called()
        self.assertEqual(result['skipped_reason'], 'binary_missing')

    def test_bad_http_url_skips_without_cli_fallback(self):
        from reNgine.tasks.email_verification import verify_domain_mailboxes
        scan = _make_scan()
        with patch('reNgine.tasks.email_verification.shutil.which', return_value='/bin/check_if_email_exists'), \
             patch('reNgine.tasks.email_verification.verify_address') as mock_v:
            result = verify_domain_mailboxes(
                'example.com', scan,
                {'email_security': {
                    'mailbox_verification': {'http_url': 'file:///etc/passwd'}
                }},
            )
        mock_v.assert_not_called()
        self.assertEqual(result['skipped_reason'], 'bad_http_url')

    def test_timeout_budget_skips_without_checks(self):
        from reNgine.tasks.email_verification import verify_domain_mailboxes
        scan = _make_scan()
        with patch('reNgine.tasks.email_verification.shutil.which', return_value='/usr/local/bin/check_if_email_exists'), \
             patch('reNgine.tasks.email_verification.verify_address') as mock_v:
            result = verify_domain_mailboxes(
                'example.com', scan, {}, remaining_seconds=10,
            )
        mock_v.assert_not_called()
        self.assertEqual(result['skipped_reason'], 'timeout_budget')

    def test_cancel_stops_before_remaining_candidates(self):
        from reNgine.tasks.email_verification import verify_domain_mailboxes
        scan = _make_scan()
        cancel_calls = {'n': 0}

        def fake_cancelled():
            cancel_calls['n'] += 1
            # Allow both sentinel checks (calls 1-2), cancel before first candidate (call 3).
            return cancel_calls['n'] > 2

        def fake_verify(address, options):
            return {
                'input': address, 'is_reachable': 'invalid', 'is_catch_all': False,
                'is_role_account': False, 'is_disposable': False, 'mx_accepts_mail': True,
            }

        with patch('reNgine.tasks.email_verification.shutil.which', return_value='/usr/local/bin/check_if_email_exists'), \
             patch('reNgine.tasks.email_verification.build_candidates',
                   return_value=['admin@example.com', 'support@example.com']), \
             patch('reNgine.tasks.email_verification.verify_address', side_effect=fake_verify) as mock_v, \
             patch('reNgine.tasks.email_verification._is_activity_cancelled', side_effect=fake_cancelled), \
             patch('reNgine.tasks.email_verification.time.sleep'):
            result = verify_domain_mailboxes('example.com', scan, {
                'email_security': {'mailbox_verification': {'delay_ms': 0}}
            })
        self.assertEqual(result['skipped_reason'], 'cancelled')
        self.assertEqual(mock_v.call_count, 2)
        self.assertEqual(result['confirmed'], [])

