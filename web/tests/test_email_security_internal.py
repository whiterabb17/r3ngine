"""Tests for migrated email_security internal module."""
from unittest.mock import patch, MagicMock
from django.test import TestCase


class TestEmailSecurityImport(TestCase):
    def test_check_spf_importable(self):
        from reNgine.tasks.email_security import check_spf
        self.assertTrue(callable(check_spf))

    def test_check_dmarc_importable(self):
        from reNgine.tasks.email_security import check_dmarc
        self.assertTrue(callable(check_dmarc))

    def test_check_dkim_importable(self):
        from reNgine.tasks.email_security import check_dkim
        self.assertTrue(callable(check_dkim))

    def test_check_spf_returns_dict(self):
        from reNgine.tasks.email_security import check_spf
        with patch('dns.resolver.resolve', side_effect=Exception('no DNS')):
            result = check_spf('example.com')
        self.assertIn('found', result)
        self.assertIn('weak', result)
        self.assertFalse(result['found'])

    def test_check_dmarc_returns_dict(self):
        from reNgine.tasks.email_security import check_dmarc
        with patch('dns.resolver.resolve', side_effect=Exception('no DNS')):
            result = check_dmarc('example.com')
        self.assertIn('found', result)
        self.assertFalse(result['found'])

    def test_check_ssl_cert_importable(self):
        from reNgine.tasks.email_security import check_ssl_cert
        self.assertTrue(callable(check_ssl_cert))

    def test_check_ssl_cert_returns_dict_on_connection_failure(self):
        from reNgine.tasks.email_security import check_ssl_cert
        with patch('socket.create_connection', side_effect=ConnectionRefusedError):
            result = check_ssl_cert('mail.example.com', 465)
        self.assertFalse(result['connected'])
        self.assertIn('expired', result)
        self.assertIn('self_signed', result)
        self.assertIn('hostname_mismatch', result)


class TestEmailSecurityHasNoSmtpUserEnum(TestCase):
    def test_smtp_user_enum_removed(self):
        import reNgine.tasks.email_security as mod
        self.assertFalse(hasattr(mod, 'smtp_user_enum'))


class TestEmailSecurityCallsVerifier(TestCase):
    def test_activity_calls_verify_even_without_smtp_hosts(self):
        from django.utils import timezone
        from startScan.models import ScanHistory
        from targetApp.models import Domain
        from scanEngine.models import EngineType
        from reNgine.temporal.activities import _run_email_security_sync

        engine = EngineType.objects.create(engine_name='es-wire', yaml_configuration='')
        domain = Domain.objects.create(name='example.com', insert_date=timezone.now())
        scan = ScanHistory.objects.create(
            domain=domain, scan_type=engine, scan_status=2, start_scan_date=timezone.now(),
        )
        ctx = {
            'scan_history_id': scan.id,
            'domain_name': 'example.com',
            'yaml_configuration': {},
        }
        with patch('reNgine.tasks.email_security.check_spf', return_value={'found': True, 'record': 'v=spf1 -all', 'weak': False}), \
             patch('reNgine.tasks.email_security.check_dmarc', return_value={'found': True, 'record': 'v=DMARC1; p=reject', 'policy': 'reject'}), \
             patch('reNgine.tasks.email_security.check_dkim', return_value={'found': True, 'selector': 'google', 'record': 'v=DKIM1'}), \
             patch('reNgine.common_func.get_random_proxy', return_value=None), \
             patch('reNgine.tasks.email_verification.verify_domain_mailboxes', return_value={
                 'catch_all': False,
                 'checked': 1,
                 'confirmed': ['admin@example.com'],
                 'findings': [{'name': 'Valid Mailboxes Confirmed', 'severity': 2, 'description': '1 valid mailbox'}],
                 'skipped_reason': None,
             }) as mock_v, \
             patch('reNgine.common_func.save_vulnerability') as mock_sv:
            result = _run_email_security_sync(ctx)
        mock_v.assert_called_once()
        self.assertEqual(mock_v.call_args[0][0], 'example.com')
        self.assertIn('activity_id', mock_v.call_args.kwargs)
        self.assertIsNone(mock_v.call_args.kwargs.get('proxy_url'))
        names = [call.kwargs.get('name') for call in mock_sv.call_args_list]
        self.assertIn('Valid Mailboxes Confirmed', names)
        self.assertEqual(result.get('mailboxes_confirmed'), 1)

    def test_activity_selects_socks5_proxy_for_mailbox(self):
        from django.utils import timezone
        from startScan.models import ScanHistory
        from targetApp.models import Domain
        from scanEngine.models import EngineType
        from reNgine.temporal.activities import _run_email_security_sync

        engine = EngineType.objects.create(engine_name='es-proxy', yaml_configuration='')
        domain = Domain.objects.create(name='example.com', insert_date=timezone.now())
        scan = ScanHistory.objects.create(
            domain=domain, scan_type=engine, scan_status=2, start_scan_date=timezone.now(),
        )
        ctx = {
            'scan_history_id': scan.id,
            'domain_name': 'example.com',
            'yaml_configuration': {},
        }
        with patch('reNgine.tasks.email_security.check_spf', return_value={'found': True, 'record': 'v=spf1 -all', 'weak': False}), \
             patch('reNgine.tasks.email_security.check_dmarc', return_value={'found': True, 'record': 'v=DMARC1; p=reject', 'policy': 'reject'}), \
             patch('reNgine.tasks.email_security.check_dkim', return_value={'found': True, 'selector': 'google', 'record': 'v=DKIM1'}), \
             patch('reNgine.common_func.get_random_proxy', return_value='socks5://u:p@10.0.0.2:1080') as mock_proxy, \
             patch('reNgine.tasks.email_verification.verify_domain_mailboxes', return_value={
                 'catch_all': False,
                 'checked': 0,
                 'confirmed': [],
                 'findings': [],
                 'skipped_reason': None,
             }) as mock_v, \
             patch('reNgine.common_func.save_vulnerability'):
            _run_email_security_sync(ctx)
        mock_proxy.assert_called_once_with(socks5_only=True)
        self.assertEqual(mock_v.call_args.kwargs.get('proxy_url'), 'socks5://u:p@10.0.0.2:1080')
