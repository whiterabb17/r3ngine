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


class TestSmtpUserEnumDomainFlag(TestCase):
    """Verify smtp_user_enum passes -d domain to smtp-user-enum when domain is given."""

    def _run(self, domain=''):
        from reNgine.tasks.email_security import smtp_user_enum
        captured = {}

        def fake_run_command(cmd, **kwargs):
            captured['cmd'] = cmd
            return 0, ''

        with patch('os.path.isfile', return_value=True), \
             patch('reNgine.tasks.email_security.run_command', side_effect=fake_run_command):
            smtp_user_enum([('mail.example.com', 25)], domain=domain)

        return captured.get('cmd', [])

    def test_domain_flag_absent_when_no_domain(self):
        cmd = self._run(domain='')
        self.assertNotIn('-d', cmd)

    def test_domain_flag_present_when_domain_given(self):
        cmd = self._run(domain='example.com')
        self.assertIn('-d', cmd)
        idx = cmd.index('-d')
        self.assertEqual(cmd[idx + 1], 'example.com')

    def test_host_and_port_always_present(self):
        cmd = self._run(domain='example.com')
        self.assertIn('mail.example.com', cmd)
        self.assertIn('25', cmd)

    def test_empty_targets_returns_early(self):
        from reNgine.tasks.email_security import smtp_user_enum
        with patch('os.path.isfile', return_value=True), \
             patch('reNgine.tasks.email_security.run_command') as mock_rc:
            result = smtp_user_enum([], domain='example.com')
        mock_rc.assert_not_called()
        self.assertEqual(result['users_found'], {})
