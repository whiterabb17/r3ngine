"""Unit tests for the email_security plugin.

Run in container:
  python manage.py test tests.test_email_security_plugin -v 2
"""

import sys
import os
import unittest
from unittest import TestCase
from unittest.mock import patch, MagicMock

# Allow importing plugin source directly without installation
_PLUGIN_SRC = os.path.join(
    os.path.dirname(os.path.abspath(__file__)), '..', '..',
    'r3ngine-plugins', 'email_security'
)
sys.path.insert(0, _PLUGIN_SRC)


def setUpModule():
    """Skip rather than error when the plugin repository is not checked out.

    r3ngine-plugins is a separate repository cloned next to this one. Without it
    every test here raised ModuleNotFoundError on `backend.email_tasks`, which
    put 22 errors into the suite for a missing optional dependency and buried
    the failures that were real.
    """
    if not os.path.isdir(_PLUGIN_SRC):
        raise unittest.SkipTest(
            'r3ngine-plugins checkout not present at %s' % _PLUGIN_SRC
        )


class TestCheckSpf(TestCase):

    @patch('dns.resolver.resolve')
    def test_missing_returns_not_found(self, mock_resolve):
        import dns.exception
        from backend.email_tasks import check_spf
        mock_resolve.side_effect = dns.exception.DNSException("NXDOMAIN")
        result = check_spf('example.com')
        self.assertFalse(result['found'])
        self.assertIsNone(result['record'])
        self.assertFalse(result['weak'])

    @patch('dns.resolver.resolve')
    def test_strong_policy_not_weak(self, mock_resolve):
        from backend.email_tasks import check_spf
        rdata = MagicMock()
        rdata.__str__ = lambda self: '"v=spf1 include:_spf.example.com -all"'
        mock_resolve.return_value = [rdata]
        result = check_spf('example.com')
        self.assertTrue(result['found'])
        self.assertFalse(result['weak'])

    @patch('dns.resolver.resolve')
    def test_softfail_is_weak(self, mock_resolve):
        from backend.email_tasks import check_spf
        rdata = MagicMock()
        rdata.__str__ = lambda self: '"v=spf1 include:_spf.example.com ~all"'
        mock_resolve.return_value = [rdata]
        result = check_spf('example.com')
        self.assertTrue(result['found'])
        self.assertTrue(result['weak'])

    @patch('dns.resolver.resolve')
    def test_plus_all_is_weak(self, mock_resolve):
        from backend.email_tasks import check_spf
        rdata = MagicMock()
        rdata.__str__ = lambda self: '"v=spf1 +all"'
        mock_resolve.return_value = [rdata]
        result = check_spf('example.com')
        self.assertTrue(result['weak'])


class TestCheckDmarc(TestCase):

    @patch('dns.resolver.resolve')
    def test_missing_returns_not_found(self, mock_resolve):
        import dns.exception
        from backend.email_tasks import check_dmarc
        mock_resolve.side_effect = dns.exception.DNSException("NXDOMAIN")
        result = check_dmarc('example.com')
        self.assertFalse(result['found'])
        self.assertIsNone(result['policy'])

    @patch('dns.resolver.resolve')
    def test_policy_reject(self, mock_resolve):
        from backend.email_tasks import check_dmarc
        rdata = MagicMock()
        rdata.__str__ = lambda self: '"v=DMARC1; p=reject; rua=mailto:dmarc@example.com"'
        mock_resolve.return_value = [rdata]
        result = check_dmarc('example.com')
        self.assertTrue(result['found'])
        self.assertEqual(result['policy'], 'reject')

    @patch('dns.resolver.resolve')
    def test_policy_none(self, mock_resolve):
        from backend.email_tasks import check_dmarc
        rdata = MagicMock()
        rdata.__str__ = lambda self: '"v=DMARC1; p=none"'
        mock_resolve.return_value = [rdata]
        result = check_dmarc('example.com')
        self.assertEqual(result['policy'], 'none')

    @patch('dns.resolver.resolve')
    def test_policy_quarantine(self, mock_resolve):
        from backend.email_tasks import check_dmarc
        rdata = MagicMock()
        rdata.__str__ = lambda self: '"v=DMARC1; p=quarantine; pct=50"'
        mock_resolve.return_value = [rdata]
        result = check_dmarc('example.com')
        self.assertEqual(result['policy'], 'quarantine')


class TestAssessSpoofability(TestCase):

    def test_no_spf_no_dmarc_severity_3(self):
        from backend.email_tasks import assess_spoofability
        findings = assess_spoofability(
            {"found": False, "record": None, "weak": False},
            {"found": False, "record": None, "policy": None},
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['name'], 'Direct Email Spoofing Feasible')
        self.assertEqual(findings[0]['severity'], 3)

    def test_weak_spf_dmarc_none_severity_2(self):
        from backend.email_tasks import assess_spoofability
        findings = assess_spoofability(
            {"found": True, "record": "v=spf1 ~all", "weak": True},
            {"found": True, "record": "v=DMARC1; p=none", "policy": "none"},
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['severity'], 2)

    def test_weak_spf_no_dmarc_severity_2(self):
        from backend.email_tasks import assess_spoofability
        findings = assess_spoofability(
            {"found": True, "record": "v=spf1 ~all", "weak": True},
            {"found": False, "record": None, "policy": None},
        )
        self.assertEqual(len(findings), 1)
        self.assertEqual(findings[0]['severity'], 2)

    def test_strong_spf_dmarc_reject_no_findings(self):
        from backend.email_tasks import assess_spoofability
        findings = assess_spoofability(
            {"found": True, "record": "v=spf1 -all", "weak": False},
            {"found": True, "record": "v=DMARC1; p=reject", "policy": "reject"},
        )
        self.assertEqual(len(findings), 0)

    def test_strong_spf_no_dmarc_no_findings(self):
        from backend.email_tasks import assess_spoofability
        # Strong SPF alone is not spoofable (no weak_spf flag)
        findings = assess_spoofability(
            {"found": True, "record": "v=spf1 -all", "weak": False},
            {"found": False, "record": None, "policy": None},
        )
        self.assertEqual(len(findings), 0)


class TestSwaksRelayTest(TestCase):

    @patch('backend.email_tasks.subprocess.run')
    def test_open_relay_detected(self, mock_run):
        from backend.email_tasks import swaks_relay_test
        mock_run.return_value = MagicMock(
            stdout=' -> RCPT TO:<probe@relay-test-probe.invalid>\n <- 250 OK\n',
            stderr='',
        )
        result = swaks_relay_test('mail.example.com', 25, 'example.com')
        self.assertTrue(result['open_relay'])

    @patch('backend.email_tasks.subprocess.run')
    def test_relay_rejected(self, mock_run):
        from backend.email_tasks import swaks_relay_test
        mock_run.return_value = MagicMock(
            stdout=' <- 550 Relay not permitted\n',
            stderr='',
        )
        result = swaks_relay_test('mail.example.com', 25, 'example.com')
        self.assertFalse(result['open_relay'])

    @patch('backend.email_tasks.subprocess.run')
    def test_starttls_supported(self, mock_run):
        from backend.email_tasks import swaks_starttls_check
        mock_run.return_value = MagicMock(
            stdout=' <- 250-STARTTLS\n <- 250 HELP\n',
            stderr='',
        )
        result = swaks_starttls_check('mail.example.com', 25)
        self.assertTrue(result['starttls_supported'])

    @patch('backend.email_tasks.subprocess.run')
    def test_starttls_absent(self, mock_run):
        from backend.email_tasks import swaks_starttls_check
        mock_run.return_value = MagicMock(
            stdout=' <- 250-SIZE 10240000\n <- 250-8BITMIME\n',
            stderr='',
        )
        result = swaks_starttls_check('mail.example.com', 25)
        self.assertFalse(result['starttls_supported'])

    @patch('backend.email_tasks.subprocess.run')
    def test_swaks_not_found_returns_no_relay(self, mock_run):
        from backend.email_tasks import swaks_relay_test
        mock_run.side_effect = FileNotFoundError("swaks not found")
        result = swaks_relay_test('mail.example.com', 25, 'example.com')
        self.assertFalse(result['open_relay'])
        self.assertIsNone(result['banner'])


class TestSmtpUserEnum(TestCase):

    @patch('backend.email_tasks.subprocess.run')
    def test_users_found(self, mock_run):
        from backend.email_tasks import smtp_user_enum
        mock_run.return_value = MagicMock(
            stdout='mail.example.com: admin EXISTS\nmail.example.com: root EXISTS\n',
            stderr='',
        )
        result = smtp_user_enum('mail.example.com', 25)
        self.assertIn('admin', result['users_found'])
        self.assertIn('root', result['users_found'])

    @patch('backend.email_tasks.subprocess.run')
    def test_no_users_found(self, mock_run):
        from backend.email_tasks import smtp_user_enum
        mock_run.return_value = MagicMock(stdout='No valid usernames found.\n', stderr='')
        result = smtp_user_enum('mail.example.com', 25)
        self.assertEqual(result['users_found'], [])

    @patch('backend.email_tasks.subprocess.run')
    def test_email_addresses_excluded(self, mock_run):
        from backend.email_tasks import smtp_user_enum
        # Lines with '@' in the user part should be excluded
        mock_run.return_value = MagicMock(
            stdout='host: admin@example.com EXISTS\nhost: root EXISTS\n',
            stderr='',
        )
        result = smtp_user_enum('mail.example.com', 25)
        self.assertNotIn('admin@example.com', result['users_found'])
        self.assertIn('root', result['users_found'])

    @patch('backend.email_tasks.subprocess.run')
    def test_tool_not_found_returns_empty(self, mock_run):
        from backend.email_tasks import smtp_user_enum
        mock_run.side_effect = FileNotFoundError("smtp-user-enum not found")
        result = smtp_user_enum('mail.example.com', 25)
        self.assertEqual(result['users_found'], [])
