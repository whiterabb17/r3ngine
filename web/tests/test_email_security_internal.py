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
