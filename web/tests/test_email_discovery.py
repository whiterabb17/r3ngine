"""Tests for email discovery orchestrator, tools, and model changes."""
from unittest.mock import patch, MagicMock
from django.test import TestCase
from startScan.models import Email, ScanHistory
from reNgine.utils.task import save_email


class TestEmailSourceField(TestCase):
    def test_email_created_with_default_source(self):
        email = Email.objects.create(address='test@example.com')
        self.assertEqual(email.source, Email.SOURCE_HUNTER)

    def test_email_created_with_manual_source(self):
        email = Email.objects.create(address='manual@example.com', source=Email.SOURCE_MANUAL)
        self.assertEqual(email.source, Email.SOURCE_MANUAL)

    def test_source_choices_defined(self):
        choices = dict(Email.SOURCE_CHOICES)
        self.assertIn(Email.SOURCE_MANUAL, choices)
        self.assertIn(Email.SOURCE_HUNTER, choices)
        self.assertIn(Email.SOURCE_HARVESTER, choices)
        self.assertIn(Email.SOURCE_PHONEBOOK, choices)
        self.assertIn(Email.SOURCE_PATTERN, choices)
        self.assertIn(Email.SOURCE_CRAWLED, choices)


class TestSaveEmailSource(TestCase):
    def test_save_email_default_source_is_hunter(self):
        email, created = save_email('default@example.com')
        self.assertTrue(created)
        self.assertEqual(email.source, Email.SOURCE_HUNTER)

    def test_save_email_manual_source(self):
        email, created = save_email('manual@example.com', source=Email.SOURCE_MANUAL)
        self.assertTrue(created)
        self.assertEqual(email.source, Email.SOURCE_MANUAL)

    def test_save_email_dedup_preserves_existing_source(self):
        # First call creates with manual source
        save_email('dup@example.com', source=Email.SOURCE_MANUAL)
        # Second call with different source — get_or_create means source won't change
        email, created = save_email('dup@example.com', source=Email.SOURCE_HUNTER)
        self.assertFalse(created)
        self.assertEqual(email.source, Email.SOURCE_MANUAL)
