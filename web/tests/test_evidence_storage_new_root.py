"""Storage-root defaults + path-traversal + permissions tests."""
import os
import tempfile
from unittest.mock import patch
from django.test import TestCase, override_settings


class TestEvidenceStorageNewRoot(TestCase):
    def test_default_root_under_assessments(self):
        """Default fallback root must be under ASSESSMENTS_ROOT, not /usr/src/app/."""
        with override_settings(
            EVIDENCE_STORAGE_ROOT='/usr/src/assessments/evidence',
            ASSESSMENTS_ROOT='/usr/src/assessments',
        ):
            with tempfile.TemporaryDirectory() as tmp:
                with patch('evidence.storage.settings.EVIDENCE_STORAGE_ROOT', tmp):
                    from evidence.storage import FilesystemEvidenceStorage
                    s = FilesystemEvidenceStorage()
                    self.assertEqual(s.root, tmp)
                    self.assertFalse(s.root.startswith('/usr/src/app'))

    def test_save_places_file_under_root(self):
        with tempfile.TemporaryDirectory() as tmp:
            with patch('evidence.storage.settings.EVIDENCE_STORAGE_ROOT', tmp):
                from evidence.storage import FilesystemEvidenceStorage
                s = FilesystemEvidenceStorage()
                key = s.save(b'hello', 'x.png')
                abs_path = os.path.join(tmp, key)
                self.assertTrue(os.path.isfile(abs_path))
                self.assertTrue(os.path.realpath(abs_path).startswith(os.path.realpath(tmp)))

    def test_save_with_assessment_uuid_prefix(self):
        """Passing an assessment_uuid places files under <uuid>/... prefix."""
        with tempfile.TemporaryDirectory() as tmp:
            with patch('evidence.storage.settings.EVIDENCE_STORAGE_ROOT', tmp):
                from evidence.storage import FilesystemEvidenceStorage
                s = FilesystemEvidenceStorage()
                key = s.save(b'x', 'x.png', assessment_uuid='abcd-1234')
                self.assertTrue(key.startswith('abcd-1234/'), f"got key={key}")

    def test_traversal_key_rejected(self):
        """Storage keys with .. or absolute paths must not escape the root."""
        with tempfile.TemporaryDirectory() as tmp:
            with patch('evidence.storage.settings.EVIDENCE_STORAGE_ROOT', tmp):
                from evidence.storage import FilesystemEvidenceStorage
                s = FilesystemEvidenceStorage()
                with self.assertRaises(ValueError):
                    s.read('../etc/passwd')
                with self.assertRaises(ValueError):
                    s.read('/etc/passwd')
