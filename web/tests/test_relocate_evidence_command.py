"""Coverage for the `relocate_evidence` management command.

Exercises the dry-run filtering, --clean pollution removal, and idempotent
sha256-skip behavior described in apme/management/commands/relocate_evidence.py.
"""
import hashlib
import io
import os
import tempfile

from django.core.management import call_command
from django.test import TestCase, override_settings


class TestRelocateEvidenceCommand(TestCase):
    def test_filter_rejects_non_evidence_files(self):
        """A .py file at the legacy root must be skipped; a properly-shaped
        date-partitioned evidence file must be reported as copyable."""
        with tempfile.TemporaryDirectory() as legacy_root, \
                tempfile.TemporaryDirectory() as dest_root:
            py_path = os.path.join(legacy_root, 'models.py')
            with open(py_path, 'w') as f:
                f.write("# not evidence\n")

            evidence_dir = os.path.join(legacy_root, 'subfolder', '2026', '07', '03')
            os.makedirs(evidence_dir)
            evidence_path = os.path.join(evidence_dir, 'deadbeef.txt')
            with open(evidence_path, 'w') as f:
                f.write("evidence content")

            with override_settings(EVIDENCE_STORAGE_ROOT=dest_root):
                out = io.StringIO()
                call_command(
                    'relocate_evidence',
                    '--legacy-root', legacy_root,
                    '--dry-run',
                    stdout=out,
                )
            output = out.getvalue()

            self.assertIn("DRY-RUN skip (non-evidence)", output)
            self.assertIn(py_path, output)
            self.assertIn("DRY-RUN copy", output)
            self.assertIn(evidence_path, output)

            # Dry-run must not actually copy anything.
            self.assertFalse(os.path.isfile(os.path.join(dest_root, 'models.py')))
            self.assertFalse(os.path.isfile(
                os.path.join(dest_root, 'subfolder', '2026', '07', '03', 'deadbeef.txt')
            ))

    def test_clean_removes_pollution(self):
        """--clean must delete non-evidence files at the destination while
        leaving properly date-partitioned evidence files untouched."""
        with tempfile.TemporaryDirectory() as legacy_root, \
                tempfile.TemporaryDirectory() as dest_root:
            polluted_path = os.path.join(dest_root, 'models.py')
            with open(polluted_path, 'w') as f:
                f.write("# stray source file\n")

            evidence_dir = os.path.join(dest_root, 'screenshot', '2026', '07', '03')
            os.makedirs(evidence_dir)
            evidence_path = os.path.join(evidence_dir, 'cafebabe.png')
            with open(evidence_path, 'wb') as f:
                f.write(b'fake-png-bytes')

            with override_settings(EVIDENCE_STORAGE_ROOT=dest_root):
                out = io.StringIO()
                call_command(
                    'relocate_evidence',
                    '--legacy-root', legacy_root,
                    '--clean',
                    stdout=out,
                )

            self.assertFalse(os.path.isfile(polluted_path))
            self.assertTrue(os.path.isfile(evidence_path))

    def test_idempotent_sha256_skip(self):
        """A file present with identical content at both source and destination
        must be skipped (copied=0, skipped=1) on a real (non-dry-run) invocation."""
        with tempfile.TemporaryDirectory() as legacy_root, \
                tempfile.TemporaryDirectory() as dest_root:
            rel_dir = os.path.join('subfolder', '2026', '07', '03')
            content = b'identical evidence content'

            src_dir = os.path.join(legacy_root, rel_dir)
            os.makedirs(src_dir)
            src_path = os.path.join(src_dir, 'feedface.txt')
            with open(src_path, 'wb') as f:
                f.write(content)

            dst_dir = os.path.join(dest_root, rel_dir)
            os.makedirs(dst_dir)
            dst_path = os.path.join(dst_dir, 'feedface.txt')
            with open(dst_path, 'wb') as f:
                f.write(content)

            # Sanity check both files hash identically before running the command.
            self.assertEqual(
                hashlib.sha256(content).hexdigest(),
                hashlib.sha256(open(dst_path, 'rb').read()).hexdigest(),
            )

            with override_settings(EVIDENCE_STORAGE_ROOT=dest_root):
                out = io.StringIO()
                call_command(
                    'relocate_evidence',
                    '--legacy-root', legacy_root,
                    stdout=out,
                )
            output = out.getvalue()

            self.assertIn("copied=0 skipped=1", output)
