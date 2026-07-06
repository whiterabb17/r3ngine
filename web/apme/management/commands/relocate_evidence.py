"""Copy legacy evidence files from an old storage root to the new assessments
root. Idempotent — skips files whose sha256 already exists at the destination.

**Only files whose path matches the storage backend's naming pattern are
copied.** The `FilesystemEvidenceStorage._unique_key` helper produces keys
of the form `[<subfolder>/]YYYY/MM/DD/<32-hex>.<ext>`, so we require the
relative path to contain a `YYYY/MM/DD/` segment. This prevents copying
Django app source files that may sit alongside evidence in a bind-mounted
legacy root (e.g. `/usr/src/app/evidence/` — which is the Django `evidence`
app source directory).

Usage:
    python manage.py relocate_evidence               # copy live
    python manage.py relocate_evidence --dry-run     # report only
    python manage.py relocate_evidence --legacy-root /custom/path
    python manage.py relocate_evidence --clean       # also delete non-evidence
                                                     # files at the destination
"""
import hashlib
import os
import re
import shutil

from django.conf import settings
from django.core.management.base import BaseCommand

# Legitimate evidence relative paths must contain a YYYY/MM/DD/ date partition.
_DATE_PARTITION_RE = re.compile(r'(?:^|/)(\d{4})/(\d{2})/(\d{2})/[^/]+$')


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


def _looks_like_evidence(rel_path: str) -> bool:
    """Return True when the relative path matches the evidence naming pattern.

    Rejects paths like `models.py`, `migrations/0001_initial.py`, or anything
    else that isn't nested under a YYYY/MM/DD/ date partition.
    """
    posix = rel_path.replace(os.sep, '/')
    return bool(_DATE_PARTITION_RE.search(posix))


class Command(BaseCommand):
    help = "Copy legacy evidence to ASSESSMENTS_ROOT/evidence/ with strict pattern filtering."

    def add_arguments(self, parser):
        parser.add_argument('--legacy-root', default='/usr/src/app/evidence')
        parser.add_argument('--dry-run', action='store_true')
        parser.add_argument(
            '--clean',
            action='store_true',
            help='After relocation, delete any files at the destination that do not '
                 'match the evidence naming pattern (YYYY/MM/DD/<hex>.<ext>).',
        )

    def handle(self, *args, legacy_root, dry_run, clean, **_):
        dest_root = settings.EVIDENCE_STORAGE_ROOT
        copied = 0
        skipped = 0
        rejected = 0
        errors = 0

        if os.path.isdir(legacy_root):
            os.makedirs(dest_root, mode=0o750, exist_ok=True)

            for dirpath, _, filenames in os.walk(legacy_root):
                for name in filenames:
                    src = os.path.join(dirpath, name)
                    rel_path = os.path.relpath(src, legacy_root)
                    if not _looks_like_evidence(rel_path):
                        rejected += 1
                        if dry_run:
                            self.stdout.write(
                                self.style.WARNING("DRY-RUN skip (non-evidence) %s" % src)
                            )
                        continue

                    dst = os.path.join(dest_root, rel_path)
                    if os.path.isfile(dst):
                        try:
                            if _sha256(src) == _sha256(dst):
                                skipped += 1
                                continue
                        except OSError:
                            pass

                    if dry_run:
                        self.stdout.write("DRY-RUN copy %s -> %s" % (src, dst))
                        copied += 1
                        continue

                    try:
                        os.makedirs(os.path.dirname(dst), mode=0o750, exist_ok=True)
                        shutil.copy2(src, dst)
                        os.chmod(dst, 0o640)
                        copied += 1
                        if copied % 100 == 0:
                            self.stdout.write(self.style.SUCCESS(
                                "relocated %d files so far..." % copied
                            ))
                    except OSError as exc:
                        self.stderr.write(self.style.ERROR(
                            "Failed to copy %s: %s" % (src, exc)
                        ))
                        errors += 1
        else:
            self.stdout.write(self.style.WARNING(
                "Legacy root %s does not exist. Nothing to relocate." % legacy_root
            ))

        cleaned = 0
        if clean and os.path.isdir(dest_root):
            for dirpath, _, filenames in os.walk(dest_root):
                for name in filenames:
                    fpath = os.path.join(dirpath, name)
                    rel_path = os.path.relpath(fpath, dest_root)
                    if _looks_like_evidence(rel_path):
                        continue
                    if dry_run:
                        self.stdout.write(
                            self.style.WARNING("DRY-RUN would delete non-evidence: %s" % fpath)
                        )
                        cleaned += 1
                        continue
                    try:
                        os.remove(fpath)
                        cleaned += 1
                    except OSError as exc:
                        self.stderr.write(self.style.ERROR(
                            "Failed to delete %s: %s" % (fpath, exc)
                        ))
                        errors += 1
            # Prune now-empty directories left behind by the cleanup.
            if not dry_run:
                for dirpath, dirnames, filenames in os.walk(dest_root, topdown=False):
                    if dirpath == dest_root:
                        continue
                    if not dirnames and not filenames:
                        try:
                            os.rmdir(dirpath)
                        except OSError:
                            pass

        self.stdout.write(self.style.SUCCESS(
            "Done. copied=%d skipped=%d rejected=%d cleaned=%d errors=%d dest=%s" % (
                copied, skipped, rejected, cleaned, errors, dest_root,
            )
        ))
