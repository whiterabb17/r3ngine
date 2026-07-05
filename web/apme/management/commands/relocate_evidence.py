"""Copy legacy evidence files from /usr/src/app/evidence/ to the new
assessments root. Idempotent — skips files whose sha256 already exists
at the destination.

Usage:
    python manage.py relocate_evidence               # copy live
    python manage.py relocate_evidence --dry-run     # report only
    python manage.py relocate_evidence --legacy-root /custom/path
"""
import hashlib
import os
import shutil

from django.conf import settings
from django.core.management.base import BaseCommand


def _sha256(path: str) -> str:
    h = hashlib.sha256()
    with open(path, 'rb') as f:
        for chunk in iter(lambda: f.read(1 << 20), b''):
            h.update(chunk)
    return h.hexdigest()


class Command(BaseCommand):
    help = "Copy legacy evidence from /usr/src/app/evidence/ to ASSESSMENTS_ROOT/evidence/"

    def add_arguments(self, parser):
        parser.add_argument('--legacy-root', default='/usr/src/app/evidence')
        parser.add_argument('--dry-run', action='store_true')

    def handle(self, *args, legacy_root, dry_run, **_):
        dest_root = settings.EVIDENCE_STORAGE_ROOT
        if not os.path.isdir(legacy_root):
            self.stdout.write(self.style.WARNING(
                "Legacy root %s does not exist. Nothing to relocate." % legacy_root
            ))
            return

        os.makedirs(dest_root, mode=0o750, exist_ok=True)

        copied = 0
        skipped = 0
        errors = 0
        for dirpath, _, filenames in os.walk(legacy_root):
            rel_dir = os.path.relpath(dirpath, legacy_root)
            for name in filenames:
                src = os.path.join(dirpath, name)
                dst_dir = os.path.join(dest_root, rel_dir) if rel_dir != '.' else dest_root
                dst = os.path.join(dst_dir, name)
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
                    os.makedirs(dst_dir, mode=0o750, exist_ok=True)
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

        self.stdout.write(self.style.SUCCESS(
            "Done. copied=%d skipped=%d errors=%d dest=%s" % (
                copied, skipped, errors, dest_root
            )
        ))
