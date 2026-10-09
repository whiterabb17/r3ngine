"""OpSec metadata stripping cleans every supported file under a results dir.

strip_directory used to return right after its settings check, so enabling
"metadata stripping" in the OpSec settings had no effect on scan results.
"""
import os
import tempfile
from types import SimpleNamespace
from unittest import TestCase
from unittest.mock import patch

from PIL import Image

from reNgine.utils.opsec import OpSecManager

EXIF_ORIENTATION = 0x0112


def _jpeg_with_exif(path: str) -> None:
    exif = Image.Exif()
    exif[EXIF_ORIENTATION] = 3
    Image.new('RGB', (4, 4), 'red').save(path, exif=exif.tobytes())


def _has_exif(path: str) -> bool:
    with Image.open(path) as img:
        return bool(img.getexif())


def _manager(enabled: bool = True, stripping: bool = True) -> OpSecManager:
    manager = OpSecManager.__new__(OpSecManager)
    manager.settings = SimpleNamespace(enable_metadata_stripping=stripping)
    return manager


class StripDirectoryTests(TestCase):

    def test_strips_supported_files_recursively_and_skips_links(self):
        with tempfile.TemporaryDirectory() as results, tempfile.TemporaryDirectory() as outside:
            nested = os.path.join(results, 'osint', 'docs')
            os.makedirs(nested)
            inside = os.path.join(nested, 'photo.jpg')
            _jpeg_with_exif(inside)
            target = os.path.join(outside, 'elsewhere.jpg')
            _jpeg_with_exif(target)
            os.symlink(target, os.path.join(results, 'link.jpg'))
            notes = os.path.join(results, 'notes.txt')
            with open(notes, 'w') as fh:
                fh.write('keep me')

            with patch.object(OpSecManager, 'is_enabled', return_value=True):
                _manager().strip_directory(results)

            self.assertTrue(os.path.exists(inside))
            self.assertFalse(_has_exif(inside))
            self.assertTrue(_has_exif(target), 'a file behind a symlink must not be rewritten')
            with open(notes) as fh:
                self.assertEqual(fh.read(), 'keep me')

    def test_does_nothing_when_stripping_is_off(self):
        with tempfile.TemporaryDirectory() as results:
            photo = os.path.join(results, 'photo.jpg')
            _jpeg_with_exif(photo)
            with patch.object(OpSecManager, 'is_enabled', return_value=True):
                _manager(stripping=False).strip_directory(results)
            self.assertTrue(_has_exif(photo))

    def test_missing_directory_is_ignored(self):
        with patch.object(OpSecManager, 'is_enabled', return_value=True):
            _manager().strip_directory('/nonexistent/results/dir')
