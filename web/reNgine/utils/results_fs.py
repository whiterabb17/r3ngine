"""Deleting scan output under RENGINE_RESULTS without ever leaving it."""
import logging
import os
import shutil

from django.conf import settings

from reNgine.utilities import is_safe_path

logger = logging.getLogger(__name__)

SCREENSHOT_DIR_NAME = 'screenshots'


def remove_results_dir(path: str) -> bool:
    """Recursively delete ``path`` if it is a directory strictly inside RENGINE_RESULTS.

    Returns True when something was deleted. An empty path, the results root
    itself, or anything outside it is refused, so a bad ``results_dir`` value
    in the database can never widen a delete.
    """
    if not path or '\x00' in path:
        return False
    root = os.path.realpath(settings.RENGINE_RESULTS)
    target = os.path.realpath(path)
    if target == root or not is_safe_path(root, target):
        logger.warning('Refusing to delete %s: not inside %s', path, root)
        return False
    if not os.path.isdir(target):
        return False
    shutil.rmtree(target)
    return True


def delete_screenshot_files() -> int:
    """Delete every ``screenshots`` directory under RENGINE_RESULTS; return how many."""
    root = os.path.realpath(settings.RENGINE_RESULTS)
    removed = 0
    for dirpath, dirnames, _ in os.walk(root):
        if SCREENSHOT_DIR_NAME in dirnames:
            dirnames.remove(SCREENSHOT_DIR_NAME)
            if remove_results_dir(os.path.join(dirpath, SCREENSHOT_DIR_NAME)):
                removed += 1
    return removed
