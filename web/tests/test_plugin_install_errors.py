"""The plugin install status shows validation errors, never internal failure text.

The install status (polled by the UI through /api/plugins/install-status/)
used to carry str(e) of any exception, including pg_dump and migration stderr.
Rule 8.2: known, user-facing validation errors are shown as they are; anything
else becomes the generic message and stays in the server log.
"""
from unittest.mock import patch

from django.core.cache import cache
from django.test import TestCase

from plugins.utils import AtomicInstaller, PluginInstallError, PluginManager
from reNgine.definitions import INTERNAL_ERROR_MESSAGE

INSTALL_ID = 'test-install-errors'


class PluginInstallErrorReportingTests(TestCase):

    def setUp(self):
        cache.delete(f'plugin:install:{INSTALL_ID}')

    def _install_failing_with(self, exc: Exception) -> dict:
        with patch.object(PluginManager, 'ensure_dirs'), \
                patch.object(PluginManager, 'extract_plugin', return_value='/nonexistent/plugin-tmp'), \
                patch.object(PluginManager, 'validate_manifest', side_effect=exc), \
                self.assertLogs('plugins.utils', level='ERROR'):
            with self.assertRaises(type(exc)):
                AtomicInstaller.install('/nonexistent/upload.zip', install_id=INSTALL_ID)
        return cache.get(f'plugin:install:{INSTALL_ID}')

    def test_validation_error_is_shown(self):
        status = self._install_failing_with(PluginInstallError('Manifest.yaml not found in plugin archive.'))
        self.assertEqual(status['status'], 'failed')
        self.assertEqual(status['error'], 'Manifest.yaml not found in plugin archive.')
        failed = [step for step in status['steps'] if step['status'] == 'failed']
        self.assertEqual([step['message'] for step in failed], ['Manifest.yaml not found in plugin archive.'])

    def test_internal_error_text_is_not_shown(self):
        status = self._install_failing_with(RuntimeError('pg_dump: password authentication failed for user "rengine"'))
        self.assertEqual(status['error'], INTERNAL_ERROR_MESSAGE)
        self.assertNotIn('pg_dump', repr(status))
