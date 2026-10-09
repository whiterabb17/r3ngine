"""Engines saved with a top-level leaks_and_secrets still run secret scanning."""
from django.test import TestCase

from scanEngine.models import EngineType


class EngineTasksSecretScanningTest(TestCase):

    def _tasks(self, yaml_configuration):
        return EngineType(engine_name='t', yaml_configuration=yaml_configuration).tasks

    def test_legacy_leaks_and_secrets_enables_secret_scanning(self):
        tasks = self._tasks('http_crawl: {}\nleaks_and_secrets:\n  gitleaks: true\n')
        self.assertEqual(tasks, ['http_crawl', 'leaks_and_secrets', 'secret_scanning'])

    def test_secret_scanning_is_not_duplicated(self):
        tasks = self._tasks('secret_scanning: {}\nleaks_and_secrets: {}\n')
        self.assertEqual(tasks.count('secret_scanning'), 1)

    def test_engines_without_either_key_are_unchanged(self):
        self.assertEqual(self._tasks('osint:\n  leaks_and_secrets:\n    gitleaks: true\n'), ['osint'])
