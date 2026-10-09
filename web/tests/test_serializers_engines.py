"""Tests for EngineSerializer.configured_tools_count and the dir_file_fuzz tool switches."""
import types
import unittest

from api.serializers.engines import EngineSerializer


def _count(yaml_text: str) -> int:
    return EngineSerializer().get_configured_tools_count(types.SimpleNamespace(yaml_configuration=yaml_text))


class TestConfiguredToolsCountDirFileFuzz(unittest.TestCase):

    def test_ffuf_counted_by_default(self):
        self.assertEqual(_count('dir_file_fuzz:\n  threads: 10\n'), 1)

    def test_ffuf_counted_for_empty_section(self):
        self.assertEqual(_count('dir_file_fuzz:\n'), 1)

    def test_ffuf_not_counted_when_run_ffuf_false(self):
        self.assertEqual(_count('dir_file_fuzz:\n  run_ffuf: false\n'), 0)

    def test_every_enabled_fuzzer_counted(self):
        yaml_text = 'dir_file_fuzz:\n  run_ffuf: true\n  run_dirsearch: true\n  run_feroxbuster: true\n'
        self.assertEqual(_count(yaml_text), 3)
