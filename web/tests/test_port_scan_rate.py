"""Where naabu's -rate comes from in the engine YAML."""
import tempfile
import unittest
from types import SimpleNamespace

from reNgine.tasks.port_scan import port_scan


class PortScanRateTests(unittest.TestCase):

    def _cmd(self, yaml_configuration: dict) -> str:
        with tempfile.TemporaryDirectory() as d:
            task = SimpleNamespace(results_dir=d, yaml_configuration=yaml_configuration)
            return port_scan(task, hosts=['a.example.test'], ctx={}, prepare_only=True)['cmd']

    def test_section_rate_limit_written_by_the_engine_editor_is_used(self) -> None:
        self.assertIn(' -rate 1000 ', self._cmd({'rate_limit': 50, 'port_scan': {'rate_limit': 1000}}))

    def test_legacy_rate_key_still_wins(self) -> None:
        self.assertIn(' -rate 300 ', self._cmd({'port_scan': {'rate': 300, 'rate_limit': 1000}}))

    def test_engine_global_rate_limit_is_the_fallback(self) -> None:
        self.assertIn(' -rate 75 ', self._cmd({'rate_limit': 75, 'port_scan': {}}))
