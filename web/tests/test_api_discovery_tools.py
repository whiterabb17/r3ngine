"""web_api_discovery honours the run_<tool> flags the engine editor writes."""
import unittest
from pathlib import Path

import yaml

from reNgine.common_func import resolve_api_discovery_tools

FIXTURES = Path(__file__).resolve().parent.parent / 'fixtures' / 'scan_engines'


class ResolveApiDiscoveryToolsTest(unittest.TestCase):

    def test_uses_tools_alone_is_returned_unchanged(self):
        section = {'uses_tools': ['kiterunner', 'linkfinder']}
        self.assertEqual(resolve_api_discovery_tools(section), ['kiterunner', 'linkfinder'])

    def test_true_flag_adds_the_tool_once(self):
        section = {
            'uses_tools': ['linkfinder', 'sourcemapper'],
            'run_favirecon': True,
            'run_sourcemapper': True,
        }
        self.assertEqual(
            resolve_api_discovery_tools(section),
            ['linkfinder', 'sourcemapper', 'favirecon'],
        )

    def test_false_flag_keeps_a_listed_tool(self):
        section = {'uses_tools': ['linkfinder', 'grpcurl'], 'run_grpcurl': False}
        self.assertEqual(resolve_api_discovery_tools(section), ['linkfinder', 'grpcurl'])

    def test_default_applies_only_without_uses_tools(self):
        default = ['kiterunner', 'arjun']
        self.assertEqual(
            resolve_api_discovery_tools({'run_julius': True}, default=default),
            ['kiterunner', 'arjun', 'julius'],
        )
        self.assertEqual(resolve_api_discovery_tools({'uses_tools': []}, default=default), [])
        self.assertEqual(resolve_api_discovery_tools(None), [])

    def test_non_boolean_flags_and_unknown_tools_are_ignored(self):
        section = {'uses_tools': ['linkfinder'], 'run_favirecon': 'yes', 'run_nmap': True}
        self.assertEqual(resolve_api_discovery_tools(section), ['linkfinder'])

    def test_input_list_is_not_mutated(self):
        tools = ['linkfinder']
        resolve_api_discovery_tools({'uses_tools': tools, 'run_julius': True})
        self.assertEqual(tools, ['linkfinder'])

    def test_engine_saved_by_the_editor_runs_the_checked_tools(self):
        # The shape the engine editor writes: the built-in list plus checkboxes.
        fixture = yaml.safe_load((FIXTURES / '06_rengine_recommended.yaml').read_text(encoding='utf-8'))
        section = yaml.safe_load(fixture[0]['fields']['yaml_configuration'])['web_api_discovery']
        section.update(run_favirecon=True, run_sourcemapper=True, run_grpcurl=False)
        tools = resolve_api_discovery_tools(section)
        self.assertEqual(tools[:len(section['uses_tools'])], section['uses_tools'])
        self.assertIn('favirecon', tools)
        self.assertIn('sourcemapper', tools)
        self.assertNotIn('grpcurl', tools)
