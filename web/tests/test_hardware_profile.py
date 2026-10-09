"""How a scan's hardware profile combines with its engine's resource limits."""
import unittest

from reNgine.temporal.activities.core import apply_hardware_profile

PROFILE = {'threads': 4, 'rate_limit': 50, 'delay': 1, 'retries': 2}


class HardwareProfileTests(unittest.TestCase):

    def test_a_tool_section_value_wins(self) -> None:
        conf = {'threads': 30, 'port_scan': {'threads': 100, 'rate_limit': 1000}}
        apply_hardware_profile(conf, PROFILE)
        self.assertEqual(conf['port_scan']['threads'], 100)
        self.assertEqual(conf['port_scan']['rate_limit'], 1000)

    def test_the_profile_beats_the_engine_global_value(self) -> None:
        # The engine editor always writes these, so they must not cancel the profile.
        conf = {'threads': 30, 'rate_limit': 150, 'retries': 1, 'dir_file_fuzz': {}}
        apply_hardware_profile(conf, PROFILE)
        self.assertEqual((conf['threads'], conf['rate_limit'], conf['retries']), (4, 50, 2))
        self.assertEqual(conf['dir_file_fuzz']['threads'], 4)
        self.assertEqual(conf['dir_file_fuzz']['rate_limit'], 50)

    def test_the_engine_global_value_fills_what_the_profile_leaves_unset(self) -> None:
        conf = {'threads': 30, 'delay': 5, 'osint': {}}
        apply_hardware_profile(conf, {'threads': None, 'rate_limit': 50, 'delay': None, 'retries': None})
        self.assertEqual(conf['osint']['threads'], 30)
        self.assertEqual(conf['osint']['delay'], 5)
        self.assertEqual(conf['osint']['rate_limit'], 50)

    def test_an_explicit_zero_in_a_section_is_kept(self) -> None:
        conf = {'osint': {'retries': 0, 'delay': 0}}
        apply_hardware_profile(conf, PROFILE)
        self.assertEqual(conf['osint']['retries'], 0)
        self.assertEqual(conf['osint']['delay'], 0)

    def test_scalar_sections_are_left_alone(self) -> None:
        conf = {'dns_security': True, 'custom_headers': ['X-Test: 1']}
        apply_hardware_profile(conf, PROFILE)
        self.assertIs(conf['dns_security'], True)
        self.assertEqual(conf['custom_headers'], ['X-Test: 1'])

    def test_timeout_stays_with_the_engine(self) -> None:
        conf = {'timeout': 5, 'port_scan': {}}
        apply_hardware_profile(conf, {**PROFILE, 'timeout': 60})
        self.assertEqual(conf['timeout'], 5)
        self.assertNotIn('timeout', conf['port_scan'])
