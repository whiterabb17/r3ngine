"""Lean-image routing contract: ROUTED_TOOLS membership and go env overlay."""
from django.test import SimpleTestCase


class RoutedToolsLeanContractTests(SimpleTestCase):
    def test_lean_split_tools_are_routed(self):
        from reNgine.utils.task import ROUTED_TOOLS

        for name in (
            'xurlfind3r', 'getasn', 'jswhois', 'fping', 'arp-scan',
            'enumerepo', 'titus', 'reconx', 'gosearch', 'exifray', 'vulnx',
            'k6', 'wrk', 'hping3', 'vigolium', 'gitleaks', 'trufflehog',
            'noseyparker',
        ):
            self.assertIn(name, ROUTED_TOOLS)

    def test_python_native_tools_stay_unrouted(self):
        from reNgine.utils.task import ROUTED_TOOLS

        for name in ('bbot', 'wafw00f', 'arjun', 'bup', 'gato', 'whoisdomain'):
            self.assertNotIn(name, ROUTED_TOOLS)

    def test_go_executor_payload_includes_env_overlay(self):
        from reNgine.utils.task import _go_executor_workflow_input

        payload = _go_executor_workflow_input(
            ['vulnx', 'id', '--json', 'CVE-2024-0001'],
            timeout=30,
            tool='vulnx',
            env={'PDCP_API_KEY': 'secret', 'EMPTY': ''},
        )
        self.assertEqual(payload['env'], {'PDCP_API_KEY': 'secret'})
        self.assertEqual(payload['command'], ['vulnx id --json CVE-2024-0001'])
