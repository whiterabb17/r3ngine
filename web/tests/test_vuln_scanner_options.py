"""Scanner options the engine editor writes under vulnerability_scan, and the commands they build."""
import os
import shlex
import tempfile
import unittest
from types import SimpleNamespace
from unittest.mock import MagicMock, patch

from reNgine.definitions import CPANEL_SCANNER_DEFAULT_WORDLIST, S3SCANNER_DEFAULT_PROVIDERS
from reNgine.tasks.vuln import dalfox_xss_scan, s3scanner
from reNgine.tasks.vulnerability import cpanel_scan_settings


def _task(yaml_configuration: dict, results_dir: str) -> SimpleNamespace:
    return SimpleNamespace(
        yaml_configuration=yaml_configuration,
        results_dir=results_dir,
        history_file=None,
        scan_id=1,
        activity_id=None,
        domain=None,
        scan=None,
        subscan=None,
    )


class DalfoxCommandTests(unittest.TestCase):

    def setUp(self) -> None:
        self.results_dir = tempfile.mkdtemp()

    def _command(self, dalfox: dict, **global_keys) -> list:
        conf = {'vulnerability_scan': {'fetch_gpt_report': False, 'dalfox': dalfox}, **global_keys}
        opsec = MagicMock()
        opsec.apply_stealth.side_effect = lambda _tool, cmd, proxy=None: cmd
        with patch('reNgine.tasks.vuln.stream_command', return_value=iter([])) as mock_stream, \
                patch('reNgine.tasks.vuln.get_opsec_manager', return_value=opsec), \
                patch('reNgine.tasks.vuln.Proxy') as mock_proxy, \
                patch('reNgine.tasks.vuln.Notification'):
            mock_proxy.objects.first.return_value = None
            dalfox_xss_scan(_task(conf, self.results_dir), urls=['https://app.example.test/?q=1'])
        return shlex.split(mock_stream.call_args.args[0])

    def test_reads_the_lowercase_keys_the_editor_writes(self) -> None:
        argv = self._command({
            'deep_scan': True, 'remote_payloads': True, 'remote_wordlists': True, 'scan_timeout': 60,
        })
        self.assertIn('--deep-scan', argv)
        self.assertIn('--remote-payloads', argv)
        self.assertIn('--remote-wordlists', argv)
        self.assertEqual(argv[argv.index('--scan-timeout') + 1], '60')

    def test_still_reads_the_old_uppercase_keys(self) -> None:
        argv = self._command({'DEEP_SCAN': True, 'SCAN_TIMEOUT': 90})
        self.assertIn('--deep-scan', argv)
        self.assertEqual(argv[argv.index('--scan-timeout') + 1], '90')

    def test_defaults_when_nothing_is_set(self) -> None:
        argv = self._command({})
        self.assertNotIn('--deep-scan', argv)
        self.assertNotIn('--waf-evasion', argv)
        self.assertNotIn('--delay', argv)
        self.assertNotIn('--timeout', argv)
        self.assertEqual(argv[argv.index('--scan-timeout') + 1], '300')
        self.assertEqual(argv[argv.index('--workers') + 1], '30')

    def test_zero_scan_timeout_drops_the_limit(self) -> None:
        self.assertNotIn('--scan-timeout', self._command({'scan_timeout': 0}))

    def test_tuning_options_reach_the_command(self) -> None:
        argv = self._command(
            {'waf_evasion': True, 'delay': 250, 'timeout': 20, 'threads': 7, 'blind_xss_server': 'https://cb.example.test'},
        )
        self.assertIn('--waf-evasion', argv)
        self.assertEqual(argv[argv.index('--delay') + 1], '250')
        self.assertEqual(argv[argv.index('--timeout') + 1], '20')
        self.assertEqual(argv[argv.index('--workers') + 1], '7')
        self.assertEqual(argv[argv.index('-b') + 1], 'https://cb.example.test')

    def test_a_browser_user_agent_stays_one_argument(self) -> None:
        agent = 'Mozilla/5.0 (X11; Linux x86_64) Test/1.0'
        argv = self._command({'user_agent': agent})
        self.assertEqual(argv[argv.index('--user-agent') + 1], agent)

    def test_falls_back_to_the_global_user_agent_and_threads(self) -> None:
        argv = self._command({}, user_agent='GlobalAgent/1.0', threads=12)
        self.assertEqual(argv[argv.index('--user-agent') + 1], 'GlobalAgent/1.0')
        self.assertEqual(argv[argv.index('--workers') + 1], '12')


class S3ScannerCommandTests(unittest.TestCase):

    def setUp(self) -> None:
        self.results_dir = tempfile.mkdtemp()
        with open(os.path.join(self.results_dir, 'subdomain_discovery.txt'), 'w') as f:
            f.write('app.example.test\n')

    def _commands(self, s3_config: dict, **global_keys) -> list:
        conf = {'vulnerability_scan': {'s3scanner': s3_config}, **global_keys}
        with patch('reNgine.tasks.vuln.stream_command', return_value=iter([])) as mock_stream, \
                patch('reNgine.tasks.vuln.ScanHistory'):
            s3scanner(_task(conf, self.results_dir))
        return [shlex.split(call.args[0]) for call in mock_stream.call_args_list]

    def test_one_run_per_selected_provider_with_its_threads(self) -> None:
        commands = self._commands({'providers': ['aws', 'linode'], 'threads': 4})
        self.assertEqual([argv[argv.index('-provider') + 1] for argv in commands], ['aws', 'linode'])
        self.assertTrue(all(argv[argv.index('-threads') + 1] == '4' for argv in commands))

    def test_defaults_to_every_provider_and_the_global_threads(self) -> None:
        commands = self._commands({}, threads=9)
        self.assertEqual([argv[argv.index('-provider') + 1] for argv in commands], S3SCANNER_DEFAULT_PROVIDERS)
        self.assertTrue(all(argv[argv.index('-threads') + 1] == '9' for argv in commands))


class CpanelSettingsTests(unittest.TestCase):

    def test_an_existing_wordlist_is_used(self) -> None:
        with tempfile.NamedTemporaryFile(suffix='.txt') as wordlist:
            self.assertEqual(cpanel_scan_settings({'cpanel_user_wordlist': wordlist.name})[0], wordlist.name)

    def test_a_missing_wordlist_falls_back_to_the_default(self) -> None:
        conf = {'cpanel_user_wordlist': '/nonexistent/cpanel_users.txt'}
        self.assertEqual(cpanel_scan_settings(conf)[0], CPANEL_SCANNER_DEFAULT_WORDLIST)
        self.assertEqual(cpanel_scan_settings({})[0], CPANEL_SCANNER_DEFAULT_WORDLIST)

    def test_default_wordlist_is_the_one_the_entrypoints_download(self) -> None:
        self.assertEqual(CPANEL_SCANNER_DEFAULT_WORDLIST, '/usr/src/wordlist/cpanel_users.txt')

    def test_single_and_the_old_static_spelling_use_one_proxy(self) -> None:
        self.assertTrue(cpanel_scan_settings({'proxy_type': 'single'})[1])
        self.assertTrue(cpanel_scan_settings({'proxy_type': 'static'})[1])
        self.assertFalse(cpanel_scan_settings({'proxy_type': 'rotating'})[1])
        self.assertFalse(cpanel_scan_settings({})[1])
