"""Tests for Temporal activity correctness — focus on durability constraints."""
import inspect
from django.test import TestCase


class TestOsintNoDaemonThreads(TestCase):
    def test_finish_osint_does_not_spawn_thread(self):
        """finish_osint must call osint_orchestrator directly, not in a daemon thread."""
        import reNgine.tasks as tasks_mod
        source = inspect.getsource(tasks_mod.finish_osint)
        self.assertNotIn(
            "threading.Thread",
            source,
            "finish_osint must not spawn a daemon thread — call osint_orchestrator synchronously",
        )

    def test_osint_function_does_not_spawn_thread_for_orchestrator(self):
        """The osint() task body must not launch osint_orchestrator in a daemon thread."""
        import reNgine.tasks as tasks_mod
        source = inspect.getsource(tasks_mod.osint)
        lines = source.split('\n')
        for i, line in enumerate(lines):
            if 'daemon=True' in line:
                context = '\n'.join(lines[max(0, i-3):i+2])
                if 'osint_orchestrator' in context:
                    self.fail(
                        f"osint() must not spawn daemon threads for osint_orchestrator.\nContext:\n{context}"
                    )


class TestRunGenericTaskAllowlist(TestCase):

    def test_permitted_task_names_accepted(self):
        """Tasks in the allowlist must not raise ValueError."""
        from reNgine.temporal_activities import _PERMITTED_GENERIC_TASKS
        # spot-check a few known tasks
        for name in ("subdomain_discovery", "http_crawl", "vulnerability_scan"):
            self.assertIn(name, _PERMITTED_GENERIC_TASKS)

    def test_unknown_task_name_raises(self):
        """A task name not in the allowlist must raise ValueError before any import."""
        from unittest.mock import patch, MagicMock
        from reNgine.temporal_activities import run_generic_task_activity
        fake_ctx = {"scan_history_id": 1, "domain_id": 1, "engine_id": 1}
        with self.assertRaises(ValueError) as cm:
            with patch("temporalio.activity.logger"):
                run_generic_task_activity(fake_ctx, "exec_shell_command")
        self.assertIn("exec_shell_command", str(cm.exception))

    def test_allowlist_check_before_import(self):
        """Allowlist must be checked BEFORE attempting to import from tasks module."""
        import importlib
        from unittest.mock import patch, MagicMock
        from reNgine.temporal_activities import run_generic_task_activity
        fake_ctx = {"scan_history_id": 1, "domain_id": 1, "engine_id": 1}
        with patch("temporalio.activity.logger"):
            with patch("importlib.import_module") as mock_import:
                try:
                    run_generic_task_activity(fake_ctx, "not_in_allowlist")
                except ValueError:
                    pass
            mock_import.assert_not_called()


class TestScanContext(TestCase):
    def test_required_fields_accepted(self):
        from reNgine.scan_context import ScanContext
        ctx: ScanContext = {
            "scan_history_id": 1,
            "engine_id": 2,
            "domain_id": 3,
        }
        self.assertEqual(ctx["scan_history_id"], 1)

    def test_optional_fields_accepted(self):
        from reNgine.scan_context import ScanContext
        ctx: ScanContext = {
            "scan_history_id": 1,
            "engine_id": 2,
            "domain_id": 3,
            "tasks": ["osint", "port_scan"],
            "subdomain_id": 5,
        }
        self.assertEqual(ctx["tasks"], ["osint", "port_scan"])


class TestSubScanDispatchRegistry(TestCase):
    def test_all_known_scan_types_in_registry(self):
        from reNgine.temporal_workflows import _SUBSCAN_DISPATCH
        # All top-level YAML keys that can appear in any scan engine fixture or
        # default_yaml_config.yaml must be registered here so SubScanWorkflow's
        # ValueError guard is never triggered by a valid scan type.
        required = {
            # Standard pipeline tasks
            "osint", "subdomain_discovery", "port_scan", "fetch_url",
            "dir_file_fuzz", "screenshot", "waf_detection",
            "vulnerability_scan", "baddns", "http_crawl", "web_api_discovery",
            "param_discovery", "waf_bypass", "firewall_vpn_scan",
            "spiderfoot_scan", "secret_scanning", "attack_path_modeling",
            "vigolium_harvest", "vigolium_discovery", "vigolium_analysis",
            "vigolium_scan", "dns_security",
            # Standalone workflows dispatched as child workflows
            "url_vuln", "url_crawl", "url_fuzz", "url_dirsearch", "url_params_fuzz",
            "subdomain_recon", "domain_recon", "host_recon", "cidr_recon",
            "code_scan", "vigolium_audit",
        }
        for t in required:
            self.assertIn(t, _SUBSCAN_DISPATCH, f"'{t}' is missing from _SUBSCAN_DISPATCH")

    def test_regular_entry_has_required_keys(self):
        from reNgine.temporal_workflows import _SUBSCAN_DISPATCH
        for scan_type, entry in _SUBSCAN_DISPATCH.items():
            if entry is None:
                continue  # special-case — handled inline
            self.assertIn("activity", entry, f"{scan_type}: missing 'activity' key")
            self.assertIn("timeout", entry, f"{scan_type}: missing 'timeout' key")
            self.assertIn("args_builder", entry, f"{scan_type}: missing 'args_builder' key")


class TestCheckpointStubRemoval(TestCase):
    def test_load_checkpoint_activity_is_noop(self):
        """LoadCheckpointActivity must exist as a no-op backward-compat stub.

        Workflows started before the checkpoint stubs were removed have
        LoadCheckpointActivity in their event history. The worker must have
        the activity registered so those histories can replay without a
        TMPRL1100 nondeterminism error.  The stub must return {}.
        """
        from reNgine import temporal_activities
        self.assertTrue(
            hasattr(temporal_activities, "load_checkpoint_activity"),
            "load_checkpoint_activity backward-compat stub must exist for in-flight workflow replay",
        )
        result = temporal_activities.load_checkpoint_activity({})
        self.assertEqual(result, {})

    def test_save_checkpoint_activity_is_noop(self):
        """SaveCheckpointActivity must exist as a no-op backward-compat stub."""
        from reNgine import temporal_activities
        self.assertTrue(
            hasattr(temporal_activities, "save_checkpoint_activity"),
            "save_checkpoint_activity backward-compat stub must exist for in-flight workflow replay",
        )
        result = temporal_activities.save_checkpoint_activity({})
        self.assertIsNone(result)

class TestCreateProxyListActivity(TestCase):
    def setUp(self):
        from scanEngine.models import Proxy
        Proxy.objects.all().delete()
        
    def test_create_proxy_list_enabled_http(self):
        """If mocked proxies are enabled and HTTP, it creates the list."""
        from scanEngine.models import Proxy
        from reNgine.temporal_activities import create_proxy_list_activity
        import os
        
        Proxy.objects.create(use_proxy=True, proxies="127.0.0.1:8080")
        
        ctx = {'scan_history_id': 9999}
        file_path = create_proxy_list_activity(ctx)
        
        self.assertIsNotNone(file_path)
        self.assertTrue(os.path.exists(file_path))
        with open(file_path, 'r') as f:
            self.assertEqual(f.read().strip(), 'http://127.0.0.1:8080')
            
        os.remove(file_path)

    def test_create_proxy_list_socks_proxy(self):
        """If it returns a socks proxy, then it's Tor and should not create the list."""
        from scanEngine.models import Proxy
        from reNgine.temporal_activities import create_proxy_list_activity
        
        # Test case where socks proxy is explicitly given or tor is enabled
        Proxy.objects.create(use_proxy=True, proxies="socks5://127.0.0.1:9050")
        
        ctx = {'scan_history_id': 9999}
        file_path = create_proxy_list_activity(ctx)
        
        self.assertIsNone(file_path)

    def test_create_proxy_list_not_enabled(self):
        """If not enabled (returns empty list), skip."""
        from scanEngine.models import Proxy
        from reNgine.temporal_activities import create_proxy_list_activity
        
        Proxy.objects.create(use_proxy=False, proxies="http://127.0.0.1:8080")
        
        ctx = {'scan_history_id': 9999}
        file_path = create_proxy_list_activity(ctx)
        
        self.assertIsNone(file_path)

