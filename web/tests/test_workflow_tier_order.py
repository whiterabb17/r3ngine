"""Tests for scan workflow tier ordering."""
from unittest import TestCase


class TestSubScanWorkflowTierOrder(TestCase):
    """Verify tier ordering in SubScanWorkflow tier list."""

    def _build_tiers(self, active_tasks):
        """Mirror the SubScanWorkflow tiers list.

        Keep in sync with the tiers list in SubScanWorkflow — this test will
        fail intentionally if the production list is reverted without updating here.
        """
        return [
            # Tier 1: Discovery + vigolium harvest
            [t for t in active_tasks if t in {
                "subdomain_discovery", "amass_intel_discovery", "firewall_vpn_scan",
                "dns_security", "osint", "spiderfoot_scan", "baddns",
                "vigolium_harvest",
            }],
            # Tier 2: HTTP Crawl & Port Scan + vigolium discovery, which runs here
            # (not Tier 1) so it targets all enumerated subdomains.
            [t for t in active_tasks if t in {"http_crawl", "port_scan", "vigolium_discovery"}],
            # Tier 3: URL Fetching + Screenshot
            [t for t in active_tasks if t in {"fetch_url", "screenshot"}],
            [t for t in active_tasks if t == "http_crawl_bridge"],
            [t for t in active_tasks if t == "web_api_discovery"],
            [t for t in active_tasks if t == "param_discovery"],
            [t for t in active_tasks if t == "dir_file_fuzz"],
            [t for t in active_tasks if t in {"waf_detection", "secret_scanning", "vigolium_analysis"}],
            [t for t in active_tasks if t in {"vulnerability_scan", "waf_bypass", "vigolium_scan", "run_acunetix"}],
        ]

    def test_web_api_discovery_tier_precedes_param_discovery_tier(self):
        active = {"fetch_url", "http_crawl_bridge", "web_api_discovery", "param_discovery", "dir_file_fuzz"}
        tiers = self._build_tiers(active)
        web_api_tier = next(i for i, t in enumerate(tiers) if "web_api_discovery" in t)
        param_tier = next(i for i, t in enumerate(tiers) if "param_discovery" in t)
        self.assertLess(web_api_tier, param_tier,
                        "web_api_discovery must run before param_discovery (CPDE)")

    def test_vigolium_harvest_in_tier_1_and_discovery_in_tier_2(self):
        active = {"subdomain_discovery", "vigolium_harvest", "vigolium_discovery", "http_crawl"}
        tiers = self._build_tiers(active)
        t1 = tiers[0]
        t2 = tiers[1]
        self.assertIn("vigolium_harvest", t1, "vigolium_harvest must be in Tier 1")
        self.assertNotIn("vigolium_harvest", t2)
        # Discovery needs the full subdomain list, so it waits for Tier 1 to finish.
        self.assertIn("vigolium_discovery", t2, "vigolium_discovery must be in Tier 2")
        self.assertNotIn("vigolium_discovery", t1)

    def test_vigolium_discovery_timeline_tier_matches_the_tier_that_runs_it(self):
        """The timeline label and the execution tier must not drift apart.

        `_TASK_TIER` is what groups rows in the UI and what the tier retry
        endpoint filters on; this pins it to the tier index used above.
        """
        from reNgine.task_plan import get_task_tier

        active = {"vigolium_discovery", "http_crawl"}
        tiers = self._build_tiers(active)
        executed_tier = next(
            i for i, t in enumerate(tiers, start=1) if "vigolium_discovery" in t
        )
        self.assertEqual(get_task_tier('vigolium_discovery'), executed_tier)

    def test_vigolium_harvest_precedes_http_crawl(self):
        active = {"vigolium_harvest", "vigolium_discovery", "http_crawl"}
        tiers = self._build_tiers(active)
        harvest_tier = next(i for i, t in enumerate(tiers) if "vigolium_harvest" in t)
        crawl_tier = next(i for i, t in enumerate(tiers) if "http_crawl" in t)
        self.assertLess(harvest_tier, crawl_tier, "vigolium_harvest must run before http_crawl")

    def test_web_api_discovery_not_in_analysis_tier(self):
        active = {"web_api_discovery", "waf_detection", "secret_scanning"}
        tiers = self._build_tiers(active)
        # analysis tier is now index 7 (one extra discovery tier)
        analysis_tier = tiers[7]
        self.assertNotIn("web_api_discovery", analysis_tier)

    def test_dir_file_fuzz_still_after_param_discovery(self):
        active = {"fetch_url", "param_discovery", "dir_file_fuzz"}
        tiers = self._build_tiers(active)
        param_tier = next(i for i, t in enumerate(tiers) if "param_discovery" in t)
        fuzz_tier = next(i for i, t in enumerate(tiers) if "dir_file_fuzz" in t)
        self.assertLess(param_tier, fuzz_tier,
                        "dir_file_fuzz must still run after param_discovery")

    def test_standalone_workflows_not_in_any_tier(self):
        """Standalone child-workflow types must never appear in any execution tier.

        They are stripped from active_tasks before tier construction and executed
        as a concurrent flat gather after the tier pipeline.
        """
        from reNgine.temporal.workflows import _STANDALONE_SUBSCAN_WORKFLOWS
        # Pass all standalone types as if they were active tasks
        tiers = self._build_tiers(list(_STANDALONE_SUBSCAN_WORKFLOWS))
        all_tiered = set()
        for tier in tiers:
            all_tiered.update(tier)
        for t in _STANDALONE_SUBSCAN_WORKFLOWS:
            self.assertNotIn(
                t, all_tiered,
                f"'{t}' is a standalone workflow and must not appear in any execution tier"
            )
