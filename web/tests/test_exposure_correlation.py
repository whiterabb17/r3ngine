from django.test import TestCase
from django.utils import timezone
from startScan.models import (
    ScanHistory, Domain, Subdomain, EndPoint, Screenshot,
    Vulnerability, Exposure, ExposureEvidence, Technology,
    IpAddress, Port,
)
from scanEngine.models import EngineType
from reNgine.exposure_correlation import ExposureCorrelationEngine


class ExposureCorrelationEngineTests(TestCase):
    def setUp(self):
        self.domain = Domain.objects.create(name="example.com")
        self.engine = EngineType.objects.create(
            engine_name="Test Engine",
            yaml_configuration="{}"
        )
        self.scan_history = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            start_scan_date=timezone.now(),
            scan_status=2
        )
        self.subdomain = Subdomain.objects.create(
            scan_history=self.scan_history,
            target_domain=self.domain,
            name="vpn.example.com",
            http_status=200,
            http_url="https://vpn.example.com",
            page_title="GlobalProtect Portal",
            webserver="nginx"
        )
        self.tech_vpn = Technology.objects.create(name="Pulse Secure")
        self.subdomain.technologies.add(self.tech_vpn)

    def _make_subdomain(self, name, **kwargs):
        defaults = {
            'scan_history': self.scan_history,
            'target_domain': self.domain,
        }
        defaults.update(kwargs)
        return Subdomain.objects.create(name=name, **defaults)

    def _correlate(self):
        engine = ExposureCorrelationEngine(scan_history=self.scan_history)
        engine.correlate_exposures()

    # ------------------------------------------------------------------
    # Original tests
    # ------------------------------------------------------------------

    def test_classify_vpn_gateway(self):
        self._correlate()
        exposure = Exposure.objects.get(subdomain=self.subdomain)
        self.assertIn("VPN Gateway", exposure.type)
        self.assertEqual(exposure.status, "open")

    def test_collect_evidence_and_link_vulns(self):
        vuln = Vulnerability.objects.create(
            scan_history=self.scan_history,
            target_domain=self.domain,
            subdomain=self.subdomain,
            name="Open Port Info",
            severity=0,
            http_url="https://vpn.example.com"
        )

        self._correlate()
        exposure = Exposure.objects.get(subdomain=self.subdomain)

        evidence_count = ExposureEvidence.objects.filter(exposure=exposure).count()
        self.assertGreater(evidence_count, 0)

        vuln.refresh_from_db()
        self.assertEqual(vuln.exposure_id, exposure.id)

    def test_database_classification(self):
        db_sub = self._make_subdomain("db.example.com")
        ip = IpAddress.objects.create(address="10.0.0.1")
        port = Port.objects.create(number=5432)
        ip.ports.add(port)
        db_sub.ip_addresses.add(ip)

        self._correlate()
        exposure = Exposure.objects.get(subdomain=db_sub)
        self.assertIn("Database", exposure.type)

    # ------------------------------------------------------------------
    # Classification helper tests
    # ------------------------------------------------------------------

    def test_has_keyword_matches_substring(self):
        self.assertTrue(ExposureCorrelationEngine._has_keyword("vpn gateway portal", ["vpn"]))
        self.assertFalse(ExposureCorrelationEngine._has_keyword("some page title", ["vpn"]))

    def test_has_tech_matches_substring_in_set(self):
        corpus = {"nginx", "postgresql 15.2", "openssl"}
        self.assertTrue(ExposureCorrelationEngine._has_tech(corpus, ["postgres"]))
        self.assertFalse(ExposureCorrelationEngine._has_tech(corpus, ["mysql"]))

    # ------------------------------------------------------------------
    # Staging / Dev classification — tightened to subdomain prefixes
    # ------------------------------------------------------------------

    def test_staging_prefix_classified(self):
        sub = self._make_subdomain("staging.example.com")
        self._correlate()
        exposure = Exposure.objects.get(subdomain=sub)
        self.assertIn("Staging / Dev", exposure.type)

    def test_dev_prefix_classified(self):
        sub = self._make_subdomain("dev.example.com")
        self._correlate()
        exposure = Exposure.objects.get(subdomain=sub)
        self.assertIn("Staging / Dev", exposure.type)

    def test_developer_subdomain_not_staging(self):
        sub = self._make_subdomain("developer.example.com")
        self._correlate()
        exposure = Exposure.objects.get(subdomain=sub)
        self.assertNotIn("Staging / Dev", exposure.type)

    def test_attestation_subdomain_not_staging(self):
        sub = self._make_subdomain("attestation.example.com")
        self._correlate()
        exposure = Exposure.objects.get(subdomain=sub)
        self.assertNotIn("Staging / Dev", exposure.type)

    # ------------------------------------------------------------------
    # Admin Portal — 'login' removed to avoid false positives
    # ------------------------------------------------------------------

    def test_admin_keyword_classified(self):
        sub = self._make_subdomain(
            "panel.example.com",
            page_title="Admin Dashboard",
            http_status=200,
        )
        self._correlate()
        exposure = Exposure.objects.get(subdomain=sub)
        self.assertIn("Admin Portal", exposure.type)

    def test_login_page_not_admin(self):
        sub = self._make_subdomain(
            "app.example.com",
            page_title="Login - My App",
            http_status=200,
        )
        self._correlate()
        exposure = Exposure.objects.get(subdomain=sub)
        self.assertNotIn("Admin Portal", exposure.type)

    # ------------------------------------------------------------------
    # Evidence: re-scan replaces evidence (no duplicates)
    # ------------------------------------------------------------------

    def test_rescan_replaces_evidence_no_duplicates(self):
        self._correlate()
        exposure = Exposure.objects.get(subdomain=self.subdomain)
        first_count = ExposureEvidence.objects.filter(exposure=exposure).count()
        self.assertGreater(first_count, 0)

        self._correlate()
        exposure.refresh_from_db()
        second_count = ExposureEvidence.objects.filter(exposure=exposure).count()
        self.assertEqual(first_count, second_count)

    # ------------------------------------------------------------------
    # Evidence caps
    # ------------------------------------------------------------------

    def test_evidence_endpoint_cap(self):
        for i in range(10):
            EndPoint.objects.create(
                scan_history=self.scan_history,
                subdomain=self.subdomain,
                target_domain=self.domain,
                http_url=f"https://vpn.example.com/path{i}",
                http_status=200,
            )
        self._correlate()
        exposure = Exposure.objects.get(subdomain=self.subdomain)
        crawler_evidence = ExposureEvidence.objects.filter(
            exposure=exposure, source_tool="Crawler"
        ).count()
        self.assertLessEqual(crawler_evidence, 5)

    # ------------------------------------------------------------------
    # No scan_history provided
    # ------------------------------------------------------------------

    def test_no_scan_history_returns_early(self):
        engine = ExposureCorrelationEngine(scan_history=None)
        engine.correlate_exposures()
        self.assertEqual(Exposure.objects.count(), 0)

    # ------------------------------------------------------------------
    # Multi-classification
    # ------------------------------------------------------------------

    def test_multiple_classifications(self):
        sub = self._make_subdomain(
            "jenkins.example.com",
            page_title="Jenkins CI Dashboard",
            http_status=200,
        )
        self._correlate()
        exposure = Exposure.objects.get(subdomain=sub)
        self.assertIn("CI/CD & Automation", exposure.type)
        self.assertIn("Admin Portal", exposure.type)

    # ------------------------------------------------------------------
    # Unclassified fallback
    # ------------------------------------------------------------------

    def test_unclassified_fallback(self):
        sub = self._make_subdomain("unknown.example.com")
        self._correlate()
        exposure = Exposure.objects.get(subdomain=sub)
        self.assertIn("Unclassified Asset", exposure.type)

    # ------------------------------------------------------------------
    # Remote Access via ports
    # ------------------------------------------------------------------

    def test_remote_access_via_ssh_port(self):
        sub = self._make_subdomain("host.example.com")
        ip = IpAddress.objects.create(address="10.0.0.2")
        port = Port.objects.create(number=22)
        ip.ports.add(port)
        sub.ip_addresses.add(ip)

        self._correlate()
        exposure = Exposure.objects.get(subdomain=sub)
        self.assertIn("Remote Access Protocol", exposure.type)

    # ------------------------------------------------------------------
    # Email server via ports
    # ------------------------------------------------------------------

    def test_email_server_via_smtp_port(self):
        sub = self._make_subdomain("mail.example.com")
        ip = IpAddress.objects.create(address="10.0.0.3")
        port = Port.objects.create(number=25)
        ip.ports.add(port)
        sub.ip_addresses.add(ip)

        self._correlate()
        exposure = Exposure.objects.get(subdomain=sub)
        self.assertIn("Email Server", exposure.type)

    # --- Risk score tests ---

    def test_risk_score_nonzero_after_correlation(self):
        """VPN Gateway with no vulns should have a non-zero risk score (asset type weight alone)."""
        self._correlate()
        exposure = Exposure.objects.get(subdomain=self.subdomain)
        self.assertGreater(exposure.risk_score, 0.0)

    def test_risk_score_increases_with_critical_vuln(self):
        """A critical vulnerability must push the risk score above the type-only baseline."""
        # Correlate once to get the baseline (no vulns)
        self._correlate()
        baseline = Exposure.objects.get(subdomain=self.subdomain).risk_score

        # Add a critical vuln, recorrelate
        Vulnerability.objects.create(
            scan_history=self.scan_history,
            target_domain=self.domain,
            subdomain=self.subdomain,
            name="Critical RCE",
            severity=4,
            http_url="https://vpn.example.com",
        )
        self._correlate()
        exposure = Exposure.objects.get(subdomain=self.subdomain)
        self.assertGreater(exposure.risk_score, baseline)

    def test_risk_score_dampened_by_false_positive_history(self):
        """Prior false_positive on same subdomain name should dampen the risk score by 30%."""
        # Seed a prior scan's exposure for the same subdomain name, marked false_positive
        prior_scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            start_scan_date=timezone.now(),
            scan_status=2,
        )
        prior_sub = Subdomain.objects.create(
            scan_history=prior_scan,
            target_domain=self.domain,
            name="vpn.example.com",
            http_status=200,
            http_url="https://vpn.example.com",
            page_title="GlobalProtect Portal",
        )
        Exposure.objects.create(
            scan_history=prior_scan,
            subdomain=prior_sub,
            target_domain=self.domain,
            type=["VPN Gateway"],
            status='false_positive',
            risk_score=7.0,
        )
        # Add a critical vuln to the current scan's subdomain
        Vulnerability.objects.create(
            scan_history=self.scan_history,
            target_domain=self.domain,
            subdomain=self.subdomain,
            name="Critical RCE",
            severity=4,
            http_url="https://vpn.example.com",
        )
        self._correlate()
        exposure = Exposure.objects.get(subdomain=self.subdomain)
        # Undampened: 0.5*10 + 0.35*9 = 5 + 3.15 = 8.15
        # Dampened:   8.15 * 0.7 = 5.705
        self.assertLess(exposure.risk_score, 8.0)
        self.assertGreater(exposure.risk_score, 0.0)

    # --- URL-false-positive regression tests ---

    def test_dashboard_in_url_does_not_classify_admin_portal(self):
        """A subdomain whose URL contains 'dashboard' but whose page title does not
        should NOT be classified as Admin Portal."""
        sub = self._make_subdomain(
            "dashboardv3.example.com",
            http_url="https://dashboardv3.example.com",
            http_status=200,
            page_title="Product Overview",
        )
        EndPoint.objects.create(
            scan_history=self.scan_history,
            subdomain=sub,
            target_domain=self.domain,
            http_url="https://dashboardv3.example.com/home",
            http_status=200,
        )
        self._correlate()
        exposure = Exposure.objects.get(subdomain=sub)
        self.assertNotIn("Admin Portal", exposure.type)

    def test_admin_in_page_title_still_classifies_admin_portal(self):
        """Page title containing 'admin' must still classify as Admin Portal (regression guard)."""
        sub = self._make_subdomain(
            "panel.example.com",
            http_url="https://panel.example.com",
            http_status=200,
            page_title="Admin Control Panel",
        )
        self._correlate()
        exposure = Exposure.objects.get(subdomain=sub)
        self.assertIn("Admin Portal", exposure.type)

    def test_endpoint_url_keyword_does_not_leak_into_classification(self):
        """Endpoint URLs should not contribute to keyword-based classification signals."""
        sub = self._make_subdomain(
            "branding.example.com",
            http_url="https://branding.example.com",
            http_status=200,
            page_title="Brand Assets",
        )
        # Endpoint URL contains 'admin' in the path — must NOT trigger Admin Portal
        EndPoint.objects.create(
            scan_history=self.scan_history,
            subdomain=sub,
            target_domain=self.domain,
            http_url="https://branding.example.com/admin-resources",
            http_status=200,
        )
        self._correlate()
        exposure = Exposure.objects.get(subdomain=sub)
        self.assertNotIn("Admin Portal", exposure.type)
