import os
import django
from django.test import TestCase
from django.utils import timezone

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'reNgine.settings')
os.environ['RENGINE_SECRET_KEY'] = 'secret'
django.setup()

from startScan.models import *
from reNgine.correlation import VulnerabilityCorrelationEngine

class TestVulnerabilityCorrelation(TestCase):
    def setUp(self):
        # Setup basic data
        self.domain, _ = Domain.objects.get_or_create(name='test-correlation.com')
        self.engine, _ = EngineType.objects.get_or_create(engine_name='test_engine', yaml_configuration='')
        self.scan, _ = ScanHistory.objects.get_or_create(
            domain=self.domain,
            scan_type=self.engine,
            start_scan_date=timezone.now()
        )
        self.subdomain, _ = Subdomain.objects.get_or_create(
            name='app.test-correlation.com',
            target_domain=self.domain,
            scan_history=self.scan
        )
        self.correlator = VulnerabilityCorrelationEngine(scan_history=self.scan)

    def tearDown(self):
        # Clean up in reverse order to respect foreign keys
        VulnerabilityHistory.objects.filter(scan_history=self.scan).delete()
        ImpactAssessment.objects.filter(scan_history=self.scan).delete()
        Vulnerability.objects.filter(scan_history=self.scan).delete()
        self.subdomain.delete()
        self.scan.delete()
        self.domain.delete()
        self.engine.delete()

    def test_correlation_score_calculation(self):
        # Create a vulnerability
        vuln = Vulnerability.objects.create(
            name="SQL Injection",
            severity=3, # High
            subdomain=self.subdomain,
            scan_history=self.scan,
            type="DAST",
            source="nuclei"
        )
        
        self.correlator.correlate_findings(subdomain_id=self.subdomain.id)
        vuln.refresh_from_db()
        
        # Expected calculation:
        # Severity (3/4 * 0.4) = 0.3
        # Multi-tool (1 tool, boost = 0.3 * 0.25) = 0.075
        # Exploit (0.3 * 0.2) = 0.06
        # Criticality (1/5 * 0.1) = 0.02
        # Temporal (0 days old, score = 1.0 * 0.05) = 0.05
        # Total = 0.505 * 100 = 50.5
        self.assertEqual(vuln.correlation_score, 50.5)

    def test_multi_tool_boost(self):
        # Create a CVE
        cve, _ = CveId.objects.get_or_create(name="CVE-2024-TEST")
        
        # Vuln 1: Nuclei (DAST)
        vuln1 = Vulnerability.objects.create(
            name="Nuclei: CVE-2024-TEST",
            severity=4,
            subdomain=self.subdomain,
            scan_history=self.scan,
            type="DAST",
            source="nuclei"
        )
        vuln1.cve_ids.add(cve)
        
        # Vuln 2: Semgrep (SAST)
        vuln2 = Vulnerability.objects.create(
            name="Semgrep: CVE-2024-TEST",
            severity=4,
            subdomain=self.subdomain,
            scan_history=self.scan,
            type="SAST",
            source="semgrep"
        )
        vuln2.cve_ids.add(cve)
        
        # Run correlation
        self.correlator.correlate_findings(subdomain_id=self.subdomain.id)
        
        vuln1.refresh_from_db()
        
        # Expected calculation with boost:
        # Severity (4/4 * 0.4) = 0.4
        # Multi-tool boost (2 tools, boost = 0.7 * 0.25) = 0.175
        # Exploit (0.3 * 0.2) = 0.06
        # Criticality (1/5 * 0.1) = 0.02
        # Temporal (1.0 * 0.05) = 0.05
        # Total = 0.705 * 100 = 70.5
        self.assertEqual(vuln1.correlation_score, 70.5)

    def test_attack_chain_generation(self):
        vuln = Vulnerability.objects.create(
            name="Insecure Library",
            severity=2,
            subdomain=self.subdomain,
            scan_history=self.scan,
            type="SCA",
            source="retire"
        )
        
        self.correlator.correlate_findings(subdomain_id=self.subdomain.id)
        
        from startScan.models import ImpactAssessment
        impact = ImpactAssessment.objects.filter(vulnerability=vuln).first()
        
        self.assertIsNotNone(impact)
        self.assertIsNotNone(impact.potential_attack_chain)
        self.assertEqual(impact.potential_attack_chain['confidence'], 'Medium')
        
        phases = [step['phase'] for step in impact.potential_attack_chain['steps']]
        self.assertIn('Discovery', phases)
        self.assertIn('Exploitation', phases)
        self.assertIn('Post-Exploitation', phases)

    def test_validation_result_methods(self):
        vuln = Vulnerability.objects.create(
            name="Path Traversal",
            severity=2,
            subdomain=self.subdomain,
            scan_history=self.scan,
            http_url="http://test-correlation.com/api/v1/download",
            source="nuclei"
        )
        cve = CveId.objects.create(name="CVE-2024-PATH")
        vuln.cve_ids.add(cve)
        
        res = ValidationResult.objects.create(
            vulnerability=vuln,
            tool="ERL",
            validated=True
        )
        # Test helper methods do not raise AttributeErrors and return correct values
        self.assertEqual(res.get_severity(), 2)
        self.assertEqual(res.get_path(), "/api/v1/download")
        self.assertIn("CVE-2024-PATH", res.get_cve_str())

    def test_duplicate_detection_and_suppression(self):
        # Create two identical vulnerabilities
        vuln1 = Vulnerability.objects.create(
            name="XSS Vulnerability",
            severity=2,
            subdomain=self.subdomain,
            scan_history=self.scan,
            source="nuclei"
        )
        vuln2 = Vulnerability.objects.create(
            name="XSS Vulnerability",
            severity=2,
            subdomain=self.subdomain,
            scan_history=self.scan,
            source="nuclei"
        )
        
        self.correlator.correlate_findings(subdomain_id=self.subdomain.id)
        
        vuln1.refresh_from_db()
        vuln2.refresh_from_db()
        
        # Verify one is suppressed
        self.assertTrue(vuln1.is_suppressed or vuln2.is_suppressed)
        self.assertFalse(vuln1.is_suppressed and vuln2.is_suppressed)
        
        # Verify only the kept one has an ImpactAssessment
        kept_vuln = vuln1 if not vuln1.is_suppressed else vuln2
        suppressed_vuln = vuln2 if not vuln1.is_suppressed else vuln1
        
        self.assertTrue(ImpactAssessment.objects.filter(vulnerability=kept_vuln).exists())
        self.assertFalse(ImpactAssessment.objects.filter(vulnerability=suppressed_vuln).exists())

    def test_vulnerability_history_tracking(self):
        vuln = Vulnerability.objects.create(
            name="Leaked Secret Key",
            severity=3,
            subdomain=self.subdomain,
            scan_history=self.scan,
            source="gitleaks"
        )
        
        # Run correlation for the first scan
        self.correlator.correlate_findings(subdomain_id=self.subdomain.id)
        vuln.refresh_from_db()
        
        # Verify history record is created
        history_qs = VulnerabilityHistory.objects.filter(group_key=vuln.group_key)
        self.assertTrue(history_qs.exists())
        self.assertFalse(history_qs.first().is_remediated)
        
        # Create a second scan history for the same domain
        second_scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            start_scan_date=timezone.now()
        )
        
        # Run correlation on second scan where the vulnerability is resolved (not created)
        second_correlator = VulnerabilityCorrelationEngine(scan_history=second_scan)
        second_correlator.correlate_findings()
        
        # Verify history is marked remediated
        history_record = VulnerabilityHistory.objects.filter(group_key=vuln.group_key).order_by('-last_seen').first()
        self.assertTrue(history_record.is_remediated)
        self.assertIsNotNone(history_record.remediation_date)
        
        # Clean up second scan data
        second_scan.delete()

    def test_cve_enrichment_service(self):
        from unittest.mock import patch
        from reNgine.cve_enrichment import CVEEnrichmentService

        service = CVEEnrichmentService()

        class MockResponse:
            def __init__(self, json_data, status_code=200):
                self.json_data = json_data
                self.status_code = status_code

            def json(self):
                return self.json_data

            def raise_for_status(self):
                if self.status_code >= 400:
                    import requests
                    raise requests.HTTPError(f"HTTP Error {self.status_code}", response=self)

        def mock_get(url, *args, **kwargs):
            if "services.nvd.nist.gov" in url:
                return MockResponse({
                    "vulnerabilities": [{
                        "cve": {
                            "published": "2026-06-01T12:00:00.000",
                            "lastModified": "2026-06-02T12:00:00.000",
                            "metrics": {
                                "cvssMetricV31": [{
                                    "cvssData": {
                                        "baseScore": 8.8,
                                        "attackVector": "NETWORK",
                                        "attackComplexity": "LOW",
                                        "privilegesRequired": "NONE",
                                        "userInteraction": "REQUIRED",
                                        "confidentialityImpact": "HIGH",
                                        "integrityImpact": "HIGH",
                                        "availabilityImpact": "HIGH"
                                    }
                                }]
                            }
                        }
                    }]
                })
            elif "api.first.org" in url:
                return MockResponse({
                    "data": [{
                        "epss": "0.12345",
                        "percentile": "0.85"
                    }]
                })
            elif "known_exploited_vulnerabilities.json" in url:
                return MockResponse({
                    "vulnerabilities": [
                        {"cveID": "CVE-2024-99999"}
                    ]
                })
            return MockResponse({}, status_code=404)

        from startScan.models import EpssFeedData
        EpssFeedData.objects.create(
            cve_id="CVE-2024-99999",
            epss_score=0.12345,
            epss_percentile=85.0
        )

        with patch("requests.get", side_effect=mock_get):
            cve_obj = service.enrich_cve("CVE-2024-99999")
            self.assertEqual(cve_obj.name, "CVE-2024-99999")
            self.assertEqual(cve_obj.cvss_v31_base_score, 8.8)
            self.assertEqual(cve_obj.attack_vector, "NETWORK")
            self.assertEqual(cve_obj.attack_complexity, "LOW")
            self.assertEqual(cve_obj.epss_score, 0.12345)
            self.assertEqual(cve_obj.epss_percentile, 85.0)

            service.sync_cisa_kev_catalog()
            cve_obj.refresh_from_db()
            self.assertTrue(cve_obj.is_cisa_kev)
            
            # Clean up CVE ID
            cve_obj.delete()

