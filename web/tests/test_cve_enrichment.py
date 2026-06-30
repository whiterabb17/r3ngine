"""
Test suite for CVE enrichment service and correlation integration.
"""

import os
import django
import json
from unittest.mock import patch, MagicMock
from datetime import timedelta

# Setup Django environment
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'reNgine.settings')
os.environ['RENGINE_SECRET_KEY'] = 'secret'
django.setup()

from django.test import TestCase
from django.utils import timezone
from django.core.cache import cache

from startScan.models import CveId, Vulnerability, ScanHistory, Subdomain
from reNgine.cve_enrichment import CVEEnrichmentService, CVEBatchEnricher
from reNgine.correlation import VulnerabilityCorrelationEngine
from scanEngine.models import EngineType
from targetApp.models import Domain


class CVEEnrichmentServiceTestCase(TestCase):
    """
    Test case to verify the functionality of CVEEnrichmentService.
    Covers fetching from NVD API, FIRST EPSS API, and CISA KEV synchronization.
    """
    
    def setUp(self):
        """Set up test environment and clear cache before each test."""
        self.service = CVEEnrichmentService()
        cache.clear()
    
    def tearDown(self):
        """Clean up cache after each test."""
        cache.clear()
    
    @patch('requests.get')
    def test_enrich_cve_bare_year_number_format(self, mock_get):
        """Verify that bare YYYY-NNNNN values (missing the CVE- prefix) are normalised."""
        mock_response = MagicMock()
        mock_response.status_code = 404
        mock_response.json.return_value = {"vulnerabilities": []}
        mock_get.return_value = mock_response

        cve = self.service.enrich_cve("2026-6127")

        self.assertIsNotNone(cve)
        self.assertEqual(cve.name, "CVE-2026-6127")

    def test_enrich_cve_invalid_format_proceeds(self):
        """Verify that a value that is not a CVE ID and not YYYY-NNNNN still creates the object and proceeds."""
        result = self.service.enrich_cve("NOT-A-CVE")
        self.assertIsNotNone(result)
        self.assertEqual(result.name, "NOT-A-CVE")

    @patch('requests.get')
    def test_enrich_cve_from_nvd(self, mock_get):
        """
        Verify that NVD API responses are correctly parsed and applied to CveId objects.
        
        Args:
            mock_get: Mocked requests.get function.
        """
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [{
                "cve": {
                    "id": "CVE-2024-1234",
                    "published": "2024-01-15T10:00:00.000Z",
                    "lastModified": "2024-06-01T10:00:00.000Z",
                    "metrics": {
                        "cvssMetricV31": [{
                            "cvssData": {
                                "baseScore": 9.8,
                                "attackVector": "NETWORK",
                                "attackComplexity": "LOW",
                                "privilegesRequired": "NONE",
                                "userInteraction": "NONE",
                                "confidentialityImpact": "HIGH",
                                "integrityImpact": "HIGH",
                                "availabilityImpact": "HIGH"
                            }
                        }]
                    }
                }
            }]
        }
        mock_get.return_value = mock_response
        
        cve = CveId.objects.create(name="CVE-2024-1234")
        self.service._enrich_from_nvd(cve)
        
        self.assertIsNotNone(cve)
        self.assertEqual(cve.name, "CVE-2024-1234")
        self.assertEqual(cve.cvss_v31_base_score, 9.8)
        self.assertEqual(cve.attack_vector, "NETWORK")
        self.assertIsNotNone(cve.published_date)
    
    def test_enrich_cve_from_epss(self):
        """
        Verify that FIRST EPSS data from local EpssFeedData is applied to CveId objects.
        """
        from startScan.models import EpssFeedData
        
        cve = CveId.objects.create(name="CVE-2024-1234")
        
        EpssFeedData.objects.create(
            cve_id="CVE-2024-1234",
            epss_score=0.95842,
            epss_percentile=98.765
        )
        
        self.service._enrich_from_epss(cve)
        
        self.assertAlmostEqual(cve.epss_score, 0.95842, places=5)
        self.assertAlmostEqual(cve.epss_percentile, 98.765, places=3)
    
    @patch('requests.get')
    def test_sync_cisa_kev_catalog(self, mock_get):
        """
        Verify that the CISA KEV catalog sync successfully identifies KEV CVEs and updates local records.

        Args:
            mock_get: Mocked requests.get function.
        """
        mock_response = MagicMock()
        mock_response.status_code = 200
        mock_response.json.return_value = {
            "vulnerabilities": [
                {"cveID": "CVE-2024-1234"},
                {"cveID": "CVE-2024-5678"},
            ]
        }
        mock_get.return_value = mock_response
        
        # Pre-create one CVE
        CveId.objects.create(name="CVE-2024-1234", is_cisa_kev=False)
        
        result = self.service.sync_cisa_kev_catalog()
        
        cve = CveId.objects.get(name="CVE-2024-1234")
        self.assertTrue(cve.is_cisa_kev)
        self.assertEqual(result['updated'], 1)
    
    @patch('requests.get')
    def test_enrich_multiple_cves(self, mock_get):
        """
        Verify batch enrichment handles multiple CVE queries correctly.

        Args:
            mock_get: Mocked requests.get function.
        """
        def mock_get_side_effect(*args, **kwargs):
            mock_response = MagicMock()
            mock_response.status_code = 200
            cve_id = kwargs.get('params', {}).get('cveId', 'CVE-2024-0000')
            
            if 'cves/2.0' in args[0]:  # NVD API
                mock_response.json.return_value = {
                    "vulnerabilities": [{
                        "cve": {
                            "id": cve_id,
                            "published": "2024-01-15T10:00:00.000Z",
                            "metrics": {
                                "cvssMetricV31": [{
                                    "cvssData": {"baseScore": 8.5}
                                }]
                            }
                        }
                    }]
                }
            else:  # EPSS API
                mock_response.json.return_value = {"data": []}
            
            return mock_response
        
        mock_get.side_effect = mock_get_side_effect
        
        results = self.service.enrich_multiple_cves([
            "CVE-2024-1111",
            "CVE-2024-2222",
        ])
        
        self.assertEqual(len(results), 2)
        self.assertIn("CVE-2024-1111", results)


    @patch('subprocess.run')
    @patch('dashboard.models.ProjectDiscoveryAPIKey.objects')
    def test_enrich_cve_from_vulnx(self, mock_objects, mock_run):
        """Verify that vulnx output is correctly parsed and applied to CveId objects."""
        mock_key = MagicMock()
        mock_key.key = "test-pdcp-key"
        mock_objects.first.return_value = mock_key
        mock_objects.exists.return_value = True

        mock_result = MagicMock()
        mock_result.returncode = 0
        mock_result.stdout = json.dumps({
            "cvss_score": 9.8,
            "epss_score": 0.95842,
            "epss_percentile": 0.98765,
            "is_kev": True,
            "is_poc": True,
            "is_template": True,
            "cve_created_at": "2024-01-15T10:00:00Z",
            "cve_updated_at": "2024-06-01T10:00:00Z"
        })
        mock_run.return_value = mock_result

        cve = CveId.objects.create(name="CVE-2024-1234")
        self.service._enrich_from_vulnx(cve)

        self.assertEqual(cve.cvss_v31_base_score, 9.8)
        self.assertAlmostEqual(cve.epss_score, 0.95842, places=5)
        self.assertAlmostEqual(cve.epss_percentile, 0.98765, places=5)
        self.assertTrue(cve.is_cisa_kev)
        self.assertTrue(cve.is_poc)
        self.assertTrue(cve.is_template)


class CorrelationWithEnrichmentTestCase(TestCase):
    """
    Test case to verify the correlation engine integrates correctly with enriched CVE metadata.
    """
    
    def setUp(self):
        """Set up standard scan and subdomain fixtures for correlation testing."""
        self.domain, _ = Domain.objects.get_or_create(name='example.com')
        self.engine, _ = EngineType.objects.get_or_create(engine_name='test_engine', yaml_configuration='')
        self.scan, _ = ScanHistory.objects.get_or_create(
            domain=self.domain,
            scan_type=self.engine,
            start_scan_date=timezone.now()
        )
        self.subdomain, _ = Subdomain.objects.get_or_create(
            scan_history=self.scan,
            target_domain=self.domain,
            name='test.example.com'
        )
    
    def test_correlation_score_uses_cvss(self):
        """
        Verify that the correlation engine calculates score correctly using the CVSS score,
        and applies the CISA KEV priority boost.
        """
        # Increase asset criticality level to ensure the score is >= 75 for verification boost
        self.subdomain.criticality_level = 5
        self.subdomain.save()

        # Create enriched CVE
        cve = CveId.objects.create(
            name="CVE-2024-ENRICHED",
            cvss_v31_base_score=9.8,
            is_cisa_kev=True,
            epss_percentile=95.0
        )
        
        # Create vulnerability linked to enriched CVE
        vuln = Vulnerability.objects.create(
            name="Critical RCE",
            severity=4,
            scan_history=self.scan,
            subdomain=self.subdomain,
            source="nuclei"
        )
        vuln.cve_ids.add(cve)
        
        # Run correlation
        correlator = VulnerabilityCorrelationEngine(scan_history=self.scan)
        correlator.correlate_findings(subdomain_id=self.subdomain.id)
        
        # Verify scoring incorporated CVSS
        vuln.refresh_from_db()
        self.assertGreater(vuln.correlation_score, 50)  # Should be high due to CVSS
        self.assertEqual(vuln.validation_status, 'verified')  # CISA KEV boost


class VulnerabilityHistoryTestCase(TestCase):
    """
    Test case to verify cross-scan vulnerability tracking and remediation date calculation.
    """
    
    def setUp(self):
        """Set up standard scan and subdomain fixtures for history testing."""
        self.domain, _ = Domain.objects.get_or_create(name='example.com')
        self.engine, _ = EngineType.objects.get_or_create(engine_name='test_engine', yaml_configuration='')
        self.scan1, _ = ScanHistory.objects.get_or_create(
            domain=self.domain,
            scan_type=self.engine,
            start_scan_date=timezone.now()
        )
        self.subdomain, _ = Subdomain.objects.get_or_create(
            scan_history=self.scan1,
            target_domain=self.domain,
            name='test.example.com'
        )
    
    def test_vulnerability_history_tracking(self):
        """Verify that vulnerability history tracking detects remediation when a vuln is absent in subsequent scans."""
        from startScan.models import VulnerabilityHistory
        
        # Create vulnerability in scan 1
        vuln = Vulnerability.objects.create(
            name="Persistent XSS",
            severity=2,
            scan_history=self.scan1,
            subdomain=self.subdomain,
            source="nuclei"
        )
        
        # Run correlation (creates history)
        correlator = VulnerabilityCorrelationEngine(scan_history=self.scan1)
        correlator.correlate_findings(subdomain_id=self.subdomain.id)
        
        # Refresh vulnerability to fetch the calculated group_key
        vuln.refresh_from_db()
        
        # Verify history created
        history1 = VulnerabilityHistory.objects.filter(
            group_key=vuln.group_key
        ).first()
        self.assertIsNotNone(history1)
        self.assertFalse(history1.is_remediated)
        self.assertEqual(history1.total_occurrences, 1)
        
        # Create scan 2 (vulnerability NOT found)
        scan2 = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            start_scan_date=timezone.now() + timedelta(days=7)
        )
        
        # Run correlation on empty scan 2
        correlator2 = VulnerabilityCorrelationEngine(scan_history=scan2)
        correlator2.correlate_findings()
        
        # Verify history marked as remediated
        history1.refresh_from_db()
        self.assertTrue(history1.is_remediated)
        self.assertIsNotNone(history1.remediation_date)
    
    def test_vulnerability_history_persistence(self):
        """Verify that persistent vulnerability occurrence counting works correctly across multiple scans."""
        from startScan.models import VulnerabilityHistory
        
        # Create same vulnerability in multiple scans
        for i in range(3):
            scan_obj = self.scan1 if i == 0 else ScanHistory.objects.create(
                domain=self.domain,
                scan_type=self.engine,
                start_scan_date=timezone.now() + timedelta(days=7*i)
            )
            # Create a separate subdomain for each scan to match its scan_history
            subdomain = self.subdomain if i == 0 else Subdomain.objects.create(
                scan_history=scan_obj,
                target_domain=self.domain,
                name='test.example.com'
            )
            vuln = Vulnerability.objects.create(
                name="Persistent SQL Injection",
                severity=3,
                scan_history=scan_obj,
                subdomain=subdomain,
                source="nuclei"
            )
            
            correlator = VulnerabilityCorrelationEngine(
                scan_history=vuln.scan_history
            )
            correlator.correlate_findings(subdomain_id=subdomain.id)
        
        # Refresh vulnerability to fetch the calculated group_key
        vuln.refresh_from_db()
        
        # Get latest history record
        history = VulnerabilityHistory.objects.filter(
            group_key=vuln.group_key
        ).order_by('-last_seen').first()
        
        self.assertIsNotNone(history)
        self.assertEqual(history.total_occurrences, 3)
        # Verify first_seen is a valid datetime (time tracking working correctly)
        self.assertIsNotNone(history.first_seen)
        self.assertIsNotNone(history.last_seen)
