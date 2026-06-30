"""
Integration test: End-to-end CVE enrichment + correlation flow.

Tests the complete pipeline:
  CVE Enrichment (mocked NVD/EPSS APIs)
    -> Vulnerability Creation
      -> Correlation Engine (deduplication, scoring)
        -> VulnerabilityHistory Tracking
          -> Remediation Detection

Bugs fixed vs. phase6.md source:
  - Added missing `from unittest.mock import patch, MagicMock`
  - Replaced invalid `self.stdout.write(self.style.SUCCESS(...))` with `print()`
    (django.test.TestCase has no stdout/style attributes)
  - Added Django environment setup consistent with other test modules
  - Fixed deduplication assertion: _generate_group_key uses source+name+subdomain+endpoint.
    Deduplication fires only when two findings share the same group_key. Two vulns with
    different sources (nuclei vs semgrep) produce DIFFERENT group_keys and are not
    deduplicated; they instead produce a multi-tool CVE confirmation boost.
    Test now uses same-source duplicates to exercise the deduplication code path.
"""

import os
import django

# Setup Django environment before importing any Django models
os.environ.setdefault('DJANGO_SETTINGS_MODULE', 'reNgine.settings')
os.environ['RENGINE_SECRET_KEY'] = 'secret'
django.setup()

from django.test import TestCase
from django.utils import timezone
from unittest.mock import patch, MagicMock

from startScan.models import (
    CveId, Vulnerability, ScanHistory, Subdomain,
    VulnerabilityHistory, ImpactAssessment
)
from reNgine.cve_enrichment import CVEEnrichmentService
from reNgine.correlation import VulnerabilityCorrelationEngine
from scanEngine.models import EngineType
from targetApp.models import Domain


class EndToEndCVECorrelationTestCase(TestCase):
    """Test complete flow: enrichment -> correlation -> history tracking -> remediation detection."""

    @patch('requests.get')
    def test_full_enrichment_correlation_flow(self, mock_get):
        """
        Verify the end-to-end pipeline:
          1. Enrich a CVE via mocked NVD + EPSS APIs
          2. Create two duplicate vulnerability findings (same source - deduplication scenario)
          3. Run the correlation engine - one finding should be suppressed (deduplication)
          4. Verify the kept finding has an ImpactAssessment attack chain
          5. Verify VulnerabilityHistory record is created for the kept finding
          6. Create a second scan where the vulnerability is absent
          7. Run correlation on empty scan - history should be marked remediated

        Note on group_key: _generate_group_key hashes source+name+subdomain+endpoint.
        Deduplication only fires when two findings produce the SAME group_key.
        For different-source findings (nuclei vs semgrep) the engine applies a
        multi-tool CVE boost rather than suppressing one of them.

        Args:
            mock_get: Mocked requests.get injected by @patch decorator.
        """

        # ============ SETUP ============

        domain = Domain.objects.create(name='app.example-integration.com')
        engine, _ = EngineType.objects.get_or_create(engine_name='test_engine', yaml_configuration='')
        scan = ScanHistory.objects.create(
            domain=domain,
            scan_type=engine,
            start_scan_date=timezone.now()
        )
        subdomain = Subdomain.objects.create(
            scan_history=scan,
            target_domain=domain,
            name='api.app.example-integration.com',
            criticality_level=4  # High - boosts correlation score
        )

        # ============ PHASE 1: CVE ENRICHMENT ============

        def mock_get_side_effect(url, *args, **kwargs):
            """
            Returns mocked responses depending on which API is being called.

            Args:
                url (str): The URL being requested.
            """
            mock_response = MagicMock()
            mock_response.status_code = 200

            if 'services.nvd.nist.gov' in url:
                # Mocked NVD API v2.0 response with full CVSS v3.1 data
                mock_response.json.return_value = {
                    "vulnerabilities": [{
                        "cve": {
                            "id": "CVE-2024-CRITICAL",
                            "published": "2024-06-01T00:00:00Z",
                            "lastModified": "2024-06-04T00:00:00Z",
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
            else:
                mock_response.json.return_value = {}

            return mock_response

        mock_get.side_effect = mock_get_side_effect

        # Create EpssFeedData directly since the app reads from local cache
        from startScan.models import EpssFeedData
        EpssFeedData.objects.create(
            cve_id='CVE-2024-99999',
            epss_score=0.98765,
            epss_percentile=99.0
        )

        # Enrich CVE via mocked external APIs
        service = CVEEnrichmentService()
        cve = service.enrich_cve('CVE-2024-99999')

        # Assert enrichment applied correctly
        self.assertIsNotNone(cve, "CVE enrichment returned None - check CVEEnrichmentService")
        self.assertEqual(cve.cvss_v31_base_score, 9.8)
        self.assertAlmostEqual(cve.epss_percentile, 99.0, places=1)
        self.assertEqual(cve.attack_vector, 'NETWORK')

        # ============ PHASE 2: CREATE DUPLICATE VULNERABILITY FINDINGS ============
        # Both findings have the SAME source so they produce the SAME group_key.
        # This correctly exercises the in-scan deduplication path.
        # (group_key = SHA256(source:name:subdomain:endpoint))

        vuln1 = Vulnerability.objects.create(
            name='Remote Code Execution via API',
            severity=4,  # Critical
            scan_history=scan,
            subdomain=subdomain,
            source='nuclei'  # Same source as vuln2
        )
        vuln1.cve_ids.add(cve)

        vuln2 = Vulnerability.objects.create(
            name='Remote Code Execution via API',  # Same name
            severity=4,
            scan_history=scan,
            subdomain=subdomain,
            source='nuclei'  # Same source - ensures identical group_key -> deduplication
        )
        vuln2.cve_ids.add(cve)

        # ============ PHASE 3: CORRELATION ============

        correlator = VulnerabilityCorrelationEngine(scan_history=scan)
        correlator.correlate_findings(subdomain_id=subdomain.id)

        vuln1.refresh_from_db()
        vuln2.refresh_from_db()

        # Verify deduplication: exactly one suppressed, one kept
        # (Both have same source+name+subdomain+endpoint -> same group_key)
        self.assertTrue(
            vuln1.is_suppressed or vuln2.is_suppressed,
            "Expected one vulnerability to be suppressed (deduplication failed)."
        )
        self.assertFalse(
            vuln1.is_suppressed and vuln2.is_suppressed,
            "Both vulnerabilities were suppressed - deduplication logic incorrect"
        )

        kept_vuln = vuln1 if not vuln1.is_suppressed else vuln2

        # Verify correlation scoring is non-trivially high due to CVSS 9.8 + high criticality
        self.assertGreater(
            kept_vuln.correlation_score, 50,
            "Expected correlation score > 50, got {}".format(kept_vuln.correlation_score)
        )

        # Verify attack chain was generated for the kept vulnerability
        assessment = ImpactAssessment.objects.filter(vulnerability=kept_vuln).first()
        self.assertIsNotNone(
            assessment,
            "Expected ImpactAssessment to be created for the kept vulnerability"
        )
        self.assertIsNotNone(
            assessment.potential_attack_chain,
            "Expected potential_attack_chain to be populated"
        )
        self.assertIn(
            'steps', assessment.potential_attack_chain,
            "Attack chain JSON should contain 'steps' key"
        )

        # ============ PHASE 4: HISTORY TRACKING ============

        history = VulnerabilityHistory.objects.filter(
            group_key=kept_vuln.group_key
        ).first()

        self.assertIsNotNone(
            history,
            "Expected VulnerabilityHistory record to be created for kept vulnerability"
        )
        self.assertGreaterEqual(history.total_occurrences, 1)
        self.assertFalse(history.is_remediated)
        self.assertEqual(
            history.cve, cve,
            "VulnerabilityHistory should link to the enriched CVE"
        )

        # ============ PHASE 5: REMEDIATION DETECTION ============

        # Create second scan where the vulnerability is NOT found
        scan2 = ScanHistory.objects.create(
            domain=domain,
            scan_type=engine,
            start_scan_date=timezone.now() + timezone.timedelta(days=7)
        )

        # Run correlation on the empty scan - should detect previous finding is remediated
        correlator2 = VulnerabilityCorrelationEngine(scan_history=scan2)
        correlator2.correlate_findings()

        # Verify remediation detection updated the history record from scan 1
        history.refresh_from_db()
        self.assertTrue(
            history.is_remediated,
            "VulnerabilityHistory should be marked remediated when not found in subsequent scan"
        )
        self.assertIsNotNone(
            history.remediation_date,
            "remediation_date should be set when vulnerability is marked remediated"
        )

        print(
            '✅ End-to-end integration test passed: '
            'Enrichment -> Correlation -> Deduplication -> History -> Remediation detection'
        )
