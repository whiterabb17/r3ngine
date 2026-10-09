import json
from unittest.mock import patch, MagicMock
from django.test import TransactionTestCase
from django.utils import timezone
from django.contrib.auth import get_user_model
from rest_framework.test import APIClient

from startScan.models import Domain, ScanHistory, Vulnerability, ScanReport
from scanEngine.models import EngineType, OpSec, Proxy, VulnerabilityReportSetting
from engagements.models import Client, Engagement, Assessment
from reNgine.tasks.report import build_vuln_context
from reNgine.temporal.activities.assessment_activities import auto_validate_findings_activity

User = get_user_model()

class FindingLifecycleTest(TransactionTestCase):
    """
    Test suite to verify the Finding Lifecycle Engine:
    - Status transitions and choice options.
    - Exporters & Report generation filters (only verified).
    - Triage queue API endpoints.
    - Temporal auto-validation activity heuristics.
    """

    def setUp(self):
        # Create users & client for authentication
        self.user = User.objects.create_superuser(
            username="admin",
            email="admin@r3ngine.local",
            password="adminpassword"
        )
        self.client = APIClient()
        self.client.force_login(self.user)
        self.client.force_authenticate(user=self.user)

        # Create basic target & scan models
        self.domain = Domain.objects.create(name="target.io")
        self.engine = EngineType.objects.create(engine_name="lifecycle_test_engine")
        OpSec.objects.get_or_create(id=1)
        Proxy.objects.get_or_create(id=1)

        # Create Client, Engagement and Assessment for scan history
        self.client_org = Client.objects.create(name="Test Client")
        self.engagement = Engagement.objects.create(client=self.client_org, name="Test Engagement")
        self.assessment = Assessment.objects.create(
            engagement=self.engagement,
            name="Test Assessment",
            assessment_type="Web",
            status="Draft",
            created_by=self.user
        )

        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_status=2,
            start_scan_date=timezone.now(),
            scan_type=self.engine,
            assessment=self.assessment
        )

        # Create sample vulnerabilities in different lifecycle states
        self.vuln_new = Vulnerability.objects.create(
            scan_history=self.scan,
            name="New Vulnerability",
            severity=3,
            validation_status="new",
            validation_confidence=0.5
        )

        self.vuln_review = Vulnerability.objects.create(
            scan_history=self.scan,
            name="Needs Review Vulnerability",
            severity=2,
            validation_status="needs_review",
            validation_confidence=0.7
        )

        self.vuln_verified = Vulnerability.objects.create(
            scan_history=self.scan,
            name="Verified Vulnerability",
            severity=4,
            validation_status="verified",
            validation_confidence=0.9
        )

        self.vuln_false_positive = Vulnerability.objects.create(
            scan_history=self.scan,
            name="False Positive Vulnerability",
            severity=1,
            validation_status="false_positive",
            validation_confidence=0.1
        )

    def test_report_generation_excludes_dismissed_findings(self):
        """
        Reports keep every finding that has not been dismissed: new, needs_review
        and verified stay in; false_positive (like accepted_risk and resolved) is
        dropped. Filtering to verified-only hid findings nobody had triaged yet.
        """
        # Create report settings to prevent context generation failures
        VulnerabilityReportSetting.objects.get_or_create(
            company_name="Test Corp",
            show_executive_summary=True
        )

        context = build_vuln_context(self.scan, ignore_info=False)

        all_vulns = context['all_vulnerabilities']
        self.assertCountEqual(
            all_vulns.values_list('validation_status', flat=True),
            ['new', 'needs_review', 'verified'],
        )

        unique_names = {v['name'] for v in context['unique_vulnerabilities']}
        self.assertNotIn("False Positive Vulnerability", unique_names)
        self.assertIn("Verified Vulnerability", unique_names)

    def test_triage_queue_endpoint(self):
        """
        Verify that GET /api/listVulnerability/queue/ returns only 'new' or 'needs_review' findings.
        """
        response = self.client.get("/api/listVulnerability/queue/")
        self.assertEqual(response.status_code, 200)
        
        # Parse output
        data = response.json()
        results = data.get("results", [])
        
        # Check that we only see queue items
        statuses = [r["validation_status"] for r in results]
        self.assertTrue(all(s in ["new", "needs_review"] for s in statuses))
        
        # Verify specific items present/absent
        names = [r["name"] for r in results]
        self.assertIn("New Vulnerability", names)
        self.assertIn("Needs Review Vulnerability", names)
        self.assertNotIn("Verified Vulnerability", names)

    def test_verify_action_endpoint(self):
        """
        Verify that POST /api/listVulnerability/{id}/verify/ changes status to verified.
        """
        url = f"/api/listVulnerability/{self.vuln_new.id}/verify/"
        response = self.client.post(url)
        self.assertEqual(response.status_code, 200)

        # Reload from database and assert
        self.vuln_new.refresh_from_db()
        self.assertEqual(self.vuln_new.validation_status, "verified")

    def test_reject_action_endpoint_requires_reason(self):
        """
        Verify that POST /api/listVulnerability/{id}/reject/ changes status to false_positive
        and requires a reason justification.
        """
        url = f"/api/listVulnerability/{self.vuln_new.id}/reject/"
        
        # Request without reason should fail with 400
        response = self.client.post(url, data={})
        self.assertEqual(response.status_code, 400)

        # Request with reason should succeed
        response = self.client.post(url, data={"reason": "Confirmed false positive template match."})
        self.assertEqual(response.status_code, 200)

        # Reload from database and assert
        self.vuln_new.refresh_from_db()
        self.assertEqual(self.vuln_new.validation_status, "false_positive")
        self.assertEqual(self.vuln_new.validation_reason, "Confirmed false positive template match.")

    def test_auto_validate_findings_activity(self):
        """
        Verify auto_validate_findings_activity classifies findings based on confidence threshold (0.8).
        """
        from asgiref.sync import async_to_sync

        # Let's create vulnerabilities specifically for this test
        vuln_high_conf = Vulnerability.objects.create(
            scan_history=self.scan,
            name="High Conf Vuln",
            severity=3,
            validation_status="new",
            validation_confidence=0.85
        )

        vuln_low_conf = Vulnerability.objects.create(
            scan_history=self.scan,
            name="Low Conf Vuln",
            severity=3,
            validation_status="new",
            validation_confidence=0.55
        )

        # Execute auto_validate_findings_activity using assessment UUID string
        async_to_sync(auto_validate_findings_activity)(str(self.assessment.uuid))

        # Assert statuses were updated correctly
        vuln_high_conf.refresh_from_db()
        vuln_low_conf.refresh_from_db()

        # High confidence (0.85 > 0.8) -> verified
        self.assertEqual(vuln_high_conf.validation_status, "verified")
        # Low confidence (0.55 <= 0.8) -> needs_review
        self.assertEqual(vuln_low_conf.validation_status, "needs_review")
