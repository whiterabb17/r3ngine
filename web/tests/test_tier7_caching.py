from django.test import TestCase
from unittest.mock import patch, MagicMock
from django.utils import timezone

from targetApp.models import Domain
from scanEngine.models import EngineType
from startScan.models import Vulnerability, ImpactAssessment, GPTVulnerabilityReport, ScanHistory
from reNgine.tasks import get_vulnerability_gpt_report, generate_impact_assessment
from reNgine.utilities import get_gpt_vuln_input_description

class TestTier7Caching(TestCase):

    def setUp(self):
        self.domain = Domain.objects.create(name="test.com")
        self.engine = EngineType.objects.create(engine_name="Test Engine")
        self.scan_history = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            start_scan_date=timezone.now()
        )
        self.vuln = Vulnerability.objects.create(
            name="Reflected XSS",
            severity=3,
            description="A cross site scripting vulnerability.",
            http_url="http://test.com/path",
            scan_history=self.scan_history
        )

    def test_get_gpt_vuln_input_description_is_agnostic(self):
        """Ensure the prompt description does not include the target URL/path."""
        desc = get_gpt_vuln_input_description("Reflected XSS", "http://test.com/path")
        self.assertNotIn("test.com", desc)
        self.assertNotIn("http://test.com/path", desc)
        self.assertIn("Reflected XSS", desc)

    @patch('reNgine.tasks.LLMVulnerabilityReportGenerator')
    def test_get_vulnerability_gpt_report_uses_cache(self, mock_generator_class):
        # Create an existing report for this title
        GPTVulnerabilityReport.objects.create(
            title="Reflected XSS",
            description="Cached Description",
            impact="Cached Impact",
            remediation="Cached Remediation",
            url_path="http://other.com/otherpath" # Different path, same title
        )
        
        mock_instance = MagicMock()
        mock_generator_class.return_value = mock_instance
        
        # Call the task
        vuln_tuple = ("Reflected XSS", "http://test.com/path", 3)
        get_vulnerability_gpt_report(
            vuln_tuple,
            vulnerability_id=self.vuln.id
        )
        
        # Generator should NOT be called because it found the cache by title
        mock_instance.generate.assert_not_called()
        
        # The vulnerability should be updated with the cached data
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.description, "Cached Description")
        self.assertEqual(self.vuln.impact, "Cached Impact")

    @patch('reNgine.llm.llm_env_enabled', return_value=False)
    def test_generate_impact_assessment_skips_when_llm_disabled(self, _mock_llm_enabled):
        """Disabled LLM must skip without returning False (Temporal treats False as failure)."""
        mock_self = MagicMock()
        mock_self.subscan = None

        result = generate_impact_assessment(
            mock_self,
            scan_history_id=self.scan_history.id,
        )

        self.assertIsNone(result)
        self.assertFalse(ImpactAssessment.objects.filter(vulnerability=self.vuln).exists())

    @patch('reNgine.llm.llm_env_enabled', return_value=True)
    @patch('reNgine.tasks.LLMImpactGenerator')
    def test_generate_impact_assessment_uses_cache(self, mock_generator_class, _mock_llm_enabled):
        # Create an existing AI generated assessment for this vulnerability type
        # We need a dummy vulnerability to link to
        other_vuln = Vulnerability.objects.create(
            name="Reflected XSS",
            severity=2,
            scan_history=self.scan_history
        )
        ImpactAssessment.objects.create(
            vulnerability=other_vuln,
            potential_impact="Cached Potential Impact",
            is_ai_generated=True
        )
        
        mock_instance = MagicMock()
        mock_generator_class.return_value = mock_instance
        
        mock_self = MagicMock()
        mock_self.subscan = None
        
        generate_impact_assessment(
            mock_self,
            vulnerability_id=self.vuln.id
        )
        
        # Generator should NOT be called because it found the cache by vuln name
        mock_instance.generate.assert_not_called()
        
        # The impact assessment for self.vuln should be created using the cached text
        assessment = ImpactAssessment.objects.get(vulnerability=self.vuln)
        self.assertEqual(assessment.potential_impact, "Cached Potential Impact")
        self.assertTrue(assessment.is_ai_generated)

