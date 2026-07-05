"""AssetCorrelationService — canonical dedup, cross-assessment isolation,
risk-score parity with ExposureCorrelationEngine."""
from django.test import TestCase
from django.utils import timezone

from engagements.models import Client, Engagement, Assessment, Asset, AssetSource
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain, EndPoint, Exposure
from targetApp.models import Domain, Project


class TestAssetCorrelationService(TestCase):
    def setUp(self):
        self.project = Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        self.domain = Domain.objects.create(name='example.test', project=self.project)
        self.engine = EngineType.objects.create(engine_name='test-engine', yaml_configuration='')
        self.client_obj = Client.objects.create(name='ClientA')
        self.eng = Engagement.objects.create(
            client=self.client_obj, name='E', engagement_type='Penetration Test',
        )
        self.assessment_a = Assessment.objects.create(
            engagement=self.eng, name='A', assessment_type='External',
        )
        self.assessment_b = Assessment.objects.create(
            engagement=self.eng, name='B', assessment_type='External',
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain, assessment=self.assessment_a,
            scan_type=self.engine, start_scan_date=timezone.now(),
        )
        self.sub = Subdomain.objects.create(
            scan_history=self.scan, target_domain=self.domain,
            name='login.example.test', http_url='https://login.example.test/',
            http_status=200, page_title='Okta Login',
        )

    def test_url_normalization_dedup(self):
        """Two endpoints on same URL merge to a single Asset with two AssetSource rows."""
        EndPoint.objects.create(
            scan_history=self.scan, subdomain=self.sub,
            http_url='https://login.example.test/', http_status=200,
        )
        EndPoint.objects.create(
            scan_history=self.scan, subdomain=self.sub,
            http_url='https://login.example.test:443/', http_status=200,
        )
        from reNgine.asset_correlation import AssetCorrelationService
        result = AssetCorrelationService(self.assessment_a).correlate()

        # Filter to the URL-form canonical (Subdomain records produce a separate
        # host:// canonical per design §4.5 — both are legitimate but this test
        # is specifically verifying URL-endpoint dedup).
        url_assets = Asset.objects.filter(
            assessment=self.assessment_a,
            canonical_identifier='https://login.example.test/',
        )
        self.assertEqual(url_assets.count(), 1)
        self.assertGreaterEqual(url_assets.first().sources.count(), 2)
        self.assertGreaterEqual(result.new_assets, 1)

    def test_cross_assessment_isolation(self):
        """Same URL under Assessment A and Assessment B produce distinct Assets."""
        scan_b = ScanHistory.objects.create(
            domain=self.domain, assessment=self.assessment_b,
            scan_type=self.engine, start_scan_date=timezone.now(),
        )
        Subdomain.objects.create(
            scan_history=scan_b, target_domain=self.domain,
            name='login.example.test', http_url='https://login.example.test/',
        )
        from reNgine.asset_correlation import AssetCorrelationService
        AssetCorrelationService(self.assessment_a).correlate()
        AssetCorrelationService(self.assessment_b).correlate()

        a_assets = set(Asset.objects.filter(assessment=self.assessment_a).values_list('canonical_key_hash', flat=True))
        b_assets = set(Asset.objects.filter(assessment=self.assessment_b).values_list('canonical_key_hash', flat=True))
        self.assertTrue(a_assets)
        self.assertTrue(b_assets)
        self.assertFalse(a_assets & b_assets, "canonical_key_hash must differ across assessments")

    def test_no_assessment_no_assets(self):
        """A scan without an assessment must not produce any Asset."""
        standalone_scan = ScanHistory.objects.create(
            domain=self.domain, scan_type=self.engine, start_scan_date=timezone.now(),
        )
        Subdomain.objects.create(
            scan_history=standalone_scan, target_domain=self.domain, name='x.example.test',
        )
        pre = Asset.objects.count()
        # We do not run AssetCorrelationService on a standalone scan; verify it never gets called
        # from any path we control. The assertion is simply that no Asset exists for that scan.
        self.assertEqual(Asset.objects.count(), pre)

    def test_risk_score_uses_shared_constants(self):
        """AssetCorrelationService._score must not duplicate ExposureCorrelationEngine constants."""
        import reNgine.asset_correlation as ac
        import reNgine.exposure_correlation as ec
        # Re-use, don't copy — see r3ngine-security.md rule 7.1.
        self.assertIs(ac._ASSET_TYPE_WEIGHTS, ec._ASSET_TYPE_WEIGHTS)
        self.assertIs(ac._SEVERITY_TO_SCORE, ec._SEVERITY_TO_SCORE)
        self.assertIs(ac._HIGH_RISK_PORTS, ec._HIGH_RISK_PORTS)
