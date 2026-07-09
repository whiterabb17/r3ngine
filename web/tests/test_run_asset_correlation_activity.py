"""Test activity for asset correlation: idempotency, flag-skip, event emission."""
import asyncio
from unittest.mock import patch
from django.test import TransactionTestCase, override_settings
from django.utils import timezone

from engagements.models import Client, Engagement, Assessment, AssessmentEvent
from targetApp.models import Project, Domain


class TestRunAssetCorrelationActivity(TransactionTestCase):
    def setUp(self):
        Project.objects.create(name='p', slug='p', insert_date=timezone.now())
        Domain.objects.create(name='x.test', insert_date=timezone.now())
        self.client_obj = Client.objects.create(name='C')
        self.eng = Engagement.objects.create(
            client=self.client_obj, name='E', engagement_type='Penetration Test',
        )
        self.assessment = Assessment.objects.create(
            engagement=self.eng, name='A', assessment_type='External',
        )

    @override_settings(ASSESSMENT_ASSET_CORRELATION_ENABLED=False)
    def test_flag_off_skips(self):
        from reNgine.temporal.activities.asset_correlation_activities import (
            run_asset_correlation_activity,
        )
        result = asyncio.run(run_asset_correlation_activity(str(self.assessment.uuid)))
        self.assertEqual(result['status'], 'skipped_flag_off')
        self.assertFalse(
            AssessmentEvent.objects.filter(
                assessment=self.assessment, event_type='assets_correlated'
            ).exists()
        )

    @override_settings(ASSESSMENT_ASSET_CORRELATION_ENABLED=True)
    @patch('reNgine.temporal.activities.asset_correlation_activities.AssetCorrelationService')
    def test_flag_on_runs_and_emits_event(self, mock_service_cls):
        from reNgine.asset_correlation import AssetCorrelationResult
        mock_service_cls.return_value.correlate.return_value = AssetCorrelationResult(
            new_assets=3, updated_assets=1, new_sources=7, scans_processed=2,
        )
        from reNgine.temporal.activities.asset_correlation_activities import (
            run_asset_correlation_activity,
        )
        result = asyncio.run(run_asset_correlation_activity(str(self.assessment.uuid)))
        self.assertEqual(result['status'], 'ok')
        self.assertEqual(result['new_assets'], 3)
        self.assertTrue(
            AssessmentEvent.objects.filter(
                assessment=self.assessment, event_type='assets_correlated',
            ).exists()
        )
