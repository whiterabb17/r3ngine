from django.test import TestCase
from django.utils import timezone
from startScan.models import ScanHistory, EngineType, TargetReport
from targetApp.models import Domain
from dashboard.models import Project


class TargetReportModelTest(TestCase):
    def setUp(self):
        self.project = Project.objects.create(
            name='Test Project TR',
            slug='test-project-tr',
            insert_date=timezone.now(),
        )
        self.domain = Domain.objects.create(
            name='test.example.com',
            project=self.project,
            insert_date=timezone.now(),
        )
        self.engine = EngineType.objects.create(
            engine_name='test-engine-tr',
            yaml_configuration='',
        )
        self.scan1 = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=2,
            start_scan_date=timezone.now(),
        )
        self.scan2 = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=2,
            start_scan_date=timezone.now(),
        )

    def test_create_target_report(self):
        report = TargetReport.objects.create(
            domain=self.domain,
            selected_scan_ids=[self.scan1.id, self.scan2.id],
        )
        self.assertEqual(report.status, 1)
        self.assertEqual(report.domain, self.domain)

    def test_selected_scan_ids_stored_correctly(self):
        ids = [self.scan1.id, self.scan2.id]
        report = TargetReport.objects.create(
            domain=self.domain,
            selected_scan_ids=ids,
        )
        report.refresh_from_db()
        self.assertEqual(report.selected_scan_ids, ids)

    def test_included_sections_default_empty(self):
        report = TargetReport.objects.create(
            domain=self.domain,
            selected_scan_ids=[self.scan1.id, self.scan2.id],
        )
        self.assertEqual(report.included_sections, [])

    def test_status_transition_to_complete(self):
        report = TargetReport.objects.create(
            domain=self.domain,
            selected_scan_ids=[self.scan1.id, self.scan2.id],
        )
        report.status = 2
        report.completed_at = timezone.now()
        report.save()
        report.refresh_from_db()
        self.assertEqual(report.status, 2)
        self.assertIsNotNone(report.completed_at)

    def test_status_transition_to_failed(self):
        report = TargetReport.objects.create(
            domain=self.domain,
            selected_scan_ids=[self.scan1.id, self.scan2.id],
        )
        report.status = 0
        report.error_message = 'Something went wrong'
        report.save()
        report.refresh_from_db()
        self.assertEqual(report.status, 0)
        self.assertEqual(report.error_message, 'Something went wrong')

    def test_str_representation(self):
        report = TargetReport.objects.create(
            domain=self.domain,
            selected_scan_ids=[self.scan1.id, self.scan2.id],
        )
        self.assertIn('test.example.com', str(report))
