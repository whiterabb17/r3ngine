"""Regression tests for the /api/scan_status/ query count.

The dashboard polls this endpoint. ScanHistorySerializer declares eighteen
SerializerMethodField entries and SubScanSerializer dereferences two foreign
keys plus a many-to-many, so without annotations and prefetching the cost grew
with every row on screen rather than staying flat.

These tests assert the invariant rather than an absolute number: serializing
five scans must cost exactly what serializing one costs. If a method field
regresses into a per-row query, the counts diverge and the test says so.
"""
from django.db import connection
from django.test import TestCase
from django.test.utils import CaptureQueriesContext
from django.utils import timezone

from api.serializers import ScanHistorySerializer, SubScanSerializer
from api.views import ScanStatus
from dashboard.models import Project
from reNgine.definitions import RUNNING_TASK, SUCCESS_TASK
from scanEngine.models import EngineType
from startScan.models import ScanActivity, ScanHistory, SubScan, Subdomain
from targetApp.models import Domain

SLUG = 'query-count'


class ScanStatusQueryCountTests(TestCase):

	def setUp(self):
		self.project = Project.objects.create(
			name='query-count', slug=SLUG, insert_date=timezone.now()
		)
		self.engine = EngineType.objects.create(
			engine_name='qc-engine', yaml_configuration=''
		)
		self.domain = Domain.objects.create(
			name='qc.example', project=self.project, insert_date=timezone.now()
		)

	def _add_scans(self, count):
		"""Create `count` running scans, each with activities and a subdomain."""
		for index in range(count):
			scan = ScanHistory.objects.create(
				domain=self.domain,
				scan_type=self.engine,
				scan_status=RUNNING_TASK,
				start_scan_date=timezone.now(),
			)
			ScanActivity.objects.create(
				scan_of=scan, name='subdomain_discovery',
				title='Subdomain Discovery', tier=1,
				status=SUCCESS_TASK, time=timezone.now(),
			)
			ScanActivity.objects.create(
				scan_of=scan, name='vulnerability_scan',
				title='Vulnerability Scan', tier=6,
				status=RUNNING_TASK, time=timezone.now(),
			)
			subdomain = Subdomain.objects.create(
				scan_history=scan, target_domain=self.domain,
				name=f'host{index}.qc.example',
			)
			SubScan.objects.create(
				scan_history=scan, subdomain=subdomain, engine=self.engine,
				status=RUNNING_TASK, start_scan_date=timezone.now(),
			)

	def _scan_cost(self):
		queryset = ScanStatus()._scan_queryset(SLUG).filter(scan_status=RUNNING_TASK)
		with CaptureQueriesContext(connection) as captured:
			ScanHistorySerializer(queryset, many=True).data
		return len(captured)

	def _task_cost(self):
		queryset = ScanStatus()._task_queryset(SLUG).filter(status=RUNNING_TASK)
		with CaptureQueriesContext(connection) as captured:
			SubScanSerializer(queryset, many=True).data
		return len(captured)

	def test_scan_serialization_cost_is_flat(self):
		self._add_scans(1)
		one = self._scan_cost()

		self._add_scans(4)
		five = self._scan_cost()

		self.assertEqual(
			one, five,
			f'serializing five scans cost {five} queries against {one} for one. '
			'A ScanHistorySerializer method field has regressed into a per-row '
			'query, or an annotation was dropped from ScanStatus._scan_queryset.'
		)

	def test_task_serialization_cost_is_flat(self):
		self._add_scans(1)
		one = self._task_cost()

		self._add_scans(4)
		five = self._task_cost()

		self.assertEqual(
			one, five,
			f'serializing five subscans cost {five} queries against {one} for '
			'one. A SubScanSerializer field has regressed into a per-row query, '
			'or a select_related was dropped from ScanStatus._task_queryset.'
		)

	def test_counts_and_severity_match_the_unannotated_result(self):
		"""The annotations must agree with the per-row fallback they replace."""
		self._add_scans(1)
		scan = ScanHistory.objects.get()

		annotated = ScanHistorySerializer(
			ScanStatus()._scan_queryset(SLUG).get(pk=scan.pk)
		).data
		plain = ScanHistorySerializer(ScanHistory.objects.get(pk=scan.pk)).data

		for field in ('subdomain_count', 'endpoint_count',
					  'vulnerability_count', 'max_severity',
					  'successful_task_count', 'failed_task_count',
					  'total_task_count', 'organizations'):
			self.assertEqual(
				annotated[field], plain[field],
				f'{field} differs between the annotated and fallback paths'
			)
