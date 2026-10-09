from django.db.models import Q
from rest_framework import viewsets
from rest_framework.response import Response
from rest_framework.views import APIView

from api.permissions import IsAuditor, IsPenetrationTester
from api.serializers import CommandSerializer, ScanHistorySerializer, SubScanSerializer
from api.serializers.scans import with_scan_history_serializer_data
from startScan.models import Command, ScanHistory, SubScan


class ScanStatus(APIView):
	permission_classes = [IsPenetrationTester]

	# The completed buckets were already capped, but running/pending were not.
	# This endpoint is polled from the dashboard, so an unbounded queue meant a
	# poll could serialize the entire backlog into a web worker at once.
	_ACTIVE_LIMIT = 100

	def _scan_queryset(self, slug):
		return with_scan_history_serializer_data(
			ScanHistory.objects.filter(domain__project__slug=slug)
		).order_by('-start_scan_date')

	def _task_queryset(self, slug):
		"""Base subscan queryset.

		SubScanSerializer dereferences subdomain and engine, and Meta.fields is
		'__all__', which pulls the subdomain_subscan_ids many-to-many per row.
		"""
		return (
			SubScan.objects
			.filter(scan_history__domain__project__slug=slug)
			.select_related('subdomain', 'engine')
			.prefetch_related('subdomain_subscan_ids')
			.order_by('-start_scan_date')
		)

	def get(self, request):
		req = self.request
		slug = self.request.GET.get('project', None)

		scans = self._scan_queryset(slug)
		tasks = self._task_queryset(slug)

		# main tasks
		recently_completed_scans = scans.filter(
			Q(scan_status=0) | Q(scan_status=2) | Q(scan_status=3))[:10]
		current_scans = scans.filter(scan_status=1)[:self._ACTIVE_LIMIT]
		pending_scans = scans.filter(scan_status=-1)[:self._ACTIVE_LIMIT]

		# subtasks
		recently_completed_tasks = tasks.filter(
			Q(status=0) | Q(status=2) | Q(status=3))[:15]
		current_tasks = tasks.filter(status=1)[:self._ACTIVE_LIMIT]
		pending_tasks = tasks.filter(status=-1)[:self._ACTIVE_LIMIT]

		response = {
			'scans': {
				'pending': ScanHistorySerializer(pending_scans, many=True).data,
				'scanning': ScanHistorySerializer(current_scans, many=True).data,
				'completed': ScanHistorySerializer(recently_completed_scans, many=True).data
			},
			'tasks': {
				'pending': SubScanSerializer(pending_tasks, many=True).data,
				'running': SubScanSerializer(current_tasks, many=True).data,
				'completed': SubScanSerializer(recently_completed_tasks, many=True).data
			}
		}
		
		return Response(response)


class ListScanHistory(APIView):
	permission_classes = [IsAuditor]
	def get(self, request, format=None):
		req = self.request
		scan_history = with_scan_history_serializer_data(
			ScanHistory.objects.all()
		).order_by('-start_scan_date')
		project = req.query_params.get('project')
		if project:
			scan_history = scan_history.filter(domain__project__slug=project)
		scan_history = ScanHistorySerializer(scan_history, many=True)
		return Response(scan_history.data)


class ListActivityLogsViewSet(viewsets.ModelViewSet):
	permission_classes = [IsPenetrationTester]
	serializer_class = CommandSerializer
	queryset = Command.objects.none()
	def get_queryset(self):
		req = self.request
		activity_id = req.query_params.get('activity_id')
		self.queryset = Command.objects.filter(activity__id=activity_id)
		return self.queryset


class ListScanLogsViewSet(viewsets.ModelViewSet):
	permission_classes = [IsPenetrationTester]
	serializer_class = CommandSerializer
	queryset = Command.objects.none()
	def get_queryset(self):
		req = self.request
		scan_id = req.query_params.get('scan_id')
		self.queryset = Command.objects.filter(scan_history__id=scan_id)
		return self.queryset
