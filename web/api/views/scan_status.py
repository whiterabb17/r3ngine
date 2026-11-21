from rest_framework import viewsets
from rest_framework.pagination import LimitOffsetPagination
from rest_framework.response import Response
from rest_framework.views import APIView

from api.permissions import IsAuditor, IsPenetrationTester
from api.serializers import CommandSerializer
from api.serializers.scans import (
	ScanHistoryListSerializer,
	SubScanStatusSerializer,
	with_scan_history_serializer_data,
)
from startScan.models import Command, ScanHistory, SubScan


class ScanHistoryListPagination(LimitOffsetPagination):
	default_limit = 100
	max_limit = 500


class ScanStatus(APIView):
	permission_classes = [IsPenetrationTester]

	# The completed buckets were already capped, but running/pending were not.
	# This endpoint is polled from the dashboard, so an unbounded queue meant a
	# poll could serialize the entire backlog into a web worker at once.
	_ACTIVE_LIMIT = 100
	_COMPLETED_SCANS = 10
	_COMPLETED_TASKS = 15

	def _scan_queryset(self, slug):
		return with_scan_history_serializer_data(
			ScanHistory.objects.filter(domain__project__slug=slug)
		).order_by('-start_scan_date')

	def _task_queryset(self, slug):
		"""Base subscan queryset for status polls (no M2M prefetch)."""
		return (
			SubScan.objects
			.filter(scan_history__domain__project__slug=slug)
			.select_related('subdomain', 'engine')
			.order_by('-start_scan_date')
		)

	def get(self, request):
		slug = self.request.GET.get('project', None)

		# Separate limited filters per bucket so a large pending backlog cannot
		# crowd running scans (or completed) out of a single mixed window.
		scans = self._scan_queryset(slug)
		tasks = self._task_queryset(slug)

		pending_scans = list(scans.filter(scan_status=-1)[:self._ACTIVE_LIMIT])
		current_scans = list(scans.filter(scan_status=1)[:self._ACTIVE_LIMIT])
		recently_completed_scans = list(
			scans.filter(scan_status__in=[0, 2, 3])[:self._COMPLETED_SCANS]
		)

		pending_tasks = list(tasks.filter(status=-1)[:self._ACTIVE_LIMIT])
		current_tasks = list(tasks.filter(status=1)[:self._ACTIVE_LIMIT])
		recently_completed_tasks = list(
			tasks.filter(status__in=[0, 2, 3])[:self._COMPLETED_TASKS]
		)

		response = {
			'scans': {
				'pending': ScanHistoryListSerializer(pending_scans, many=True).data,
				'scanning': ScanHistoryListSerializer(current_scans, many=True).data,
				'completed': ScanHistoryListSerializer(recently_completed_scans, many=True).data,
			},
			'tasks': {
				'pending': SubScanStatusSerializer(pending_tasks, many=True).data,
				'running': SubScanStatusSerializer(current_tasks, many=True).data,
				'completed': SubScanStatusSerializer(recently_completed_tasks, many=True).data,
			},
		}

		return Response(response)


class ListScanHistory(APIView):
	permission_classes = [IsAuditor]
	pagination_class = ScanHistoryListPagination

	def get(self, request, format=None):
		req = self.request
		scan_history = with_scan_history_serializer_data(
			ScanHistory.objects.all()
		).order_by('-start_scan_date')
		project = req.query_params.get('project')
		if project:
			scan_history = scan_history.filter(domain__project__slug=project)

		paginator = self.pagination_class()
		page = paginator.paginate_queryset(scan_history, request, view=self)
		serializer = ScanHistoryListSerializer(page, many=True)
		return paginator.get_paginated_response(serializer.data)


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
