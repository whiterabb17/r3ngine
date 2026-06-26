import json
import re
import socket
import logging
import subprocess
import threading
import mimetypes
import os
import requests
import validators
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime
from ipaddress import IPv4Network
from packaging import version

from django.conf import settings
from django.core.cache import cache
from django.core.exceptions import ObjectDoesNotExist
from django.db import connections
from django.db.models import CharField, Count, F, Max, Q, Value
from django.db.models.functions import Lower
from django.http import FileResponse, Http404, HttpResponse
from django.shortcuts import get_object_or_404
from django.template.defaultfilters import slugify
from django.utils import timezone

from rest_framework import mixins, viewsets, serializers, status
from rest_framework.decorators import action
from rest_framework.pagination import PageNumberPagination
from rest_framework.permissions import AllowAny
from rest_framework.renderers import JSONRenderer
from rest_framework.response import Response
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_204_NO_CONTENT, HTTP_202_ACCEPTED
from rest_framework.views import APIView
from rest_framework_datatables.pagination import DatatablesPageNumberPagination

from dashboard.models import *
from recon_note.models import *
from reNgine.common_func import *
from reNgine.utils.database import *
from reNgine.definitions import (
    ABORTED_TASK, RUNNING_TASK, SUCCESS_TASK,
    PERM_MODIFY_TARGETS, PERM_MODIFY_SCAN_CONFIGURATIONS,
    PERM_MODIFY_WORDLISTS, PERM_INITATE_SCANS_SUBSCANS,
    PERM_MODIFY_SCAN_REPORT, PERM_MODIFY_SCAN_RESULTS,
)
from reNgine.tasks import *
from reNgine.llm import *
from reNgine.utilities import is_safe_path
from scanEngine.models import *
from startScan.models import *
from startScan.models import EndPoint
from targetApp.models import *
from api.shared_api_tasks import import_hackerone_programs_task, sync_bookmarked_programs_task
from api.permissions import *
from api.serializers import *
from reNgine.utils.graph import Neo4jManager
from reNgine.temporal_client import TemporalClientProvider, run_and_close

logger = logging.getLogger(__name__)

class OsintStagingViewSet(viewsets.ModelViewSet):
	permission_classes = [IsPenetrationTester]
	queryset = OsintStaging.objects.filter(status='pending').order_by('-confidence', '-discovered_date')
	serializer_class = OsintStagingSerializer

	def get_queryset(self):
		queryset = self.queryset
		scan_id = self.request.query_params.get('scan_id')
		target_id = self.request.query_params.get('target_id')
		osint_type = self.request.query_params.get('osint_type')
		status_param = self.request.query_params.get('status')
		
		if scan_id:
			queryset = queryset.filter(scan_history_id=scan_id)
		if target_id:
			queryset = queryset.filter(target_domain_id=target_id)
		if osint_type:
			queryset = queryset.filter(osint_type=osint_type)
		if status_param:
			queryset = OsintStaging.objects.filter(status=status_param) # Allow override to see validated/ignored
		
		# Universal Search for Staging
		search = self.request.query_params.get('search')
		if search:
			queryset = queryset.filter(
				Q(content__icontains=search) |
				Q(source__icontains=search) |
				Q(metadata__icontains=search) |
				Q(osint_type__icontains=search)
			)
			
		return queryset

	@action(detail=False, methods=['post'])
	def bulk_discard(self, request):
		"""Bulk delete staging items."""
		ids = request.data.get('ids', [])
		if not ids:
			return Response({'error': 'No IDs provided'}, status=status.HTTP_400_BAD_REQUEST)
		
		OsintStaging.objects.filter(id__in=ids).delete()
		return Response({'status': 'success', 'message': f'Deleted {len(ids)} items'})

	@action(detail=False, methods=['post'])
	def bulk_promote(self, request):
		"""Bulk promote staging items to primary tables."""
		from reNgine.tasks import persist_osint_item
		ids = request.data.get('ids', [])
		if not ids:
			return Response({'error': 'No IDs provided'}, status=status.HTTP_400_BAD_REQUEST)
		
		items = OsintStaging.objects.filter(id__in=ids)
		count = 0
		for item in items:
			ctx = {
				'scan_history_id': item.scan_history.id,
				'domain_id': item.target_domain.id
			}
			persist_osint_item(
				scan_history=item.scan_history,
				domain=item.target_domain,
				osint_type=item.osint_type,
				e_data=item.content,
				confidence=item.confidence,
				source_data=item.metadata.get('source_data'),
				event_type=item.metadata.get('sf_type'),
				ctx=ctx
			)
			item.status = 'validated'
			item.save()
			count += 1
			
		return Response({'status': 'success', 'message': f'Promoted {count} items'})

	@action(detail=True, methods=['post'])
	def promote(self, request, pk=None):
		"""Individual promote."""
		from reNgine.tasks import persist_osint_item
		item = self.get_object()
		ctx = {
			'scan_history_id': item.scan_history.id,
			'domain_id': item.target_domain.id
		}
		persist_osint_item(
			scan_history=item.scan_history,
			domain=item.target_domain,
			osint_type=item.osint_type,
			e_data=item.content,
			confidence=item.confidence,
			source_data=item.metadata.get('source_data'),
			event_type=item.metadata.get('sf_type'),
			ctx=ctx
		)
		item.status = 'validated'
		item.save()
		return Response({'status': 'success'})

	@action(detail=True, methods=['post'])
	def discard(self, request, pk=None):
		"""Individual discard."""
		item = self.get_object()
		item.delete()
		return Response({'status': 'success'})



class MonitoringDiscoveryViewSet(viewsets.ModelViewSet):
    permission_classes = [IsPenetrationTester]
    queryset = MonitoringDiscovery.objects.all()
    serializer_class = MonitoringDiscoverySerializer

    def get_queryset(self):
        slug = self.request.query_params.get('slug')
        if slug:
            return self.queryset.filter(domain__project__slug=slug).order_by('-discovered_at')
        return self.queryset.order_by('-discovered_at')

    @action(detail=False, methods=['get'])
    def statistics(self, request):
        slug = self.request.query_params.get('slug')
        if not slug:
            return Response({'error': 'Slug is required'}, status=status.HTTP_400_BAD_REQUEST)
        
        project = get_object_or_404(Project, slug=slug)
        discoveries = MonitoringDiscovery.objects.filter(domain__project=project)
        
        stats = {
            'total_discoveries': discoveries.count(),
            'subdomain_discoveries': discoveries.filter(discovery_type='subdomain').count(),
            'endpoint_discoveries': discoveries.filter(discovery_type='directory').count(),
            'login_discoveries': discoveries.filter(discovery_type='login').count(),
        }
        return Response(stats)



class WafDetector(APIView):
	permission_classes = [IsPenetrationTester]
	def get(self, request):
		req = self.request
		url= req.query_params.get('url')
		response = {}
		response['status'] = False

		# validate url as a first step to avoid command injection
		if not (validators.url(url) or validators.domain(url)):
			response['message'] = 'Invalid Domain/URL provided!'
			return Response(response)
		
		_, output = run_command(['wafw00f', url], shell=False, remove_ansi_sequence=True)
		regex = r"behind (.*?) WAF"
		group = re.search(regex, output)
		if group:
			response['status'] = True
			response['results'] = group.group(1)
		else:
			response['message'] = 'Could not detect any WAF!'

		return Response(response)


class AddReconNote(APIView):
	permission_classes = [IsPenetrationTester]
	def post(self, request):
		req = self.request
		data = req.data

		subdomain_id = data.get('subdomain_id')
		title = data.get('title')
		description = data.get('description')
		project = data.get('project')

		try:
			project = Project.objects.get(slug=project)
			note = TodoNote()
			note.title = title
			note.description = description

			# get scan history for subdomain_id
			if subdomain_id:
				subdomain = Subdomain.objects.get(id=subdomain_id)
				note.subdomain = subdomain

				# also get scan history
				scan_history_id = subdomain.scan_history.id
				scan_history = ScanHistory.objects.get(id=scan_history_id)
				note.scan_history = scan_history

			note.project = project
			note.save()
			response = {'status': True}
		except Exception as e:
			response = {'status': False, 'message': str(e)}

		return Response(response)


class SearchHistoryView(APIView):
	permission_classes = [IsPenetrationTester]
	def get(self, request):
		req = self.request

		response = {}
		response['status'] = False

		scan_history = SearchHistory.objects.all().order_by('-id')[:5]

		if scan_history:
			response['status'] = True
			response['results'] = SearchHistorySerializer(scan_history, many=True).data

		return Response(response)


class UniversalSearch(APIView):
	permission_classes = [IsPenetrationTester]
	def get(self, request):
		req = self.request
		query = req.query_params.get('query')

		response = {}
		response['status'] = False

		if not query:
			response['message'] = 'No query parameter provided!'
			return Response(response)

		response['results'] = {}

		# search history to be saved
		SearchHistory.objects.get_or_create(
			query=query
		)

		# lookup query in subdomain
		subdomain = Subdomain.objects.filter(
			Q(name__icontains=query) |
			Q(cname__icontains=query) |
			Q(page_title__icontains=query) |
			Q(http_url__icontains=query)
		).distinct('name').prefetch_related(
			'screenshots', 'technologies', 'ip_addresses', 'ip_addresses__ports'
		)
		subdomain_data = SubdomainSerializer(subdomain, many=True).data
		response['results']['subdomains'] = subdomain_data

		endpoint = EndPoint.objects.filter(
			Q(http_url__icontains=query) |
			Q(page_title__icontains=query) |
			Q(parameters__name__icontains=query)
		).distinct('http_url')
		endpoint_data = EndpointSerializer(endpoint, many=True).data
		response['results']['endpoints'] = endpoint_data

		vulnerability = Vulnerability.objects.filter(
			Q(http_url__icontains=query) |
			Q(name__icontains=query) |
			Q(description__icontains=query)
		).distinct()
		vulnerability_data = VulnerabilitySerializer(vulnerability, many=True).data
		response['results']['vulnerabilities'] = vulnerability_data

		response['results']['others'] = {}

		if subdomain_data or endpoint_data or vulnerability_data:
			response['status'] = True

		return Response(response)


class GetScanGraphData(APIView):
	"""Fetch Cytoscape-compatible graph data for a specific scan."""
	permission_classes = [IsAuditor]
	def get(self, request, scan_id):
		graph = Neo4jManager()
		data = graph.get_cytoscape_json(scan_id)
		graph.close()
		return Response(data)

class GetTargetGraphData(APIView):
	"""Fetch Cytoscape-compatible graph data for an entire target."""
	permission_classes = [IsAuditor]
	def get(self, request, target_id):
		target = get_object_or_404(Domain, id=target_id)
		graph = Neo4jManager()
		data = graph.get_target_graph_data(target.name)
		graph.close()
		return Response(data)

class GetNodeDetails(APIView):
	"""Fetch detailed metadata for a specific graph node."""
	permission_classes = [IsAuditor]
	def get(self, request, node_id):
		graph = Neo4jManager()
		data = graph.get_node_details(node_id)
		graph.close()
		return Response(data)


# ── Email discovery endpoints ─────────────────────────────────────────────────

import uuid as _uuid

from reNgine.utils.task import save_email
from reNgine.tasks.email_discovery import (
    run_email_discovery,
    _get_active_job,
    _set_active,
    _redis as _email_redis,
)


class ManualEmailAddView(APIView):
    """POST /api/emails/manual/ — add one or more email addresses to a scan."""
    permission_classes = [IsPenetrationTester]

    def post(self, request: 'rest_framework.request.Request') -> Response:
        scan_id = request.data.get('scan_id')
        addresses = request.data.get('addresses', [])

        if not scan_id:
            return Response({'error': 'scan_id is required'}, status=400)

        try:
            scan_history = ScanHistory.objects.get(pk=scan_id)
        except ScanHistory.DoesNotExist:
            return Response({'error': 'scan not found'}, status=404)

        added: int = 0
        skipped: int = 0
        for address in addresses:
            address = (address or '').strip().lower()
            if not address or not validators.email(address):
                skipped += 1
                continue
            email_obj, created = save_email(address, scan_history=scan_history, source=Email.SOURCE_MANUAL)
            if email_obj:
                added += 1
            else:
                skipped += 1

        status_code = 207 if skipped > 0 else 200
        return Response({'added': added, 'skipped': skipped}, status=status_code)


class StartEmailDiscoveryView(APIView):
    """POST /api/emailDiscovery/start/ — kick off background email discovery for a scan."""
    permission_classes = [IsPenetrationTester]

    def post(self, request: 'rest_framework.request.Request') -> Response:
        scan_id = request.data.get('scan_id')
        if not scan_id:
            return Response({'error': 'scan_id is required'}, status=400)

        try:
            scan = ScanHistory.objects.select_related('domain').get(pk=scan_id)
        except ScanHistory.DoesNotExist:
            return Response({'error': 'scan not found'}, status=404)

        existing_job: str | None = _get_active_job(scan_id)
        if existing_job:
            return Response({'job_id': existing_job}, status=409)

        job_id: str = str(_uuid.uuid4())
        _set_active(scan_id, job_id)

        t = threading.Thread(
            target=run_email_discovery,
            args=[int(scan_id), scan.domain.name, job_id],
            daemon=True,
        )
        t.start()

        return Response({'job_id': job_id}, status=202)


class StopEmailDiscoveryView(APIView):
    """POST /api/emailDiscovery/stop/ — signal an active discovery job to stop."""
    permission_classes = [IsPenetrationTester]

    def post(self, request: 'rest_framework.request.Request') -> Response:
        job_id: str | None = request.data.get('job_id')
        if not job_id:
            return Response({'error': 'job_id is required'}, status=400)

        r = _email_redis()
        r.set(f'email_discovery:{job_id}:stop', '1', ex=3600)
        return Response({'status': 'stopping'})


class EmailDiscoveryReplayView(APIView):
    """GET /api/emailDiscovery/<job_id>/replay/ — replay log stream events for a job."""
    permission_classes = [IsPenetrationTester]

    def get(self, request: 'rest_framework.request.Request', job_id: str) -> Response:
        r = _email_redis()
        scan_id: str | None = r.get(f'email_discovery:job:{job_id}:scan_id')
        if not scan_id:
            return Response({'events': [], 'complete': False})

        stream_data = r.xread({f'scan:logs:{scan_id}': '0'}, count=1000)
        events: list = []
        complete: bool = False
        for _stream_name, messages in (stream_data or []):
            for _msg_id, data in messages:
                try:
                    payload = json.loads(data['data'])
                except (json.JSONDecodeError, KeyError):
                    continue
                if payload.get('job_id') != job_id:
                    continue
                events.append(payload)
                if payload.get('type') == 'email_discovery_complete':
                    complete = True

        return Response({'events': events, 'complete': complete})
