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
from rest_framework.permissions import IsAuthenticated, AllowAny
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

class ProjectViewSet(viewsets.ModelViewSet):
	queryset = Project.objects.all().order_by('-insert_date')
	serializer_class = ProjectSerializer
	permission_classes = [IsAuthenticated]
	renderer_classes = [JSONRenderer]


	@action(detail=True, methods=['post'])
	def delete_project(self, request, pk=None):
		if not request.user.has_perm('dashboard.modify_targets'):
			return Response({'status': False, 'message': 'Permission Denied'}, status=403)
		project = self.get_object()
		project.delete()
		return Response({'status': True})


class CreateProjectApi(APIView):

	permission_classes = [HasPermission]
	permission_required = PERM_MODIFY_TARGETS
	renderer_classes = [JSONRenderer]


	def post(self, request):
		req = self.request
		project_name = req.data.get('name')
		if not project_name:
			return Response({'status': False, 'error': 'Project name is required'}, status=HTTP_400_BAD_REQUEST)
		slug = slugify(project_name)
		insert_date = timezone.now()

		try:
			project = Project.objects.create(
				name=project_name,
				slug=slug,
				insert_date =insert_date
			)
			response = {
				'status': True,
				'project_name': project_name
			}
			return Response(response)
		except Exception as e:
			response = {
				'status': False,
				'error': str(e)
			}
			return Response(response, status=HTTP_400_BAD_REQUEST)



class DeleteMultipleRows(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_MODIFY_TARGETS

	def post(self, request):
		req = self.request
		data = req.data

		try:
			row_ids = [int(r) for r in data.get('rows', [])]
			if data['type'] == 'subscan':
				SubScan.objects.filter(id__in=row_ids).delete()
			elif data['type'] == 'organization':
				Organization.objects.filter(id__in=row_ids).delete()
			elif data['type'] == 'scan_engine':
				EngineType.objects.filter(id__in=row_ids).delete()
			elif data['type'] == 'wordlist':
				Wordlist.objects.filter(id__in=row_ids).delete()
			elif data['type'] == 'target':
				Domain.objects.filter(id__in=row_ids).delete()
			elif data['type'] == 'scan_history':
				ScanHistory.objects.filter(id__in=row_ids).delete()
			response = True
		except Exception as e:
			response = False

		return Response({'status': response})


class ListInterestingKeywords(APIView):
	permission_classes = [IsPenetrationTester]
	def get(self, request, format=None):
		req = self.request
		keywords = get_lookup_keywords()
		return Response(keywords)


class ToggleMonitoringAPIView(APIView):
	permission_classes = [IsAuthenticated, HasPermission]
	permission_required = PERM_MODIFY_TARGETS

	def post(self, request):
		domain_id = request.data.get('domain_id')
		try:
			from targetApp.models import Domain
			domain = Domain.objects.get(id=domain_id)
			domain.is_monitored = not domain.is_monitored
			domain.save()
			from targetApp.views import manage_monitoring_task
			manage_monitoring_task(domain)
			return Response({
				'status': True,
				'is_monitored': domain.is_monitored,
				'message': f'Monitoring {"enabled" if domain.is_monitored else "disabled"} for {domain.name}'
			})
		except Exception as e:
			return Response({'status': False, 'message': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class MobileMediaServeView(APIView):
	permission_classes = [IsAuthenticated]
	def get(self, request):
		path = request.query_params.get('path')
		if not path:
			return Response({'error': 'Path is required'}, status=status.HTTP_400_BAD_REQUEST)
		
		# Normalize path
		if path.startswith(settings.MEDIA_ROOT):
			path = os.path.relpath(path, settings.MEDIA_ROOT)
		elif path.startswith('/usr/src/scan_results'):
			path = os.path.relpath(path, '/usr/src/scan_results')
		
		if path.startswith('scan_results/'):
			path = path[len('scan_results/'):]
		elif path.startswith('media/'):
			path = path[len('media/'):]
		elif path.startswith('/media/'):
			path = path[len('/media/'):]
		
		path = path.lstrip('/')
		file_path = os.path.normpath(os.path.join(settings.MEDIA_ROOT, path))
		
		# Security check
		if not is_safe_path(settings.MEDIA_ROOT, file_path):
			logger.error("is_safe_path failed for %s", file_path)
			raise Http404("File not found")
			
		if os.path.exists(file_path):
			if os.path.isdir(file_path):
				raise Http404("File not found")
				
			content_type, _ = mimetypes.guess_type(file_path)
			return FileResponse(open(file_path, 'rb'), content_type=content_type)
		else:
			logger.error("File not found: %s", file_path)
			raise Http404("File not found")


class ScanProfileViewSet(viewsets.ModelViewSet):
    queryset = ScanProfile.objects.all().order_by('category', 'name')
    serializer_class = ScanProfileSerializer
    permission_classes = [IsAuthenticated]
    lookup_field = 'name'

    def destroy(self, request, *args, **kwargs):
        profile = self.get_object()
        if profile.is_builtin:
            return Response(
                {'error': 'Cannot delete built-in profiles.'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        return super().destroy(request, *args, **kwargs)


# ---------------------------------------------------------------------------
# LinkedIn session management endpoints
# ---------------------------------------------------------------------------

_LINKEDIN_CAPTURE_SCRIPT = '''\
#!/usr/bin/env python3
"""
LinkedIn Session Capture Helper -- r3ngine
==========================================
Run this script on your LOCAL machine (not inside Docker) to capture a LinkedIn
authenticated session state file for upload to r3ngine.

Requirements (local machine):
    pip install playwright playwright-stealth
    playwright install chromium

Usage:
    python linkedin_capture.py
    # A browser window opens. Log in to LinkedIn (including any MFA steps).
    # The script saves storage_state.json once you reach the feed.
    # Upload that file in r3ngine: Settings -> API Keys -> LinkedIn.
"""
from playwright.sync_api import sync_playwright

OUTPUT_FILE = "storage_state.json"

def main():
    with sync_playwright() as p:
        browser = p.chromium.launch(headless=False)
        context = browser.new_context()
        page = context.new_page()
        print("Opening LinkedIn login...")
        page.goto("https://www.linkedin.com/login")
        print("Complete login in the browser (including MFA if prompted).")
        print("Waiting for feed page...")
        page.wait_for_url("**/feed/**", timeout=0)
        print("Login confirmed. Saving session...")
        context.storage_state(path=OUTPUT_FILE)
        browser.close()
        print(f"Done. Upload \'{OUTPUT_FILE}\' to r3ngine via Settings -> API Keys -> LinkedIn.")

if __name__ == "__main__":
    main()
'''


class LinkedInSessionUploadView(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request):
        from dashboard.models import LinkedInCredentials

        cookies_json = request.data.get('cookies_json')
        if cookies_json:
            try:
                json.loads(cookies_json)
            except (json.JSONDecodeError, TypeError, ValueError):
                return Response({'error': 'Invalid cookies_json -- must be a valid JSON array.'}, status=400)
            session, _ = LinkedInCredentials.objects.get_or_create(id=1)
            session.cookies_json = cookies_json
            session.is_valid = False
            session.save(update_fields=['cookies_json', 'is_valid'])
            return Response({'status': 'cookies saved'})

        state_file = request.FILES.get('state_file')
        if not state_file:
            return Response({'error': 'Provide state_file (multipart) or cookies_json (JSON).'}, status=400)

        try:
            content = state_file.read()
            json.loads(content)
        except (json.JSONDecodeError, Exception):
            return Response({'error': 'Uploaded file is not valid JSON.'}, status=400)

        state_dir = os.path.join(settings.RENGINE_RESULTS, 'context', 'linkedin')
        os.makedirs(state_dir, exist_ok=True)
        state_path = os.path.join(state_dir, 'storage_state.json')
        with open(state_path, 'wb') as fh:
            fh.write(content)

        session, _ = LinkedInCredentials.objects.get_or_create(id=1)
        session.state_file_path = state_path
        session.is_valid = False
        session.save(update_fields=['state_file_path', 'is_valid'])
        return Response({'status': 'state file saved'})


class LinkedInSessionStatusView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from dashboard.models import LinkedInCredentials
        session = LinkedInCredentials.objects.first()
        if not session:
            return Response({
                'is_valid': False,
                'last_validated_at': None,
                'username': '',
                'has_state_file': False,
                'has_cookies': False,
            })
        return Response({
            'is_valid': session.is_valid,
            'last_validated_at': session.last_validated_at,
            'username': session.username,
            'has_state_file': bool(
                session.state_file_path and os.path.isfile(session.state_file_path)
            ),
            'has_cookies': bool(session.cookies_json),
        })


class LinkedInSessionDeleteView(APIView):
    permission_classes = [IsAuthenticated]

    def delete(self, request):
        import logging as _logging
        from dashboard.models import LinkedInCredentials
        _logger = _logging.getLogger(__name__)
        session = LinkedInCredentials.objects.first()
        if session:
            if session.state_file_path and os.path.isfile(session.state_file_path):
                try:
                    os.remove(session.state_file_path)
                except OSError as exc:
                    _logger.warning("Could not delete LinkedIn state file: %s", exc)
            session.cookies_json = ''
            session.state_file_path = ''
            session.is_valid = False
            session.last_validated_at = None
            session.save()
        return Response({'status': 'session cleared'})


class LinkedInHelperScriptView(APIView):
    permission_classes = [IsAuthenticated]

    def get(self, request):
        response = HttpResponse(_LINKEDIN_CAPTURE_SCRIPT, content_type='text/x-python')
        response['Content-Disposition'] = 'attachment; filename="linkedin_capture.py"'
        return response

