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

class UploadWordlist(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_MODIFY_WORDLISTS

	def post(self, request):
		data = request.data
		name = data.get('name')
		short_name = data.get('short_name')
		upload_file = request.FILES.get('upload_file')

		if not name or not short_name or not upload_file:
			return Response({
				'status': False,
				'message': 'Name, short name and file are required'
			}, status=status.HTTP_400_BAD_REQUEST)

		try:
			safe_short_name = re.sub(r'[^a-zA-Z0-9_\-]', '', short_name)
			if not safe_short_name:
				return Response({'status': False, 'message': 'Invalid short_name'}, status=status.HTTP_400_BAD_REQUEST)

			wordlist_content = upload_file.read().decode('UTF-8', "ignore")
			wordlist_dir = '/usr/src/wordlist/'
			if not os.path.exists(wordlist_dir):
				os.makedirs(wordlist_dir)

			file_path = os.path.realpath(os.path.join(wordlist_dir, f"{safe_short_name}.txt"))
			if not file_path.startswith(os.path.realpath(wordlist_dir) + os.sep):
				return Response({'status': False, 'message': 'Invalid path'}, status=status.HTTP_400_BAD_REQUEST)
			with open(file_path, 'w') as f:
				f.write(wordlist_content)

			Wordlist.objects.create(
				name=name,
				short_name=short_name,
				count=wordlist_content.count('\n')
			)
			return Response({
				'status': True,
				'message': 'Wordlist uploaded successfully'
			})
		except Exception as e:
			return Response({
				'status': False,
				'message': str(e)
			}, status=status.HTTP_400_BAD_REQUEST)


class GetWordlistContent(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_MODIFY_WORDLISTS

	def get(self, request):
		wordlist_id = request.query_params.get('wordlist_id')
		if not wordlist_id:
			return Response({
				'status': False,
				'message': 'Wordlist ID is required'
			}, status=status.HTTP_400_BAD_REQUEST)

		try:
			wordlist = Wordlist.objects.get(id=wordlist_id)
			file_path = f'/usr/src/wordlist/{wordlist.short_name}.txt'
			if os.path.exists(file_path):
				with open(file_path, 'r', encoding='utf-8', errors='ignore') as f:
					# Read first 1000 lines or something to avoid huge responses
					content = "".join([next(f) for _ in range(1000)])
					return Response({
						'status': True,
						'content': content,
						'name': wordlist.name
					})
			return Response({
				'status': False,
				'message': 'File not found'
			}, status=status.HTTP_404_NOT_FOUND)
		except Exception as e:
			return Response({
				'status': False,
				'message': str(e)
			}, status=status.HTTP_400_BAD_REQUEST)


class GetEngineDetails(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_MODIFY_SCAN_CONFIGURATIONS

	def get(self, request):
		engine_id = request.query_params.get('engine_id')
		if not engine_id:
			return Response({
				'status': False,
				'message': 'Engine ID is required'
			}, status=status.HTTP_400_BAD_REQUEST)

		try:
			engine = EngineType.objects.get(id=engine_id)
			return Response({
				'status': True,
				'engine_name': engine.engine_name,
				'yaml_configuration': engine.yaml_configuration
			})
		except Exception as e:
			return Response({
				'status': False,
				'message': str(e)
			}, status=status.HTTP_400_BAD_REQUEST)


class CreateEngine(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_MODIFY_SCAN_CONFIGURATIONS

	def post(self, request):
		data = request.data
		name = data.get('engine_name')
		yaml_configuration = data.get('yaml_configuration')

		if not name or not yaml_configuration:
			return Response({
				'status': False,
				'message': 'Name and YAML configuration are required'
			}, status=status.HTTP_400_BAD_REQUEST)

		try:
			EngineType.objects.create(
				engine_name=name,
				yaml_configuration=yaml_configuration
			)
			return Response({
				'status': True,
				'message': 'Engine created successfully'
			})
		except Exception as e:
			return Response({
				'status': False,
				'message': str(e)
			}, status=status.HTTP_400_BAD_REQUEST)


class UpdateEngine(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_MODIFY_SCAN_CONFIGURATIONS

	def post(self, request):
		data = request.data
		engine_id = data.get('engine_id')
		name = data.get('engine_name')
		yaml_configuration = data.get('yaml_configuration')

		if not engine_id or not name or not yaml_configuration:
			return Response({
				'status': False,
				'message': 'Engine ID, name and YAML configuration are required'
			}, status=status.HTTP_400_BAD_REQUEST)

		try:
			engine = EngineType.objects.get(id=engine_id)
			engine.engine_name = name
			engine.yaml_configuration = yaml_configuration
			engine.save()
			return Response({
				'status': True,
				'message': 'Engine updated successfully'
			})
		except Exception as e:
			return Response({
				'status': False,
				'message': str(e)
			}, status=status.HTTP_400_BAD_REQUEST)


class RunSearchsploitAction(APIView):
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        from startScan.models import Subdomain
        import subprocess
        import json
        try:
            subdomain = Subdomain.objects.get(id=pk)
        except Subdomain.DoesNotExist:
            return Response({'status': False, 'message': 'Subdomain not found'}, status=status.HTTP_404_NOT_FOUND)

        query = request.data.get('query')
        if not query:
            return Response({'status': False, 'message': 'query parameter is required'}, status=status.HTTP_400_BAD_REQUEST)

        import os
        import shutil
        if not os.path.exists('/root/.searchsploit_rc') and os.path.exists('/usr/src/exploitdb/.searchsploit_rc'):
            try:
                shutil.copy('/usr/src/exploitdb/.searchsploit_rc', '/root/.searchsploit_rc')
            except Exception as e:
                logger.error("Failed to copy searchsploit_rc dynamically", exc_info=True)

        cmd = ['searchsploit', '--json', query]
        try:
            result = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
            data = json.loads(result.stdout)
            exploits = data.get('RESULTS_EXPLOIT', [])
            return Response({'status': True, 'results': exploits})
        except Exception as e:
            return Response({'status': False, 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

class LaunchADAssessmentFromSubdomain(APIView):
	"""Create an ADAssessment pre-populated from a Subdomain's root domain.

	The AD Intelligence plugin must be installed. The assessment is created
	in PENDING state; users start it explicitly from the AD plugin dashboard.
	This view intentionally does NOT start the workflow automatically to avoid
	unintended automated enumeration activity.
	"""
	permission_classes = [HasPermission]
	permission_required = PERM_INITATE_SCANS_SUBSCANS

	def post(self, request):
		subdomain_id = request.data.get('subdomain_id')
		if not subdomain_id:
			return Response(
				{'error': 'subdomain_id is required.'},
				status=HTTP_400_BAD_REQUEST,
			)
		try:
			subdomain = Subdomain.objects.select_related(
				'scan_history__domain'
			).get(id=subdomain_id)
		except Subdomain.DoesNotExist:
			return Response(
				{'error': f'Subdomain {subdomain_id} not found.'},
				status=status.HTTP_404_NOT_FOUND,
			)

		target_domain = subdomain.scan_history.domain.name

		try:
			from plugins_data.active_directory.backend.models import ADAssessment as _ADAssessment
		except ImportError:
			return Response(
				{'error': 'AD Intelligence plugin is not installed.'},
				status=HTTP_400_BAD_REQUEST,
			)

		try:
			assessment = _ADAssessment.objects.create(
				name=f'AD Assessment — {target_domain}',
				target_domain=target_domain,
				status='PENDING',
				created_by=request.user,
			)
		except Exception as exc:
			logger.error('[AD Bridge] Failed to create ADAssessment', exc_info=True)
			return Response(
				{'error': 'Failed to create assessment.'},
				status=status.HTTP_500_INTERNAL_SERVER_ERROR,
			)
		return Response({
			'assessment_id': assessment.id,
			'assessment_name': assessment.name,
			'target_domain': target_domain,
			'status': 'created',
		}, status=status.HTTP_201_CREATED)


# ---------------------------------------------------------------------------
# Phase 2 — Standalone workflow launcher API
# ---------------------------------------------------------------------------

_WORKFLOW_REGISTRY = {
    'user-hunt':       ('UserHuntWorkflow',       ['target', 'target_type']),
    'url-bypass':      ('URLBypassWorkflow',       ['urls']),
    'wordpress':       ('WordPressWorkflow',       ['urls']),
    'host-recon':      ('HostReconWorkflow',       ['target', 'target_type']),
    'cidr-recon':      ('CIDRReconWorkflow',       ['cidr']),
    'code-scan':       ('CodeScanWorkflow',        ['target', 'target_type']),
    'domain-recon':    ('DomainReconWorkflow',     ['domain']),
    'subdomain-recon': ('SubdomainReconWorkflow',  ['domain']),
    'url-crawl':       ('URLCrawlWorkflow',        ['urls']),
    'url-dirsearch':   ('URLDirSearchWorkflow',    ['urls']),
    'url-fuzz':        ('URLFuzzWorkflow',         ['urls']),
    'url-params-fuzz': ('URLParamsFuzzWorkflow',   ['urls']),
    'url-vuln':        ('URLVulnWorkflow',         ['urls']),
}

