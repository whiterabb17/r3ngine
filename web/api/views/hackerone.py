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

class HackerOneProgramViewSet(viewsets.ViewSet):
	permission_classes = [IsPenetrationTester]
	"""
		This class manages the HackerOne Program model, 
		provides basic fetching of programs and caching
	"""
	CACHE_KEY = 'hackerone_programs'
	CACHE_TIMEOUT = 60 * 30 # 30 minutes
	PROGRAM_CACHE_KEY = 'hackerone_program_{}'

	API_BASE = 'https://api.hackerone.com/v1/hackers'

	ALLOWED_ASSET_TYPES = ["WILDCARD", "DOMAIN", "IP_ADDRESS", "CIDR", "URL"]

	def list(self, request):
		try:
			sort_by = request.query_params.get('sort_by', 'age')
			sort_order = request.query_params.get('sort_order', 'desc')

			programs = self.get_cached_programs()

			if sort_by == 'name':
				programs = sorted(programs, key=lambda x: x['attributes']['name'].lower(), 
						reverse=(sort_order.lower() == 'desc'))
			elif sort_by == 'reports':
				programs = sorted(programs, key=lambda x: x['attributes'].get('number_of_reports_for_user', 0), 
						reverse=(sort_order.lower() == 'desc'))
			elif sort_by == 'age':
				programs = sorted(programs, 
					key=lambda x: datetime.strptime(x['attributes'].get('started_accepting_at', '1970-01-01T00:00:00.000Z'), '%Y-%m-%dT%H:%M:%S.%fZ'), 
					reverse=(sort_order.lower() == 'desc')
				)

			serializer = HackerOneProgramSerializer(programs, many=True)
			return Response(serializer.data)
		except Exception as e:
			return self.handle_exception(e)
	
	def get_api_credentials(self):
		try:
			api_key = HackerOneAPIKey.objects.first()
			if not api_key:
				raise ObjectDoesNotExist("HackerOne API credentials not found")
			return api_key.username, api_key.key
		except ObjectDoesNotExist:
			raise Exception("HackerOne API credentials not configured")

	@action(detail=False, methods=['get'])
	def bookmarked_programs(self, request):
		try:
			# do not cache bookmarked programs due to the user specific nature
			programs = self.fetch_programs_from_hackerone()
			bookmarked = [p for p in programs if p['attributes']['bookmarked']]
			serializer = HackerOneProgramSerializer(bookmarked, many=True)
			return Response(serializer.data)
		except Exception as e:
			return self.handle_exception(e)
	
	@action(detail=False, methods=['get'])
	def bounty_programs(self, request):
		try:
			programs = self.get_cached_programs()
			bounty_programs = [p for p in programs if p['attributes']['offers_bounties']]
			serializer = HackerOneProgramSerializer(bounty_programs, many=True)
			return Response(serializer.data)
		except Exception as e:
			return self.handle_exception(e)

	def get_cached_programs(self):
		programs = cache.get(self.CACHE_KEY)
		if programs is None:
			programs = self.fetch_programs_from_hackerone()
			cache.set(self.CACHE_KEY, programs, self.CACHE_TIMEOUT)
		return programs

	def fetch_programs_from_hackerone(self):
		url = f'{self.API_BASE}/programs?page[size]=100'
		headers = {'Accept': 'application/json'}
		all_programs = []
		try:
			username, api_key = self.get_api_credentials()
		except Exception as e:
			raise Exception("API credentials error: " + str(e))

		while url:
			response = requests.get(
				url,
				headers=headers,
				auth=(username, api_key)
			)

			if response.status_code == 401:
				raise Exception("Invalid API credentials")
			elif response.status_code != 200:
				raise Exception(f"HackerOne API request failed with status code {response.status_code}")

			data = response.json()
			all_programs.extend(data['data'])
			
			url = data['links'].get('next')

		return all_programs

	@action(detail=False, methods=['post'])
	def refresh_cache(self, request):
		try:
			programs = self.fetch_programs_from_hackerone()
			cache.set(self.CACHE_KEY, programs, self.CACHE_TIMEOUT)
			return Response({"status": "Cache refreshed successfully"})
		except Exception as e:
			return self.handle_exception(e)
	
	@action(detail=True, methods=['get'])
	def program_details(self, request, pk=None):
		try:
			program_handle = pk
			cache_key = self.PROGRAM_CACHE_KEY.format(program_handle)
			program_details = cache.get(cache_key)

			if program_details is None:
				program_details = self.fetch_program_details_from_hackerone(program_handle)
				if program_details:
					cache.set(cache_key, program_details, self.CACHE_TIMEOUT)

			if program_details:
				filtered_scopes = [
					scope for scope in program_details.get('relationships', {}).get('structured_scopes', {}).get('data', [])
					if scope.get('attributes', {}).get('asset_type') in self.ALLOWED_ASSET_TYPES
				]

				program_details['relationships']['structured_scopes']['data'] = filtered_scopes

				return Response(program_details)
			else:
				return Response({"error": "Program not found"}, status=status.HTTP_404_NOT_FOUND)
		except Exception as e:
			return self.handle_exception(e)

	def fetch_program_details_from_hackerone(self, program_handle):
		url = f'{self.API_BASE}/programs/{program_handle}'
		headers = {'Accept': 'application/json'}
		try:
			username, api_key = self.get_api_credentials()
		except Exception as e:
			raise Exception("API credentials error: " + str(e))

		response = requests.get(
			url,
			headers=headers,
			auth=(username, api_key)
		)

		if response.status_code == 401:
			raise Exception("Invalid API credentials")
		elif response.status_code == 200:
			return response.json()
		else:
			return None
		
	@action(detail=False, methods=['post'])
	def import_programs(self, request):
		try:
			project_slug = request.query_params.get('project_slug')
			if not project_slug:
				return Response({"error": "Project slug is required"}, status=status.HTTP_400_BAD_REQUEST)
			handles = request.data.get('handles', [])

			if not handles:
				return Response({"error": "No program handles provided"}, status=status.HTTP_400_BAD_REQUEST)

			from reNgine.temporal_client import TemporalClientProvider
			import asyncio
			async def _start():
				client = await TemporalClientProvider.get_client()
				await client.start_workflow(
					"HackerOneImportWorkflow",
					args=[handles, project_slug, False],
					id=f"h1-import-{project_slug}-{int(timezone.now().timestamp())}",
					task_queue="python-orchestrator-queue"
				)
			loop = asyncio.new_event_loop()
			try:
				loop.run_until_complete(_start())
			finally:
				loop.close()

			create_inappnotification(
				title="HackerOne Program Import Started",
				description=f"Import process for {len(handles)} program(s) has begun.",
				notification_type=PROJECT_LEVEL_NOTIFICATION,
				project_slug=project_slug,
				icon="mdi-download",
				status='info'
			)

			return Response({"message": f"Import process for {len(handles)} program(s) has begun."}, status=status.HTTP_202_ACCEPTED)
		except Exception as e:
			return self.handle_exception(e)
	
	@action(detail=False, methods=['get'])
	def sync_bookmarked(self, request):
		try:
			project_slug = request.query_params.get('project_slug')
			if not project_slug:
				return Response({"error": "Project slug is required"}, status=status.HTTP_400_BAD_REQUEST)

			from reNgine.temporal_client import TemporalClientProvider
			import asyncio
			async def _start():
				client = await TemporalClientProvider.get_client()
				await client.start_workflow(
					"HackerOneSyncBookmarkedWorkflow",
					args=[project_slug],
					id=f"h1-sync-bookmarked-{project_slug}-{int(timezone.now().timestamp())}",
					task_queue="python-orchestrator-queue"
				)
			loop = asyncio.new_event_loop()
			try:
				loop.run_until_complete(_start())
			finally:
				loop.close()

			create_inappnotification(
				title="HackerOne Bookmarked Programs Sync Started",
				description="Sync process for bookmarked programs has begun.",
				notification_type=PROJECT_LEVEL_NOTIFICATION,
				project_slug=project_slug,
				icon="mdi-sync",
				status='info'
			)

			return Response({"message": "Sync process for bookmarked programs has begun."}, status=status.HTTP_202_ACCEPTED)
		except Exception as e:
			return self.handle_exception(e)

	def handle_exception(self, exc):
		if isinstance(exc, ObjectDoesNotExist):
			return Response({"error": "HackerOne API credentials not configured"}, status=status.HTTP_503_SERVICE_UNAVAILABLE)
		elif str(exc) == "Invalid API credentials":
			return Response({"error": "Invalid HackerOne API credentials"}, status=status.HTTP_401_UNAUTHORIZED)
		else:
			return Response({"error": str(exc)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
