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

class ToggleBugBountyModeView(APIView):
	permission_classes = [IsAuthenticated]
	"""
		This class manages the user bug bounty mode
	"""
	def post(self, request, *args, **kwargs):
		user_preferences = get_object_or_404(UserPreferences, user=request.user)
		user_preferences.bug_bounty_mode = not user_preferences.bug_bounty_mode
		user_preferences.save()
		return Response({
			'bug_bounty_mode': user_preferences.bug_bounty_mode
		}, status=status.HTTP_200_OK)


class ToggleScanQueueingView(APIView):
	permission_classes = [IsAuthenticated]
	"""
		This class manages the user scan queuing mode
	"""
	def post(self, request, *args, **kwargs):
		user_preferences = get_object_or_404(UserPreferences, user=request.user)
		user_preferences.enable_scan_queueing = not getattr(user_preferences, 'enable_scan_queueing', False)
		user_preferences.save()
		return Response({
			'enable_scan_queueing': user_preferences.enable_scan_queueing
		}, status=status.HTTP_200_OK)


class UpdateThemeView(APIView):
	permission_classes = [IsAuthenticated]
	"""
		This class manages the user theme and intensity
	"""
	def post(self, request, *args, **kwargs):
		user_preferences = get_object_or_404(UserPreferences, user=request.user)
		ui_version = request.data.get('ui_version')
		v3_intensity = request.data.get('v3_intensity')
		if ui_version:
			user_preferences.ui_version = ui_version
		if v3_intensity:
			user_preferences.v3_intensity = v3_intensity
		user_preferences.save()
		return Response({
			'status': True,
			'ui_version': user_preferences.ui_version,
			'v3_intensity': user_preferences.v3_intensity
		}, status=status.HTTP_200_OK)


class SOCSettingsViewSet(viewsets.ModelViewSet):
	"""ViewSet for managing global SOC configuration."""
	permission_classes = [IsAuditor]
	serializer_class = SOCConfigurationSerializer
	queryset = SOCConfiguration.objects.all()

	def get_queryset(self):
		return SOCConfiguration.objects.all()

	def list(self, request, *args, **kwargs):
		# Ensure at least one config exists
		config, created = SOCConfiguration.objects.get_or_create(id=1)
		serializer = self.get_serializer(config)
		return Response(serializer.data)

	@action(detail=False, methods=['post'])
	def toggle_streaming(self, request):
		config, created = SOCConfiguration.objects.get_or_create(id=1)
		config.enable_live_log_streaming = not config.enable_live_log_streaming
		config.save()
		return Response({
			'enable_live_log_streaming': config.enable_live_log_streaming
		}, status=status.HTTP_200_OK)


class RengineSystemSettingsAPIView(APIView):
	permission_classes = [IsAuthenticated, HasPermission]
	permission_required = PERM_MODIFY_SYSTEM_CONFIGURATIONS

	def get(self, request):
		import shutil
		total, used, _ = shutil.disk_usage("/")
		total_gb = total // (2**30)
		used_gb = used // (2**30)
		free_gb = total_gb - used_gb
		consumed_percent = int(100 * float(used_gb) / float(total_gb)) if total_gb > 0 else 0

		user_preferences = getattr(request.user, 'user_preferences', None)
		if not user_preferences:
			from dashboard.models import UserPreferences
			user_preferences, _ = UserPreferences.objects.get_or_create(user=request.user)

		return Response({
			'total': total_gb,
			'used': used_gb,
			'free': free_gb,
			'consumed_percent': consumed_percent,
			'enable_scan_queueing': user_preferences.enable_scan_queueing
		})


class RengineUpdateCheck(APIView):
	permission_classes = [IsPenetrationTester]
	def get(self, request):
		req = self.request
		github_api = \
			'https://api.github.com/repos/whiterabb17/r3ngine/releases'
		
		return_response = {
			'status': False,
			'update_available': False,
			'latest_version': None,
			'current_version': RENGINE_CURRENT_VERSION,
			'redirect_link': 'https://github.com/whiterabb17/r3ngine/releases'
		}

		def safe_parse_version(v_str):
			if not v_str:
				return version.parse('0.0.0')
			v_str = v_str.strip().lstrip('v')
			try:
				return version.parse(v_str)
			except version.InvalidVersion:
				# PEP 440 sanitization fallback
				sanitized = v_str.replace('-beta.rc', 'b').replace('-rc', 'rc').replace('-beta', 'b').replace('-', '.')
				try:
					return version.parse(sanitized)
				except version.InvalidVersion:
					digits = re.findall(r'\d+', v_str)
					if digits:
						try:
							return version.parse('.'.join(digits))
						except version.InvalidVersion:
							pass
					return version.parse('0.0.0')

		try:
			response = requests.get(github_api, timeout=15).json()
			if 'message' in response and 'rate limit' in response['message'].lower():
				return_response['message'] = 'RateLimited'
			elif isinstance(response, list) and len(response) > 0:
				latest_release_name = response[0]['name']
				latest_release_version = re.search(r'v?(\d+\.)?(\d+\.)?(\*|\d+)', latest_release_name)
				if latest_release_version:
					latest_release_version = latest_release_version.group(0).replace('v', '')
					return_response['latest_version'] = latest_release_version
					return_response['changelog'] = response[0]['body']
					return_response['status'] = True
		except Exception as e:
			logger.error("Error fetching GitHub releases", exc_info=True)

		# Fallback: check .version file in master branch
		version_url = 'https://raw.githubusercontent.com/whiterabb17/r3ngine/main/web/.version'
		try:
			raw_version_response = requests.get(version_url, timeout=15)
			if raw_version_response.status_code == 200:
				raw_version = raw_version_response.text.strip().replace('v', '')
				# If raw_version is higher than latest release or no release found
				if not return_response['latest_version'] or safe_parse_version(raw_version) > safe_parse_version(return_response['latest_version']):
					return_response['latest_version'] = raw_version
					return_response['redirect_link'] = 'https://github.com/whiterabb17/r3ngine'
					return_response['changelog'] = 'A new update is available in the repository. Please pull the latest changes from the main branch.'
					return_response['status'] = True
		except Exception as e:
			logger.error("Error fetching raw .version", exc_info=True)

		if return_response['status'] and return_response['latest_version']:
			is_version_update_available = safe_parse_version(return_response['current_version']) < safe_parse_version(return_response['latest_version'])
			return_response['update_available'] = is_version_update_available

			if is_version_update_available:
				create_inappnotification(
					title='r3ngine Update Available',
					description=f'Update to version {return_response["latest_version"]} is available',
					notification_type=SYSTEM_LEVEL_NOTIFICATION,
					project_slug=None,
					icon='mdi-update',
					redirect_link=return_response['redirect_link'],
					open_in_new_tab=True
				)

		return Response(return_response)


class NotificationSettingsAPIView(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_MODIFY_SCAN_CONFIGURATIONS

	def get(self, request):
		notification = Notification.objects.first()
		if not notification:
			notification = Notification.objects.create()
		serializer = NotificationSettingsSerializer(notification)
		return Response(serializer.data)

	def post(self, request):
		notification = Notification.objects.first()
		serializer = NotificationSettingsSerializer(notification, data=request.data, partial=True)
		if serializer.is_valid():
			serializer.save()
			# Send test messages if requested or on every save (to match legacy)
			if request.data.get('send_test', True):
				send_slack_message('*reNgine*\nCongratulations! your notification services are working.')
				send_lark_message('*reNgine*\nCongratulations! your notification services are working.')
				send_telegram_message('*reNgine*\nCongratulations! your notification services are working.')
				send_discord_message('**reNgine**\nCongratulations! your notification services are working.')
			return Response({'status': True, 'message': 'Notification settings updated and test message sent.'})
		return Response(serializer.errors, status=400)

class ReportSettingsAPIView(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_MODIFY_SCAN_REPORT

	def get(self, request):
		report_setting = VulnerabilityReportSetting.objects.first()
		if not report_setting:
			# Create default settings if not exists
			report_setting = VulnerabilityReportSetting.objects.create()
		serializer = VulnerabilityReportSettingSerializer(report_setting)
		return Response(serializer.data)

	def post(self, request):
		report_setting = VulnerabilityReportSetting.objects.first()
		if not report_setting:
			report_setting = VulnerabilityReportSetting.objects.create()
		serializer = VulnerabilityReportSettingSerializer(report_setting, data=request.data, partial=True)
		if serializer.is_valid():
			serializer.save()
			return Response(serializer.data)
		return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)
class SystemHealthAPIView(APIView):
	permission_classes = [IsPenetrationTester]

	def get(self, request):
		import shutil
		import os
		import time
		from django.db import connection

		# 1. Database Health
		db_start = time.time()
		db_up = True
		try:
			with connection.cursor() as cursor:
				cursor.execute("SELECT 1")
		except Exception:
			db_up = False
		db_latency = int((time.time() - db_start) * 1000)

		# 2. Worker Status (Temporal orchestrator)
		try:
			import asyncio
			from reNgine.temporal_client import TemporalClientProvider
			_loop = asyncio.new_event_loop()
			asyncio.set_event_loop(_loop)
			try:
				_client = _loop.run_until_complete(TemporalClientProvider.get_client())
				workers_online = _client is not None
			finally:
				_loop.close()
			worker_count = 1 if workers_online else 0
		except Exception:
			workers_online = False
			worker_count = 0

		# 3. Disk Usage
		try:
			total, used, free = shutil.disk_usage("/")
			disk_used_percent = int(100 * used / total)
		except Exception:
			disk_used_percent = 0
			free = 0

		# 4. System Load
		try:
			load_avg = os.getloadavg()
		except AttributeError:
			load_avg = (0.0, 0.0, 0.0)

		return Response({
			"status": "online" if db_up and workers_online else "degraded",
			"database": {
				"status": "up" if db_up else "down",
				"latency_ms": db_latency
			},
			"workers": {
				"status": "online" if workers_online else "offline",
				"count": worker_count
			},
			"disk": {
				"used_percent": disk_used_percent,
				"free_gb": free // (2**30)
			},
			"load": load_avg[0],
			"timestamp": time.time()
		})


class GetSystemLogs(APIView):
	"""Fetch the tail of system, database, temporal, or scan logs.

	Restricted to SysAdmins. The request takes an optional 'type' parameter
	to specify which log file to retrieve.
	"""
	permission_classes = [IsSysAdmin]

	def get(self, request):
		"""Fetch system logs based on log type query parameter.

		Args:
			request (HttpRequest): The incoming HTTP request.
				Query parameter 'type' specifies the log log_type. Options:
				- 'system': Retrieve errors.log (system errors)
				- 'db': Retrieve db.log (database backend errors/queries)
				- 'temporal': Retrieve temporal.log (temporal workflow events)
				- 'scan': Retrieve scan.log (legacy scan runner events)

		Returns:
			Response: JSON response containing operation status and list of log lines.
		"""
		# Extract log type query parameter (default to 'system')
		log_type = request.query_params.get('type', 'system')

		# Hardcoded, safe mapping of log types to file names
		log_map = {
			'system': 'errors.log',
			'db': 'db.log',
			'temporal': 'temporal.log',
			'scan': 'scan.log'
		}

		filename = log_map.get(log_type)
		if not filename:
			return Response({'status': False, 'message': 'Invalid log type'}, status=400)

		# SECURITY: Prevent directory traversal by sanitizing and verifying the path
		log_file = os.path.normpath(os.path.join(settings.BASE_DIR, filename))

		# Strict assertion: Ensure the log file sits strictly within BASE_DIR
		if not log_file.startswith(os.path.normpath(settings.BASE_DIR)):
			return Response({'status': False, 'message': 'Forbidden log path'}, status=403)

		# Return an empty list if the log file does not exist yet to avoid 404 spam in frontend
		if not os.path.exists(log_file):
			return Response({'status': True, 'logs': []})

		try:
			with open(log_file, 'r', encoding='utf-8', errors='replace') as f:
				# Efficiently read the last ~50KB to fetch roughly the last 500 lines
				f.seek(0, os.SEEK_END)
				filesize = f.tell()
				offset = min(filesize, 50000)
				f.seek(filesize - offset)
				# Read remaining content and split into lines safely
				data = f.read()
				lines = data.splitlines()
				# Return at most 500 lines to keep responses lightweight
				return Response({'status': True, 'logs': lines[-500:]})
		except Exception as e:
			logger.error("Error reading system logs (%s)", log_type, exc_info=True)
			return Response({'status': False, 'message': 'Internal error reading logs'}, status=500)


class ProxySettingsAPIView(APIView):
	permission_classes = [IsAuthenticated, HasPermission]
	permission_required = PERM_MODIFY_SCAN_CONFIGURATIONS

	def get(self, request):
		from reNgine.common_func import get_valid_proxy_count

		proxy = Proxy.objects.first()
		serializer = ProxySerializer(proxy)
		payload = dict(serializer.data) if proxy else {
			'use_proxy': False,
			'proxies': '',
			'use_proxychains': False,
			'use_tor': False,
		}
		payload['valid_proxy_count'] = get_valid_proxy_count(proxy)
		return Response(payload)

	def post(self, request):
		proxy = Proxy.objects.first()
		if not proxy:
			proxy = Proxy.objects.create()
		data = request.data.copy()
		message = 'Proxies updated successfully'
		skip_validation = request.data.get('skip_validation') == 'true'
		if data.get('use_proxy') and data.get('proxies') and not skip_validation:
			from reNgine.common_func import validate_proxies
			original_count = len([line for line in data['proxies'].splitlines() if line.strip()])
			validated = validate_proxies(data['proxies'])
			data['proxies'] = validated
			saved_count = len([line for line in validated.splitlines() if line.strip()])
			message = f'Proxies updated. Validated {saved_count}/{original_count} live proxies.'
		serializer = ProxySerializer(proxy, data=data, partial=True)
		if serializer.is_valid():
			serializer.save()
			return Response({'status': True, 'message': message})
		return Response(serializer.errors, status=status.HTTP_400_BAD_REQUEST)


class ProxyFetchAPIView(APIView):
	permission_classes = [IsAuthenticated, HasPermission]
	permission_required = PERM_MODIFY_SCAN_CONFIGURATIONS

	def post(self, request):
		try:
			from reNgine.tasks import fetch_proxies_task
			from reNgine.job_tracker import create_job
			import threading
			limit = request.data.get('limit', 1000)
			try:
				limit = int(limit)
			except Exception:
				limit = 1000
			job_id = create_job()
			logger.info("[ProxyFetch] Starting proxy fetch workflow (limit=%d, job_id=%s)", limit, job_id)
			from reNgine.temporal_client import TemporalClientProvider
			import asyncio
			async def _start():
				client = await TemporalClientProvider.get_client()
				await client.start_workflow(
					"ProxyFetchWorkflow",
					args=[limit, job_id],
					id=f"proxy-fetch-{job_id}",
					task_queue="python-orchestrator-queue"
				)
			loop = asyncio.new_event_loop()
			try:
				loop.run_until_complete(_start())
			except Exception as e:
				from reNgine.job_tracker import update_job
				update_job(job_id, "FAILED", 100, f"Failed to start workflow: {e}")
				logger.error("[ProxyFetch] Failed to start proxy fetch workflow: %s", e)
			finally:
				loop.close()
			return Response({'status': True, 'task_id': job_id})
		except Exception:
			logger.exception("[ProxyFetch] Unexpected error in ProxyFetchAPIView")
			return Response({'status': False, 'message': INTERNAL_ERROR_MESSAGE}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class TorStatusAPIView(APIView):
	permission_classes = [IsAuthenticated]

	def get(self, request):
		from reNgine.tor_manager import TorManager
		try:
			return Response(TorManager().status())
		except Exception as e:
			# A probe that errors should read as "tor is not running", not as
			# a 500 on a status endpoint the UI polls.
			logger.warning('[TorStatus] Could not determine TOR state: %s', e)
			return Response({'running': False, 'hint': TorManager.enable_hint()})


class TorExitIPAPIView(APIView):
	permission_classes = [IsAuthenticated]

	def get(self, request):
		from reNgine.tor_manager import TorManager
		try:
			if not TorManager().is_running():
				return Response({'ip': None})
			import requests as req_lib
			proxies = {'http': 'socks5h://tor:9050', 'https': 'socks5h://tor:9050'}
			resp = req_lib.get('https://api.ipify.org', proxies=proxies, timeout=10)
			return Response({'ip': resp.text.strip()})
		except Exception:
			return Response({'ip': None})


class HardwareProfileViewSet(viewsets.ModelViewSet):
	permission_classes = [IsAuditor]
	queryset = HardwareProfile.objects.all().order_by('id')
	serializer_class = HardwareProfileSerializer


class ListConfigurations(APIView):
	permission_classes = [IsAuditor]
	def get(self, request, format=None):
		configurations = Configuration.objects.all()
		configuration_serializer = ConfigurationSerializer(configurations, many=True)
		return Response({'configurations': configuration_serializer.data})
