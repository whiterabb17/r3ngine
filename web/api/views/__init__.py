import json
import re
import socket
import logging
import subprocess
# threading.Thread - retained for migration test checks
import threading
from concurrent.futures import ThreadPoolExecutor
from django.db import connections
import requests
import validators
from django.conf import settings

from ipaddress import IPv4Network
from django.db.models import CharField, Count, F, Max, Q, Value
from django.utils import timezone
from packaging import version
from django.template.defaultfilters import slugify
from datetime import datetime
from django.db.models.functions import Lower
from rest_framework import mixins, viewsets, serializers, status
from rest_framework.pagination import PageNumberPagination
from rest_framework_datatables.pagination import DatatablesPageNumberPagination
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.renderers import JSONRenderer
from django.http import FileResponse, Http404, HttpResponse
import mimetypes
import os


from django.shortcuts import get_object_or_404
from rest_framework.status import HTTP_400_BAD_REQUEST, HTTP_204_NO_CONTENT, HTTP_202_ACCEPTED
from rest_framework.decorators import action
from django.core.exceptions import ObjectDoesNotExist
from django.core.cache import cache

from dashboard.models import *
from recon_note.models import *
from reNgine.common_func import *
from reNgine.utils.database import *
from reNgine.definitions import (
	ABORTED_TASK,
	RUNNING_TASK,
	SUCCESS_TASK,
	PERM_MODIFY_TARGETS,
	PERM_MODIFY_SCAN_CONFIGURATIONS,
	PERM_MODIFY_WORDLISTS,
	PERM_INITATE_SCANS_SUBSCANS,
	PERM_MODIFY_SCAN_REPORT,
	PERM_MODIFY_SCAN_RESULTS,
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


logger = logging.getLogger(__name__)

from reNgine.temporal_client import TemporalClientProvider, run_and_close


from api.views.scan import (
    InitiateScan, InitiateSubTask, StopScan, ResumeScan, PauseScan, UnpauseScan,
    FetchSubscanResults, ListSubScans, StartWorkflowView, ScanActivityRetryAPIView,
    DirectoryFileDispatchView, DirectoryFileDeleteView, ExtractAuthLogsView,
)
from api.views.targets import (
    AddTarget, UpdateTarget, ListTargetsDatatableViewSet, AddManualSubdomain,
    DeleteSubdomain, ToggleSubdomainImportantStatus, QueryInterestingSubdomains,
    ParameterSummaryView, SecretLeakViewSet, EmailBreachViewSet, CheckEmailBreach,
    ScreenshotViewSet, DirectoryViewSet,
)
from api.views.vulns import (
    VulnerabilityPagination, VulnerabilityViewSet, ExposurePagination, ExposureViewSet,
    CVEDetails, GenerateCveDescription, FetchMostCommonVulnerability, FetchMostVulnerable, DeleteVulnerability,
)
from api.views.recon import (
    OsintStagingViewSet, MonitoringDiscoveryViewSet, WafDetector, AddReconNote,
    SearchHistoryView, UniversalSearch, GetScanGraphData, GetTargetGraphData, GetNodeDetails,
)
from api.views.llm import GPTAttackSuggestion, LLMVulnerabilityReportGenerator, OllamaManager
from api.views.tools import (
    UploadWordlist, GetWordlistContent, GetEngineDetails, CreateEngine, UpdateEngine,
    RunSearchsploitAction, LaunchADAssessmentFromSubdomain,
    _WORKFLOW_REGISTRY,
)
from api.views.settings import (
    ToggleBugBountyModeView, ToggleScanQueueingView, UpdateThemeView, SOCSettingsViewSet,
    RengineSystemSettingsAPIView, RengineUpdateCheck, NotificationSettingsAPIView,
    ReportSettingsAPIView, SystemHealthAPIView, GetSystemLogs,
)
from api.views.notifications import InAppNotificationManagerViewSet, RegisterPushTokenView
from api.views.hackerone import HackerOneProgramViewSet
from api.views.workers import ScanWorkerViewSet, WorkerHeartbeatAPIView
from api.views.misc import (
    ProjectViewSet, CreateProjectApi, DeleteMultipleRows, ListInterestingKeywords,
    ToggleMonitoringAPIView, MobileMediaServeView, ScanProfileViewSet,
    LinkedInSessionUploadView, LinkedInSessionStatusView, LinkedInSessionDeleteView,
    LinkedInHelperScriptView,
)
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
		except Exception as e:
			logger.exception("[ProxyFetch] Unexpected error in ProxyFetchAPIView: %s", e)
			return Response({'status': False, 'message': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class TorStatusAPIView(APIView):
	permission_classes = [IsAuthenticated]

	def get(self, request):
		from reNgine.tor_manager import TorManager, TorUnavailableError
		try:
			running = TorManager().is_running()
			return Response({'running': running})
		except TorUnavailableError:
			return Response({'running': False})


class TorExitIPAPIView(APIView):
	permission_classes = [IsAuthenticated]

	def get(self, request):
		from reNgine.tor_manager import TorManager, TorUnavailableError
		try:
			if not TorManager().is_running():
				return Response({'ip': None})
			import requests as req_lib
			proxies = {'http': 'socks5h://tor:9050', 'https': 'socks5h://tor:9050'}
			resp = req_lib.get('https://api.ipify.org', proxies=proxies, timeout=10)
			return Response({'ip': resp.text.strip()})
		except Exception:
			return Response({'ip': None})


class UninstallTool(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_MODIFY_SYSTEM_CONFIGURATIONS

	def get(self, request):
		req = self.request
		tool_id = req.query_params.get('tool_id')
		tool_name = req.query_params.get('name')

		if tool_id:
			tool = InstalledExternalTool.objects.get(id=tool_id)
		elif tool_name:
			tool = InstalledExternalTool.objects.get(name=tool_name)


		if tool.is_default:
			return Response({'status': False, 'message': 'Default tools can not be uninstalled'})

		# check install instructions, if it is installed using go, then remove from go bin path,
		# else try to remove from github clone path

		# getting tool name is tricky!

		if 'go install' in tool.install_command:
			tool_name = tool.install_command.split('/')[-1].split('@')[0]
			uninstall_command = 'rm /usr/local/bin/' + tool_name
		elif 'git clone' in tool.install_command:
			tool_name = tool.install_command[:-1] if tool.install_command[-1] == '/' else tool.install_command
			tool_name = tool_name.split('/')[-1]
			uninstall_command = 'rm -rf ' + tool.github_clone_path
		else:
			return Response({'status': False, 'message': 'Cannot uninstall tool!'})

		run_command(uninstall_command, shell=True)

		tool.delete()

		return Response({'status': True, 'message': 'Uninstall Tool Success'})


class UpdateTool(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_MODIFY_SYSTEM_CONFIGURATIONS

	def get(self, request):
		req = self.request
		tool_id = req.query_params.get('tool_id')
		tool_name = req.query_params.get('name')

		if tool_id:
			tool = InstalledExternalTool.objects.get(id=tool_id)
		elif tool_name:
			tool = InstalledExternalTool.objects.get(name=tool_name)

		# if git clone was used for installation, then we must use git pull inside project directory,
		# otherwise use the same command as given

		update_command = tool.update_command.lower()

		if not update_command:
			return Response({'status': False, 'message': tool.name + 'has missing update command! Cannot update the tool.'})
		elif update_command == 'git pull':
			tool_name = tool.install_command[:-1] if tool.install_command[-1] == '/' else tool.install_command
			tool_name = tool_name.split('/')[-1]
			update_command = 'cd /usr/src/github/' + tool_name + ' && git pull && cd -'

		
		try:
			return_code, output = run_command(update_command, shell=True)
			if return_code == 0:
				return Response({'status': True, 'message': tool.name + ' updated successfully.'})
			else:
				logger.error("Update failed for %s: %s", tool.name, output)
				return Response({'status': False, 'message': f'Update failed: {output[:200]}...'})
		except Exception as e:
			logger.error(str(e))
			return Response({'status': False, 'message': str(e)})

class UninstallTool(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_MODIFY_SYSTEM_CONFIGURATIONS

	def get(self, request):
		req = self.request
		tool_id = req.query_params.get('tool_id')
		if not InstalledExternalTool.objects.filter(id=tool_id).exists():
			return Response({'status': False, 'message': 'Tool Not found'})
		tool = InstalledExternalTool.objects.get(id=tool_id)
		
		try:
			return_code, output = run_command(tool.uninstall_command, shell=True)
			if return_code == 0:
				tool.delete()
				return Response({'status': True, 'message': tool.name + ' uninstalled successfully.'})
			else:
				return Response({'status': False, 'message': f'Uninstall failed: {output[:200]}'})
		except Exception as e:
			logger.error(str(e))
			return Response({'status': False, 'message': str(e)})

class GetExternalToolCurrentVersion(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_MODIFY_SYSTEM_CONFIGURATIONS

	def get(self, request):
		req = self.request
		# toolname is also the command
		tool_id = req.query_params.get('tool_id')
		tool_name = req.query_params.get('name')
		# can supply either tool id or tool_name

		tool = None

		if tool_id:
			if not InstalledExternalTool.objects.filter(id=tool_id).exists():
				return Response({'status': False, 'message': 'Tool Not found'})
			tool = InstalledExternalTool.objects.get(id=tool_id)
		elif tool_name:
			if not InstalledExternalTool.objects.filter(name=tool_name).exists():
				return Response({'status': False, 'message': 'Tool Not found'})
			tool = InstalledExternalTool.objects.get(name=tool_name)

		if not tool.version_lookup_command:
			return Response({'status': False, 'message': 'Version Lookup command not provided.'})

		version_number = None
		try:
			return_code, stdout = run_command(tool.version_lookup_command, shell=True)
			if return_code != 0:
				logger.warning("Version lookup failed for %s with code %s", tool.name, return_code)
				return Response({'status': False, 'message': 'Tool not found or check failed.'})
		except Exception as e:
			logger.error("Error running version lookup command", exc_info=True)
			return Response({'status': False, 'message': f'Error running version lookup command: {str(e)}'})

		if tool.version_match_regex:
			version_number = re.search(re.compile(tool.version_match_regex), str(stdout))
		else:
			# Improved regex: must look like a version and NOT be part of a path
			# Looks for version at start of line or preceded by space, and not followed by /
			version_match_regex = r'(?:^|\s)(?i:v)?(\d+\.\d+(?:\.\d+)*)(?!\/)'
			version_number = re.search(version_match_regex, str(stdout))
		
		if not version_number:
			return Response({'status': False, 'message': 'Tool installed but version could not be parsed.'})

		# Use group(1) to get the captured version number without the leading space
		version = version_number.group(1) if version_number.groups() else version_number.group(0)
		
		# Final check: if version is just a single digit, it's probably wrong (unless it matches a strict regex)
		if not tool.version_match_regex and len(version.strip()) < 3 and '.' not in version:
			return Response({'status': False, 'message': 'Invalid version parsed.'})

		return Response({'status': True, 'version_number': version.strip(), 'tool_name': tool.name})



class GithubToolCheckGetLatestRelease(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_MODIFY_SYSTEM_CONFIGURATIONS
	
	def get(self, request):
		req = self.request

		tool_id = req.query_params.get('tool_id')
		tool_name = req.query_params.get('name')

		if not InstalledExternalTool.objects.filter(id=tool_id).exists():
			return Response({'status': False, 'message': 'Tool Not found'})

		if tool_id:
			tool = InstalledExternalTool.objects.get(id=tool_id)
		elif tool_name:
			tool = InstalledExternalTool.objects.get(name=tool_name)

		if not tool.github_url:
			return Response({'status': False, 'message': 'Github URL is not provided, Cannot check updates'})

		# if tool_github_url has https://github.com/ remove and also remove trailing /
		tool_github_url = tool.github_url.replace('http://github.com/', '').replace('https://github.com/', '')
		tool_github_url = remove_lead_and_trail_slash(tool_github_url)
		github_api = f'https://api.github.com/repos/{tool_github_url}/releases'
		try:
			res = requests.get(github_api, timeout=10)
			if res.status_code == 403:
				return Response({'status': False, 'message': 'GitHub Rate Limit Exceeded'})
			response = res.json()
		except requests.exceptions.Timeout:
			return Response({'status': False, 'message': 'GitHub API Timeout'})
		except Exception as e:
			return Response({'status': False, 'message': f'Error fetching from GitHub: {str(e)}'})

		# check if api rate limit exceeded
		if isinstance(response, dict) and 'message' in response:
			if 'rate limit' in response['message'].lower():
				return Response({'status': False, 'message': 'RateLimited'})
			elif 'Not Found' in response['message']:
				return Response({'status': False, 'message': 'Repository Not Found'})
		
		if not response or not isinstance(response, list):
			return Response({'status': False, 'message': 'No releases found'})

		# only send latest release
		response = response[0]

		# Try to find a version string in tag_name or name
		latest_version = response.get('tag_name') or response.get('name') or 'Unknown'
		# If tag_name was used, use name as a secondary identifier
		release_name = response.get('name') or response.get('tag_name') or 'Unknown'

		api_response = {
			'status': True,
			'url': response.get('html_url'),
			'id': response.get('id'),
			'name': release_name,
			'version_number': latest_version,
			'changelog': response.get('body'),
		}
		return Response(api_response)


class ScanStatus(APIView):
	permission_classes = [IsPenetrationTester]
	def get(self, request):
		req = self.request
		slug = self.request.GET.get('project', None)

		# main tasks
		recently_completed_scans = (
			ScanHistory.objects
			.filter(domain__project__slug=slug)
			.order_by('-start_scan_date')
			.filter(Q(scan_status=0) | Q(scan_status=2) | Q(scan_status=3))[:10]
		)
		current_scans = (
			ScanHistory.objects
			.filter(domain__project__slug=slug)
			.order_by('-start_scan_date')
			.filter(scan_status=1)
		)
		pending_scans = (
			ScanHistory.objects
			.filter(domain__project__slug=slug)
			.filter(scan_status=-1)
		)

		# subtasks
		recently_completed_tasks = (
			SubScan.objects
			.filter(scan_history__domain__project__slug=slug)
			.order_by('-start_scan_date')
			.filter(Q(status=0) | Q(status=2) | Q(status=3))[:15]
		)
		current_tasks = (
			SubScan.objects
			.filter(scan_history__domain__project__slug=slug)
			.order_by('-start_scan_date')
			.filter(status=1)
		)
		pending_tasks = (
			SubScan.objects
			.filter(scan_history__domain__project__slug=slug)
			.filter(status=-1)
		)
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


class Whois(APIView):
	permission_classes = [IsPenetrationTester]
	def get(self, request):
		req = self.request
		target = req.query_params.get('target')
		if not target:
			return Response({'status': False, 'message': 'Target IP/Domain required!'})
		if not (validators.domain(target) or validators.ipv4(target) or validators.ipv6(target)):
			logger.warning('Ip address or domain "%s" did not pass validator.', target)
			return Response({'status': False, 'message': 'Invalid domain or IP'})
		is_force_update = req.query_params.get('is_reload')
		is_force_update = True if is_force_update and 'true' == is_force_update.lower() else False
		response = query_whois(target, is_force_update)
		return Response(response)


class ReverseWhois(APIView):
	permission_classes = [IsPenetrationTester]
	def get(self, request):
		req = self.request
		lookup_keyword = req.query_params.get('lookup_keyword')
		response = query_reverse_whois(lookup_keyword)
		return Response(response)


class DomainIPHistory(APIView):
	permission_classes = [IsPenetrationTester]
	def get(self, request):
		req = self.request
		domain = req.query_params.get('domain')
		response = query_ip_history(domain)
		return Response(response)


class CMSDetector(APIView):
	permission_classes = [IsPenetrationTester]
	def get(self, request):
		req = self.request
		url = req.query_params.get('url')
		#save_db = True if 'save_db' in req.query_params else False
		response = {'status': False}

		if not (validators.url(url) or validators.domain(url)):
			response['message'] = 'Invalid Domain/URL provided!'
			return Response(response)

		try:
			# response = get_cms_details(url)
			response = {}
			_, output = run_command(
				['python3', '/usr/src/github/CMSeeK/cmseek.py',
				 '--random-agent', '--batch', '--follow-redirect', '-u', url],
				shell=False, remove_ansi_sequence=True)

			response['message'] = 'Could not detect CMS!'

			parsed_url = urlparse(url)

			domain_name = parsed_url.hostname
			port = parsed_url.port

			find_dir = domain_name

			if port:
				find_dir += '_{}'.format(port)
			# look for result path in output
			path_regex = r"Result: (\/usr\/src[^\"\s]*)"
			match = re.search(path_regex, output)
			if match:
				cms_json_path = match.group(1)
				if os.path.isfile(cms_json_path):
					cms_file_content = json.loads(open(cms_json_path, 'r').read())
					if not cms_file_content.get('cms_id'):
						return response
					response = {}
					response = cms_file_content
					response['status'] = True
					try:
						# remove results
						cms_dir_path = os.path.dirname(cms_json_path)
						shutil.rmtree(cms_dir_path)
					except Exception as e:
						logger.error(e)
					return Response(response)
			return Response(response)
		except Exception as e:
			response = {'status': False, 'message': str(e)}
			return Response(response)


class IPToDomain(APIView):
	permission_classes = [IsPenetrationTester]
	def get(self, request):
		req = self.request
		ip_address = req.query_params.get('ip_address')
		if not ip_address:
			return Response({
				'status': False,
				'message': 'IP Address Required'
			})
		try:
			logger.info('Resolving IP address %s ...', ip_address)
			resolved_ips = []
			for ip in IPv4Network(ip_address, False):
				domains = []
				ips = []
				try:
					(domain, domains, ips) = socket.gethostbyaddr(str(ip))
				except socket.herror:
					logger.info('No PTR record for %s', ip_address)
					domain = str(ip)
				if domain not in domains:
					domains.append(domain)
				resolved_ips.append({'ip': str(ip),'domain': domain, 'domains': domains, 'ips': ips})
			response = {
				'status': True,
				'orig': ip_address,
				'ip_address': resolved_ips,
			}
		except Exception as e:
			logger.exception(e)
			response = {
				'status': False,
				'ip_address': ip_address,
				'message': f'Exception {e}'
			}
		finally:
			return Response(response)


class VulnerabilityReport(APIView):
	permission_classes = [IsPenetrationTester]
	def get(self, request):
		req = self.request
		vulnerability_id = req.query_params.get('vulnerability_id')
		return Response({"status": send_hackerone_report(vulnerability_id)})


class GetFileContents(APIView):
	permission_classes = [IsPenetrationTester]
	def get(self, request, format=None):
		import pathlib
		req = self.request
		name = req.query_params.get('name')

		response = {}
		response['status'] = False

		if 'nuclei_config' in req.query_params:
			path = "/root/.config/nuclei/config.yaml"
			if not os.path.exists(path):
				pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
				pathlib.Path(path).touch()
				response['message'] = 'File Created!'
			f = open(path, "r")
			response['status'] = True
			response['content'] = f.read()
			return Response(response)

		if 'subfinder_config' in req.query_params:
			path = "/root/.config/subfinder/config.yaml"
			if not os.path.exists(path):
				pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
				pathlib.Path(path).touch()
				response['message'] = 'File Created!'
			f = open(path, "r")
			response['status'] = True
			response['content'] = f.read()
			return Response(response)

		if 'naabu_config' in req.query_params:
			path = "/root/.config/naabu/config.yaml"
			if not os.path.exists(path):
				pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
				pathlib.Path(path).touch()
				response['message'] = 'File Created!'
			f = open(path, "r")
			response['status'] = True
			response['content'] = f.read()
			return Response(response)

		if 'theharvester_config' in req.query_params:
			path = "/usr/src/github/theHarvester/api-keys.yaml"
			if not os.path.exists(path):
				pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
				pathlib.Path(path).touch()
				response['message'] = 'File Created!'
			f = open(path, "r")
			response['status'] = True
			response['content'] = f.read()
			return Response(response)

		if 'spiderfoot_config' in req.query_params:
			path = "/usr/src/github/spiderfoot/spiderfoot.cfg"
			if not os.path.exists(path):
				# Create a default config or just touch
				pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
				pathlib.Path(path).touch()
				response['message'] = 'File Created!'
			f = open(path, "r")
			response['status'] = True
			response['content'] = f.read()
			return Response(response)

		if 'amass_config' in req.query_params:
			path = "/root/.config/amass.ini"
			if not os.path.exists(path):
				pathlib.Path(path).parent.mkdir(parents=True, exist_ok=True)
				pathlib.Path(path).touch()
				response['message'] = 'File Created!'
			f = open(path, "r")
			response['status'] = True
			response['content'] = f.read()
			return Response(response)

		if 'gf_pattern' in req.query_params:
			basedir = '/root/.gf'
			path = f'/root/.gf/{name}.json'
			if is_safe_path(basedir, path) and os.path.exists(path):
				content = open(path, "r").read()
				response['status'] = True
				response['content'] = content
			else:
				response['message'] = "Invalid path!"
				response['status'] = False
			return Response(response)


		if 'nuclei_template' in req.query_params:
			safe_dir = '/root/nuclei-templates'
			path = f'/root/nuclei-templates/{name}'
			if is_safe_path(safe_dir, path) and os.path.exists(path):
				content = open(path.format(name), "r").read()
				response['status'] = True
				response['content'] = content
			else:
				response['message'] = 'Invalid Path!'
				response['status'] = False
			return Response(response)

		response['message'] = 'Invalid Query Params'
		return Response(response)


class ListTodoNotes(APIView):
	permission_classes = [IsPenetrationTester]
	def get(self, request, format=None):
		req = self.request
		notes = TodoNote.objects.all().order_by('-id')
		scan_id = req.query_params.get('scan_id')
		project = req.query_params.get('project')
		if project:
			notes = notes.filter(project__slug=project)
		target_id = req.query_params.get('target_id')
		todo_id = req.query_params.get('todo_id')
		subdomain_id = req.query_params.get('subdomain_id')
		if target_id:
			notes = notes.filter(scan_history__in=ScanHistory.objects.filter(domain__id=target_id))
		elif scan_id:
			notes = notes.filter(scan_history__id=scan_id)
		if todo_id:
			notes = notes.filter(id=todo_id)
		if subdomain_id:
			notes = notes.filter(subdomain__id=subdomain_id)
		notes = ReconNoteSerializer(notes, many=True)
		return Response({'notes': notes.data})


class ToggleTodoStatus(APIView):
	permission_classes = [IsPenetrationTester]
	def post(self, request):
		todo_id = request.data.get('id')
		try:
			note = TodoNote.objects.get(id=todo_id)
			note.is_done = not note.is_done
			note.save()
			return Response({'status': True, 'is_done': note.is_done})
		except TodoNote.DoesNotExist:
			return Response({'status': False, 'message': 'Note not found'}, status=404)


class ToggleNoteImportance(APIView):
	permission_classes = [IsPenetrationTester]
	def post(self, request):
		todo_id = request.data.get('id')
		try:
			note = TodoNote.objects.get(id=todo_id)
			note.is_important = not note.is_important
			note.save()
			return Response({'status': True, 'is_important': note.is_important})
		except TodoNote.DoesNotExist:
			return Response({'status': False, 'message': 'Note not found'}, status=404)


class DeleteReconNote(APIView):
	permission_classes = [IsPenetrationTester]
	def post(self, request):
		todo_id = request.data.get('id')
		try:
			TodoNote.objects.filter(id=todo_id).delete()
			return Response({'status': True})
		except Exception as e:
			return Response({'status': False, 'message': str(e)}, status=400)


class ListScanHistory(APIView):
	permission_classes = [IsAuditor]
	def get(self, request, format=None):
		req = self.request
		scan_history = ScanHistory.objects.all().order_by('-start_scan_date')
		project = req.query_params.get('project')
		if project:
			scan_history = scan_history.filter(domain__project__slug=project)
		scan_history = ScanHistorySerializer(scan_history, many=True)
		return Response(scan_history.data)


class ListEngines(APIView):
	permission_classes = [IsAuditor]
	def get(self, request, format=None):
		req = self.request
		engines = EngineType.objects.order_by('engine_name').all()
		engine_serializer = EngineSerializer(engines, many=True)
		return Response({'engines': engine_serializer.data})


class HardwareProfileViewSet(viewsets.ModelViewSet):
	permission_classes = [IsAuditor]
	queryset = HardwareProfile.objects.all().order_by('id')
	serializer_class = HardwareProfileSerializer


class ListOrganizations(APIView):
	permission_classes = [IsAuthenticated, IsAuditor]
	def get(self, request, format=None):
		req = self.request
		organizations = Organization.objects.all()
		organization_serializer = OrganizationSerializer(organizations, many=True)
		return Response({'organizations': organization_serializer.data})


class CreateOrganization(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_MODIFY_TARGETS

	def post(self, request):
		data = request.data
		name = data.get('name')
		description = data.get('description', '')
		domains = data.get('domains', [])
		slug = data.get('slug')

		if not name or not slug:
			return Response({'status': False, 'message': 'Name and project slug are required'}, status=400)

		try:
			project = Project.objects.get(slug=slug)
			organization = Organization.objects.create(
				name=name,
				description=description,
				project=project,
				insert_date=timezone.now()
			)
			for domain_id in domains:
				domain = Domain.objects.get(id=domain_id)
				organization.domains.add(domain)
			return Response({'status': True, 'message': 'Organization created successfully', 'id': organization.id})
		except Exception as e:
			return Response({'status': False, 'message': str(e)}, status=400)


class UpdateOrganization(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_MODIFY_TARGETS

	def post(self, request):
		data = request.data
		org_id = data.get('id')
		name = data.get('name')
		description = data.get('description', '')
		domains = data.get('domains', [])

		if not org_id or not name:
			return Response({'status': False, 'message': 'ID and Name are required'}, status=400)

		try:
			organization = Organization.objects.get(id=org_id)
			organization.name = name
			organization.description = description
			organization.save()
			
			# Update domains
			organization.domains.clear()
			for domain_id in domains:
				domain = Domain.objects.get(id=domain_id)
				organization.domains.add(domain)
				
			return Response({'status': True, 'message': 'Organization updated successfully'})
		except Exception as e:
			return Response({'status': False, 'message': str(e)}, status=400)


class ListWordlists(APIView):
	permission_classes = [IsAuditor]
	def get(self, request, format=None):
		wordlists = Wordlist.objects.all()
		wordlist_serializer = WordlistSerializer(wordlists, many=True)
		return Response({'wordlists': wordlist_serializer.data})


class ListTools(APIView):
	"""
	API view to list all installed external tools in the system.
	Requires IsAuditor permission.
	"""
	permission_classes = [IsAuditor]

	def get(self, request, format=None):
		"""
		Handles GET request to list all installed external tools.

		Args:
			request: Django REST framework request object.
			format: Optional format suffix.

		Returns:
			Response: A REST Framework Response object containing a dict with the list of tools.
		"""
		tools = InstalledExternalTool.objects.all().order_by('id')
		tools_list = []
		for tool in tools:
			tools_list.append({
				'id': tool.id,
				'name': tool.name,
				'description': tool.description,
				'logo_url': tool.logo_url,
				'github_url': tool.github_url,
				'license_url': tool.license_url,
				'is_default': tool.is_default,
				'is_subdomain_gathering': tool.is_subdomain_gathering,
				'is_github_cloned': tool.is_github_cloned,
				'github_clone_path': tool.github_clone_path,
				'install_command': tool.install_command,
				'update_command': tool.update_command,
				'version_lookup_command': tool.version_lookup_command,
			})
		return Response({'tools': tools_list})


class ListConfigurations(APIView):
	permission_classes = [IsAuditor]
	def get(self, request, format=None):
		configurations = Configuration.objects.all()
		configuration_serializer = ConfigurationSerializer(configurations, many=True)
		return Response({'configurations': configuration_serializer.data})


class ListTargetsInOrganization(APIView):
	permission_classes = [IsAuthenticated, HasPermission]
	def get(self, request, format=None):
		req = self.request
		organization_id = req.query_params.get('organization_id')
		organization = Organization.objects.filter(id=organization_id)
		targets = Domain.objects.filter(domains__in=organization)
		organization_serializer = OrganizationSerializer(organization, many=True)
		targets_serializer = OrganizationTargetsSerializer(targets, many=True)
		return Response({'organization': organization_serializer.data, 'domains': targets_serializer.data})


class ListTargetsWithoutOrganization(APIView):
	permission_classes = [IsAuditor]
	def get(self, request, format=None):
		req = self.request
		targets = Domain.objects.exclude(domains__in=Organization.objects.all())
		targets_serializer = OrganizationTargetsSerializer(targets, many=True)
		return Response({'domains': targets_serializer.data})


class VisualiseData(APIView):
	permission_classes = [IsAuditor]
	def get(self, request, format=None):
		req = self.request
		scan_id = req.query_params.get('scan_id')
		target_id = req.query_params.get('target_id')
		if scan_id:
			mitch_data = ScanHistory.objects.filter(id=scan_id)
		elif target_id:
			mitch_data = ScanHistory.objects.filter(domain__id=target_id).order_by('-start_scan_date')[:1]
		else:
			return Response([])

		serializer = VisualiseDataSerializer(mitch_data, many=True)
		return Response(serializer.data)


class ListTechnology(APIView):
	permission_classes = [IsAuditor]
	def get(self, request, format=None):
		req = self.request
		scan_id = req.query_params.get('scan_id')
		target_id = req.query_params.get('target_id')

		if target_id:
			tech = Technology.objects.filter(
				technologies__in=Subdomain.objects.filter(
					target_domain__id=target_id)).annotate(
				count=Count('name')).order_by('-count')
			serializer = TechnologyCountSerializer(tech, many=True)
			return Response({"technologies": serializer.data})
		elif scan_id:
			tech = Technology.objects.filter(
				technologies__in=Subdomain.objects.filter(
					scan_history__id=scan_id)).annotate(
				count=Count('name')).order_by('-count')
			serializer = TechnologyCountSerializer(tech, many=True)
			return Response({"technologies": serializer.data})
		else:
			tech = Technology.objects.filter(
				technologies__in=Subdomain.objects.all()).annotate(
				count=Count('name')).order_by('-count')
			serializer = TechnologyCountSerializer(tech, many=True)
			return Response({"technologies": serializer.data})


class ListDorkTypes(APIView):
	permission_classes = [IsAuditor]
	def get(self, request, format=None):
		req = self.request
		scan_id = req.query_params.get('scan_id')
		if scan_id:
			dork = Dork.objects.filter(
				dorks__in=ScanHistory.objects.filter(id=scan_id)
			).values('type').annotate(count=Count('type')).order_by('-count')
			serializer = DorkCountSerializer(dork, many=True)
			return Response({"dorks": serializer.data})
		else:
			dork = Dork.objects.filter(
				dorks__in=ScanHistory.objects.all()
			).values('type').annotate(count=Count('type')).order_by('-count')
			serializer = DorkCountSerializer(dork, many=True)
			return Response({"dorks": serializer.data})


class ListEmails(APIView):
	permission_classes = [IsAuditor]
	def get(self, request, format=None):
		req = self.request
		scan_id = req.query_params.get('scan_id')
		if scan_id:
			email = Email.objects.filter(
				emails__in=ScanHistory.objects.filter(id=scan_id)).order_by('password')
			serializer = EmailSerializer(email, many=True)
			return Response({"emails": serializer.data})


class ListDorks(APIView):
	permission_classes = [IsAuditor]
	def get(self, request, format=None):
		req = self.request
		scan_id = req.query_params.get('scan_id')
		type = req.query_params.get('type')
		if scan_id:
			dork = Dork.objects.filter(
				dorks__in=ScanHistory.objects.filter(id=scan_id))
		else:
			dork = Dork.objects.filter(
				dorks__in=ScanHistory.objects.all())
		if scan_id and type:
			dork = dork.filter(type=type)
		serializer = DorkSerializer(dork, many=True)
		grouped_res = {}
		for item in serializer.data:
			item_type = item['type']
			if item_type not in grouped_res:
				grouped_res[item_type] = []
			grouped_res[item_type].append(item)
		return Response({"dorks": grouped_res})


class ListEmployees(APIView):
	permission_classes = [IsAuditor]
	def get(self, request, format=None):
		req = self.request
		scan_id = req.query_params.get('scan_id')
		if scan_id:
			employee = Employee.objects.filter(
				employees__in=ScanHistory.objects.filter(id=scan_id))
			serializer = EmployeeSerializer(employee, many=True)
			return Response({"employees": serializer.data})


class ListPorts(APIView):
	permission_classes = [IsAuditor]
	def get(self, request, format=None):
		req = self.request
		scan_id = req.query_params.get('scan_id')
		target_id = req.query_params.get('target_id')
		ip_address = req.query_params.get('ip_address')

		if target_id:
			port = Port.objects.filter(
				ports__in=IpAddress.objects.filter(
					ip_addresses__in=Subdomain.objects.filter(
						target_domain__id=target_id))).distinct()
		elif scan_id:
			port = Port.objects.filter(
				ports__in=IpAddress.objects.filter(
					ip_addresses__in=Subdomain.objects.filter(
						scan_history__id=scan_id))).distinct()
		else:
			port = Port.objects.filter(
				ports__in=IpAddress.objects.filter(
					ip_addresses__in=Subdomain.objects.all())).distinct()

		if ip_address:
			port = port.filter(ports__address=ip_address).distinct()

		serializer = PortSerializer(port, many=True)
		return Response({"ports": serializer.data})


class ListSubdomains(APIView):
	permission_classes = [IsAuditor]
	def get(self, request, format=None):
		req = self.request
		scan_id = req.query_params.get('scan_id')
		project = req.query_params.get('project')
		target_id = req.query_params.get('target_id')
		ip_address = req.query_params.get('ip_address')
		port = req.query_params.get('port')
		tech = req.query_params.get('tech')

		subdomains = Subdomain.objects.all()
		if project:
			subdomains = subdomains.filter(target_domain__project__slug=project)

		if scan_id:
			subdomain_query = subdomains.filter(scan_history__id=scan_id).distinct('name')
		elif target_id:
			subdomain_query = subdomains.filter(target_domain__id=target_id).distinct('name')
		else:
			subdomain_query = subdomains.all().distinct('name')

		# Prefetch for performance
		subdomain_query = subdomain_query.prefetch_related(
			'screenshots', 'technologies', 'ip_addresses', 'ip_addresses__ports'
		)

		if ip_address:
			subdomain_query = subdomain_query.filter(ip_addresses__address=ip_address)

		if tech:
			subdomain_query = subdomain_query.filter(technologies__name=tech)

		if port:
			subdomain_query = subdomain_query.filter(
				ip_addresses__in=IpAddress.objects.filter(
					ports__in=Port.objects.filter(
						number=port)))

		if 'only_important' in req.query_params:
			subdomain_query = subdomain_query.filter(is_important=True)

		if 'no_lookup_interesting' in req.query_params:
			serializer = OnlySubdomainNameSerializer(subdomain_query, many=True)
		else:
			serializer = SubdomainSerializer(subdomain_query, many=True)
		return Response({"subdomains": serializer.data})

	def post(self, req):
		req = self.request
		data = req.data

		subdomain_ids = data.get('subdomain_ids')

		subdomain_names = []

		for id in subdomain_ids:
			subdomain_names.append(Subdomain.objects.get(id=id).name)

		if subdomain_names:
			return Response({'status': True, "results": subdomain_names})

		return Response({'status': False})



class ListOsintUsers(APIView):
	permission_classes = [IsAuditor]
	def get(self, request, format=None):
		req = self.request
		scan_id = req.query_params.get('scan_id')
		if scan_id:
			documents = MetaFinderDocument.objects.filter(scan_history__id=scan_id).exclude(author__isnull=True).values('author').distinct()
			serializer = MetafinderUserSerializer(documents, many=True)
			return Response({"users": serializer.data})


class ListMetadata(APIView):
	permission_classes = [IsAuditor]
	def get(self, request, format=None):
		req = self.request
		scan_id = req.query_params.get('scan_id')
		if scan_id:
			documents = MetaFinderDocument.objects.filter(scan_history__id=scan_id).distinct()
			serializer = MetafinderDocumentSerializer(documents, many=True)
			return Response({"metadata": serializer.data})


class ListIPs(APIView):
	permission_classes = [IsAuditor]
	def get(self, request, format=None):
		req = self.request
		scan_id = req.query_params.get('scan_id')
		target_id = req.query_params.get('target_id')

		port = req.query_params.get('port')

		if target_id:
			ips = IpAddress.objects.filter(
				ip_addresses__in=Subdomain.objects.filter(
					target_domain__id=target_id)).distinct()
		elif scan_id:
			ips = IpAddress.objects.filter(
				ip_addresses__in=Subdomain.objects.filter(
					scan_history__id=scan_id)).distinct()
		else:
			ips = IpAddress.objects.filter(
				ip_addresses__in=Subdomain.objects.all()).distinct()

		if port:
			ips = ips.filter(
				ports__in=Port.objects.filter(
					number=port)).distinct()


		serializer = IpSerializer(ips, many=True)
		return Response({"ips": serializer.data})


class IpAddressViewSet(viewsets.ModelViewSet):
	permission_classes = [IsPenetrationTester]
	queryset = Subdomain.objects.none()
	serializer_class = IpSubdomainSerializer

	def get_queryset(self):
		req = self.request
		scan_id = req.query_params.get('scan_id')

		if scan_id:
			self.queryset = Subdomain.objects.filter(
				scan_history__id=scan_id).exclude(
				ip_addresses__isnull=True).distinct()
		else:
			self.serializer_class = IpSerializer
			self.queryset = IpAddress.objects.all()
		return self.queryset

	def paginate_queryset(self, queryset, view=None):
		if 'no_page' in self.request.query_params:
			return None
		return self.paginator.paginate_queryset(
			queryset, self.request, view=self)


class SubdomainsViewSet(viewsets.ModelViewSet):
	permission_classes = [IsPenetrationTester]
	queryset = Subdomain.objects.none()
	serializer_class = SubdomainSerializer

	def get_queryset(self):
		req = self.request
		scan_id = req.query_params.get('scan_id')
		if scan_id:
			queryset = Subdomain.objects.filter(scan_history__id=scan_id).prefetch_related(
				'screenshots', 'technologies', 'ip_addresses', 'ip_addresses__ports'
			)
			if 'only_screenshot' in self.request.query_params:
				return queryset.filter(
					Q(screenshot_path__isnull=False) | Q(screenshots__isnull=False)
				).distinct()
			return queryset

	def paginate_queryset(self, queryset, view=None):
		if 'no_page' in self.request.query_params:
			return None
		return self.paginator.paginate_queryset(
			queryset, self.request, view=self)


class SubdomainChangesViewSet(viewsets.ModelViewSet):
	permission_classes = [IsPenetrationTester]
	'''
		This viewset will return the Subdomain changes
		To get the new subdomains, we will look for ScanHistory with
		subdomain_discovery = True and the status of the last scan has to be
		successful and calculate difference
	'''
	queryset = Subdomain.objects.none()
	serializer_class = SubdomainChangesSerializer

	def get_queryset(self):
		req = self.request
		scan_id = req.query_params.get('scan_id')
		changes = req.query_params.get('changes')
		domain_id = ScanHistory.objects.filter(id=scan_id)[0].domain.id
		scan_history_query = (
			ScanHistory.objects
			.filter(domain=domain_id)
			.filter(tasks__overlap=['subdomain_discovery'])
			.filter(id__lte=scan_id)
			.exclude(Q(scan_status=-1) | Q(scan_status=1))
		)
		if scan_history_query.count() > 1:
			last_scan = scan_history_query.order_by('-start_scan_date')[1]
			scanned_host_q1 = (
				Subdomain.objects
				.filter(scan_history__id=scan_id)
				.values('name')
			)
			scanned_host_q2 = (
				Subdomain.objects
				.filter(scan_history__id=last_scan.id)
				.values('name')
			)
			added_subdomain = scanned_host_q1.difference(scanned_host_q2)
			removed_subdomains = scanned_host_q2.difference(scanned_host_q1)
			if changes == 'added':
				return (
					Subdomain.objects
					.filter(scan_history=scan_id)
					.filter(name__in=added_subdomain)
					.annotate(
						change=Value('added', output_field=CharField())
					)
				)
			elif changes == 'removed':
				return (
					Subdomain.objects
					.filter(scan_history=last_scan)
					.filter(name__in=removed_subdomains)
					.annotate(
						change=Value('removed', output_field=CharField())
					)
				)
			else:
				added_subdomain = (
					Subdomain.objects
					.filter(scan_history=scan_id)
					.filter(name__in=added_subdomain)
					.annotate(
						change=Value('added', output_field=CharField())
					)
				)
				removed_subdomains = (
					Subdomain.objects
					.filter(scan_history=last_scan)
					.filter(name__in=removed_subdomains)
					.annotate(
						change=Value('removed', output_field=CharField())
					)
				)
				changes = added_subdomain.union(removed_subdomains)
				return changes
		return self.queryset

	def paginate_queryset(self, queryset, view=None):
		if 'no_page' in self.request.query_params:
			return None
		return self.paginator.paginate_queryset(
			queryset, self.request, view=self)


class EndPointChangesViewSet(viewsets.ModelViewSet):
	permission_classes = [IsPenetrationTester]
	'''
		This viewset will return the EndPoint changes
	'''
	queryset = EndPoint.objects.none()
	serializer_class = EndPointChangesSerializer

	def get_queryset(self):
		req = self.request
		scan_id = req.query_params.get('scan_id')
		changes = req.query_params.get('changes')
		domain_id = ScanHistory.objects.filter(id=scan_id).first().domain.id
		scan_history = (
			ScanHistory.objects
			.filter(domain=domain_id)
			.filter(tasks__overlap=['fetch_url'])
			.filter(id__lte=scan_id)
			.filter(scan_status=2)
		)
		if scan_history.count() > 1:
			last_scan = scan_history.order_by('-start_scan_date')[1]
			scanned_host_q1 = (
				EndPoint.objects
				.filter(scan_history__id=scan_id)
				.values('http_url')
			)
			scanned_host_q2 = (
				EndPoint.objects
				.filter(scan_history__id=last_scan.id)
				.values('http_url')
			)
			added_endpoints = scanned_host_q1.difference(scanned_host_q2)
			removed_endpoints = scanned_host_q2.difference(scanned_host_q1)
			if changes == 'added':
				return (
					EndPoint.objects
					.filter(scan_history=scan_id)
					.filter(http_url__in=added_endpoints)
					.annotate(change=Value('added', output_field=CharField()))
				)
			elif changes == 'removed':
				return (
					EndPoint.objects
					.filter(scan_history=last_scan)
					.filter(http_url__in=removed_endpoints)
					.annotate(change=Value('removed', output_field=CharField()))
				)
			else:
				added_endpoints = (
					EndPoint.objects
					.filter(scan_history=scan_id)
					.filter(http_url__in=added_endpoints)
					.annotate(change=Value('added', output_field=CharField()))
				)
				removed_endpoints = (
					EndPoint.objects
					.filter(scan_history=last_scan)
					.filter(http_url__in=removed_endpoints)
					.annotate(change=Value('removed', output_field=CharField()))
				)
				changes = added_endpoints.union(removed_endpoints)
				return changes
		return self.queryset

	def paginate_queryset(self, queryset, view=None):
		if 'no_page' in self.request.query_params:
			return None
		return self.paginator.paginate_queryset(
			queryset, self.request, view=self)


class InterestingSubdomainViewSet(viewsets.ModelViewSet):
	permission_classes = [IsPenetrationTester]
	queryset = Subdomain.objects.none()
	serializer_class = SubdomainSerializer

	def get_queryset(self):
		req = self.request
		scan_id = req.query_params.get('scan_id')
		domain_id = req.query_params.get('target_id')

		if 'only_subdomains' in self.request.query_params:
			self.serializer_class = InterestingSubdomainSerializer

		if scan_id:
			self.queryset = get_interesting_subdomains(scan_history=scan_id)
		elif domain_id:
			self.queryset = get_interesting_subdomains(domain_id=domain_id)
		else:
			self.queryset = get_interesting_subdomains()

		return self.queryset

	def filter_queryset(self, qs):
		qs = self.queryset.filter()
		search_value = self.request.GET.get(u'search[value]', None)
		_order_col = self.request.GET.get(u'order[0][column]', None)
		_order_direction = self.request.GET.get(u'order[0][dir]', None)
		order_col = 'content_length'
		if _order_col == '0':
			order_col = 'name'
		elif _order_col == '1':
			order_col = 'page_title'
		elif _order_col == '2':
			order_col = 'http_status'
		elif _order_col == '3':
			order_col = 'content_length'

		if _order_direction == 'desc':
			order_col = f'-{order_col}'

		if search_value:
			qs = self.queryset.filter(
				Q(name__icontains=search_value) |
				Q(page_title__icontains=search_value) |
				Q(http_status__icontains=search_value)
			)
		return qs.order_by(order_col)

	def paginate_queryset(self, queryset, view=None):
		if 'no_page' in self.request.query_params:
			return None
		return self.paginator.paginate_queryset(
			queryset, self.request, view=self)


class InterestingEndpointViewSet(viewsets.ModelViewSet):
	permission_classes = [IsPenetrationTester]
	queryset = EndPoint.objects.none()
	serializer_class = EndpointSerializer

	def get_queryset(self):
		req = self.request
		scan_id = req.query_params.get('scan_id')
		target_id = req.query_params.get('target_id')
		if 'only_endpoints' in self.request.query_params:
			self.serializer_class = InterestingEndPointSerializer
		if scan_id:
			return get_interesting_endpoints(scan_history=scan_id)
		elif target_id:
			return get_interesting_endpoints(target=target_id)
		else:
			return get_interesting_endpoints()

	def paginate_queryset(self, queryset, view=None):
		if 'no_page' in self.request.query_params:
			return None
		return self.paginator.paginate_queryset(
			queryset, self.request, view=self)


class SubdomainDatatableViewSet(viewsets.ModelViewSet):
	permission_classes = [IsPenetrationTester]
	queryset = Subdomain.objects.none()
	serializer_class = SubdomainSerializer

	def _latest_subdomain_rows_by_name(self, queryset):
		latest_ids = (
			queryset
			.annotate(norm_name=Lower('name'))
			.values('norm_name')
			.annotate(latest_id=Max('id'))
			.values_list('latest_id', flat=True)
		)
		return Subdomain.objects.filter(id__in=latest_ids)

	def get_queryset(self):
		req = self.request
		scan_id = req.query_params.get('scan_id')
		target_id = req.query_params.get('target_id')
		url_query = req.query_params.get('query_param')
		ip_address = req.query_params.get('ip_address')
		name = req.query_params.get('name')
		project = req.query_params.get('project')
		http_status = req.query_params.get('http_status')
		is_important = req.query_params.get('is_important')
		has_vulnerabilities = req.query_params.get('has_vulnerabilities')
		ports = req.query_params.get('ports')
		has_ip = req.query_params.get('has_ip')

		subdomains = Subdomain.objects.filter(target_domain__project__slug=project)

		if is_important is not None:
			if is_important.lower() in ('true', '1', 't', 'y', 'yes'):
				subdomains = subdomains.filter(is_important=True)
			elif is_important.lower() in ('false', '0', 'f', 'n', 'no'):
				subdomains = subdomains.filter(is_important=False)
		elif 'is_important' in req.query_params and not req.query_params.get('is_important'):
			# Fallback for old behaviour if just `?is_important` was passed empty
			subdomains = subdomains.filter(is_important=True)

		if target_id:
			self.queryset = (
				self._latest_subdomain_rows_by_name(
					subdomains.filter(target_domain__id=target_id)
				)
			)
		elif url_query:
			self.queryset = (
				subdomains
				.filter(Q(target_domain__name=url_query))
				.distinct()
			)
		elif scan_id:
			self.queryset = (
				subdomains
				.filter(scan_history__id=scan_id)
				.distinct()
			)
		else:
			self.queryset = subdomains.distinct()

		if 'only_directory' in req.query_params and str(req.query_params.get('only_directory')).lower() != 'false':
			self.queryset = self.queryset.exclude(directories__isnull=True)

		if ip_address:
			self.queryset = self.queryset.filter(ip_addresses__address__icontains=ip_address)

		if name:
			self.queryset = self.queryset.filter(name=name)

		if http_status:
			try:
				self.queryset = self.queryset.filter(http_status=int(http_status))
			except ValueError:
				pass

		if has_vulnerabilities is not None:
			if has_vulnerabilities.lower() in ('true', '1', 't', 'y', 'yes'):
				self.queryset = self.queryset.filter(vulnerability__isnull=False).distinct()
			elif has_vulnerabilities.lower() in ('false', '0', 'f', 'n', 'no'):
				self.queryset = self.queryset.filter(vulnerability__isnull=True).distinct()

		if ports:
			port_list = [p.strip() for p in ports.split(',') if p.strip()]
			if port_list:
				self.queryset = self.queryset.filter(ip_addresses__ports__number__in=port_list).distinct()

		if has_ip is not None:
			if has_ip.lower() in ('true', '1', 't', 'y', 'yes'):
				self.queryset = self.queryset.filter(ip_addresses__isnull=False).distinct()
			elif has_ip.lower() in ('false', '0', 'f', 'n', 'no'):
				self.queryset = self.queryset.filter(ip_addresses__isnull=True).distinct()

		self.queryset = (
			self.queryset
			.select_related('scan_history', 'target_domain')
			.prefetch_related(
				'ip_addresses',
				'ip_addresses__ports',
				'waf',
				'technologies',
				'directories',
				'waf_bypass_findings',
				'screenshots'
			)
		)
		return self.queryset

	def filter_queryset(self, qs):
		qs = self.queryset.filter()
		search_value = self.request.GET.get(u'search[value]', None)
		_order_col = self.request.GET.get(u'order[0][column]', None)
		_order_direction = self.request.GET.get(u'order[0][dir]', None)
		order_col = 'content_length'
		if _order_col == '0':
			order_col = 'checked'
		elif _order_col == '1':
			order_col = 'name'
		elif _order_col == '4':
			order_col = 'http_status'
		elif _order_col == '5':
			order_col = 'page_title'
		elif _order_col == '8':
			order_col = 'content_length'
		elif _order_col == '10':
			order_col = 'response_time'
		if _order_direction == 'desc':
			order_col = f'-{order_col}'
		# if the search query is separated by = means, it is a specific lookup
		# divide the search query into two half and lookup
		if search_value:
			operators = ['=', '&', '|', '>', '<', '!']
			if any(x in search_value for x in operators):
				if '&' in search_value:
					complex_query = search_value.split('&')
					for query in complex_query:
						if query.strip():
							qs = qs & self.special_lookup(query.strip())
				elif '|' in search_value:
					qs = Subdomain.objects.none()
					complex_query = search_value.split('|')
					for query in complex_query:
						if query.strip():
							qs = self.special_lookup(query.strip()) | qs
				else:
					qs = self.special_lookup(search_value)
			else:
				qs = self.general_lookup(search_value)
		return qs.order_by(order_col)

	def general_lookup(self, search_value):
		qs = self.queryset.filter(
			Q(name__icontains=search_value) |
			Q(cname__icontains=search_value) |
			Q(http_status__icontains=search_value) |
			Q(page_title__icontains=search_value) |
			Q(http_url__icontains=search_value) |
			Q(technologies__name__icontains=search_value) |
			Q(webserver__icontains=search_value) |
			Q(ip_addresses__address__icontains=search_value) |
			Q(ip_addresses__ports__number__icontains=search_value) |
			Q(ip_addresses__ports__service_name__icontains=search_value) |
			Q(ip_addresses__ports__description__icontains=search_value)
		)

		if 'only_directory' in self.request.query_params:
			qs = qs | self.queryset.filter(
				Q(directories__directory_files__name__icontains=search_value)
			)

		return qs

	def special_lookup(self, search_value):
		qs = self.queryset.filter()
		if '=' in search_value:
			search_param = search_value.split("=")
			title = search_param[0].lower().strip()
			content = search_param[1].lower().strip()
			if 'name' in title:
				qs = self.queryset.filter(name__icontains=content)
			elif 'page_title' in title:
				qs = self.queryset.filter(page_title__icontains=content)
			elif 'http_url' in title:
				qs = self.queryset.filter(http_url__icontains=content)
			elif 'content_type' in title:
				qs = self.queryset.filter(content_type__icontains=content)
			elif 'cname' in title:
				qs = self.queryset.filter(cname__icontains=content)
			elif 'webserver' in title:
				qs = self.queryset.filter(webserver__icontains=content)
			elif 'ip_addresses' in title:
				qs = self.queryset.filter(
					ip_addresses__address__icontains=content)
			elif 'is_important' in title:
				if 'true' in content.lower():
					qs = self.queryset.filter(is_important=True)
				else:
					qs = self.queryset.filter(is_important=False)
			elif 'port' in title:
				qs = (
					self.queryset
					.filter(ip_addresses__ports__number__icontains=content)
					|
					self.queryset
					.filter(ip_addresses__ports__service_name__icontains=content)
					|
					self.queryset
					.filter(ip_addresses__ports__description__icontains=content)
				)
			elif 'technology' in title:
				qs = (
					self.queryset
					.filter(technologies__name__icontains=content)
				)
			elif 'http_status' in title:
				try:
					int_http_status = int(content)
					qs = self.queryset.filter(http_status=int_http_status)
				except Exception as e:
					logger.exception("Unexpected error: %s", e)
			elif 'content_length' in title:
				try:
					int_http_status = int(content)
					qs = self.queryset.filter(content_length=int_http_status)
				except Exception as e:
					logger.exception("Unexpected error: %s", e)

		elif '>' in search_value:
			search_param = search_value.split(">")
			title = search_param[0].lower().strip()
			content = search_param[1].lower().strip()
			if 'http_status' in title:
				try:
					int_val = int(content)
					qs = self.queryset.filter(http_status__gt=int_val)
				except Exception as e:
					logger.exception("Unexpected error: %s", e)
			elif 'content_length' in title:
				try:
					int_val = int(content)
					qs = self.queryset.filter(content_length__gt=int_val)
				except Exception as e:
					logger.exception("Unexpected error: %s", e)

		elif '<' in search_value:
			search_param = search_value.split("<")
			title = search_param[0].lower().strip()
			content = search_param[1].lower().strip()
			if 'http_status' in title:
				try:
					int_val = int(content)
					qs = self.queryset.filter(http_status__lt=int_val)
				except Exception as e:
					logger.exception("Unexpected error: %s", e)
			elif 'content_length' in title:
				try:
					int_val = int(content)
					qs = self.queryset.filter(content_length__lt=int_val)
				except Exception as e:
					logger.exception("Unexpected error: %s", e)

		elif '!' in search_value:
			search_param = search_value.split("!")
			title = search_param[0].lower().strip()
			content = search_param[1].lower().strip()
			if 'name' in title:
				qs = self.queryset.exclude(name__icontains=content)
			elif 'page_title' in title:
				qs = self.queryset.exclude(page_title__icontains=content)
			elif 'http_url' in title:
				qs = self.queryset.exclude(http_url__icontains=content)
			elif 'content_type' in title:
				qs = (
					self.queryset
					.exclude(content_type__icontains=content)
				)
			elif 'cname' in title:
				qs = self.queryset.exclude(cname__icontains=content)
			elif 'webserver' in title:
				qs = self.queryset.exclude(webserver__icontains=content)
			elif 'ip_addresses' in title:
				qs = self.queryset.exclude(
					ip_addresses__address__icontains=content)
			elif 'port' in title:
				qs = (
					self.queryset
					.exclude(ip_addresses__ports__number__icontains=content)
					|
					self.queryset
					.exclude(ip_addresses__ports__service_name__icontains=content)
					|
					self.queryset
					.exclude(ip_addresses__ports__description__icontains=content)
				)
			elif 'technology' in title:
				qs = (
					self.queryset
					.exclude(technologies__name__icontains=content)
				)
			elif 'http_status' in title:
				try:
					int_http_status = int(content)
					qs = self.queryset.exclude(http_status=int_http_status)
				except Exception as e:
					logger.exception("Unexpected error: %s", e)
			elif 'content_length' in title:
				try:
					int_http_status = int(content)
					qs = self.queryset.exclude(content_length=int_http_status)
				except Exception as e:
					logger.exception("Unexpected error: %s", e)

		return qs


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


class ListEndpoints(APIView):
	permission_classes = [IsAuditor]
	def get(self, request, format=None):
		req = self.request

		scan_id = req.query_params.get('scan_id')
		target_id = req.query_params.get('target_id')
		subdomain_name = req.query_params.get('subdomain_name')
		pattern = req.query_params.get('pattern')

		if scan_id:
			endpoints = (
				EndPoint.objects
				.filter(scan_history__id=scan_id)
			)
		elif target_id:
			endpoints = (
				EndPoint.objects
				.filter(target_domain__id=target_id)
				.distinct()
			)
		else:
			endpoints = EndPoint.objects.all()

		if subdomain_name:
			endpoints = endpoints.filter(subdomain__name=subdomain_name)

		if pattern:
			endpoints = endpoints.filter(matched_gf_patterns__icontains=pattern)

		if 'only_urls' in req.query_params:
			endpoints_serializer = EndpointOnlyURLsSerializer(endpoints, many=True)

		else:
			endpoints_serializer = EndpointSerializer(endpoints, many=True)

		return Response({'endpoints': endpoints_serializer.data})


class EndpointPagination(PageNumberPagination):
	page_size = 25
	page_size_query_param = 'length'
	max_page_size = 200


class EndPointViewSet(viewsets.ModelViewSet):
	permission_classes = [IsPenetrationTester]
	pagination_class = EndpointPagination
	queryset = EndPoint.objects.none()
	serializer_class = EndpointSerializer

	def get_queryset(self):
		req = self.request

		scan_id = req.query_params.get('scan_history')
		target_id = req.query_params.get('target_id')
		url_query = req.query_params.get('query_param')
		subdomain_id = req.query_params.get('subdomain_id')
		project = req.query_params.get('project')

		endpoints_obj = EndPoint.objects.filter(scan_history__domain__project__slug=project)

		gf_tag = req.query_params.get(
			'gf_tag') if 'gf_tag' in req.query_params else None

		if scan_id:
			endpoints = (
				endpoints_obj
				.filter(scan_history__id=scan_id)
				.distinct()
			)
		else:
			endpoints = endpoints_obj.distinct()

		if url_query:
			endpoints = (
				endpoints
				.filter(Q(target_domain__name=url_query))
				.distinct()
			)

		if gf_tag:
			endpoints = endpoints.filter(matched_gf_patterns__icontains=gf_tag)

		if target_id:
			endpoints = endpoints.filter(target_domain__id=target_id)

		if subdomain_id:
			endpoints = endpoints.filter(subdomain__id=subdomain_id)

		http_status = req.query_params.get('http_status')
		if http_status:
			try:
				endpoints = endpoints.filter(http_status=int(http_status))
			except ValueError:
				pass

		if 'only_urls' in req.query_params:
			self.serializer_class = EndpointOnlyURLsSerializer

		# Filter status code 404 and 0
		# endpoints = (
		# 	endpoints
		# 	.exclude(http_status=0)
		# 	.exclude(http_status=None)
		# 	.exclude(http_status=404)
		# )

		self.queryset = endpoints

		return self.queryset

	def filter_queryset(self, qs):
		qs = self.queryset.filter()
		search_value = self.request.GET.get(u'search[value]', None)
		_order_col = self.request.GET.get(u'order[0][column]', None)
		_order_direction = self.request.GET.get(u'order[0][dir]', None)
		if search_value or _order_col or _order_direction:
			order_col = 'content_length'
			if _order_col == '1':
				order_col = 'http_url'
			elif _order_col == '2':
				order_col = 'http_status'
			elif _order_col == '3':
				order_col = 'page_title'
			elif _order_col == '4':
				order_col = 'matched_gf_patterns'
			elif _order_col == '5':
				order_col = 'content_type'
			elif _order_col == '6':
				order_col = 'content_length'
			elif _order_col == '7':
				order_col = 'techs'
			elif _order_col == '8':
				order_col = 'webserver'
			elif _order_col == '9':
				order_col = 'response_time'
			if _order_direction == 'desc':
				order_col = f'-{order_col}'
			# if the search query is separated by = means, it is a specific lookup
			# divide the search query into two half and lookup
			if '=' in search_value or '&' in search_value or '|' in search_value or '>' in search_value or '<' in search_value or '!' in search_value:
				if '&' in search_value:
					complex_query = search_value.split('&')
					for query in complex_query:
						if query.strip():
							qs = qs & self.special_lookup(query.strip())
				elif '|' in search_value:
					qs = Subdomain.objects.none()
					complex_query = search_value.split('|')
					for query in complex_query:
						if query.strip():
							qs = self.special_lookup(query.strip()) | qs
				else:
					qs = self.special_lookup(search_value)
			else:
				qs = self.general_lookup(search_value)
			return qs.order_by(order_col)
		return qs

	def general_lookup(self, search_value):
		return \
			self.queryset.filter(Q(http_url__icontains=search_value) |
								 Q(page_title__icontains=search_value) |
								 Q(http_status__icontains=search_value) |
								 Q(content_type__icontains=search_value) |
								 Q(webserver__icontains=search_value) |
								 Q(techs__name__icontains=search_value) |
								 Q(content_type__icontains=search_value) |
								 Q(parameters__name__icontains=search_value) |
								 Q(matched_gf_patterns__icontains=search_value))

	def special_lookup(self, search_value):
		qs = self.queryset.filter()
		if '=' in search_value:
			search_param = search_value.split("=")
			lookup_title = search_param[0].lower().strip()
			lookup_content = search_param[1].lower().strip()
			if 'http_url' in lookup_title:
				qs = self.queryset.filter(http_url__icontains=lookup_content)
			elif 'page_title' in lookup_title:
				qs = (
					self.queryset
					.filter(page_title__icontains=lookup_content)
				)
			elif 'content_type' in lookup_title:
				qs = (
					self.queryset
					.filter(content_type__icontains=lookup_content)
				)
			elif 'webserver' in lookup_title:
				qs = self.queryset.filter(webserver__icontains=lookup_content)
			elif 'technology' in lookup_title:
				qs = (
					self.queryset
					.filter(techs__name__icontains=lookup_content)
				)
			elif 'gf_pattern' in lookup_title:
				qs = (
					self.queryset
					.filter(matched_gf_patterns__icontains=lookup_content)
				)
			elif 'http_status' in lookup_title:
				try:
					int_http_status = int(lookup_content)
					qs = self.queryset.filter(http_status=int_http_status)
				except Exception as e:
					logger.exception("Unexpected error: %s", e)
			elif 'content_length' in lookup_title:
				try:
					int_http_status = int(lookup_content)
					qs = self.queryset.filter(content_length=int_http_status)
				except Exception as e:
					logger.exception("Unexpected error: %s", e)
			elif 'parameter' in lookup_title:
				qs = (
					self.queryset
					.filter(parameters__name__icontains=lookup_content)
				)
		elif '>' in search_value:
			search_param = search_value.split(">")
			lookup_title = search_param[0].lower().strip()
			lookup_content = search_param[1].lower().strip()
			if 'http_status' in lookup_title:
				try:
					int_val = int(lookup_content)
					qs = (
						self.queryset
						.filter(http_status__gt=int_val)
					)
				except Exception as e:
					logger.exception("Unexpected error: %s", e)
			elif 'content_length' in lookup_title:
				try:
					int_val = int(lookup_content)
					qs = self.queryset.filter(content_length__gt=int_val)
				except Exception as e:
					logger.exception("Unexpected error: %s", e)
		elif '<' in search_value:
			search_param = search_value.split("<")
			lookup_title = search_param[0].lower().strip()
			lookup_content = search_param[1].lower().strip()
			if 'http_status' in lookup_title:
				try:
					int_val = int(lookup_content)
					qs = self.queryset.filter(http_status__lt=int_val)
				except Exception as e:
					logger.exception("Unexpected error: %s", e)
			elif 'content_length' in lookup_title:
				try:
					int_val = int(lookup_content)
					qs = self.queryset.filter(content_length__lt=int_val)
				except Exception as e:
					logger.exception("Unexpected error: %s", e)
		elif '!' in search_value:
			search_param = search_value.split("!")
			lookup_title = search_param[0].lower().strip()
			lookup_content = search_param[1].lower().strip()
			if 'http_url' in lookup_title:
				qs = (
					self.queryset
					.exclude(http_url__icontains=lookup_content)
				)
			elif 'page_title' in lookup_title:
				qs = (
					self.queryset
					.exclude(page_title__icontains=lookup_content)
				)
			elif 'content_type' in lookup_title:
				qs = (
					self.queryset
					.exclude(content_type__icontains=lookup_content)
				)
			elif 'webserver' in lookup_title:
				qs = (
					self.queryset
					.exclude(webserver__icontains=lookup_content)
				)
			elif 'technology' in lookup_title:
				qs = (
					self.queryset
					.exclude(techs__name__icontains=lookup_content)
				)
			elif 'gf_pattern' in lookup_title:
				qs = (
					self.queryset
					.exclude(matched_gf_patterns__icontains=lookup_content)
				)
			elif 'http_status' in lookup_title:
				try:
					int_http_status = int(lookup_content)
					qs = self.queryset.exclude(http_status=int_http_status)
				except Exception as e:
					logger.exception("Unexpected error: %s", e)
			elif 'content_length' in lookup_title:
				try:
					int_http_status = int(lookup_content)
					qs = self.queryset.exclude(content_length=int_http_status)
				except Exception as e:
					logger.exception("Unexpected error: %s", e)
		return qs

class ParameterViewSet(viewsets.ModelViewSet):
	permission_classes = [IsPenetrationTester]
	queryset = Parameter.objects.none()
	serializer_class = ParameterSerializer

	def get_queryset(self):
		req = self.request
		scan_id = req.query_params.get('scan_history')
		target_id = req.query_params.get('target_id')
		endpoint_id = req.query_params.get('endpoint_id')

		if scan_id:
			queryset = Parameter.objects.filter(endpoint__scan_history__id=scan_id)
		elif target_id:
			queryset = Parameter.objects.filter(endpoint__target_domain__id=target_id)
		else:
			queryset = Parameter.objects.all()

		if endpoint_id:
			queryset = queryset.filter(endpoint__id=endpoint_id)

		# CPDE intelligence filters
		if req.query_params.get('param_location'):
			queryset = queryset.filter(param_location=req.query_params['param_location'])
		is_auth = req.query_params.get('is_auth_related', '').lower()
		if is_auth == 'true':
			queryset = queryset.filter(is_auth_related=True)
		elif is_auth == 'false':
			queryset = queryset.filter(is_auth_related=False)
		if req.query_params.get('observed_in_js', '').lower() == 'true':
			queryset = queryset.filter(observed_in_js=True)
		if req.query_params.get('observed_in_openapi', '').lower() == 'true':
			queryset = queryset.filter(observed_in_openapi=True)
		if req.query_params.get('observed_in_graphql', '').lower() == 'true':
			queryset = queryset.filter(observed_in_graphql=True)
		confidence_min = req.query_params.get('confidence_min')
		if confidence_min is not None:
			try:
				queryset = queryset.filter(confidence__gte=int(confidence_min))
			except (ValueError, TypeError):
				pass
		if req.query_params.get('data_type'):
			queryset = queryset.filter(data_type=req.query_params['data_type'])

		return queryset.distinct()

