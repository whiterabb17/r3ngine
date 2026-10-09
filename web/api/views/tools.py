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
from rest_framework.authentication import SessionAuthentication
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
from reNgine.definitions import INTERNAL_ERROR_MESSAGE

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
		except Exception:
			logger.exception('%s failed', type(self).__name__)
			return Response({
				'status': False,
				'message': INTERNAL_ERROR_MESSAGE
			}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


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
		except Exception:
			logger.exception('%s failed', type(self).__name__)
			return Response({
				'status': False,
				'message': INTERNAL_ERROR_MESSAGE
			}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


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
		except Exception:
			logger.exception('%s failed', type(self).__name__)
			return Response({
				'status': False,
				'message': INTERNAL_ERROR_MESSAGE
			}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


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
		except Exception:
			logger.exception('%s failed', type(self).__name__)
			return Response({
				'status': False,
				'message': INTERNAL_ERROR_MESSAGE
			}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


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
		except Exception:
			logger.exception('%s failed', type(self).__name__)
			return Response({
				'status': False,
				'message': INTERNAL_ERROR_MESSAGE
			}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


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


def _resolve_tool(request):
	"""Find the InstalledExternalTool named by ``tool_id`` or ``name``, or build the error Response."""
	params = request.data if request.method == 'POST' else request.query_params
	tool_id = params.get('tool_id')
	tool_name = params.get('name')
	if tool_id:
		tool = InstalledExternalTool.objects.filter(id=tool_id).first()
	elif tool_name:
		tool = InstalledExternalTool.objects.filter(name=tool_name).first()
	else:
		return None, Response({'status': False, 'message': 'tool_id or name is required.'}, status=status.HTTP_400_BAD_REQUEST)
	if tool is None:
		return None, Response({'status': False, 'message': 'Tool Not found'}, status=status.HTTP_404_NOT_FOUND)
	return tool, None


class _ToolCommandView(APIView):
	"""Base for views that run an admin-configured tool command.

	They change state, so the browser must use POST: DRF only enforces CSRF on
	unsafe methods, and a GET would let any page trigger the command through an
	admin's session cookie. GET is still accepted from token-authenticated
	clients (the mobile /mapi/ app), which carry no ambient credentials.
	"""
	permission_classes = [HasPermission]
	permission_required = PERM_MODIFY_SYSTEM_CONFIGURATIONS

	def get(self, request):
		if isinstance(request.successful_authenticator, SessionAuthentication):
			return Response(
				{'status': False, 'message': 'Use POST for this action.'},
				status=status.HTTP_405_METHOD_NOT_ALLOWED,
			)
		return self.run(request)

	def post(self, request):
		return self.run(request)

	def run(self, request):
		raise NotImplementedError


class UpdateTool(_ToolCommandView):

	def run(self, request):
		tool, error = _resolve_tool(request)
		if error:
			return error

		# if git clone was used for installation, then we must use git pull inside project directory,
		# otherwise use the same command as given
		update_command = (tool.update_command or '').lower()

		if not update_command:
			return Response({'status': False, 'message': tool.name + ' has missing update command! Cannot update the tool.'})
		elif update_command == 'git pull':
			tool_name = tool.install_command[:-1] if tool.install_command[-1] == '/' else tool.install_command
			tool_name = tool_name.split('/')[-1]
			update_command = 'cd /usr/src/github/' + tool_name + ' && git pull && cd -'

		try:
			return_code, output = run_command(update_command, shell=True)
		except Exception:
			logger.exception('Update command failed to run for %s', tool.name)
			return Response({'status': False, 'message': 'Update failed to run; see server logs.'})
		if return_code == 0:
			return Response({'status': True, 'message': tool.name + ' updated successfully.'})
		logger.error("Update failed for %s: %s", tool.name, output)
		return Response({'status': False, 'message': f'Update failed: {output[:200]}...'})


GO_BIN_DIR = '/usr/local/bin'
GITHUB_TOOLS_DIR = '/usr/src/github'
_BINARY_NAME_RE = re.compile(r'[A-Za-z0-9][A-Za-z0-9._-]*')


def _remove_installed_tool_files(tool):
	"""Delete what the tool's install_command put on disk; return an error message or None.

	Only two install styles are known: ``go install`` (one binary in GO_BIN_DIR)
	and ``git clone`` (a checkout under GITHUB_TOOLS_DIR). Nothing is passed to a
	shell, and neither path can leave its directory.
	"""
	install_command = tool.install_command or ''
	if 'go install' in install_command:
		binary = install_command.rstrip('/').split('/')[-1].split('@')[0]
		if not _BINARY_NAME_RE.fullmatch(binary):
			return 'Cannot work out the installed binary name.'
		binary_path = os.path.join(GO_BIN_DIR, binary)
		if os.path.isfile(binary_path):
			os.remove(binary_path)
		return None
	if 'git clone' in install_command:
		clone_path = tool.github_clone_path or ''
		root = os.path.realpath(GITHUB_TOOLS_DIR)
		if not clone_path or os.path.realpath(clone_path) == root or not is_safe_path(root, clone_path):
			return 'Tool checkout is not inside the tools directory.'
		shutil.rmtree(clone_path, ignore_errors=True)
		return None
	return 'Cannot uninstall tool!'


class UninstallTool(_ToolCommandView):

	def run(self, request):
		tool, error = _resolve_tool(request)
		if error:
			return error
		if tool.is_default:
			return Response({'status': False, 'message': 'Default tools can not be uninstalled'}, status=status.HTTP_400_BAD_REQUEST)

		try:
			problem = _remove_installed_tool_files(tool)
		except OSError:
			logger.exception('Failed to remove files of tool %s', tool.name)
			return Response({'status': False, 'message': 'Uninstall failed; see server logs.'})
		if problem:
			return Response({'status': False, 'message': problem}, status=status.HTTP_400_BAD_REQUEST)
		tool.delete()
		return Response({'status': True, 'message': tool.name + ' uninstalled successfully.'})


class GetExternalToolCurrentVersion(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_MODIFY_SYSTEM_CONFIGURATIONS

	def get(self, request):
		req = self.request
		# toolname is also the command
		tool, error = _resolve_tool(req)
		if error:
			return error

		if not tool.version_lookup_command:
			return Response({'status': False, 'message': 'Version Lookup command not provided.'})

		version_number = None
		try:
			return_code, stdout = run_command(tool.version_lookup_command, shell=True)
			if return_code != 0:
				logger.warning("Version lookup failed for %s with code %s", tool.name, return_code)
				return Response({'status': False, 'message': 'Tool not found or check failed.'})
		except Exception:
			logger.error("Error running version lookup command", exc_info=True)
			return Response({'status': False, 'message': 'Error running version lookup command; see server logs.'})

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
		except Exception:
			logger.exception('Error fetching tool release from GitHub')
			return Response({'status': False, 'message': 'Error fetching from GitHub; see server logs.'})

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


class ListEngines(APIView):
	permission_classes = [IsAuditor]
	def get(self, request, format=None):
		req = self.request
		engines = EngineType.objects.order_by('engine_name').all()
		engine_serializer = EngineSerializer(engines, many=True)
		return Response({'engines': engine_serializer.data})


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
