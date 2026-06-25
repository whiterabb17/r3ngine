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
from api.views.tools import _WORKFLOW_REGISTRY

logger = logging.getLogger(__name__)

class InitiateScan(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_INITATE_SCANS_SUBSCANS

	def post(self, request):
		data = request.data
		domain_ids = data.get('domain_id')
		engine_id = data.get('engine_id')
		
		try:
			# Convert single ID to list for uniform processing
			if not isinstance(domain_ids, list):
				domain_ids = [domain_ids]

			results = []
			errors = []

			for domain_id in domain_ids:
				try:
					domain = Domain.objects.get(pk=domain_id)
					
					# Extract optional scan parameters
					subdomains_in = data.get('importSubdomainTextArea', [])
					subdomains_out = data.get('outOfScopeSubdomainTextarea', [])
					starting_point_path = data.get('startingPointPath', '').strip()
					excluded_paths = data.get('excludedPaths', [])
					if isinstance(excluded_paths, str):
						excluded_paths = [path.strip() for path in excluded_paths.split(',')]
					
					custom_dorks = data.get('customDorkTextarea', '').strip() if data.get('customDorkSwitch') else None
					spiderfoot_scan = data.get('spiderfoot_scan', False)
					selected_plugins = data.get('selected_plugins', [])
					if isinstance(selected_plugins, str):
						selected_plugins = [selected_plugins]

					# Create ScanHistory object
					scan_history_id = create_scan_object(
						host_id=domain_id,
						engine_id=engine_id,
						initiated_by_id=request.user.id,
						hardware_profile_id=data.get('hardware_profile_id')
					)
					scan = ScanHistory.objects.get(pk=scan_history_id)
					if custom_dorks:
						scan.cfg_custom_dorks = custom_dorks
						scan.save()

					# Resolve optional ScanProfile and embed its context
					_profile_ctx = {}
					_profile_name = data.get('profile_name')
					_profile_id = data.get('profile_id')
					if _profile_name or _profile_id:
						try:
							from scanEngine.models import ScanProfile as _ScanProfile
							if _profile_name:
								_profile = _ScanProfile.objects.get(name=_profile_name)
							else:
								_profile = _ScanProfile.objects.get(pk=_profile_id)
							_profile_ctx = _profile.to_ctx_dict()
						except ScanProfile.DoesNotExist:
							pass  # Unknown profile — proceed with empty profile ctx
						except Exception as exc:
							logger.warning("[SCAN] Failed to load scan profile %s: %s", _profile_name or _profile_id, exc)

					worker_name = data.get('worker_name')
					task_queue = data.get('task_queue')
					
					if worker_name:
						from django.utils import timezone
						from datetime import timedelta
						worker = ScanWorker.objects.filter(name=worker_name, is_active=True).first()
						if not worker:
							raise Exception(f"Worker '{worker_name}' not found or inactive")
						if not worker.last_heartbeat or worker.last_heartbeat < timezone.now() - timedelta(minutes=5):
							raise Exception(f"Worker '{worker_name}' is offline (last heartbeat: {worker.last_heartbeat})")
					
					# Start the scan via Temporal durable workflow orchestration
					kwargs = {
						'scan_history_id': scan.id,
						'domain_id': domain.id,
						'engine_id': engine_id,
						'scan_type': LIVE_SCAN,
						'results_dir': settings.RENGINE_RESULTS,
						'imported_subdomains': subdomains_in,
						'out_of_scope_subdomains': subdomains_out,
						'starting_point_path': starting_point_path,
						'excluded_paths': excluded_paths,
						'custom_dorks': custom_dorks,
						'enable_spiderfoot_scan': spiderfoot_scan,
						'initiated_by_id': request.user.id,
						'selected_plugin_slugs': selected_plugins,
						'profile_ctx': _profile_ctx,
						'task_queue': task_queue or worker_name,
					}
					res = initiate_scan_temporal(**kwargs)
					if not res.get('success'):
						raise Exception(res.get('error', 'Failed to initiate scan'))
					results.append({'domain': domain.name, 'scan_id': scan.id})
					
				except Exception as e:
					logger.error("Error initiating scan for domain %s", domain_id, exc_info=True)
					errors.append({'domain_id': domain_id, 'error': str(e)})

			if not results:
				return Response({
					'status': False,
					'message': 'Failed to initiate any scans',
					'errors': errors
				}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

			return Response({
				'status': True,
				'message': f'Successfully initiated {len(results)} scan(s)',
				'results': results,
				'errors': errors if errors else None
			})
		except Exception as e:
			logger.error(e)
			return Response({
				'status': False,
				'message': str(e)
			}, status=status.HTTP_400_BAD_REQUEST)


class InitiateSubTask(APIView):

	permission_classes = [HasPermission]
	permission_required = PERM_INITATE_SCANS_SUBSCANS

	def post(self, request):
		"""Initiate a set of subscans on one or more subdomains.

		Args:
			request (HttpRequest): Django HTTP request containing:
				- engine_id (int): Engine configuration ID to use.
				- tasks (list[str]): Task names to execute (e.g. 'port_scan', 'fetch_url').
				- subdomain_ids (list[int]): Subdomain IDs to run subtasks on.
		"""
		req = self.request
		data = req.data
		engine_id = data.get('engine_id')
		scan_types = data['tasks']
		selected_plugins = data.get('selected_plugins', [])
		if isinstance(selected_plugins, str):
			selected_plugins = [selected_plugins]
		worker_name = data.get('worker_name')
		task_queue = data.get('task_queue')
		
		if worker_name:
			from django.utils import timezone
			from datetime import timedelta
			worker = ScanWorker.objects.filter(name=worker_name, is_active=True).first()
			if not worker:
				return Response({'status': False, 'message': f"Worker '{worker_name}' not found or inactive"}, status=status.HTTP_400_BAD_REQUEST)
			if not worker.last_heartbeat or worker.last_heartbeat < timezone.now() - timedelta(minutes=5):
				return Response({'status': False, 'message': f"Worker '{worker_name}' is offline"}, status=status.HTTP_400_BAD_REQUEST)
		
		# Accept both subdomain_ids (list) and subdomain_id (single int) for mobile compatibility
		subdomain_ids = data.get('subdomain_ids') or []
		if not subdomain_ids:
			single = data.get('subdomain_id')
			if single:
				subdomain_ids = [single]
		subdomain_ids = list(dict.fromkeys(int(subdomain_id) for subdomain_id in subdomain_ids))

		def _run_single_subscan(sub_id):
			"""Run a single subscan launch inside a worker thread, ensuring DB connection cleanup."""
			try:
				logger.info('Running subscans %s on subdomain "%s" (concurrent) ...', scan_types, sub_id)
				ctx = {
					'scan_history_id': None,
					'subdomain_id': sub_id,
					'scan_type': scan_types,
					'engine_id': engine_id,
					'selected_plugin_slugs': selected_plugins,
					'task_queue': task_queue or worker_name,
				}
				return sub_id, initiate_subscan_temporal(**ctx)
			except Exception as ex:
				logger.exception('Error starting concurrent subscan for subdomain %s', sub_id, exc_info=True)
				return sub_id, {'success': False, 'error': str(ex)}
			finally:
				# Close all connections created or cached for this thread to prevent leaks
				connections.close_all()

		max_workers = min(len(subdomain_ids), 15)
		with ThreadPoolExecutor(max_workers=max_workers) as executor:
			results = list(executor.map(_run_single_subscan, subdomain_ids))

		errors = []
		for sub_id, res in results:
			if not res.get('success'):
				errors.append({
					'subdomain_id': sub_id,
					'error': res.get('error', 'Failed to initiate subscan'),
				})

		if errors:
			return Response({
				'status': False,
				'message': f'Failed to initiate {len(errors)} subscan(s)',
				'errors': errors,
			}, status=status.HTTP_400_BAD_REQUEST)
		return Response({'status': True})


class StopScan(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_INITATE_SCANS_SUBSCANS

	def post(self, request):
		from reNgine.utils.scan_cancellation import abort_scan_history, abort_subscan

		req = self.request
		data = req.data
		scan_ids = data.get('scan_ids', [])
		subscan_ids = data.get('subscan_ids', [])

		scan_ids = [int(id) for id in scan_ids]
		subscan_ids = [int(id) for id in subscan_ids]

		response = {'status': False}

		for scan_id in scan_ids:
			try:
				scan = ScanHistory.objects.get(id=scan_id)
				# if scan is already successful or aborted then do nothing
				if scan.scan_status == SUCCESS_TASK or scan.scan_status == ABORTED_TASK:
					continue
				response = abort_scan_history(scan, aborted_by=request.user)
			except Exception as e:
				logger.error(e)
				response = {'status': False, 'message': str(e)}

		for subscan_id in subscan_ids:
			try:
				subscan = SubScan.objects.get(id=subscan_id)
				if subscan.status == SUCCESS_TASK or subscan.status == ABORTED_TASK:
					continue
				response = abort_subscan(subscan)
			except Exception as e:
				logger.error(e)
				response = {'status': False, 'message': str(e)}

		return Response(response)


class ResumeScan(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_INITATE_SCANS_SUBSCANS

	def post(self, request):
		data = request.data
		scan_id = data.get('scan_id')

		response = {'status': False}
		if not scan_id:
			return Response({'status': False, 'message': 'Scan ID required.'})

		try:
			scan = ScanHistory.objects.get(id=scan_id)
			if scan.scan_status == SUCCESS_TASK:
				return Response({'status': False, 'message': 'Scan is already completed.'})
			if scan.recovery_count >= 3:
				return Response({'status': False, 'message': 'Max recovery limit (3) exceeded. Use the manual Resume button to override.'})

			from reNgine.tasks import resume_scan_temporal
			resume_scan_temporal(scan.id)
			
			response['status'] = True
			response['message'] = 'Scan resumption initiated successfully.'
		except ScanHistory.DoesNotExist:
			response['message'] = 'Scan not found'
		except Exception as e:
			logger.error('Error resuming scan %s', scan_id, exc_info=True)
			response['message'] = str(e)
		
		return Response(response)


class PauseScan(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_INITATE_SCANS_SUBSCANS

	def post(self, request):
		from reNgine.temporal_client import TemporalClientProvider
		from reNgine.definitions import RUNNING_TASK, PAUSED_TASK
		from startScan.models import ScanHistory, SubScan

		data = request.data
		scan_ids = data.get('scan_ids', [])
		target_id = data.get('target_id')

		if target_id:
			scans = ScanHistory.objects.filter(domain_id=target_id, scan_status=RUNNING_TASK)
		elif scan_ids:
			scan_ids = [int(sid) for sid in scan_ids]
			scans = ScanHistory.objects.filter(id__in=scan_ids)
		else:
			return Response({'status': False, 'message': 'scan_ids or target_id required.'}, status=status.HTTP_400_BAD_REQUEST)

		paused_count = 0
		for scan in scans:
			if scan.scan_status != RUNNING_TASK:
				continue
			try:
				scan.scan_status = PAUSED_TASK
				scan.save(update_fields=['scan_status'])

				subscans = SubScan.objects.filter(scan_history=scan, status=RUNNING_TASK)
				for subscan in subscans:
					subscan.status = PAUSED_TASK
					subscan.save(update_fields=['status'])
					for wf_id in subscan.workflow_ids:
						try:
							TemporalClientProvider.pause_workflow(wf_id)
						except Exception as e:
							logger.error("Failed to pause subscan workflow %s", wf_id, exc_info=True)

				for te in scan.temporal_executions.filter(status="RUNNING"):
					try:
						TemporalClientProvider.pause_workflow(te.workflow_id)
					except Exception as e:
						logger.error("Failed to pause workflow %s for scan %s", te.workflow_id, scan.id, exc_info=True)

				from reNgine.tasks import create_scan_activity
				create_scan_activity(scan.id, "Scan paused", PAUSED_TASK)
				paused_count += 1
			except Exception as e:
				logger.error("Failed to pause scan %s", scan.id, exc_info=True)

		return Response({'status': True, 'paused_count': paused_count, 'message': f'Paused {paused_count} scans.'})


class UnpauseScan(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_INITATE_SCANS_SUBSCANS

	def post(self, request):
		from reNgine.temporal_client import TemporalClientProvider
		from reNgine.definitions import RUNNING_TASK, PAUSED_TASK
		from startScan.models import ScanHistory, SubScan

		data = request.data
		scan_ids = data.get('scan_ids', [])
		target_id = data.get('target_id')

		if target_id:
			scans = ScanHistory.objects.filter(domain_id=target_id, scan_status=PAUSED_TASK)
		elif scan_ids:
			scan_ids = [int(sid) for sid in scan_ids]
			scans = ScanHistory.objects.filter(id__in=scan_ids)
		else:
			return Response({'status': False, 'message': 'scan_ids or target_id required.'}, status=status.HTTP_400_BAD_REQUEST)

		resumed_count = 0
		for scan in scans:
			if scan.scan_status != PAUSED_TASK:
				continue
			try:
				scan.scan_status = RUNNING_TASK
				scan.save(update_fields=['scan_status'])

				subscans = SubScan.objects.filter(scan_history=scan, status=PAUSED_TASK)
				for subscan in subscans:
					subscan.status = RUNNING_TASK
					subscan.save(update_fields=['status'])
					for wf_id in subscan.workflow_ids:
						try:
							TemporalClientProvider.resume_workflow(wf_id)
						except Exception as e:
							logger.error("Failed to resume subscan workflow %s", wf_id, exc_info=True)

				for te in scan.temporal_executions.filter(status="RUNNING"):
					try:
						TemporalClientProvider.resume_workflow(te.workflow_id)
					except Exception as e:
						logger.error("Failed to resume workflow %s for scan %s", te.workflow_id, scan.id, exc_info=True)

				from reNgine.tasks import create_scan_activity
				create_scan_activity(scan.id, "Scan resumed", RUNNING_TASK)
				resumed_count += 1
			except Exception as e:
				logger.error("Failed to resume/unpause scan %s", scan.id, exc_info=True)

		return Response({'status': True, 'resumed_count': resumed_count, 'message': f'Resumed {resumed_count} scans.'})


class FetchSubscanResults(APIView):
	permission_classes = [IsPenetrationTester]
	def get(self, request):
		req = self.request
		# data = req.data
		subscan_id = req.query_params.get('subscan_id')
		subscan = SubScan.objects.filter(id=subscan_id)
		if not subscan.exists():
			return Response({
				'status': False,
				'error': f'Subscan {subscan_id} does not exist'
			})

		subscan_data = SubScanResultSerializer(subscan.first(), many=False).data
		task_name = subscan_data['type']
		subscan_results = []

		if task_name == 'port_scan':
			ips_in_subscan = IpAddress.objects.filter(ip_subscan_ids__in=subscan)
			subscan_results = IpSerializer(ips_in_subscan, many=True).data

		elif task_name == 'vulnerability_scan':
			vulns_in_subscan = Vulnerability.objects.filter(vuln_subscan_ids__in=subscan)
			subscan_results = VulnerabilitySerializer(vulns_in_subscan, many=True).data

		elif task_name == 'fetch_url':
			endpoints_in_subscan = EndPoint.objects.filter(endpoint_subscan_ids__in=subscan)
			subscan_results = EndpointSerializer(endpoints_in_subscan, many=True).data

		elif task_name == 'dir_file_fuzz':
			dirs_in_subscan = DirectoryScan.objects.filter(dir_subscan_ids__in=subscan)
			subscan_results = DirectoryScanSerializer(dirs_in_subscan, many=True).data

		elif task_name == 'subdomain_discovery':
			subdomains_in_subscan = Subdomain.objects.filter(subdomain_subscan_ids__in=subscan)
			subscan_results = SubdomainSerializer(subdomains_in_subscan, many=True).data

		elif task_name == 'screenshot':
			subdomains_in_subscan = Subdomain.objects.filter(subdomain_subscan_ids__in=subscan, screenshot_path__isnull=False)
			subscan_results = SubdomainSerializer(subdomains_in_subscan, many=True).data

		logger.info(subscan_data)
		logger.info(subscan_results)

		return Response({'subscan': subscan_data, 'result': subscan_results})


class ListSubScans(APIView):
	permission_classes = [IsAuditor]
	def post(self, request):
		req = self.request
		data = req.data
		subdomain_id = data.get('subdomain_id', None)
		scan_history = data.get('scan_history_id', None)
		domain_id = data.get('domain_id', None)
		response = {}
		response['status'] = False

		if subdomain_id:
			subscans = (
				SubScan.objects
				.filter(subdomain__id=subdomain_id)
				.order_by('-stop_scan_date')
			)
			results = SubScanSerializer(subscans, many=True).data
			if subscans:
				response['status'] = True
				response['results'] = results

		elif scan_history:
			subscans = (
				SubScan.objects
				.filter(scan_history__id=scan_history)
				.order_by('-stop_scan_date')
			)
			results = SubScanSerializer(subscans, many=True).data
			if subscans:
				response['status'] = True
				response['results'] = results

		elif domain_id:
			scan_history = ScanHistory.objects.filter(domain__id=domain_id)
			subscans = (
				SubScan.objects
				.filter(scan_history__in=scan_history)
				.order_by('-stop_scan_date')
			)
			results = SubScanSerializer(subscans, many=True).data
			if subscans:
				response['status'] = True
				response['results'] = results

		return Response(response)


class StartWorkflowView(APIView):
    """Start any of the 13 rengine-ng standalone workflow types via a single endpoint.

    POST /api/v1/workflows/<workflow_slug>/start/
    Body: JSON dict with required fields per workflow type (see _WORKFLOW_REGISTRY).
    Returns: {workflow_id, status}
    """
    permission_classes = [IsAuthenticated]

    def post(self, request, workflow_slug: str):
        if workflow_slug not in _WORKFLOW_REGISTRY:
            return Response(
                {'error': f'Unknown workflow slug: {workflow_slug}'},
                status=status.HTTP_404_NOT_FOUND,
            )

        workflow_name, required_fields = _WORKFLOW_REGISTRY[workflow_slug]
        data = request.data

        ctx: dict = {
            'yaml_configuration': data.get('yaml_configuration') or {},
            'scan_history_id': data.get('scan_history_id'),
        }
        for field in required_fields:
            if field in data:
                ctx[field] = data[field]

        import asyncio
        from datetime import timedelta
        from reNgine import temporal_client as _tc
        from django.utils import timezone

        try:
            wf_id = f"{workflow_slug}-{request.user.id}-{int(timezone.now().timestamp())}"

            async def _start():
                client = await _tc.TemporalClientProvider.get_client()
                handle = await client.start_workflow(
                    workflow_name,
                    ctx,
                    id=wf_id,
                    task_queue="python-orchestrator-queue",
                    execution_timeout=timedelta(hours=24),
                )
                return handle.id

            loop = asyncio.new_event_loop()
            started_id = _tc.run_and_close(loop, _start())
            return Response(
                {'workflow_id': started_id or wf_id, 'status': 'started'},
                status=status.HTTP_200_OK,
            )
        except Exception as exc:
            logger.error(
                "[StartWorkflowView] failed to start %s: %s",
                workflow_name, str(exc),
            )
            return Response(
                {'error': 'Failed to start workflow'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class ScanActivityRetryAPIView(APIView):
    permission_classes = [HasPermission]
    permission_required = PERM_INITATE_SCANS_SUBSCANS

    def post(self, request, pk):
        import yaml
        import asyncio
        from startScan.models import ScanActivity
        from reNgine.definitions import FAILED_TASK, RUNNING_TASK, INITIATED_TASK
        from reNgine.temporal_client import TemporalClientProvider

        from django.db import transaction

        try:
            activity_obj = ScanActivity.objects.get(id=pk)
        except ScanActivity.DoesNotExist:
            return Response(
                {"status": False, "message": "Activity not found"},
                status=status.HTTP_404_NOT_FOUND,
            )

        if activity_obj.subscan_id is not None:
            return Response(
                {"status": False, "message": "Retrying subscan tasks is not yet supported"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        scan = activity_obj.scan_of

        if scan is None:
            return Response(
                {"status": False, "message": "Activity has no parent scan"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        from reNgine.definitions import PAUSED_TASK
        if scan.scan_status in (RUNNING_TASK, PAUSED_TASK):
            return Response(
                {"status": False, "message": "Cannot retry a task while the scan is running or paused"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        if activity_obj.status != FAILED_TASK:
            return Response(
                {"status": False, "message": "Task is not in a failed state"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        with transaction.atomic():
            # Reset the failed activity row so the serializer counts it as pending
            # and _create_scan_activity can claim it normally.
            ScanActivity.objects.filter(pk=activity_obj.pk).update(
                status=INITIATED_TASK,
                time_started=None,
                time_ended=None,
                error_message=None,
            )

            # Flip scan back to RUNNING so the UI reflects active state.
            scan.scan_status = RUNNING_TASK
            scan.error_message = None
            scan.stop_scan_date = None
            scan.save(update_fields=["scan_status", "error_message", "stop_scan_date"])

        yaml_config = yaml.safe_load(scan.scan_type.yaml_configuration or "")
        ctx = {
            "scan_history_id": scan.id,
            "engine_id": scan.scan_type.id,
            "domain_id": scan.domain.id,
            "results_dir": scan.results_dir,
            "yaml_configuration": yaml_config or {},
            "tasks": [activity_obj.name],
        }
        workflow_id = (
            f"retry-{activity_obj.name}-{scan.id}-{int(timezone.now().timestamp())}"
        )

        async def _start():
            client = await TemporalClientProvider.get_client()
            await client.start_workflow(
                "SingleTaskRetryWorkflow",
                args=[ctx, activity_obj.name],
                id=workflow_id,
                task_queue="python-orchestrator-queue",
            )

        loop = asyncio.new_event_loop()
        asyncio.set_event_loop(loop)
        run_and_close(loop, _start())

        return Response(
            {"status": True, "message": f"Retry started for {activity_obj.title}"}
        )

class DirectoryFileDispatchView(APIView):
    """Dispatch a security testing action against a specific directory file URL.

    POST /api/action/directory-file/dispatch/
    Body: { url: str, action: str, scan_id: int }
    Returns: { status: "dispatched", workflow_id: str }
    """
    permission_classes = [HasPermission]
    permission_required = PERM_MODIFY_SCAN_RESULTS

    _WORKFLOW_MAP = {
        'scan_vuln':   ('URLVulnWorkflow',     {}),
        'deep_fuzz':   ('URLFuzzWorkflow',      {}),
        'bypass_waf':  ('URLBypassWorkflow',    {}),
        'secret_scan': ('URLDirSearchWorkflow', {'url_dirsearch': {'hunt_secrets': True}}),
    }
    _AUTH_WORKFLOW = 'URLAuthExtractWorkflow'

    def post(self, request) -> Response:
        import asyncio
        import uuid
        from datetime import timedelta

        url: str = request.data.get('url')
        action: str = request.data.get('action')
        scan_id = request.data.get('scan_id')

        if not url or not action or scan_id is None:
            return Response(
                {'error': 'url, action, and scan_id are required'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        from urllib.parse import urlparse
        if urlparse(url).scheme not in ('http', 'https'):
            return Response(
                {'error': 'url must use http or https scheme'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        from startScan.models import ScanHistory
        if not ScanHistory.objects.filter(id=scan_id).exists():
            return Response(
                {'error': f'Scan {scan_id} does not exist'},
                status=status.HTTP_404_NOT_FOUND,
            )

        workflow_name: str = '<unknown>'
        ctx: dict = {}
        wf_id = f"dir-file-{action}-{scan_id}-{uuid.uuid4().hex[:8]}"

        if action in self._WORKFLOW_MAP:
            workflow_name, extra_yaml = self._WORKFLOW_MAP[action]
            ctx = {
                'urls': [url],
                'yaml_configuration': extra_yaml,
                'scan_history_id': scan_id,
            }
        elif action == 'extract_auth':
            workflow_name = self._AUTH_WORKFLOW
            ctx = {'url': url, 'scan_id': scan_id}
        elif action == 'brute_test':
            from plugins.models import Plugin
            plugin = Plugin.objects.filter(
                slug='credential_intelligence', is_enabled=True
            ).first()
            if not plugin:
                return Response(
                    {'error': 'Credential Intelligence plugin not installed or disabled'},
                    status=status.HTTP_403_FORBIDDEN,
                )
            from plugins_data.credential_intelligence.backend.models import CredentialTask
            from startScan.models import ScanHistory
            
            scan_hist = ScanHistory.objects.filter(id=scan_id).first()
            tool = request.data.get('tool', 'brutus')
            wordlist_user = request.data.get('wordlist_user')
            wordlist_pass = request.data.get('wordlist_pass')
            threads = request.data.get('threads', 5)
            additional_flags = request.data.get('additional_flags', '')
            
            try:
                threads = int(threads)
            except (ValueError, TypeError):
                threads = 5
                
            cred_task = CredentialTask.objects.create(
                scan_history=scan_hist,
                target_domain=scan_hist.domain if scan_hist else None,
                name=f"Brute Test for {url}",
                tool=tool,
                target=url,
                wordlist_user=wordlist_user,
                wordlist_pass=wordlist_pass,
                threads=threads,
                additional_flags=additional_flags,
                status='pending'
            )
            workflow_name = 'CredentialIntelligenceWorkflow'
            ctx = {'task_id': cred_task.id}
        else:
            return Response(
                {'error': f'Unknown action: {action}'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            async def _start():
                client = await TemporalClientProvider.get_client()
                handle = await client.start_workflow(
                    workflow_name,
                    ctx,
                    id=wf_id,
                    task_queue='python-orchestrator-queue',
                    execution_timeout=timedelta(hours=1),
                )
                return handle.id

            loop = asyncio.new_event_loop()
            started_id = run_and_close(loop, _start())
            return Response(
                {'status': 'dispatched', 'workflow_id': started_id or wf_id},
                status=status.HTTP_200_OK,
            )
        except Exception as exc:
            logger.error(
                "[DirectoryFileDispatchView] failed to start %s: %s",
                workflow_name, str(exc),
            )
            return Response(
                {'error': 'Failed to dispatch action'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )


class DirectoryFileDeleteView(APIView):
    """Delete DirectoryFile records by primary key.

    POST /api/action/directory-file/delete/
    Body: { directory_file_ids: [int] }
    Returns: { deleted: int }
    """
    permission_classes = [HasPermission]
    permission_required = PERM_MODIFY_SCAN_RESULTS

    def post(self, request) -> Response:
        from startScan.models import DirectoryFile

        ids = request.data.get('directory_file_ids')
        if not ids:
            return Response(
                {'error': 'directory_file_ids is required and must not be empty'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        if len(ids) > 500:
            return Response(
                {'error': 'directory_file_ids must not exceed 500 entries'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        deleted_count, _ = DirectoryFile.objects.filter(id__in=ids).delete()
        return Response({'deleted': deleted_count}, status=status.HTTP_200_OK)


# ---------------------------------------------------------------------------
# Phase 4 — ScanProfile CRUD API
# ---------------------------------------------------------------------------
