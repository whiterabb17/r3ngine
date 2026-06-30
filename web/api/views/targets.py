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

class AddTarget(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_MODIFY_TARGETS

	def post(self, request):
		data = request.data
		h1_team_handle = data.get('h1_team_handle')
		description = data.get('description')
		domain_name_input = data.get('domain_name', '')
		organization_name = data.get('organization')
		slug = data.get('slug')
		explicit_target_type = data.get('target_type') or None

		# Monitoring settings
		is_monitored = data.get('is_monitored', False)
		monitor_frequency = data.get('monitor_frequency', 'daily')
		monitor_scan_scope = data.get('monitor_scan_scope', 'none')
		monitor_engine_id = data.get('monitor_engine_id')

		# Advanced scan configuration
		starting_point_path = data.get('starting_point_path')
		excluded_paths = data.get('excluded_paths', [])

		# Support for multiple targets separated by newline.
		# The user wants to add multiple domains/IPs to a target when creating a new target.
		# This should create them as a SINGLE entry with secondary domains and in-scope IPs grouped.
		target_names = [t.strip().replace('*', '') for t in domain_name_input.split('\n') if t.strip()]

		# Clean up targets (remove leading dots)
		cleaned_targets = []
		for name in target_names:
			if name.startswith('.'):
				name = name[1:]
			cleaned_targets.append(name)

		if not cleaned_targets:
			return Response({'status': False, 'message': 'No valid targets provided'}, status=status.HTTP_400_BAD_REQUEST)

		# Handle extended target types (email, username, phone, cidr, crypto_address, code_path)
		# and regular targets by processing them individually to create separate primary targets.
		from reNgine.target_router import infer_target_type
		from reNgine.definitions import (
			TARGET_TYPE_EMAIL, TARGET_TYPE_USERNAME, TARGET_TYPE_PHONE,
			TARGET_TYPE_CIDR, TARGET_TYPE_CRYPTO_ADDRESS, TARGET_TYPE_CODE_PATH,
		)
		from targetApp.models import Domain as _Domain
		from dashboard.models import Project as _Project
		from django.utils import timezone as _tz

		_EXTENDED_TYPES = {
			TARGET_TYPE_EMAIL, TARGET_TYPE_USERNAME, TARGET_TYPE_PHONE,
			TARGET_TYPE_CIDR, TARGET_TYPE_CRYPTO_ADDRESS, TARGET_TYPE_CODE_PATH,
		}

		try:
			project = _Project.objects.get(slug=slug)
		except _Project.DoesNotExist:
			return Response({'status': False, 'message': 'Project not found'}, status=status.HTTP_400_BAD_REQUEST)

		regular_targets = []
		extended_targets_created = 0

		for target_name in cleaned_targets:
			effective_type = explicit_target_type or infer_target_type(target_name)
			if effective_type in _EXTENDED_TYPES:
				target_obj, created = _Domain.objects.get_or_create(
					name=target_name,
					defaults={
						'description': description or '',
						'project': project,
						'insert_date': _tz.now(),
						'target_type': effective_type,
					}
				)
				if not created:
					if target_obj.target_type != effective_type:
						target_obj.target_type = effective_type
						target_obj.save(update_fields=['target_type'])
				else:
					extended_targets_created += 1
			else:
				regular_targets.append({'name': target_name, 'description': description})

		status_import = False
		if regular_targets:
			status_import = bulk_import_targets(
				targets=regular_targets,
				organization_name=organization_name,
				h1_team_handle=h1_team_handle,
				project_slug=slug,
				is_monitored=is_monitored,
				monitor_frequency=monitor_frequency,
				monitor_engine_id=monitor_engine_id,
				monitor_scan_scope=monitor_scan_scope,
				starting_point_path=starting_point_path,
				excluded_paths=excluded_paths,
				in_scope_ips=None,
				secondary_domains=None
			)

		if status_import or extended_targets_created > 0:
			msg = f'Successfully created {len(cleaned_targets)} target{"s" if len(cleaned_targets) > 1 else ""}.'
			return Response({
				'status': True,
				'message': msg,
			})
		return Response({
			'status': False,
			'message': 'Failed to add targets! They may already exist or are invalid.'
		})




class UpdateTarget(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_MODIFY_TARGETS

	def post(self, request):
		from targetApp.views import manage_monitoring_task

		data = request.data
		target_id = data.get('id')
		if not target_id:
			return Response({'status': False, 'message': 'Target ID is required'}, status=HTTP_400_BAD_REQUEST)

		try:
			domain = Domain.objects.get(id=target_id)
		except Domain.DoesNotExist:
			return Response({'status': False, 'message': 'Target not found'}, status=HTTP_400_BAD_REQUEST)

		try:
			# Scalar fields
			if 'description' in data:
				domain.description = data.get('description') or ''
			if 'h1_team_handle' in data:
				domain.h1_team_handle = data.get('h1_team_handle') or ''
			if 'target_type' in data:
				domain.target_type = data.get('target_type') or 'domain'
			if 'starting_point_path' in data:
				domain.starting_point_path = data.get('starting_point_path') or ''
			if 'in_scope_ips' in data:
				domain.in_scope_ips = data.get('in_scope_ips') or ''
			if 'secondary_domains' in data:
				domain.secondary_domains = data.get('secondary_domains') or ''

			# excluded_paths is a JSONField — accept list or newline-separated string
			if 'excluded_paths' in data:
				excluded_paths = data.get('excluded_paths')
				if isinstance(excluded_paths, list):
					domain.excluded_paths = excluded_paths
				elif isinstance(excluded_paths, str):
					domain.excluded_paths = [p.strip() for p in excluded_paths.split('\n') if p.strip()]
				else:
					domain.excluded_paths = []

			# Monitoring fields — track whether they changed so we can update the schedule
			monitoring_changed = False
			if 'is_monitored' in data:
				new_val = bool(data.get('is_monitored'))
				if domain.is_monitored != new_val:
					monitoring_changed = True
				domain.is_monitored = new_val
			if 'monitor_frequency' in data:
				new_val = data.get('monitor_frequency') or 'daily'
				if domain.monitor_frequency != new_val:
					monitoring_changed = True
				domain.monitor_frequency = new_val
			if 'monitor_scan_scope' in data:
				new_val = data.get('monitor_scan_scope') or 'targeted'
				if domain.monitor_scan_scope != new_val:
					monitoring_changed = True
				domain.monitor_scan_scope = new_val
			if 'monitor_engine_id' in data:
				engine_id = data.get('monitor_engine_id')
				try:
					from scanEngine.models import EngineType
					new_engine = EngineType.objects.get(id=engine_id) if engine_id else None
				except EngineType.DoesNotExist:
					new_engine = None
				if domain.monitor_engine_id != (engine_id if engine_id else None):
					monitoring_changed = True
				domain.monitor_engine = new_engine

			if monitoring_changed or 'is_monitored' in data:
				domain.save()
				manage_monitoring_task(domain)
			else:
				domain.save()

			# Organization reassignment via M2M (Organization.domains)
			if 'organization' in data:
				organization_name = data.get('organization')
				# Remove domain from all current organizations in this project
				for org in Organization.objects.filter(domains=domain, project=domain.project):
					org.domains.remove(domain)
				# Add to new organization if specified
				if organization_name:
					try:
						org = Organization.objects.get(name=organization_name, project=domain.project)
						org.domains.add(domain)
					except Organization.DoesNotExist:
						pass

			return Response({'status': True, 'message': f'Target {domain.name} updated successfully'})
		except Exception as e:
			logger.error("UpdateTarget failed for id=%s: %s", target_id, e)
			return Response({'status': False, 'message': 'An error occurred while updating the target'}, status=HTTP_400_BAD_REQUEST)


class ListTargetsDatatableViewSet(viewsets.ModelViewSet):
	permission_classes = [IsPenetrationTester]
	queryset = Domain.objects.all().order_by('-id')
	serializer_class = DomainSerializer
	pagination_class = DatatablesPageNumberPagination

	def get_queryset(self):
		queryset = Domain.objects.all()
		slug = self.request.GET.get('slug', None)
		if slug:
			queryset = queryset.filter(project__slug=slug)
		
		org_id = self.request.GET.get('organization_id', None)
		if org_id:
			queryset = queryset.filter(domains__id=org_id)
			
		return queryset.order_by('-id')

	def filter_queryset(self, qs):
		search_value = self.request.GET.get(u'search[value]', None)
		_order_col = self.request.GET.get(u'order[0][column]', None)
		_order_direction = self.request.GET.get(u'order[0][dir]', None)
		if search_value or _order_col or _order_direction:
			order_col = 'id'
			if _order_col == '2':
				order_col = 'name'
			elif _order_col == '4':
				order_col = 'insert_date'
			elif _order_col == '5':
				order_col = 'start_scan_date'
				if _order_direction == 'desc':
					return qs.order_by(F('start_scan_date').desc(nulls_last=True))
				return qs.order_by(F('start_scan_date').asc(nulls_last=True))


			if _order_direction == 'desc':
				order_col = f'-{order_col}'

			qs = qs.filter(
				Q(name__icontains=search_value) |
				Q(description__icontains=search_value) |
				Q(domains__name__icontains=search_value)
			)
			return qs.order_by(order_col)
		return qs



class AddManualSubdomain(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_MODIFY_TARGETS

	def post(self, request):
		data = request.data
		subdomain_input = data.get('subdomain_name')
		target_id = data.get('target_id')
		scan_id = data.get('scan_id')

		if not subdomain_input:
			return Response({'status': False, 'message': 'Subdomain name or list is required.'}, status=400)

		# Resolve target domain
		domain = None
		if target_id:
			domain = Domain.objects.filter(id=target_id).first()
		elif scan_id:
			scan = ScanHistory.objects.filter(id=scan_id).first()
			if scan:
				domain = scan.domain

		if not domain:
			return Response({'status': False, 'message': 'Target domain not found.'}, status=404)

		if domain.target_type not in ['domain', 'subdomain']:
			return Response(
				{'status': False, 'message': 'Manual subdomains are only supported for domain-based targets.'},
				status=400
			)

		subdomains_to_process = normalize_manual_subdomains(subdomain_input)

		if not subdomains_to_process:
			return Response({'status': False, 'message': 'No valid subdomain names found in input.'}, status=400)

		# Filter out duplicates within the input itself
		subdomains_to_process = list(dict.fromkeys(subdomains_to_process))

		MAX_SUBDOMAINS_PER_REQUEST = 500
		if len(subdomains_to_process) > MAX_SUBDOMAINS_PER_REQUEST:
			return Response(
				{'status': False, 'message': f'Too many subdomains. Maximum {MAX_SUBDOMAINS_PER_REQUEST} per request.'},
				status=400
			)

		added_count = 0
		duplicate_count = 0
		invalid_count = 0
		out_of_scope_count = 0
		materialized_count = 0

		# Find the latest scan history for immediate visibility in current views.
		scan = ScanHistory.objects.filter(domain=domain).order_by('-start_scan_date').first()

		existing_manual_subdomains = domain.get_manual_subdomains()
		existing_manual_subdomains_set = set(existing_manual_subdomains)
		subdomains_to_create = []

		for sub_name in subdomains_to_process:
			# Basic validation
			if not validators.domain(sub_name):
				invalid_count += 1
				continue

			domain_name = domain.name.lower().strip()
			if sub_name != domain_name and not sub_name.endswith('.' + domain_name):
				out_of_scope_count += 1
				continue

			if sub_name in existing_manual_subdomains_set:
				duplicate_count += 1
				continue

			subdomains_to_create.append(sub_name)
			existing_manual_subdomains.append(sub_name)
			existing_manual_subdomains_set.add(sub_name)

		if subdomains_to_create:
			domain.set_manual_subdomains(existing_manual_subdomains)
			domain.save(update_fields=['manual_subdomains'])
			added_count = len(subdomains_to_create)

			if scan:
				existing_in_scan = set(
					Subdomain.objects.filter(
						target_domain=domain,
						scan_history=scan,
						name__in=[s.lower() for s in subdomains_to_create],
					).values_list('name', flat=True)
				)
				existing_lower = {n.lower() for n in existing_in_scan}
				objs = [
					Subdomain(
						scan_history=scan,
						target_domain=domain,
						name=sub_name,
						is_imported_subdomain=True,
						discovered_date=timezone.now()
					)
					for sub_name in subdomains_to_create
					if sub_name.lower() not in existing_lower
				]
				if objs:
					Subdomain.objects.bulk_create(objs, ignore_conflicts=True)
					materialized_count = len(objs)

		# Build response message
		msg_parts = []
		if added_count > 0:
			msg_parts.append(f'Successfully saved {added_count} subdomain(s) for future scans.')
		if materialized_count > 0:
			msg_parts.append(f'{materialized_count} added to the latest scan now.')
		if duplicate_count > 0:
			msg_parts.append(f'{duplicate_count} already existed in target scope.')
		if invalid_count > 0:
			msg_parts.append(f'{invalid_count} had invalid format.')
		if out_of_scope_count > 0:
			msg_parts.append(f'{out_of_scope_count} did not belong to target {domain.name}.')
		if not scan and added_count > 0:
			msg_parts.append('They will appear in the next scan for this target.')

		message = ' '.join(msg_parts)
		return Response({
			'status': added_count > 0,
			'message': message,
			'added_count': added_count,
			'materialized_count': materialized_count,
			'duplicate_count': duplicate_count,
			'invalid_count': invalid_count,
			'out_of_scope_count': out_of_scope_count
		})


class DeleteSubdomain(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_MODIFY_SCAN_RESULTS

	def post(self, request):
		req = self.request
		ids = [int(i) for i in req.data.get('subdomain_ids', [])]
		Subdomain.objects.filter(id__in=ids).delete()
		return Response({'status': True})


class ToggleSubdomainImportantStatus(APIView):
	permission_classes = [IsPenetrationTester]
	def post(self, request):
		req = self.request
		data = req.data

		subdomain_id = data.get('subdomain_id')

		response = {'status': False, 'message': 'No subdomain_id provided'}

		subdomain = Subdomain.objects.filter(id=subdomain_id).first()
		if not subdomain:
			return Response({'status': False, 'message': 'Subdomain not found'})
		subdomain.is_important = not subdomain.is_important
		subdomain.save()

		response = {'status': True}

		return Response(response)


class QueryInterestingSubdomains(APIView):
	permission_classes = [IsPenetrationTester]
	def get(self, request):
		req = self.request
		scan_id = req.query_params.get('scan_id')
		domain_id = req.query_params.get('target_id')

		if scan_id:
			queryset = get_interesting_subdomains(scan_history=scan_id)
		elif domain_id:
			queryset = get_interesting_subdomains(domain_id=domain_id)
		else:
			queryset = get_interesting_subdomains()

		queryset = queryset.distinct('name')

		return Response(InterestingSubdomainSerializer(queryset, many=True).data)


class ParameterSummaryView(APIView):
	permission_classes = [IsPenetrationTester]

	def get(self, request, *args, **kwargs):
		req = self.request
		scan_id = req.query_params.get('scan_history')
		target_id = req.query_params.get('target_id')

		if scan_id:
			base_qs = Parameter.objects.filter(endpoint__scan_history__id=scan_id)
		elif target_id:
			base_qs = Parameter.objects.filter(endpoint__target_domain__id=target_id)
		else:
			return Response({"error": "scan_history or target_id is required"}, status=400)

		summary = {
			'total': base_qs.count(),
			'high_confidence': base_qs.filter(confidence__gte=80).count(),
			'reflected': base_qs.filter(is_reflected=True).count(),
			'source': base_qs.filter(is_source=True).count(),
			'sink': base_qs.filter(is_sink=True).count(),
		}
		return Response(summary)


class SecretLeakViewSet(viewsets.ModelViewSet):
	permission_classes = [IsPenetrationTester]
	serializer_class = SecretLeakSerializer
	queryset = SecretLeak.objects.none()

	def get_queryset(self):
		req = self.request
		project = req.query_params.get('project')
		target_id = req.query_params.get('target_id')
		scan_id = req.query_params.get('scan_id')
		
		queryset = SecretLeak.objects.all()

		if project:
			queryset = queryset.filter(scan_history__domain__project__slug=project)
		if target_id:
			queryset = queryset.filter(scan_history__domain__id=target_id)
		if scan_id:
			queryset = queryset.filter(scan_history__id=scan_id)
			
		return queryset.order_by('-discovered_date')


class EmailBreachViewSet(viewsets.ModelViewSet):
	"""ViewSet for viewing email breaches.

	Allows listing email breaches filtered by scan_id, target_id, or project.
	"""
	permission_classes = [IsPenetrationTester]
	serializer_class = EmailBreachSerializer
	pagination_class = None
	queryset = EmailBreach.objects.none()

	def get_queryset(self):
		"""Retrieve query parameters and filter the EmailBreach objects.

		Returns:
			QuerySet: Filtered EmailBreach query results.
		"""
		req = self.request
		project = req.query_params.get('project')
		target_id = req.query_params.get('target_id')
		scan_id = req.query_params.get('scan_id')
		email_id = req.query_params.get('email_id')

		queryset = EmailBreach.objects.all()

		if project:
			queryset = queryset.filter(scan_history__domain__project__slug=project)
		if target_id:
			queryset = queryset.filter(scan_history__domain__id=target_id)
		if scan_id:
			queryset = queryset.filter(scan_history__id=scan_id)
		if email_id:
			queryset = queryset.filter(email__id=email_id)

		return queryset.order_by('-discovered_date')


class CheckEmailBreach(APIView):
	"""API endpoint to manually check an email address for HIBP breaches.

	POST:
		Trigger the Playwright-based HIBP crawler on demand.
	"""
	permission_classes = [IsPenetrationTester]

	def post(self, request, format=None):
		"""Handle the POST request to manually check a single email address.

		Args:
			request (Request): Request containing email_address and scan_id.

		Returns:
			Response: Serialized email and breach details.
		"""
		email_address = request.data.get('email_address')
		scan_id = request.data.get('scan_id')

		if not email_address or not scan_id:
			return Response({"error": "email_address and scan_id are required"}, status=status.HTTP_400_BAD_REQUEST)

		try:
			scan_history = ScanHistory.objects.get(id=scan_id)
		except ScanHistory.DoesNotExist:
			return Response({"error": "ScanHistory not found"}, status=status.HTTP_404_NOT_FOUND)

		# Ensure the Email object exists and is associated with this scan
		from reNgine.utils.task import save_email
		email_obj, created = save_email(email_address, scan_history=scan_history)
		if not email_obj:
			return Response({"error": "Invalid email address format"}, status=status.HTTP_400_BAD_REQUEST)

		# Trigger Playwright check asynchronously in a background thread
		from reNgine.osint.hibp_scraper import check_hibp_for_email_task
		threading.Thread(
			target=check_hibp_for_email_task,
			args=(email_address, scan_history.id, email_obj.id),
			daemon=True
		).start()

		return Response({
			"status": "checking",
			"email": EmailSerializer(email_obj).data
		}, status=status.HTTP_202_ACCEPTED)



class ScreenshotViewSet(viewsets.ModelViewSet):
	permission_classes = [IsPenetrationTester]
	queryset = Screenshot.objects.all()
	serializer_class = ScreenshotSerializer

	def get_queryset(self):
		req = self.request
		project = req.query_params.get('project')
		target_id = req.query_params.get('target_id')
		scan_id = req.query_params.get('scan_id')

		queryset = self.queryset
		if project:
			queryset = queryset.filter(scan_history__domain__project__slug=project)
		if target_id:
			queryset = queryset.filter(scan_history__domain__id=target_id)
		if scan_id:
			queryset = queryset.filter(scan_history__id=scan_id)
		
		return queryset.order_by('-created_at')


from rest_framework.permissions import AllowAny

class DirectoryViewSet(viewsets.ModelViewSet):
	permission_classes = [IsAuditor]

	queryset = EndPoint.objects.none()
	serializer_class = DirectoryFileSerializer

	def get_queryset(self):
		req = self.request
		scan_id = req.query_params.get('scan_history')
		subdomain_id = req.query_params.get('subdomain_id')
		
		if not (scan_id or subdomain_id):
			return EndPoint.objects.none()

		queryset = EndPoint.objects.filter(scan_history__id=scan_id)
		if subdomain_id and subdomain_id != '0':
			queryset = queryset.filter(subdomain__id=subdomain_id)
		
		return queryset.order_by('http_url')

	def get_serializer_class(self):
		return EndPointDirectorySerializer

	def list(self, request, *args, **kwargs):
		scan_id = self.request.query_params.get('scan_history')
		subdomain_id = self.request.query_params.get('subdomain_id')

		# Handle '0' as falsy for subdomain_id
		if subdomain_id == '0':
			subdomain_id = None

		# If subdomain_id is missing, return list of subdomains that have findings
		if scan_id and not subdomain_id:
			subdomains = Subdomain.objects.filter(
				scan_history__id=scan_id,
				endpoint__isnull=False
			).distinct()
			
			results = []
			for sd in subdomains:
				results.append({
					'id': sd.id,
					'name': sd.name,
					'directory_count': EndPoint.objects.filter(scan_history__id=scan_id, subdomain=sd).count()
				})
			return Response({
				'count': len(results),
				'next': None,
				'previous': None,
				'results': results
			})
		
		return super().list(request, *args, **kwargs)



