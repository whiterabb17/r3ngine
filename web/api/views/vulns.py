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

class VulnerabilityPagination(PageNumberPagination):
	page_size = 10
	page_size_query_param = 'length'
	max_page_size = 200


class VulnerabilityViewSet(viewsets.ModelViewSet):
	pagination_class = VulnerabilityPagination
	permission_classes = [IsPenetrationTester]
	serializer_class = VulnerabilitySerializer
	queryset = Vulnerability.objects.none()

	@staticmethod
	def _normalize_severity_filter(severity_value):
		from reNgine.definitions import NUCLEI_SEVERITY_MAP

		if severity_value is None:
			return None

		if isinstance(severity_value, int):
			return severity_value

		raw_value = str(severity_value).strip().lower()
		if raw_value == '':
			return None

		if raw_value.lstrip('-').isdigit():
			return int(raw_value)

		aliases = {
			'crit': 'critical',
			'med': 'medium',
			'informational': 'info',
		}
		normalized_value = aliases.get(raw_value, raw_value)
		return NUCLEI_SEVERITY_MAP.get(normalized_value)

	@classmethod
	def _normalize_severity_filters(cls, severity_value):
		if severity_value is None:
			return []

		raw_values = str(severity_value).split(',')
		normalized_values = []
		for raw_value in raw_values:
			normalized_value = cls._normalize_severity_filter(raw_value)
			if normalized_value is not None and normalized_value not in normalized_values:
				normalized_values.append(normalized_value)
		return normalized_values

	@staticmethod
	def _normalize_csv_filters(raw_value):
		if raw_value is None:
			return []

		normalized_values = []
		for value in str(raw_value).split(','):
			normalized_value = value.strip()
			if normalized_value and normalized_value.lower() not in [item.lower() for item in normalized_values]:
				normalized_values.append(normalized_value)
		return normalized_values

	def get_queryset(self):
		req = self.request
		project = req.query_params.get('project')
		target_id = req.query_params.get('target_id')
		scan_id = req.query_params.get('scan_history')
		domain = req.query_params.get('domain')
		severity = req.query_params.get('severity')
		exclude_severity = req.query_params.get('exclude_severity')
		validation_status = req.query_params.get('validation_status')
		open_status = req.query_params.get('open_status')
		source = req.query_params.get('source')
		exclude_source = req.query_params.get('exclude_source')
		subdomain_id = req.query_params.get('subdomain_id')
		subdomain_name = req.query_params.get('subdomain')
		vulnerability_name = req.query_params.get('vulnerability_name')
		slug = self.request.GET.get('project', None)

		if slug:
			vulnerabilities = Vulnerability.objects.filter(scan_history__domain__project__slug=slug)
		else:
			vulnerabilities = Vulnerability.objects.all()

		if scan_id:
			qs = (
				vulnerabilities
				.filter(scan_history__id=scan_id)
				.distinct()
			)
		elif target_id:
			qs = (
				vulnerabilities
				.filter(target_domain__id=target_id)
				.distinct()
			)
		elif subdomain_name:
			subdomains = Subdomain.objects.filter(name=subdomain_name)
			qs = (
				vulnerabilities
				.filter(subdomain__in=subdomains)
				.distinct()
			)
		else:
			qs = vulnerabilities.distinct()

		if domain:
			qs = qs.filter(Q(target_domain__name=domain)).distinct()
		if vulnerability_name:
			qs = qs.filter(Q(name=vulnerability_name)).distinct()
		if severity:
			severity_values = self._normalize_severity_filters(severity)
			if severity_values:
				qs = qs.filter(severity__in=severity_values)
		if exclude_severity:
			# Filter out (exclude) vulnerabilities matching these severity levels
			exclude_severity_values = self._normalize_severity_filters(exclude_severity)
			if exclude_severity_values:
				qs = qs.exclude(severity__in=exclude_severity_values)
		if validation_status:
			qs = qs.filter(validation_status__iexact=validation_status)
		if open_status is not None:
			if open_status.lower() in ('true', '1', 't', 'y', 'yes'):
				qs = qs.filter(open_status=True)
			elif open_status.lower() in ('false', '0', 'f', 'n', 'no'):
				qs = qs.filter(open_status=False)
		if source:
			source_values = self._normalize_csv_filters(source)
			if source_values:
				source_query = Q()
				for source_value in source_values:
					source_query |= Q(source__iexact=source_value)
				qs = qs.filter(source_query)
		if exclude_source:
			# Filter out (exclude) vulnerabilities matching these scanner source tools
			exclude_source_values = self._normalize_csv_filters(exclude_source)
			if exclude_source_values:
				exclude_source_query = Q()
				for source_value in exclude_source_values:
					exclude_source_query |= Q(source__iexact=source_value)
				qs = qs.exclude(exclude_source_query)
		if subdomain_id:
			qs = qs.filter(subdomain__id=subdomain_id)
		self.queryset = qs
		return self.queryset

	def filter_queryset(self, qs):
		qs = self.queryset.filter()
		search_value = self.request.GET.get(u'search[value]', '')
		_order_col = self.request.GET.get(u'order[0][column]', None)
		_order_direction = self.request.GET.get(u'order[0][dir]', None)
		if search_value or _order_col or _order_direction:
			order_col = 'severity'
			if _order_col == '1':
				order_col = 'source'
			elif _order_col == '3':
				order_col = 'name'
			elif _order_col == '7':
				order_col = 'severity'
			elif _order_col == '11':
				order_col = 'http_url'
			elif _order_col == '15':
				order_col = 'open_status'

			if _order_direction == 'desc':
				order_col = f'-{order_col}'
			# if the search query is separated by = means, it is a specific lookup
			# divide the search query into two half and lookup
			operators = ['=', '&', '|', '>', '<', '!']
			if any(x in search_value for x in operators):
				if '&' in search_value:
					complex_query = search_value.split('&')
					for query in complex_query:
						if query.strip():
							qs = qs & self.special_lookup(query.strip())
				elif '|' in search_value:
					qs = Vulnerability.objects.none()
					complex_query = search_value.split('|')
					for query in complex_query:
						if query.strip():
							qs = self.special_lookup(query.strip()) | qs
				else:
					qs = self.special_lookup(search_value)
			else:
				qs = self.general_lookup(search_value)
			return qs.order_by(order_col)
		return qs.order_by('-severity')

	def general_lookup(self, search_value):
		qs = (
			self.queryset
			.filter(Q(http_url__icontains=search_value) |
					Q(target_domain__name__icontains=search_value) |
					Q(template__icontains=search_value) |
					Q(template_id__icontains=search_value) |
					Q(name__icontains=search_value) |
					Q(severity__icontains=search_value) |
					Q(description__icontains=search_value) |
					Q(extracted_results__icontains=search_value) |
					Q(references__url__icontains=search_value) |
					Q(cve_ids__name__icontains=search_value) |
					Q(cwe_ids__name__icontains=search_value) |
					Q(cvss_metrics__icontains=search_value) |
					Q(cvss_score__icontains=search_value) |
					Q(type__icontains=search_value) |
					Q(open_status__icontains=search_value) |
					Q(hackerone_report_id__icontains=search_value) |
					Q(tags__name__icontains=search_value))
		)
		return qs

	def special_lookup(self, search_value):
		qs = self.queryset.filter()
		if '=' in search_value:
			search_param = search_value.split("=")
			lookup_title = search_param[0].lower().strip()
			lookup_content = search_param[1].lower().strip()
			if 'severity' in lookup_title:
				severity_value = NUCLEI_SEVERITY_MAP.get(lookup_content, -1)
				qs = (
					self.queryset
					.filter(severity=severity_value)
				)
			elif 'name' in lookup_title:
				qs = (
					self.queryset
					.filter(name__icontains=lookup_content)
				)
			elif 'http_url' in lookup_title:
				qs = (
					self.queryset
					.filter(http_url__icontains=lookup_content)
				)
			elif 'template' in lookup_title:
				qs = (
					self.queryset
					.filter(template__icontains=lookup_content)
				)
			elif 'template_id' in lookup_title:
				qs = (
					self.queryset
					.filter(template_id__icontains=lookup_content)
				)
			elif 'cve_id' in lookup_title or 'cve' in lookup_title:
				qs = (
					self.queryset
					.filter(cve_ids__name__icontains=lookup_content)
				)
			elif 'cwe_id' in lookup_title or 'cwe' in lookup_title:
				qs = (
					self.queryset
					.filter(cwe_ids__name__icontains=lookup_content)
				)
			elif 'cvss_metrics' in lookup_title:
				qs = (
					self.queryset
					.filter(cvss_metrics__icontains=lookup_content)
				)
			elif 'cvss_score' in lookup_title:
				qs = (
					self.queryset
					.filter(cvss_score__exact=lookup_content)
				)
			elif 'type' in lookup_title:
				qs = (
					self.queryset
					.filter(type__icontains=lookup_content)
				)
			elif 'tag' in lookup_title:
				qs = (
					self.queryset
					.filter(tags__name__icontains=lookup_content)
				)
			elif 'status' in lookup_title:
				open_status = lookup_content == 'open'
				qs = (
					self.queryset
					.filter(open_status=open_status)
				)
			elif 'description' in lookup_title:
				qs = (
					self.queryset
					.filter(Q(description__icontains=lookup_content) |
							Q(template__icontains=lookup_content) |
							Q(extracted_results__icontains=lookup_content))
				)
		elif '!' in search_value:
			search_param = search_value.split("!")
			lookup_title = search_param[0].lower().strip()
			lookup_content = search_param[1].lower().strip()
			if 'severity' in lookup_title:
				severity_value = NUCLEI_SEVERITY_MAP.get(lookup_title, -1)
				qs = (
					self.queryset
					.exclude(severity=severity_value)
				)
			elif 'name' in lookup_title:
				qs = (
					self.queryset
					.exclude(name__icontains=lookup_content)
				)
			elif 'http_url' in lookup_title:
				qs = (
					self.queryset
					.exclude(http_url__icontains=lookup_content)
				)
			elif 'template' in lookup_title:
				qs = (
					self.queryset
					.exclude(template__icontains=lookup_content)
				)
			elif 'template_id' in lookup_title:
				qs = (
					self.queryset
					.exclude(template_id__icontains=lookup_content)
				)
			elif 'cve_id' in lookup_title or 'cve' in lookup_title:
				qs = (
					self.queryset
					.exclude(cve_ids__icontains=lookup_content)
				)
			elif 'cwe_id' in lookup_title or 'cwe' in lookup_title:
				qs = (
					self.queryset
					.exclude(cwe_ids__icontains=lookup_content)
				)
			elif 'cvss_metrics' in lookup_title:
				qs = (
					self.queryset
					.exclude(cvss_metrics__icontains=lookup_content)
				)
			elif 'cvss_score' in lookup_title:
				qs = (
					self.queryset
					.exclude(cvss_score__exact=lookup_content)
				)
			elif 'type' in lookup_title:
				qs = (
					self.queryset
					.exclude(type__icontains=lookup_content)
				)
			elif 'tag' in lookup_title:
				qs = (
					self.queryset
					.exclude(tags__icontains=lookup_content)
				)
			elif 'status' in lookup_title:
				open_status = lookup_content == 'open'
				qs = (
					self.queryset
					.exclude(open_status=open_status)
				)
			elif 'description' in lookup_title:
				qs = (
					self.queryset
					.exclude(Q(description__icontains=lookup_content) |
							 Q(template__icontains=lookup_content) |
							 Q(extracted_results__icontains=lookup_content))
				)

		elif '>' in search_value:
			search_param = search_value.split(">")
			lookup_title = search_param[0].lower().strip()
			lookup_content = search_param[1].lower().strip()
			if 'cvss_score' in lookup_title:
				try:
					val = float(lookup_content)
					qs = self.queryset.filter(cvss_score__gt=val)
				except Exception as e:
					logger.exception("Unexpected error: %s", e)

		elif '<' in search_value:
			search_param = search_value.split("<")
			lookup_title = search_param[0].lower().strip()
			lookup_content = search_param[1].lower().strip()
			if 'cvss_score' in lookup_title:
				try:
					val = int(lookup_content)
					qs = self.queryset.filter(cvss_score__lt=val)
				except Exception as e:
					logger.exception("Unexpected error: %s", e)

		return qs

class ExposurePagination(PageNumberPagination):
	page_size = 10
	page_size_query_param = 'length'
	max_page_size = 200

class ExposureViewSet(
	mixins.ListModelMixin,
	mixins.RetrieveModelMixin,
	mixins.UpdateModelMixin,
	viewsets.GenericViewSet,
):
	pagination_class = ExposurePagination
	permission_classes = [IsPenetrationTester]
	serializer_class = ExposureSerializer
	queryset = Exposure.objects.none()

	def get_queryset(self):
		# Detail actions (retrieve, patch) look up by PK directly — no filter params required
		if self.action in ('retrieve', 'partial_update', 'update'):
			return Exposure.objects.all()

		req = self.request
		project = req.query_params.get('project')
		target_id = req.query_params.get('target_id')
		scan_id = req.query_params.get('scan_history')

		if project:
			qs = Exposure.objects.filter(scan_history__domain__project__slug=project)
		elif target_id:
			qs = Exposure.objects.filter(scan_history__domain__id=target_id)
		elif scan_id:
			qs = Exposure.objects.filter(scan_history__id=scan_id)
		else:
			return Exposure.objects.none()

		if scan_id and project:
			qs = qs.filter(scan_history__id=scan_id)

		exposure_status = req.query_params.get('status')
		if exposure_status:
			qs = qs.filter(status=exposure_status)

		exp_type = req.query_params.get('type')
		if exp_type:
			qs = qs.filter(type__contains=[exp_type])

		self.queryset = qs.distinct().order_by('-risk_score')
		return self.queryset

	def partial_update(self, request, *args, **kwargs):
		allowed_fields = {'status'}
		if set(request.data.keys()) - allowed_fields:
			return Response(
				{'detail': 'Only status updates are allowed.'},
				status=status.HTTP_400_BAD_REQUEST,
			)
		instance = self.get_object()
		write_ser = ExposureStatusUpdateSerializer(instance, data=request.data, partial=True)
		write_ser.is_valid(raise_exception=True)
		instance = write_ser.save()
		return Response(ExposureSerializer(instance, context={'request': request}).data)

class CVEDetails(APIView):
	"""
	API view for retrieving detailed CVE information.
	Supports checking the local database first and falling back to live NVD/EPSS enrichment.
	Also fetches additional threat intelligence context from cve.circl.lu.
	"""
	permission_classes = [IsPenetrationTester]
	
	def get(self, request):
		"""
		Retrieve CVE details, performing live enrichment if the CVE is not in the database.

		Args:
			request: DRF request object containing query parameters.
				- query_params.cve_id (str): The CVE identifier, e.g., 'CVE-2024-1234'
				  Also accepts bare YYYY-NNNNN format (e.g., '2024-1234').

		Returns:
			Response: A DRF Response object with either the CVE details or an error message.
		"""
		import re as _re

		req = self.request
		cve_id = req.query_params.get('cve_id')

		if not cve_id:
			return Response({
				'status': False,
				'message': 'CVE ID not provided'
			})

		from reNgine.cve_enrichment import CVEEnrichmentService
		from startScan.models import CveId

		# Normalize: bare YYYY-NNNNN → CVE-YYYY-NNNNN so DB lookups and
		# external API calls always use the canonical format.
		formatted_cve_id = cve_id.upper().strip()
		if _re.match(r'^\d{4}-\d+$', formatted_cve_id):
			formatted_cve_id = 'CVE-' + formatted_cve_id

		# 1. Check if the CVE exists in the local database
		try:
			cve_obj = CveId.objects.get(name__iexact=formatted_cve_id)
			logger.info("Found %s in local database", formatted_cve_id)

			# Lazy re-enrichment: if the record exists but CVSS data is missing,
			# attempt to fill it in now (e.g. first created during scanning before
			# NVD data was available).
			if cve_obj.cvss_v31_base_score is None:
				logger.info("CVE %s has no CVSS data, attempting re-enrichment", formatted_cve_id)
				try:
					service = CVEEnrichmentService()
					refreshed = service.enrich_cve(formatted_cve_id)
					if refreshed:
						cve_obj = refreshed
				except Exception as e:
					logger.warning("Re-enrichment failed for %s: %s", formatted_cve_id, e)

		except CveId.DoesNotExist:
			# 2. Attempt live enrichment from NVD and EPSS APIs
			logger.info("CVE %s not in database, attempting enrichment...", formatted_cve_id)
			try:
				service = CVEEnrichmentService()
				cve_obj = service.enrich_cve(formatted_cve_id)

				if not cve_obj:
					return Response({
						'status': False,
						'message': f'CVE {formatted_cve_id} not found in official sources'
					})

				logger.info("Successfully enriched %s", formatted_cve_id)
			except Exception as e:
				logger.error("Enrichment failed for %s: %s", formatted_cve_id, e)
				return Response({
					'status': False,
					'message': f'Failed to enrich CVE data: {str(e)}'
				})

		# 3. Fetch additional context and references from CIRCL.LU API
		# Always use the normalized CVE-YYYY-NNNNN format.
		circl_data = {}
		try:
			response = requests.get(f'https://cve.circl.lu/api/cve/{formatted_cve_id}', timeout=10)
			if response.status_code == 200:
				circl_data = response.json() or {}
		except Exception as e:
			logger.warning("CIRCL.LU lookup failed for %s: %s", formatted_cve_id, e)

		# 4. Compile the full enriched data dictionary
		circl_summary = circl_data.get('summary', '') or ''
		result = {
			'id': formatted_cve_id,
			'summary': circl_summary or cve_obj.ai_risk_assessment or 'No summary available',
			'assigner': circl_data.get('assigner', 'N/A'),
			'ai_risk_assessment': cve_obj.ai_risk_assessment,

			# NVD Data
			'cvss': circl_data.get('cvss') or cve_obj.cvss_v31_base_score,
			'cvss_v31_base_score': cve_obj.cvss_v31_base_score,
			'cvss_vector': circl_data.get('cvss-vector', 'N/A'),

			# CVSS Impact Breakdown
			'attack_vector': cve_obj.attack_vector,
			'attack_complexity': cve_obj.attack_complexity,
			'privileges_required': cve_obj.privileges_required,
			'user_interaction': cve_obj.user_interaction,
			'confidentiality_impact': cve_obj.confidentiality_impact,
			'integrity_impact': cve_obj.integrity_impact,
			'availability_impact': cve_obj.availability_impact,

			# EPSS Data
			'epss_score': cve_obj.epss_score,
			'epss_percentile': cve_obj.epss_percentile,

			# Threat Data
			'is_cisa_kev': cve_obj.is_cisa_kev,
			'is_poc': getattr(cve_obj, 'is_poc', False),
			'is_template': getattr(cve_obj, 'is_template', False),
			'vulnerability_type': cve_obj.vulnerability_type,

			# Timeline
			'published_date': cve_obj.published_date.isoformat() if cve_obj.published_date else None,
			'last_modified_date': cve_obj.last_modified_date.isoformat() if cve_obj.last_modified_date else None,

			# References
			'references': circl_data.get('references', []),
		}

		return Response({
			'status': True,
			'result': result
		})


class GenerateCveDescription(APIView):
	"""Generate and save an AI-written description for a CVE via the active LLM."""
	permission_classes = [IsPenetrationTester]

	def post(self, request):
		import re as _re
		from reNgine.llm import LLMVulnerabilityReportGenerator as LLMReportGen
		from dashboard.models import LLMConfig
		from startScan.models import CveId

		cve_id = request.data.get('cve_id')
		if not cve_id:
			return Response({'status': False, 'message': 'cve_id is required'}, status=400)

		formatted_cve_id = cve_id.upper().strip()
		if _re.match(r'^\d{4}-\d+$', formatted_cve_id):
			formatted_cve_id = 'CVE-' + formatted_cve_id

		if not LLMConfig.objects.filter(is_active=True).exists():
			return Response({'status': False, 'message': 'No active LLM configuration found'}, status=400)

		try:
			cve_obj = CveId.objects.get(name__iexact=formatted_cve_id)
		except CveId.DoesNotExist:
			return Response({'status': False, 'message': f'CVE {formatted_cve_id} not found in database'}, status=404)

		prompt = f"Analyze the vulnerability {formatted_cve_id}."
		if cve_obj.cvss_v31_base_score:
			prompt += f" CVSS v3.1 base score: {cve_obj.cvss_v31_base_score}."
		if cve_obj.attack_vector:
			prompt += f" Attack vector: {cve_obj.attack_vector}."
		prompt += " Provide a concise description of what this vulnerability is, its impact, and recommended mitigation steps."

		report_gen = LLMReportGen(logger=logger)
		response = report_gen.get_vulnerability_description(prompt)
		if not response or not response.get('status'):
			return Response({'status': False, 'message': response.get('error', 'LLM generation failed')}, status=500)

		description = response.get('description', '')
		impact = response.get('impact', '')
		remediation = response.get('remediation', '')
		assessment = f"**Description**:\n{description}\n\n**Impact**:\n{impact}\n\n**Mitigation**:\n{remediation}"

		update_fields = ['ai_risk_assessment']
		cve_obj.ai_risk_assessment = assessment
		if remediation:
			cve_obj.mitigation_ideas = remediation
			update_fields.append('mitigation_ideas')
		cve_obj.save(update_fields=update_fields)
		logger.info("Generated AI description for %s", formatted_cve_id)

		return Response({
			'status': True,
			'description': description,
			'impact': impact,
			'remediation': remediation,
			'ai_risk_assessment': assessment,
		})


class FetchMostCommonVulnerability(APIView):
	permission_classes = [IsPenetrationTester]
	def post(self, request):
		req = self.request
		data = req.data

		try:
			limit = data.get('limit', 20)
			project_slug = data.get('slug')
			scan_history_id = data.get('scan_history_id')
			target_id = data.get('target_id')
			is_ignore_info = data.get('ignore_info', False)

			response = {}
			response['status'] = False

			if project_slug:
				project = Project.objects.get(slug=project_slug)
				vulnerabilities = Vulnerability.objects.filter(target_domain__project=project)
			else:
				vulnerabilities = Vulnerability.objects.all()


			if scan_history_id:
				vuln_query = (
					vulnerabilities
					.filter(scan_history__id=scan_history_id)
					.values("name", "severity")
				)
				if is_ignore_info:
					most_common_vulnerabilities = (
						vuln_query
						.exclude(severity=0)
						.annotate(count=Count('name'))
						.order_by("-count")[:limit]
					)
				else:
					most_common_vulnerabilities = (
						vuln_query
						.annotate(count=Count('name'))
						.order_by("-count")[:limit]
					)

			elif target_id:
				vuln_query = vulnerabilities.filter(target_domain__id=target_id).values("name", "severity")
				if is_ignore_info:
					most_common_vulnerabilities = (
						vuln_query
						.exclude(severity=0)
						.annotate(count=Count('name'))
						.order_by("-count")[:limit]
					)
				else:
					most_common_vulnerabilities = (
						vuln_query
						.annotate(count=Count('name'))
						.order_by("-count")[:limit]
					)

			else:
				vuln_query = vulnerabilities.values("name", "severity")
				if is_ignore_info:
					most_common_vulnerabilities = (
						vuln_query.exclude(severity=0)
						.annotate(count=Count('name'))
						.order_by("-count")[:limit]
					)
				else:
					most_common_vulnerabilities = (
						vuln_query.annotate(count=Count('name'))
						.order_by("-count")[:limit]
					)


			most_common_vulnerabilities = [vuln for vuln in most_common_vulnerabilities]

			if most_common_vulnerabilities:
				response['status'] = True
				response['result'] = most_common_vulnerabilities
		except Exception as e:
			logger.exception("Unexpected error: %s", e)
			response = {}

		return Response(response)


class FetchMostVulnerable(APIView):
	permission_classes = [IsPenetrationTester]
	def post(self, request):
		req = self.request
		data = req.data

		project_slug = data.get('slug')
		scan_history_id = data.get('scan_history_id')
		target_id = data.get('target_id')
		limit = data.get('limit', 20)
		is_ignore_info = data.get('ignore_info', False)

		response = {}
		response['status'] = False

		if project_slug:
			project = Project.objects.get(slug=project_slug)
			subdomains = Subdomain.objects.filter(target_domain__project=project)
			domains = Domain.objects.filter(project=project)
		else:
			subdomains = Subdomain.objects.all()
			domains = Domain.objects.all()

		if scan_history_id:
			subdomain_query = subdomains.filter(scan_history__id=scan_history_id)
			if is_ignore_info:
				most_vulnerable_subdomains = (
					subdomain_query
					.annotate(
						vuln_count=Count('vulnerability__name', filter=~Q(vulnerability__severity=0))
					)
					.order_by('-vuln_count')
					.exclude(vuln_count=0)[:limit]
				)
			else:
				most_vulnerable_subdomains = (
					subdomain_query
					.annotate(vuln_count=Count('vulnerability__name'))
					.order_by('-vuln_count')
					.exclude(vuln_count=0)[:limit]
				)

				if most_vulnerable_subdomains:
					response['status'] = True
					response['result'] = (
						SubdomainSerializer(
							most_vulnerable_subdomains,
							many=True)
						.data
					)

		elif target_id:
			subdomain_query = subdomains.filter(target_domain__id=target_id)
			if is_ignore_info:
				most_vulnerable_subdomains = (
					subdomain_query
					.annotate(vuln_count=Count('vulnerability__name', filter=~Q(vulnerability__severity=0)))
					.order_by('-vuln_count')
					.exclude(vuln_count=0)[:limit]
				)
			else:
				most_vulnerable_subdomains = (
					subdomain_query
					.annotate(vuln_count=Count('vulnerability__name'))
					.order_by('-vuln_count')
					.exclude(vuln_count=0)[:limit]
				)

			if most_vulnerable_subdomains:
				response['status'] = True
				response['result'] = (
					SubdomainSerializer(
						most_vulnerable_subdomains,
						many=True)
					.data
				)
		else:
			if is_ignore_info:
				most_vulnerable_targets = (
					domains
					.annotate(vuln_count=Count('subdomain__vulnerability__name', filter=~Q(subdomain__vulnerability__severity=0)))
					.order_by('-vuln_count')
					.exclude(vuln_count=0)[:limit]
				)
			else:
				most_vulnerable_targets = (
					domains
					.annotate(vuln_count=Count('subdomain__vulnerability__name'))
					.order_by('-vuln_count')
					.exclude(vuln_count=0)[:limit]
				)

			if most_vulnerable_targets:
				response['status'] = True
				response['result'] = (
					DomainSerializer(
						most_vulnerable_targets,
						many=True)
					.data
				)

		return Response(response)


class DeleteVulnerability(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_MODIFY_SCAN_RESULTS

	def post(self, request):
		req = self.request
		ids = [int(i) for i in req.data.get('vulnerability_ids', [])]
		Vulnerability.objects.filter(id__in=ids).delete()
		return Response({'status': True})

