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

class GPTAttackSuggestion(APIView):
	"""API Endpoint to generate LLM-powered attack surface suggestions for a given subdomain.

	Provides a structured security analysis and potential attack vectors based on target recon data.
	"""
	permission_classes = [IsPenetrationTester]
	
	def get(self, request):
		"""Retrieve or trigger LLM generation of attack surface analysis for a subdomain.

		Args:
			request (Request): Django Rest Framework Request object.
				Requires 'subdomain_id' in GET parameters.

		Returns:
			Response: JSON response with 'status', 'description', and 'subdomain_name' or error details.
		"""
		req = self.request
		subdomain_id = req.query_params.get('subdomain_id')
		if not subdomain_id:
			return Response({
				'status': False,
				'error': 'Missing GET param Subdomain `subdomain_id`'
			}, status=status.HTTP_400_BAD_REQUEST)
		try:
			subdomain = Subdomain.objects.get(id=subdomain_id)
		except Exception as e:
			return Response({
				'status': False,
				'error': 'Subdomain not found with id ' + subdomain_id
			}, status=status.HTTP_404_NOT_FOUND)
		if subdomain.attack_surface:
			return Response({
				'status': True,
				'subdomain_name': subdomain.name,
				'description': subdomain.attack_surface
			})
		ip_addrs = subdomain.ip_addresses.all()
		open_ports_str = ''
		for ip in ip_addrs:
			ports = ip.ports.all()
			for port in ports:
				open_ports_str += f'{port.number}/{port.service_name}, '
		tech_used = ''
		for tech in subdomain.technologies.all():
			tech_used += f'{tech.name}, '
		llm_input = f'''
			Subdomain Name: {subdomain.name}
			Subdomain Page Title: {subdomain.page_title}
			Open Ports: {open_ports_str}
			HTTP Status: {subdomain.http_status}
			Technologies Used: {tech_used}
			Content type: {subdomain.content_type}
			Web Server: {subdomain.webserver}
			Page Content Length: {subdomain.content_length}
		'''
		llm_input = re.sub(r'\t', '', llm_input)
		gpt = LLMAttackSuggestionGenerator(logger)
		response = gpt.get_attack_suggestion(llm_input)
		response['subdomain_name'] = subdomain.name
		if response.get('status'):
			subdomain.attack_surface = response.get('description')
			subdomain.save()
			return Response(response)
		else:
			return Response(response, status=status.HTTP_500_INTERNAL_SERVER_ERROR)


class LLMVulnerabilityReportGenerator(APIView):
	"""API Endpoint to generate detailed vulnerability reports using LLMs.

	Triggers a Celery task that queries the LLM config and enrich descriptions/impacts/remediations.
	"""
	permission_classes = [IsPenetrationTester]
	
	def get(self, request):
		"""Enrich vulnerability with LLM generated descriptions and mitigation options.

		Args:
			request (Request): Django Rest Framework Request object.
				Requires vulnerability 'id' in GET parameters.

		Returns:
			Response: JSON response containing description, impact, remediation, and references.
		"""
		req = self.request
		vulnerability_id = req.query_params.get('id')
		if not vulnerability_id:
			return Response({
				'status': False,
				'error': 'Missing GET param Vulnerability `id`'
			}, status=status.HTTP_400_BAD_REQUEST)
		response = llm_vulnerability_description(vulnerability_id)
		if response and response.get('status'):
			return Response(response)
		else:
			return Response(response, status=status.HTTP_500_INTERNAL_SERVER_ERROR)



class OllamaManager(APIView):
	permission_classes = [HasPermission]
	permission_required = PERM_MODIFY_SYSTEM_CONFIGURATIONS

	def get(self, request):
		"""
		API to download Ollama Models
		sends a POST request to download the model
		"""
		req = self.request
		model_name = req.query_params.get('model')
		response = {
			'status': False
		}
		try:
			pull_model_api = f'{OLLAMA_INSTANCE}/api/pull'
			_response = requests.post(
				pull_model_api, 
				json={
					'name': model_name,
					'stream': False
				}
			).json()
			if _response.get('error'):
				response['status'] = False
				response['error'] = _response.get('error')
			else:
				response['status'] = True
		except Exception as e:
			response['error'] = str(e)		
		return Response(response)
	
	def delete(self, request):
		req = self.request
		model_name = req.query_params.get('model')
		delete_model_api = f'{OLLAMA_INSTANCE}/api/delete'
		response = {
			'status': False
		}
		try:
			_response = requests.delete(
				delete_model_api, 
				json={
					'name': model_name
				}
			).json()
			if _response.get('error'):
				response['status'] = False
				response['error'] = _response.get('error')
			else:
				response['status'] = True
		except Exception as e:
			response['error'] = str(e)
		return Response(response)
	
	def put(self, request):
		req = self.request
		model_name = req.query_params.get('model')
		# check if model_name is in DEFAULT_GPT_MODELS
		response = {
			'status': False
		}
		use_ollama = True
		if any(model['name'] == model_name for model in DEFAULT_GPT_MODELS):
			use_ollama = False
		try:
			OllamaSettings.objects.update_or_create(
				defaults={
					'selected_model': model_name,
					'use_ollama': use_ollama
				},
				id=1
			)
			response['status'] = True
		except Exception as e:
			response['error'] = str(e)
		return Response(response)

