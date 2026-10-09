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
from rest_framework.permissions import IsAuthenticated, AllowAny, SAFE_METHODS
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
from reNgine.utils.request import client_ip
from reNgine.utils.secret_tokens import token_matches
from api.serializers import *
from reNgine.utils.graph import Neo4jManager
from reNgine.temporal_client import TemporalClientProvider, run_and_close

logger = logging.getLogger(__name__)

class ScanWorkerViewSet(viewsets.ModelViewSet):
	"""Remote workers: anyone with a role may list them, only sys admins change them."""
	serializer_class = ScanWorkerSerializer
	queryset = ScanWorker.objects.all()

	def get_permissions(self):
		if self.request.method in SAFE_METHODS:
			return [IsAuditor()]
		return [IsSysAdmin()]

	def get_queryset(self):
		return ScanWorker.objects.all().order_by('-id')

class WorkerHeartbeatAPIView(APIView):
	permission_classes = [AllowAny]
	def post(self, request):
		token = request.data.get('token')
		worker_name = request.data.get('worker_name')
		if not isinstance(token, str) or not isinstance(worker_name, str) or not token or not worker_name:
			return Response({'status': False, 'message': 'Missing token or worker_name'}, status=status.HTTP_400_BAD_REQUEST)
		worker = ScanWorker.objects.filter(name=worker_name).first()
		if not worker or not token_matches(token, worker.auth_token_hash):
			return Response({'status': False, 'message': 'Invalid token or worker not found'}, status=status.HTTP_403_FORBIDDEN)
		if not worker.is_active:
			return Response({'status': False, 'message': 'Worker is inactive'}, status=status.HTTP_403_FORBIDDEN)

		worker.last_heartbeat = timezone.now()
		worker.ip_address = client_ip(request)
		worker.save(update_fields=['last_heartbeat', 'ip_address'])
		return Response({'status': True, 'message': 'Heartbeat received'})

