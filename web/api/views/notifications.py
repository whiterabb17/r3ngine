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

class InAppNotificationManagerViewSet(viewsets.ModelViewSet):
	permission_classes = [IsAuthenticated]
	"""
		This class manages the notification model, provided CRUD operation on notif model
		such as read notif, clear all, fetch all notifications etc
	"""
	serializer_class = InAppNotificationSerializer
	pagination_class = None

	def get_queryset(self):
		# we will see later if user based notif is needed
		# return InAppNotification.objects.filter(user=self.request.user)
		project_slug = self.request.query_params.get('project_slug')
		queryset = InAppNotification.objects.all()
		if project_slug:
			queryset = queryset.filter(
				Q(project__slug=project_slug) | Q(notification_type='system')
			)
		return queryset.order_by('-created_at')

	@action(detail=False, methods=['post'])
	def mark_all_read(self, request):
		# marks all notification read
		project_slug = self.request.query_params.get('project_slug')
		queryset = self.get_queryset()

		if project_slug:
			queryset = queryset.filter(
				Q(project__slug=project_slug) | Q(notification_type='system')
			)
		queryset.update(is_read=True)
		return Response(status=HTTP_204_NO_CONTENT)

	@action(detail=True, methods=['post'])
	def mark_read(self, request, pk=None):
		# mark individual notification read when cliked
		notification = self.get_object()
		notification.is_read = True
		notification.save()
		return Response(status=HTTP_204_NO_CONTENT)

	@action(detail=False, methods=['get'])
	def unread_count(self, request):
		# this fetches the count for unread notif mainly for the badge
		project_slug = self.request.query_params.get('project_slug')
		queryset = self.get_queryset()
		if project_slug:
			queryset = queryset.filter(
				Q(project__slug=project_slug) | Q(notification_type='system')
			)
		count = queryset.filter(is_read=False).count()
		return Response({'count': count})

	@action(detail=False, methods=['post'])
	def clear_all(self, request):
		# when clicked on the clear button this must be called to clear all notif
		project_slug = self.request.query_params.get('project_slug')
		queryset = self.get_queryset()
		if project_slug:
			queryset = queryset.filter(
				Q(project__slug=project_slug) | Q(notification_type='system')
			)
		queryset.delete()
		return Response(status=HTTP_204_NO_CONTENT)


class RegisterPushTokenView(APIView):
	"""
	POST /mapi/push-token/register/

	Registers or updates an Expo push notification token for the authenticated user.
	Called by the mobile app on startup after the user logs in and notification
	permissions have been granted.

	Request body:
		token (str): The Expo push token string (e.g. ExponentPushToken[xxxx]).
		device_label (str, optional): Human-readable label for the device.

	Returns 200 on success with the token record. Returns 400 if no token provided.
	"""
	permission_classes = [IsAuthenticated]

	def post(self, request):
		token_str = request.data.get('token', '').strip()
		device_label = request.data.get('device_label', '').strip() or None

		if not token_str:
			return Response({'error': 'token is required'}, status=HTTP_400_BAD_REQUEST)

		# Upsert: if this exact token already exists update its owner/label,
		# otherwise create a new record. Using update_or_create on token value.
		obj, created = MobilePushToken.objects.update_or_create(
			token=token_str,
			defaults={
				'user': request.user,
				'device_label': device_label,
				'is_active': True,
			}
		)
		return Response({
			'id': obj.id,
			'token': obj.token,
			'device_label': obj.device_label,
			'is_active': obj.is_active,
			'created': created,
		})

	def delete(self, request):
		"""
		DELETE /mapi/push-token/register/

		Deactivates all push tokens for the authenticated user so the backend
		stops delivering push notifications to their devices.
		"""
		MobilePushToken.objects.filter(user=request.user).update(is_active=False)
		return Response(status=HTTP_204_NO_CONTENT)

