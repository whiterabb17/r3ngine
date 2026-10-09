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
from django.db.models import (
	CharField, Count, F, IntegerField, Max, OuterRef, Q, Subquery, Value)
from django.utils import timezone
from packaging import version
from django.template.defaultfilters import slugify
from datetime import datetime
from django.db.models.functions import Coalesce, Lower
from rest_framework import mixins, viewsets, serializers, status
from rest_framework.pagination import PageNumberPagination
from rest_framework_datatables.pagination import DatatablesPageNumberPagination
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.authentication import SessionAuthentication
from rest_framework.permissions import IsAuthenticated, AllowAny
from rest_framework.renderers import JSONRenderer
from django.http import FileResponse, Http404, HttpResponse
import mimetypes
import os
import shutil


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
    InitiateScan, InitiateSubTask, StopScan, ResumeScan, PauseScan, UnpauseScan, SetScanHardwareProfile,
    FetchSubscanResults, ListSubScans, StartWorkflowView, ScanActivityRetryAPIView,
    DirectoryFileDispatchView, DirectoryFileDeleteView, ExtractAuthLogsView,
)
from api.views.scan_status import ScanStatus, ListScanHistory, ListActivityLogsViewSet, ListScanLogsViewSet
from api.views.targets import (
    AddTarget, UpdateTarget, ListTargetsDatatableViewSet, AddManualSubdomain,
    DeleteSubdomain, ToggleSubdomainImportantStatus, QueryInterestingSubdomains,
    ParameterSummaryView, SecretLeakViewSet, EmailBreachViewSet, CheckEmailBreach,
    ScreenshotViewSet, DirectoryViewSet,
    ListOrganizations, CreateOrganization, UpdateOrganization, ListTargetsInOrganization,
    ListTargetsWithoutOrganization,
)
from api.views.subdomains import (
    ListTechnology, ListPorts, ListSubdomains, ListIPs, IpAddressViewSet, SubdomainsViewSet,
    SubdomainChangesViewSet, InterestingSubdomainViewSet, SubdomainDatatableViewSet,
)
from api.views.endpoints import (
    EndPointChangesViewSet, InterestingEndpointViewSet, ListEndpoints, EndpointPagination,
    EndPointViewSet, ParameterViewSet,
)
from api.views.vulns import (
    VulnerabilityPagination, VulnerabilityViewSet, ExposurePagination, ExposureViewSet,
    CVEDetails, GenerateCveDescription, FetchMostCommonVulnerability, FetchMostVulnerable, DeleteVulnerability,
    VulnerabilityReport,
)
from api.views.recon import (
    OsintStagingViewSet, MonitoringDiscoveryViewSet, WafDetector, AddReconNote,
    SearchHistoryView, UniversalSearch, GetScanGraphData, GetTargetGraphData, GetNodeDetails,
    Whois, ReverseWhois, DomainIPHistory, CMSDetector, IPToDomain, VisualiseData,
    ListDorkTypes, ListEmails, ListDorks, ListEmployees, ListOsintUsers, ListMetadata,
)
from api.views.notes import ListTodoNotes, ToggleTodoStatus, ToggleNoteImportance, DeleteReconNote
from api.views.llm import GPTAttackSuggestion, LLMVulnerabilityReportGenerator, OllamaManager
from api.views.tools import (
    UploadWordlist, GetWordlistContent, GetEngineDetails, CreateEngine, UpdateEngine,
    LaunchADAssessmentFromSubdomain,
    _WORKFLOW_REGISTRY,
    _resolve_tool, _ToolCommandView, UpdateTool, GO_BIN_DIR, GITHUB_TOOLS_DIR, _BINARY_NAME_RE,
    _remove_installed_tool_files, UninstallTool, GetExternalToolCurrentVersion,
    GithubToolCheckGetLatestRelease, ListWordlists, ListTools, ListEngines, GetFileContents,
)
from api.views.settings import (
    ToggleBugBountyModeView, ToggleScanQueueingView, UpdateThemeView, SOCSettingsViewSet,
    RengineSystemSettingsAPIView, RengineUpdateCheck, NotificationSettingsAPIView,
    ReportSettingsAPIView, SystemHealthAPIView, GetSystemLogs,
    ProxySettingsAPIView, ProxyFetchAPIView, TorStatusAPIView, TorExitIPAPIView,
    ListConfigurations, HardwareProfileViewSet,
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
from reNgine.definitions import INTERNAL_ERROR_MESSAGE
