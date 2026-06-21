from django.urls import include, path, re_path
from rest_framework import routers
from rest_framework_simplejwt.views import (
    TokenObtainPairView,
    TokenRefreshView,
)
from rest_framework.throttling import AnonRateThrottle


class AuthRateThrottle(AnonRateThrottle):
    rate = '5/min'


class ThrottledTokenObtainPairView(TokenObtainPairView):
    throttle_classes = [AuthRateThrottle]

from .views import *
from .dashboard_views import DashboardAPIView, CWEInfoAPIView
from .target_summary_views import TargetSummaryAPIView
from .scan_summary_views import ScanSummaryAPIView, ScanAiExportAPIView

from .scheduled_scans import ScheduledScanViewSet
from .subscans import SubScanViewSet
from .scan_history import ScanHistoryViewSet
from .users import UserManageViewSet
from .stress_testing_views import StressTestingAPIView, StressTestingHistoryAPIView
from .apme_views import AttackPathsAPIView, TriggerLLMAPMEAPIView, RecalculateAttackPathsAPIView, AttackPathExplanationAPIView
from .scan_configuration import ScanConfigurationAPI
from .config_migration_views import ExportConfig, ImportConfig, ExportScanResults


app_name = 'api'
router = routers.DefaultRouter()
router.register(r'listDatatableSubdomain', SubdomainDatatableViewSet, basename='subdomain-datatable')
router.register(r'listTargets', ListTargetsDatatableViewSet, basename='target-datatable')
router.register(r'listSubdomains', SubdomainsViewSet, basename='subdomain-list')
router.register(r'listEndpoints', EndPointViewSet, basename='endpoint-list')
router.register(r'listDirectories', DirectoryViewSet, basename='directory')
router.register(r'listVulnerability', VulnerabilityViewSet, basename='vulnerability-list')
router.register(r'listExposures', ExposureViewSet, basename='exposure-list')
router.register(r'listInterestingSubdomains', InterestingSubdomainViewSet, basename='interesting-subdomain')
router.register(r'listInterestingEndpoints', InterestingEndpointViewSet, basename='interesting-endpoint')
router.register(r'listParameters', ParameterViewSet, basename='parameters-list')
router.register(r'listSubdomainChanges', SubdomainChangesViewSet, basename='subdomain-changes')
router.register(r'listEndPointChanges', EndPointChangesViewSet, basename='endpoint-changes')
router.register(r'listIps', IpAddressViewSet, basename='ip-address')
router.register(r'listActivityLogs', ListActivityLogsViewSet, basename='activity-log')
router.register(r'listScanLogs', ListScanLogsViewSet, basename='scan-log')
router.register(r'notifications', InAppNotificationManagerViewSet, basename='notification')
router.register(r'hackerone-programs', HackerOneProgramViewSet, basename='hackerone_program')
router.register(r'monitoring', MonitoringDiscoveryViewSet, basename='monitoring')
router.register(r'projects', ProjectViewSet, basename='projects')
router.register(r'secretLeaks', SecretLeakViewSet, basename='secret-leaks')
router.register(r'hardwareProfiles', HardwareProfileViewSet, basename='hardware-profiles')
router.register(r'scanProfiles', ScanProfileViewSet, basename='scan-profiles')

router.register(r'screenshots', ScreenshotViewSet, basename='screenshots')
router.register(r'osintStaging', OsintStagingViewSet, basename='osint-staging')
router.register(r'scheduledScans', ScheduledScanViewSet, basename='scheduled-scans')
router.register(r'subscans', SubScanViewSet, basename='subscans')
router.register(r'soc-settings', SOCSettingsViewSet, basename='soc-settings')
router.register(r'listScans', ScanHistoryViewSet, basename='list-scans')
router.register(r'users', UserManageViewSet, basename='users')


urlpatterns = [
    re_path(r'^', include(router.urls)),
    path(
        'add/target/',
        AddTarget.as_view(),
        name='addTarget'),
    path(
        'update/target/',
        UpdateTarget.as_view(),
        name='updateTarget'),
    path(
        'add/recon_note/',
        AddReconNote.as_view(),
        name='addReconNote'),
    path(
        'queryTechnologies/',
        ListTechnology.as_view(),
        name='listTechnologies'),
    path(
        'queryPorts/',
        ListPorts.as_view(),
        name='listPorts'),
    path(
        'queryIps/',
        ListIPs.as_view(),
        name='listIPs'),
    path(
        'queryInterestingSubdomains/',
        QueryInterestingSubdomains.as_view(),
        name='queryInterestingSubdomains'),
    path(
        'querySubdomains/',
        ListSubdomains.as_view(),
        name='querySubdomains'),
    path(
        'queryEndpoints/',
        ListEndpoints.as_view(),
        name='queryEndpoints'),
    path(
        'queryOsintUsers/',
        ListOsintUsers.as_view(),
        name='queryOsintUsers'),
    path(
        'queryMetadata/',
        ListMetadata.as_view(),
        name='queryMetadata'),
    path(
        'queryEmails/',
        ListEmails.as_view(),
        name='queryEmails'),
    path(
        'queryEmployees/',
        ListEmployees.as_view(),
        name='queryEmployees'),
    path(
        'queryDorks/',
        ListDorks.as_view(),
        name='queryDorks'),
    path(
        'queryDorkTypes/',
        ListDorkTypes.as_view(),
        name='queryDorkTypes'),
    path(
        'queryDorkTypes/',
        ListDorkTypes.as_view(),
        name='queryDorkTypes'),
    path(
        'queryAllScanResultVisualise/',
        VisualiseData.as_view(),
        name='queryAllScanResultVisualise'),
    path(
        'queryTargetsWithoutOrganization/',
        ListTargetsWithoutOrganization.as_view(),
        name='queryTargetsWithoutOrganization'),
    path(
        'queryTargetsInOrganization/',
        ListTargetsInOrganization.as_view(),
        name='queryTargetsInOrganization'),
    path(
        'listOrganizations/',
        ListOrganizations.as_view(),
        name='listOrganizations'),
    path(
        'createOrganization/',
        CreateOrganization.as_view(),
        name='createOrganization'),
    path(
        'updateOrganization/',
        UpdateOrganization.as_view(),
        name='updateOrganization'),
    path(
        'listEngines/',
        ListEngines.as_view(),
        name='listEngines'),
    path(
        'listWordlists/',
        ListWordlists.as_view(),
        name='listWordlists'),
    path(
        'listTools/',
        ListTools.as_view(),
        name='listTools'),
    path(
        'listConfigurations/',
        ListConfigurations.as_view(),
        name='listConfigurations'),
    path(
        'listSubScans/',
        ListSubScans.as_view(),
        name='listSubScans'),
    path(
        'listScanHistory/',
        ListScanHistory.as_view(),
        name='listScanHistory'),
    path(
        'listTodoNotes/',
        ListTodoNotes.as_view(),
        name='listTodoNotes'),
    path(
        'toggle/note/status/',
        ToggleTodoStatus.as_view(),
        name='toggle_note_status'),
    path(
        'toggle/note/importance/',
        ToggleNoteImportance.as_view(),
        name='toggle_note_importance'),
    path(
        'action/note/delete/',
        DeleteReconNote.as_view(),
        name='delete_note'),
    path(
        'listInterestingKeywords/',
        ListInterestingKeywords.as_view(),
        name='listInterestingKeywords'),
    path(
        'getFileContents/',
        GetFileContents.as_view(),
        name='getFileContents'),
    path(
        'vulnerability/report/',
        VulnerabilityReport.as_view(),
        name='vulnerability_report'),
    path(
        'tools/ip_to_domain/',
        IPToDomain.as_view(),
        name='ip_to_domain'),
    path(
        'tools/whois/',
        Whois.as_view(),
        name='whois'),
    path(
        'tools/reverse/whois/',
        ReverseWhois.as_view(),
        name='reverse_whois'),
    path(
        'tools/domain_ip_history',
        DomainIPHistory.as_view(),
        name='domain_ip_history'),
    path(
        'tools/cms_detector/',
        CMSDetector.as_view(),
        name='cms_detector'),
    path(
        'tools/cve_details/',
        CVEDetails.as_view(),
        name='cve_details'),
    path(
        'tools/cve_description_generate/',
        GenerateCveDescription.as_view(),
        name='cve_description_generate'),
    path(
        'tools/waf_detector/',
        WafDetector.as_view(),
        name='waf_detector'),
    path(
        'tools/gpt_vulnerability_report/',
        LLMVulnerabilityReportGenerator.as_view(),
        name='gpt_vulnerability_report_generator'),
    path(
        'tools/gpt_get_possible_attacks/',
        GPTAttackSuggestion.as_view(),
        name='gpt_get_possible_attacks'),
    path(
        'github/tool/get_latest_releases/',
        GithubToolCheckGetLatestRelease.as_view(),
        name='github_tool_latest_release'),
    path(
        'external/tool/get_current_release/',
        GetExternalToolCurrentVersion.as_view(),
        name='external_tool_get_current_release'),
    path(
        'tool/update/',
        UpdateTool.as_view(),
        name='update_tool'),
    path(
        'tool/uninstall/',
        UninstallTool.as_view(),
        name='uninstall_tool'),
	path(
        'tool/ollama/',
        OllamaManager.as_view(),
        name='ollama_manager'),
    path(
        'rengine/update/',
        RengineUpdateCheck.as_view(),
        name='check_rengine_update'),
    path(
        'rengine/system-settings/',
        RengineSystemSettingsAPIView.as_view(),
        name='rengine_system_settings'),
    path(
        'rengine/proxy-settings/',
        ProxySettingsAPIView.as_view(),
        name='rengine_proxy_settings'),
    path(
        'rengine/fetch-proxies/',
        ProxyFetchAPIView.as_view(),
        name='rengine_fetch_proxies'),
    path(
        'rengine/tor-status/',
        TorStatusAPIView.as_view(),
        name='rengine_tor_status'),
    path(
        'rengine/tor-exit-ip/',
        TorExitIPAPIView.as_view(),
        name='rengine_tor_exit_ip'),
    path(
        'action/directory-file/dispatch/',
        DirectoryFileDispatchView.as_view(),
        name='directory-file-dispatch',
    ),
    path(
        'action/directory-file/delete/',
        DirectoryFileDeleteView.as_view(),
        name='directory-file-delete',
    ),
    path(
        'action/subdomain/add/',
        AddManualSubdomain.as_view(),
        name='add_manual_subdomain'),
    path(
        'action/subdomain/delete/',
        DeleteSubdomain.as_view(),
        name='delete_subdomain'),
    path(
        'action/subdomain/<int:pk>/searchsploit/',
        RunSearchsploitAction.as_view(),
        name='run_searchsploit'),
    path(
        'action/vulnerability/delete/',
        DeleteVulnerability.as_view(),
        name='delete_vulnerability'),
    path(
        'action/rows/delete/',
        DeleteMultipleRows.as_view(),
        name='delete_rows'),
    path(
        'action/engine/create/',
        CreateEngine.as_view(),
        name='create_engine'),
    path(
        'action/wordlist/upload/',
        UploadWordlist.as_view(),
        name='upload_wordlist'),
    path(
        'action/wordlist/read/',
        GetWordlistContent.as_view(),
        name='read_wordlist'),
    path(
        'action/engine/get/',
        GetEngineDetails.as_view(),
        name='get_engine_details'),
    path(
        'action/engine/update/',
        UpdateEngine.as_view(),
        name='update_engine'),
    path(
        'toggle/monitoring/',
        ToggleMonitoringAPIView.as_view(),
        name='toggle_monitoring'),
    path(
        'toggle/subdomain/important/',
        ToggleSubdomainImportantStatus.as_view(),
        name='toggle_subdomain'),
    path(
        'action/initiate/subtask/',
        InitiateSubTask.as_view(),
        name='initiate_subscan'),
    path(
        'action/initiate/scan/',
        InitiateScan.as_view(),
        name='initiate_scan'),
    path(
        'action/stop/scan/',
        StopScan.as_view(),
        name='stop_scan'),
    path(
        'action/resume/scan/',
        ResumeScan.as_view(),
        name='resume_scan'),
    path(
        'action/pause/scan/',
        PauseScan.as_view(),
        name='pause_scan'),
    path(
        'action/unpause/scan/',
        UnpauseScan.as_view(),
        name='unpause_scan'),
    path(
        'fetch/results/subscan/',
        FetchSubscanResults.as_view(),
        name='fetch_subscan_results'),
    path(
        'fetch/most_vulnerable/',
        FetchMostVulnerable.as_view(),
        name='fetch_most_vulnerable'),
    path(
        'fetch/most_common_vulnerability/',
        FetchMostCommonVulnerability.as_view(),
        name='fetch_most_common_vulnerability'),
    path(
        'search/',
        UniversalSearch.as_view(),
        name='search'),
    path(
        'search/history/',
        SearchHistoryView.as_view(),
        name='search_history'),
    # API for fetching currently ongoing scans and upcoming scans
    path(
        'scan_status/',
        ScanStatus.as_view(),
        name='scan_status'),
    path(
        'action/create/project',
        CreateProjectApi.as_view(),
        name='create_project'),
    path(
        'toggle-bug-bounty-mode/', 
        ToggleBugBountyModeView.as_view(), 
        name='toggle_bug_bounty_mode'
    ),
    path(
        'toggle-scan-queueing-mode/', 
        ToggleScanQueueingView.as_view(), 
        name='toggle_scan_queueing_mode'
    ),
    path(
        'update-theme/',
        UpdateThemeView.as_view(),
        name='update_theme'
    ),
    path(
        'report-settings/',
        ReportSettingsAPIView.as_view(),
        name='report_settings'
    ),
    path(
        'settings/export/',
        ExportConfig.as_view(),
        name='settings_export'
    ),
    path(
        'settings/export/scan-results/',
        ExportScanResults.as_view(),
        name='settings_export_scan_results'
    ),
    path(
        'settings/import/',
        ImportConfig.as_view(),
        name='settings_import'
    ),
    path(
        'dashboard/<slug:slug>/',
        DashboardAPIView.as_view(),
        name='dashboard_api'
    ),
    path(
        'cwe-info/',
        CWEInfoAPIView.as_view(),
        name='cwe_info_api'
    ),
    path(
        'system/health/',
        SystemHealthAPIView.as_view(),
        name='system_health_api'
    ),
    path(
        'target-summary/<slug:slug>/<int:id>/',
        TargetSummaryAPIView.as_view(),
        name='target_summary_api'
    ),
    path(
        'scan-summary/<slug:slug>/<int:id>/',
        ScanSummaryAPIView.as_view(),
        name='scan_summary_api'
    ),
    path(
        'scan-summary/<slug:slug>/<int:id>/export-ai/',
        ScanAiExportAPIView.as_view(),
        name='scan_summary_export_ai_api'
    ),
    path(
        'notification-settings/',
        NotificationSettingsAPIView.as_view(),
        name='notification_settings_api'
    ),
    path(
        'media/',
        MobileMediaServeView.as_view(),
        name='mobile_media_serve'
    ),
    path(
        'stress-testing/history/',
        StressTestingHistoryAPIView.as_view(),
        name='stress_testing_history_api'
    ),
    path(
        'stress-testing/<int:id>/',
        StressTestingAPIView.as_view(),
        name='stress_testing_api'
    ),
    path(
        'parameters/summary/',
        ParameterSummaryView.as_view(),
        name='parameters_summary'
    ),
    path(
        'apme/paths/',
        AttackPathsAPIView.as_view(),
        name='apme_attack_paths'
    ),
    path(
        'apme/trigger/',
        TriggerLLMAPMEAPIView.as_view(),
        name='apme_trigger'
    ),
    path(
        'apme/recalculate/',
        RecalculateAttackPathsAPIView.as_view(),
        name='apme_recalculate'
    ),
    path(
        'apme/explain/',
        AttackPathExplanationAPIView.as_view(),
        name='apme_explain'
    ),
    path(
        'action/ad-assessment/from-subdomain/',
        LaunchADAssessmentFromSubdomain.as_view(),
        name='launch_ad_assessment_from_subdomain'
    ),
    path(
        'auth/token/',
        ThrottledTokenObtainPairView.as_view(),
        name='token_obtain_pair'
    ),
    path(
        'auth/token/refresh/',
        TokenRefreshView.as_view(),
        name='token_refresh'
    ),
    path(
        'scans/configuration/',
        ScanConfigurationAPI.as_view(),
        name='scan_configuration'
    ),
    # Graph and Observability (Phase 7)
    path(
        'graph/scan/<int:scan_id>/',
        GetScanGraphData.as_view(),
        name='get_scan_graph_data'
    ),
    path(
        'graph/target/<int:target_id>/',
        GetTargetGraphData.as_view(),
        name='get_target_graph_data'
    ),
    path(
        'graph/node/<str:node_id>/',
        GetNodeDetails.as_view(),
        name='get_node_details'
    ),
    path(
        'system/logs/',
        GetSystemLogs.as_view(),
        name='get_system_logs'
    ),
    path('plugins/', include('plugins.urls')),
    path(
        'push-token/register/',
        RegisterPushTokenView.as_view(),
        name='register_push_token',
    ),
    # Phase 2 — standalone workflow launcher
    path(
        'workflows/<str:workflow_slug>/start/',
        StartWorkflowView.as_view(),
        name='start-workflow',
    ),
    path(
        'linkedin/session/upload/',
        LinkedInSessionUploadView.as_view(),
        name='linkedin-session-upload'),
    path(
        'linkedin/session/status/',
        LinkedInSessionStatusView.as_view(),
        name='linkedin-session-status'),
    path(
        'linkedin/session/',
        LinkedInSessionDeleteView.as_view(),
        name='linkedin-session-delete'),
    path(
        'linkedin/session/helper/',
        LinkedInHelperScriptView.as_view(),
        name='linkedin-session-helper'),
]



# Dynamic plugin API URL discovery
# Each plugin may provide backend/api_urls.py to expose plugin-specific endpoints
# at /api/plugins/{plugin_slug}/
import importlib
import os as _os
from django.conf import settings as _settings

_plugins_data_dir = _os.path.join(_settings.BASE_DIR, 'plugins_data')
if _os.path.exists(_plugins_data_dir):
    for _plugin_slug in _os.listdir(_plugins_data_dir):
        _plugin_api_module = f"plugins_data.{_plugin_slug}.backend.api_urls"
        try:
            importlib.import_module(_plugin_api_module)
            urlpatterns.append(
                path(f'plugins/{_plugin_slug}/', include(
                    (_plugin_api_module, _plugin_slug),
                    namespace=_plugin_slug,
                ))
            )
        except ImportError:
            pass
        except Exception as _e:
            import logging as _logging
            _logging.getLogger(__name__).warning(
                f"Failed to load plugin URLs for {_plugin_slug}: {_e}")
