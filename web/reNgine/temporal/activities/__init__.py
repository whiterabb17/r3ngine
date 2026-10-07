"""
Temporal Activities for r3ngine scan pipeline.

All Python-side activities are implemented in this package. They are designed
to be called by the Python Orchestrator Worker listening on the
'python-orchestrator-queue'.

The activities delegate to the existing scan task functions in
web/reNgine/tasks/, which contain the full scan logic. Since the Python
worker runs with UnsandboxedWorkflowRunner, Django models and the existing
task code are fully accessible here without sandbox restrictions.

Design principle: Activities call existing RengineTask-decorated scan functions
directly, providing a lightweight proxy object (TemporalTaskProxy) that satisfies
the `self` interface expected by those tasks without requiring Celery.

Module map (flat, one file per domain; every module imports its shared glue
from `core` and never from this package root):

- core:            TemporalTaskProxy, `_run_task`, `_task_cancel_local`, resolve_target_host
- scan_lifecycle:  init / checkpoints / liveness / status / generic dispatch / finalisation
- discovery:       Tier 1 discovery and host/network recon tools
- enumeration:     Tiers 2-5 — HTTP crawl, port scan, screenshots, fuzzing, URL extraction, analysis
- proxies:         proxy list files, target blocking, proxy policy, proxy fetch
- vuln_scan:       Tier 6 — nuclei, DAST and the per-tool vulnerability scanners
- post_processing: Tier 7 — correlation, CVE enrichment, risk, graph sync, notifications, LLM/APME
- intel:           certificate / identity / API intel, geo, certificate resync, email security
- stress:          stress-test lifecycle
- maintenance:     startup sync, monitoring, scheduled scans, HackerOne program sync
- plugin_auth:     plugin lifecycle logging, per-tier plugin lookup, auth extraction

Sibling modules that were already separate (assessment_activities,
asset_correlation_activities, evidence_activities, followups, graph_activities)
are imported by the worker directly and are not re-exported here.

This module re-exports every name the former single-file implementation exposed,
so `from reNgine.temporal.activities import X` and the `reNgine.temporal_activities`
shim keep working unchanged.
"""

# Module-level imports of the former single-file implementation, kept so the
# package surface (and the star-importing shim) still carries these names.
import logging  # noqa: F401
import os  # noqa: F401
import threading  # noqa: F401
import yaml  # noqa: F401

from temporalio import activity  # noqa: F401
from reNgine.temporal.heartbeat import keep_alive  # noqa: F401
from django.utils import timezone  # noqa: F401

from reNgine.scan_context import ScanContext  # noqa: F401
from reNgine.utils.logger import get_module_logger, format_exception_for_log  # noqa: F401
from reNgine.tasks.auth_discovery import (  # noqa: F401
    _fetch_with_proxy_retry,
    _extract_login_forms,
)
from reNgine.common_func import get_proxy_list, get_random_proxy, merge_imported_subdomains  # noqa: F401
from targetApp.models import normalize_manual_subdomains  # noqa: F401
from reNgine.utils.task import activity_heartbeat_safe  # noqa: F401
from startScan.models import Subdomain  # noqa: F401

logger = get_module_logger(__name__)

from reNgine.temporal.activities.core import (  # noqa: E402
    resolve_target_host,
    TemporalTaskProxy,
    _start_scan_task_proxy,
    _task_cancel_local,
    _run_task,
)
from reNgine.temporal.activities.scan_lifecycle import (  # noqa: E402
    load_checkpoint_activity,
    save_checkpoint_activity,
    initialize_scan_tasks_activity,
    update_scan_status_activity,
    target_profiling_activity,
    check_scan_alive_activity,
    _PERMITTED_GENERIC_TASKS,
    run_generic_task_activity,
    finalize_subscan_activity,
    finalize_failed_scan_activity,
    check_scan_queue_status_activity,
    get_scan_final_status_activity,
)
from reNgine.temporal.activities.discovery import (  # noqa: E402
    run_subdomain_discovery_activity,
    run_amass_intel_discovery_activity,
    run_firewall_vpn_scan_activity,
    run_dns_security_activity,
    parse_discovery_results_activity,
    run_dnsx_activity,
    run_wafw00f_activity,
    run_fping_activity,
    run_arpscan_activity,
    run_mapcidr_activity,
    run_sshaudit_activity,
    get_discovered_services_activity,
    get_discovered_ips_activity,
    run_getasn_activity,
    run_netdetect_activity,
    run_jswhois_activity,
    run_whoisdomain_activity,
    run_bbot_activity,
)
from reNgine.temporal.activities.chunked import (  # noqa: E402
    plan_chunked_task_activity,
    run_chunked_task_batch_activity,
    finalize_chunked_task_activity,
    run_chunked_task_follow_up_activity,
)
from reNgine.temporal.activities.enumeration import (  # noqa: E402
    seed_endpoints_for_crawl_activity,
    run_http_crawl_activity,
    run_http_crawl_bridge_activity,
    parse_http_crawl_results_activity,
    run_port_scan_activity,
    run_tor_new_circuit_activity,
    run_screenshot_activity,
    run_fetch_url_activity,
    parse_enumeration_results_activity,
    run_dir_file_fuzz_activity,
    parse_fuzz_results_activity,
    run_target_dedup_activity,
    run_web_api_discovery_activity,
    run_waf_detection_activity,
    run_secret_scanning_activity,
    parse_analysis_results_activity,
    prepare_port_scan_activity,
    parse_port_scan_results_activity,
    run_xurlfind3r_activity,
    run_urlfinder_activity,
    run_cariddi_activity,
    run_bup_activity,
    run_arjun_activity,
    run_feroxbuster_activity,
    run_gf_activity,
    run_gf_on_all_endpoints_activity,
    run_param_discovery_activity,
    run_urlparser_activity,
)
from reNgine.temporal.activities.proxies import (  # noqa: E402
    PROXY_LIST_ROOT,
    create_proxy_list_activity,
    check_target_blocking_activity,
    get_proxy_policy_activity,
    cleanup_proxy_list_activity,
    fetch_proxies_activity,
)
from reNgine.temporal.activities.vuln_scan import (  # noqa: E402
    gather_nuclei_tags_activity,
    run_nuclei_activity,
    run_smugglex_activity,
    run_second_order_activity,
    run_nuclei_dast_activity,
    run_crlfuzz_activity,
    run_dalfox_activity,
    run_s3scanner_activity,
    run_acunetix_activity,
    submit_live_subdomains_to_acunetix_activity,
    run_cpanel_scan_activity,
    run_wpscan_activity,
    run_wptaint_scan_activity,
    run_react2shell_activity,
    run_semgrep_activity,
    run_vigolium_scan_activity,
    run_vigolium_harvest_activity,
    run_vigolium_discovery_activity,
    run_vigolium_analysis_activity,
    post_scan_processing_activity,
    mark_vulnerability_scan_complete_activity,
    run_waf_bypass_activity,
    parse_assessment_results_activity,
    run_wpprobe_activity,
    run_search_vulns_activity,
    run_grype_scan_activity,
    run_trivy_secret_scan_activity,
    run_vigolium_audit_activity,
)
from reNgine.temporal.activities.post_processing import (  # noqa: E402
    correlate_vulnerabilities_activity,
    correlate_exposures_activity,
    enrich_scan_cves_activity,
    calculate_risk_scores_activity,
    generate_impact_assessment_activity,
    sync_graph_activity,
    send_scan_notification_activity,
    run_llm_apme_activity,
    recalculate_apme_activity,
)
from reNgine.temporal.activities.intel import (  # noqa: E402
    run_certificate_intel_activity,
    run_identity_infra_activity,
    run_api_intel_activity,
    enrich_identities_activity,
    geo_localize_activity,
    resync_certificate_activity,
    run_email_security_activity,
    _run_email_security_sync,
)
from reNgine.temporal.activities.stress import (  # noqa: E402
    init_stress_test_activity,
    run_stress_tool_activity,
    finalize_stress_test_activity,
)
from reNgine.temporal.activities.maintenance import (  # noqa: E402
    run_startup_sync_activity,
    tool_probe_activity,
    run_monitoring_check_activity,
    setup_scheduled_scan_activity,
    import_hackerone_programs_activity,
    sync_bookmarked_programs_activity,
)
from reNgine.temporal.activities.plugin_auth import (  # noqa: E402
    get_enabled_plugins_for_tier_activity,
    extract_auth_for_url_activity,
    log_plugin_start_activity,
    log_plugin_end_activity,
)
