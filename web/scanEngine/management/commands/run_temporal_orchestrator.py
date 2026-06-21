"""
Django management command for the Temporal Python Orchestrator Worker.

This command starts the Python-side Temporal worker which:
  - Hosts the MasterScanWorkflow and NucleiPlannerWorkflow workflow definitions.
  - Registers all Python-based activities (Django DB reads/writes, Neo4j sync).
  - Listens on the 'python-orchestrator-queue' task queue.

The worker runs with UnsandboxedWorkflowRunner to allow transitive Django and
Celery imports that use custom threading.local proxied objects, which would
otherwise trigger sandbox validation failures.

Usage (inside the container):
    python manage.py run_temporal_orchestrator
"""

import asyncio
import datetime
import logging
import os
import signal
import sys
from concurrent.futures import ThreadPoolExecutor
from django.core.management.base import BaseCommand
from django.db import connections
from temporalio.client import (
    Client,
    Schedule,
    ScheduleActionStartWorkflow,
    ScheduleIntervalSpec,
    ScheduleOverlapPolicy,
    SchedulePolicy,
    ScheduleSpec,
    ScheduleState,
)
from temporalio.worker import Worker, UnsandboxedWorkflowRunner

logger = logging.getLogger(__name__)


class DjangoAwareThreadPoolExecutor(ThreadPoolExecutor):
    """Thread pool executor that manages Django DB connections per activity thread."""

    def submit(self, fn, *args, **kwargs):
        def wrapped_fn():
            from django.db import close_old_connections
            close_old_connections()
            try:
                return fn(*args, **kwargs)
            finally:
                connections.close_all()
        return super().submit(wrapped_fn)

# Workflows
from reNgine.temporal_workflows import (
    MasterScanWorkflow,
    NucleiPlannerWorkflow,
    SubScanWorkflow,
    StressTestWorkflow,
    StartupSyncWorkflow,
    ScheduledScanWorkflow,
    MonitoringWorkflow,
    GoExecutorTaskWorkflow,
    ApmeTaskWorkflow,
    RecalculateApmeWorkflow,
    IdentityEnrichmentWorkflow,
    GeoLocalizeWorkflow,
    HackerOneImportWorkflow,
    HackerOneSyncBookmarkedWorkflow,
    ProxyFetchWorkflow,
    # Phase 2 — rengine-ng standalone workflows
    UserHuntWorkflow,
    URLBypassWorkflow,
    WordPressWorkflow,
    HostReconWorkflow,
    CIDRReconWorkflow,
    CodeScanWorkflow,
    DomainReconWorkflow,
    SubdomainReconWorkflow,
    URLCrawlWorkflow,
    URLDirSearchWorkflow,
    URLFuzzWorkflow,
    URLParamsFuzzWorkflow,
    URLVulnWorkflow,
    URLAuthExtractWorkflow,
)

# Activities (all Python-side activities are registered here)
from reNgine.temporal_activities import (
    run_generic_task_activity,
    finalize_subscan_activity,
    finalize_failed_scan_activity,
    update_scan_status_activity,
    # Step 0: Task initialization & Target Profiling
    initialize_scan_tasks_activity,
    load_checkpoint_activity,
    save_checkpoint_activity,
    target_profiling_activity,
    check_scan_alive_activity,
    check_scan_queue_status_activity,
    get_enabled_plugins_for_tier_activity,

    # Tier 1: Discovery
    run_subdomain_discovery_activity,
    run_amass_intel_discovery_activity,
    run_firewall_vpn_scan_activity,
    run_dns_security_activity,
    parse_discovery_results_activity,
    seed_endpoints_for_crawl_activity,

    # TOR
    run_tor_new_circuit_activity,

    # Tier 2: Enumeration
    run_http_crawl_activity,
    parse_http_crawl_results_activity,
    run_port_scan_activity,
    run_screenshot_activity,
    run_fetch_url_activity,
    parse_enumeration_results_activity,

    # Tier 3/4: Fuzzing
    run_dir_file_fuzz_activity,
    parse_fuzz_results_activity,

    # Tier 5: Analysis
    run_web_api_discovery_activity,
    run_waf_detection_activity,
    run_secret_scanning_activity,
    parse_analysis_results_activity,

    # Tier 6: Assessment
    run_nuclei_activity,
    gather_nuclei_tags_activity,
    run_crlfuzz_activity,
    run_dalfox_activity,
    run_s3scanner_activity,
    run_acunetix_activity,
    run_cpanel_scan_activity,
    run_react2shell_activity,
    run_wpscan_activity,
    run_semgrep_activity,
    run_vigolium_scan_activity,
    run_vigolium_discovery_activity,
    run_vigolium_analysis_activity,
    mark_vulnerability_scan_complete_activity,
    run_waf_bypass_activity,

    parse_assessment_results_activity,

    # Tier 7: Post-Processing & Intel
    correlate_vulnerabilities_activity,
    correlate_exposures_activity,
    enrich_scan_cves_activity,
    calculate_risk_scores_activity,
    generate_impact_assessment_activity,
    sync_graph_activity,
    send_scan_notification_activity,

    # Stress Testing
    init_stress_test_activity,
    run_stress_tool_activity,
    finalize_stress_test_activity,

    # Startup sync
    run_startup_sync_activity,

    # Scheduled scan setup
    setup_scheduled_scan_activity,
    run_monitoring_check_activity,
    run_llm_apme_activity,
    recalculate_apme_activity,
    enrich_identities_activity,
    geo_localize_activity,
    import_hackerone_programs_activity,
    sync_bookmarked_programs_activity,
    fetch_proxies_activity,
    create_proxy_list_activity,
    cleanup_proxy_list_activity,

    # Phase 1 — rengine-ng workflow tool activities
    get_discovered_services_activity,
    get_discovered_ips_activity,
    run_getasn_activity,
    run_netdetect_activity,
    run_jswhois_activity,
    run_whoisdomain_activity,
    run_bbot_activity,
    run_dnsx_activity,
    run_wafw00f_activity,
    run_fping_activity,
    run_arpscan_activity,
    run_mapcidr_activity,
    run_sshaudit_activity,
    run_wpprobe_activity,
    run_search_vulns_activity,
    run_xurlfind3r_activity,
    run_urlfinder_activity,
    run_cariddi_activity,
    run_bup_activity,
    run_arjun_activity,
    run_feroxbuster_activity,
    run_gf_activity,
    run_grype_scan_activity,
    run_trivy_secret_scan_activity,
    run_vigolium_audit_activity,
    run_urlparser_activity,
    run_wptaint_scan_activity,
    run_param_discovery_activity,
    run_http_crawl_bridge_activity,
    extract_auth_for_url_activity,
)


# (task_name, first_fire_delay_seconds, always_run_per_restart)
# sync_cve_data fires after 5 minutes to allow sync_all_scans_to_graph to complete first.
# always_run_per_restart=True: workflow ID uses a timestamp so Temporal never skips it on
# multiple restarts within the same calendar day (date-based deduplication is intentional
# for the other tasks but must NOT apply to recover_stuck_scans).
_STARTUP_SYNC_TASKS = [
    ("sync_all_scans_to_graph", 30, False),
    ("sync_cisa_kev_catalog", 30, False),
    ("sync_semgrep_rules", 30, False),
    ("recover_stuck_scans", 30, True),
    ("sync_cve_data", 300, False),
    ("sync_epss_data", 10, False),
]


async def _register_startup_schedule(
    client: Client, task_name: str, today: str, interval_seconds: int = 30, always_run: bool = False
) -> None:
    """Create (or recreate) a one-shot Temporal Schedule for a startup sync task.

    The schedule is deleted first so each orchestrator restart gets a fresh one-shot
    trigger. By default the workflow ID embeds today's date so successful runs are not
    repeated within the same calendar day.

    always_run=True: uses a per-restart timestamp so Temporal never deduplicates the
    workflow away when the container restarts multiple times on the same calendar day.
    Use this for tasks that MUST execute on every restart (e.g. recover_stuck_scans).

    interval_seconds controls how soon after registration the task fires (approximately).
    """
    schedule_id = f"startup-sync-{task_name.replace('_', '-')}"
    # always_run tasks get a unique timestamp so Temporal never skips a second restart
    # on the same day. Other tasks keep the date suffix for once-per-day deduplication.
    run_key = datetime.datetime.utcnow().strftime("%Y%m%d-%H%M%S") if always_run else today
    workflow_id = f"{schedule_id}-{run_key}"

    # Remove stale schedule from the previous run (idempotent — ignore if absent)
    try:
        handle = client.get_schedule_handle(schedule_id)
        await handle.delete()
    except Exception:
        pass

    await client.create_schedule(
        schedule_id,
        Schedule(
            action=ScheduleActionStartWorkflow(
                StartupSyncWorkflow.run,
                args=[task_name],
                id=workflow_id,
                task_queue="python-orchestrator-queue",
            ),
            spec=ScheduleSpec(
                intervals=[ScheduleIntervalSpec(every=datetime.timedelta(seconds=interval_seconds))],
            ),
            policy=SchedulePolicy(overlap=ScheduleOverlapPolicy.SKIP),
            state=ScheduleState(
                limited_actions=True,
                remaining_actions=1,
                note=f"One-shot startup sync: {task_name}",
            ),
        ),
    )
    logger.info(f"[Startup] Registered one-shot schedule '{schedule_id}' → workflow '{workflow_id}' (fires in ~{interval_seconds}s)")


async def _register_daily_cron_schedule(
    client: Client, task_name: str, hour: int = 8, minute: int = 0
) -> None:
    """Create a daily cron schedule for a startup sync task."""
    from temporalio.client import ScheduleCalendarSpec, ScheduleRange
    schedule_id = f"daily-cron-{task_name.replace('_', '-')}"
    
    # Try to delete if exists to allow recreating/updating
    try:
        handle = client.get_schedule_handle(schedule_id)
        await handle.delete()
    except Exception:
        pass

    await client.create_schedule(
        schedule_id,
        Schedule(
            action=ScheduleActionStartWorkflow(
                StartupSyncWorkflow.run,
                args=[task_name],
                id=f"{schedule_id}-workflow",
                task_queue="python-orchestrator-queue",
            ),
            spec=ScheduleSpec(
                calendars=[ScheduleCalendarSpec(
                    hour=[ScheduleRange(hour)],
                    minute=[ScheduleRange(minute)],
                )],
            ),
            policy=SchedulePolicy(overlap=ScheduleOverlapPolicy.SKIP),
            state=ScheduleState(note=f"Daily cron sync: {task_name}"),
        ),
    )
    logger.info(f"[Startup] Registered daily cron schedule '{schedule_id}' for {hour:02d}:{minute:02d}")


class Command(BaseCommand):
    help = 'Runs the Python Temporal Orchestrator Worker on python-orchestrator-queue.'

    def handle(self, *args, **options):
        # Install plugin tools in THIS container before starting the worker.
        # Tools must be present in the orchestrator — not the web container — because
        # activities (swaks, smtp-user-enum, etc.) run here. This is the only place
        # tool installation should be triggered; AppConfig.ready() must not do it.
        try:
            from plugins.tasks import verify_all_plugin_tools
            import threading
            t = threading.Thread(target=verify_all_plugin_tools, daemon=True)
            t.start()
            t.join(timeout=120)  # wait up to 2 min for apt installs before starting worker
        except Exception as tool_err:
            logger.error(f"Plugin tool installation failed at startup: {tool_err}")

        # Clear needs_restart flags synchronously before entering the async event loop.
        try:
            from django.core.cache import cache
            from plugins.models import Plugin
            for plugin in Plugin.objects.all():
                cache.set(f"plugin_{plugin.slug}_needs_restart", False, timeout=None)
            self.stdout.write(self.style.SUCCESS("Cleared needs_restart flags for all plugins."))
        except Exception as cache_err:
            logger.error(f"Failed to clear needs_restart flags: {cache_err}")

        async def main():

            temporal_host = os.environ.get("TEMPORAL_HOST", "temporal:7233")
            namespace = os.environ.get("TEMPORAL_NAMESPACE", "default")

            self.stdout.write(self.style.MIGRATE_LABEL(
                f"Connecting to Temporal Server at {temporal_host} (namespace: {namespace})..."
            ))

            # -------------------------------------------------------------------
            # Connect with exponential-style retry backoff
            # -------------------------------------------------------------------
            client = None
            max_retries = 30
            retry_interval = 2
            for attempt in range(1, max_retries + 1):
                try:
                    client = await Client.connect(temporal_host, namespace=namespace)
                    break
                except Exception as conn_err:
                    if attempt == max_retries:
                        raise conn_err
                    self.stdout.write(self.style.WARNING(
                        f"Failed to connect to Temporal (attempt {attempt}/{max_retries}): "
                        f"{conn_err}. Retrying in {retry_interval}s..."
                    ))
                    await asyncio.sleep(retry_interval)

            # -------------------------------------------------------------------
            # Register the 'default' namespace (idempotent — ignores if already exists)
            # -------------------------------------------------------------------
            from temporalio.api.workflowservice.v1 import RegisterNamespaceRequest
            from google.protobuf.duration_pb2 import Duration
            try:
                await client.workflow_service.register_namespace(
                    RegisterNamespaceRequest(
                        namespace=namespace,
                        workflow_execution_retention_period=Duration(
                            seconds=7 * 24 * 60 * 60  # 7-day retention
                        )
                    )
                )
                self.stdout.write(self.style.SUCCESS(
                    f"Successfully registered Temporal namespace: '{namespace}'"
                ))
            except Exception as ns_err:
                # NamespaceAlreadyExistsError is expected on subsequent starts
                self.stdout.write(self.style.WARNING(
                    f"Namespace '{namespace}' registration check (might already exist): {ns_err}"
                ))

            # -------------------------------------------------------------------
            # Register one-shot startup sync schedules (Phase 4B)
            # -------------------------------------------------------------------
            today = datetime.date.today().isoformat()
            for task_name, interval_secs, always_run in _STARTUP_SYNC_TASKS:
                try:
                    await _register_startup_schedule(client, task_name, today, interval_secs, always_run)
                except Exception as sched_err:
                    # Non-fatal: log and continue — don't block worker startup
                    logger.error(f"[Startup] Failed to register schedule for '{task_name}': {sched_err}")
                    
            try:
                await _register_daily_cron_schedule(client, "sync_epss_data", hour=8, minute=0)
            except Exception as sched_err:
                logger.error(f"[Startup] Failed to register daily cron schedule for 'sync_epss_data': {sched_err}")

            # -------------------------------------------------------------------
            # Collect all registered activities
            # -------------------------------------------------------------------
            all_activities = [
                # Generic & Dynamic
                run_generic_task_activity,
                finalize_subscan_activity,
                finalize_failed_scan_activity,
                update_scan_status_activity,

                # Step 0
                initialize_scan_tasks_activity,
                load_checkpoint_activity,
                save_checkpoint_activity,
                target_profiling_activity,
                check_scan_alive_activity,
                check_scan_queue_status_activity,
                get_enabled_plugins_for_tier_activity,

                # Tier 1
                run_subdomain_discovery_activity,
                run_amass_intel_discovery_activity,
                run_firewall_vpn_scan_activity,
                run_dns_security_activity,
                parse_discovery_results_activity,
                seed_endpoints_for_crawl_activity,

                # TOR
                run_tor_new_circuit_activity,

                # Tier 2
                run_http_crawl_activity,
                run_http_crawl_bridge_activity,
                parse_http_crawl_results_activity,
                run_port_scan_activity,
                run_screenshot_activity,
                run_fetch_url_activity,
                parse_enumeration_results_activity,

                # Tier 3/4
                run_param_discovery_activity,
                run_dir_file_fuzz_activity,
                parse_fuzz_results_activity,

                # Tier 5
                run_web_api_discovery_activity,
                run_waf_detection_activity,
                run_secret_scanning_activity,
                parse_analysis_results_activity,

                # Tier 6
                run_nuclei_activity,
                gather_nuclei_tags_activity,
                run_crlfuzz_activity,
                run_dalfox_activity,
                run_s3scanner_activity,
                run_acunetix_activity,
                run_cpanel_scan_activity,
                run_react2shell_activity,
                run_wpscan_activity,
                run_semgrep_activity,
                run_wptaint_scan_activity,
                run_vigolium_scan_activity,
                run_vigolium_discovery_activity,
                run_vigolium_analysis_activity,
                mark_vulnerability_scan_complete_activity,
                run_waf_bypass_activity,

                parse_assessment_results_activity,

                # Tier 7
                correlate_vulnerabilities_activity,
                correlate_exposures_activity,
                enrich_scan_cves_activity,
                calculate_risk_scores_activity,
                generate_impact_assessment_activity,
                sync_graph_activity,
                send_scan_notification_activity,

                # Stress Testing
                init_stress_test_activity,
                run_stress_tool_activity,
                finalize_stress_test_activity,

                # Startup sync
                run_startup_sync_activity,

                # Scheduled scan setup (Phase 4C)
                setup_scheduled_scan_activity,

                # Domain monitoring (Phase 4D)
                run_monitoring_check_activity,
                
                # New utility / integration activities
                run_llm_apme_activity,
                recalculate_apme_activity,
                enrich_identities_activity,
                geo_localize_activity,
                import_hackerone_programs_activity,
                sync_bookmarked_programs_activity,
                fetch_proxies_activity,
                create_proxy_list_activity,
                cleanup_proxy_list_activity,

                # Phase 1 — rengine-ng workflow tool activities
                get_discovered_services_activity,
                get_discovered_ips_activity,
                run_getasn_activity,
                run_netdetect_activity,
                run_jswhois_activity,
                run_whoisdomain_activity,
                run_bbot_activity,
                run_dnsx_activity,
                run_wafw00f_activity,
                run_fping_activity,
                run_arpscan_activity,
                run_mapcidr_activity,
                run_sshaudit_activity,
                run_wpprobe_activity,
                run_search_vulns_activity,
                run_xurlfind3r_activity,
                run_urlfinder_activity,
                run_cariddi_activity,
                run_bup_activity,
                run_arjun_activity,
                run_feroxbuster_activity,
                run_gf_activity,
                run_grype_scan_activity,
                run_trivy_secret_scan_activity,
                run_vigolium_audit_activity,
                run_urlparser_activity,
                extract_auth_for_url_activity,
            ]

            # -------------------------------------------------------------------
            # -------------------------------------------------------------------
            # Load dynamic plugins from the Temporal Registry
            # -------------------------------------------------------------------
            from asgiref.sync import sync_to_async
            from plugins.temporal_registry import PluginTemporalRegistry
            try:
                plugin_workflows = await sync_to_async(PluginTemporalRegistry.get_all_plugin_workflows)()
                plugin_activities = await sync_to_async(PluginTemporalRegistry.get_all_plugin_activities)()
                
                # Append to existing
                _p2_workflows = [UserHuntWorkflow, URLBypassWorkflow, WordPressWorkflow,
                                 HostReconWorkflow, CIDRReconWorkflow, CodeScanWorkflow,
                                 DomainReconWorkflow, SubdomainReconWorkflow, URLCrawlWorkflow,
                                 URLDirSearchWorkflow, URLFuzzWorkflow, URLParamsFuzzWorkflow,
                                 URLVulnWorkflow, URLAuthExtractWorkflow]
                all_workflows = [MasterScanWorkflow, NucleiPlannerWorkflow, SubScanWorkflow, StressTestWorkflow, StartupSyncWorkflow, ScheduledScanWorkflow, MonitoringWorkflow, GoExecutorTaskWorkflow, ApmeTaskWorkflow, RecalculateApmeWorkflow, IdentityEnrichmentWorkflow, GeoLocalizeWorkflow, HackerOneImportWorkflow, HackerOneSyncBookmarkedWorkflow, ProxyFetchWorkflow] + _p2_workflows + plugin_workflows
                all_activities.extend(plugin_activities)
            except Exception as e:
                logger.error(f"Failed to load dynamic plugin temporal exports: {e}")
                _p2_workflows = [UserHuntWorkflow, URLBypassWorkflow, WordPressWorkflow,
                                 HostReconWorkflow, CIDRReconWorkflow, CodeScanWorkflow,
                                 DomainReconWorkflow, SubdomainReconWorkflow, URLCrawlWorkflow,
                                 URLDirSearchWorkflow, URLFuzzWorkflow, URLParamsFuzzWorkflow,
                                 URLVulnWorkflow, URLAuthExtractWorkflow]
                all_workflows = [MasterScanWorkflow, NucleiPlannerWorkflow, SubScanWorkflow, StressTestWorkflow, StartupSyncWorkflow, ScheduledScanWorkflow, MonitoringWorkflow, GoExecutorTaskWorkflow, ApmeTaskWorkflow, RecalculateApmeWorkflow, IdentityEnrichmentWorkflow, GeoLocalizeWorkflow, HackerOneImportWorkflow, HackerOneSyncBookmarkedWorkflow, ProxyFetchWorkflow] + _p2_workflows

            # -------------------------------------------------------------------
            # Start the Temporal Worker
            # -------------------------------------------------------------------
            with DjangoAwareThreadPoolExecutor(max_workers=10) as executor:
                worker = Worker(
                    client,
                    task_queue="python-orchestrator-queue",
                    workflows=all_workflows,
                    activities=all_activities,
                    activity_executor=executor,
                    workflow_runner=UnsandboxedWorkflowRunner(),
                    max_concurrent_activities=10
                )

                self.stdout.write(self.style.SUCCESS(
                    f"Temporal Python Worker started. "
                    f"Listening on python-orchestrator-queue "
                    f"with {len(all_activities)} registered activities..."
                ))

                loop = asyncio.get_event_loop()

                def handle_shutdown():
                    self.stdout.write(self.style.WARNING("\nShutdown signal received, stopping worker..."))
                    logger.info("Temporal worker shutdown initiated")

                for sig in (signal.SIGTERM, signal.SIGINT):
                    try:
                        loop.add_signal_handler(sig, handle_shutdown)
                    except (NotImplementedError, RuntimeError):
                        pass  # Windows doesn't support add_signal_handler

                try:
                    await worker.run()
                except KeyboardInterrupt:
                    pass
                finally:
                    self.stdout.write(self.style.SUCCESS("Temporal worker stopped."))

        def start_redis_listener():
            import redis
            import time
            import signal
            import os
            from django.conf import settings

            def listen():
                while True:
                    try:
                        rdb = redis.StrictRedis(
                            host=settings.REDIS_HOST,
                            port=settings.REDIS_PORT,
                            password=settings.REDIS_PASSWORD,
                            db=0
                        )
                        pubsub = rdb.pubsub()
                        pubsub.subscribe('orchestrator_control')
                        logger.info("[Control] Subscribed to orchestrator_control Redis channel.")
                        for message in pubsub.listen():
                            if message['type'] == 'message':
                                data = message['data'].decode('utf-8')
                                if data == 'restart':
                                    logger.warning("[Control] Received restart command. Terminating process...")
                                    os.kill(os.getpid(), signal.SIGTERM)
                                    time.sleep(2)
                                    os._exit(0)
                    except Exception as e:
                        logger.error(f"[Control] Redis listener error: {e}. Retrying in 5 seconds...")
                        time.sleep(5)

            import threading
            t = threading.Thread(target=listen, daemon=True)
            t.start()

        start_redis_listener()

        def _make_exception_handler(stdout):
            """Return an asyncio loop exception handler that suppresses expected
            Temporal SDK cleanup noise ('Task exception was never retrieved' /
            'Task was destroyed but it is pending!' for RPCError: operation was
            canceled). These fire on every worker shutdown as the gRPC channel
            tears down while SDK polling tasks are still pending — they are not
            actionable and obscure real errors in the logs."""
            def handler(loop, context):
                exc = context.get('exception')
                msg = context.get('message', '')
                if isinstance(exc, Exception) and 'operation was canceled' in str(exc):
                    return
                if 'operation was canceled' in msg:
                    return
                loop.default_exception_handler(context)
            return handler

        try:
            loop = asyncio.new_event_loop()
            loop.set_exception_handler(_make_exception_handler(self.stdout))
            asyncio.set_event_loop(loop)
            loop.run_until_complete(main())
        except KeyboardInterrupt:
            self.stdout.write(self.style.WARNING("\nWorker stopped by user request."))
            sys.exit(0)
        except Exception as e:
            self.stdout.write(self.style.ERROR(f"Error running worker: {e}"))
            sys.exit(1)
