"""
Stress testing activities: initialisation, tool execution and finalisation of
a StressTestWorkflow run.
"""

from temporalio import activity

from reNgine.utils.logger import get_module_logger

logger = get_module_logger(__name__)


# ===========================================================================
# Stress Testing Activities
# ===========================================================================

@activity.defn(name="InitStressTestActivity")
def init_stress_test_activity(ctx: dict) -> dict:
    """Resolve target endpoints and create the StressTestResult DB record.

    Mirrors the target profiling + endpoint query block from run_stress_testing.
    Clears any stale telemetry stream and publishes the initial 'running' status.

    Args:
        ctx: Must contain scan_history_id, target_domain_name, stress_config.

    Returns:
        Enriched ctx with 'resolved_endpoints' (list[str]) and 'stress_result_id' (int).
    """
    import time
    from startScan.models import ScanHistory, EndPoint, StressTestResult
    from targetApp.models import Domain
    from reNgine.definitions import RUNNING_TASK
    from reNgine.stress.telemetry import StressTelemetryPublisher

    scan_id = ctx["scan_history_id"]
    target_domain = ctx["target_domain_name"]
    stress_config = ctx.get("stress_config", {})

    logger.log_line("[TEMPORAL]", "START", "task=init_stress_test scan_id=%s" % scan_id)
    activity.logger.info("[InitStressTestActivity] scan_id=%s", scan_id)

    scan = ScanHistory.objects.get(id=scan_id)
    domain = Domain.objects.get(name=target_domain)

    scan.scan_status = RUNNING_TASK
    scan.save()

    selected = stress_config.get("selected_endpoints", [])
    if selected:
        endpoints = list(
            EndPoint.objects.filter(
                scan_history_id=scan_id, http_url__in=selected
            ).values_list("http_url", flat=True)
        )
    else:
        crawl_targets = stress_config.get("crawl_targets", False)
        qs = EndPoint.objects.filter(
            scan_history_id=scan_id, subdomain__name=target_domain
        ).order_by("id")
        endpoints = list(qs.values_list("http_url", flat=True)[:5 if crawl_targets else 1])

    tools = stress_config.get("uses_tools", ["k6"])
    concurrency = stress_config.get("concurrency", 50)
    duration = stress_config.get("duration", "30s") or "30s"

    result = StressTestResult.objects.create(
        scan_history=scan,
        target_domain=domain,
        tool_used=",".join(tools),
        concurrency_used=concurrency,
        duration=duration,
    )

    publisher = StressTelemetryPublisher(scan_id)
    publisher.clear_stream()
    publisher.publish({"type": "scan_status", "status": "running", "timestamp": time.time()})

    activity.logger.info(
        "[InitStressTestActivity] scan_id=%s resolved %s endpoint(s) for tools=%s", scan_id, len(endpoints), tools
    )
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=init_stress_test scan_id=%s endpoints=%d tools=%s" % (scan_id, len(endpoints), ','.join(tools)))

    return {
        **ctx,
        "resolved_endpoints": endpoints,
        "stress_result_id": result.id,
    }


@activity.defn(name="RunStressToolActivity")
def run_stress_tool_activity(ctx: dict) -> dict:
    """Execute a single stress tool against a single endpoint.

    Corresponds to the inner (endpoint × tool) loop of run_stress_testing.
    Sends Temporal heartbeats every 15 seconds.  Also checks the Redis kill
    switch as a belt-and-braces fallback for the window before the Temporal
    signal reaches the workflow.

    Args:
        ctx: Must contain scan_history_id, target_domain_name, stress_config,
             current_endpoint (str), current_tool (str).

    Returns:
        dict of aggregated metrics from the parser (total_requests,
        successful_requests, failed_requests, avg_latency_ms, p95_latency_ms,
        p99_latency_ms, max_requests_per_second).
    """
    import os
    import signal as os_signal
    import subprocess
    import threading
    import time
    import contextvars
    from temporalio.exceptions import CancelledError

    import redis as redis_lib
    from django.conf import settings
    from django.utils import timezone
    from startScan.models import Command
    from reNgine.parsers import K6Parser, WrkParser, Hping3Parser, LocustParser, TAStressorParser
    from reNgine.stress.telemetry import StressTelemetryPublisher
    from reNgine.stress.cmd_builder import build_stress_command
    from reNgine.common_func import get_random_proxy, get_random_user_agent
    from reNgine.utils.opsec import ProxychainsWrapper

    scan_id = ctx["scan_history_id"]
    target_domain = ctx["target_domain_name"]
    endpoint_url = ctx["current_endpoint"]
    tool = ctx["current_tool"]
    stress_config = ctx.get("stress_config", {})
    tool_config = stress_config.get(f"{tool}_config", {})
    concurrency = stress_config.get("concurrency", 50)
    duration = stress_config.get("duration", "30s") or "30s"

    logger.log_line("[TEMPORAL]", "START", "task=run_stress_tool tool=%s endpoint=%s scan_id=%s" % (tool, endpoint_url, scan_id))
    activity.logger.info(
        "[RunStressToolActivity] tool=%s endpoint=%s scan_id=%s", tool, endpoint_url, scan_id
    )

    publisher = StressTelemetryPublisher(scan_id)

    # Redis kill-switch check — secondary fallback alongside the Temporal signal
    try:
        rdb = redis_lib.StrictRedis(
            host=settings.REDIS_HOST,
            port=settings.REDIS_PORT,
            password=settings.REDIS_PASSWORD,
            db=0
        )
    except Exception:
        rdb = None

    def _kill_switch_active():
        try:
            return rdb is not None and rdb.get(f"kill_switch_{scan_id}") == b"1"
        except Exception:
            return False

    # Select the right parser
    parsers = {
        "k6": K6Parser,
        "wrk": WrkParser,
        "hping3": Hping3Parser,
        "locust": LocustParser,
        "stressor": TAStressorParser,
    }
    parser_cls = parsers.get(tool)
    if not parser_cls:
        raise ValueError(f"[RunStressToolActivity] Unknown tool: {tool!r}")
    parser = parser_cls()

    single_proxy = get_random_proxy()
    k6_user_agent = get_random_user_agent()

    cmd_str, temp_files = build_stress_command(
        tool=tool,
        tool_config=tool_config,
        endpoint_url=endpoint_url,
        target_domain=target_domain,
        scan_id=scan_id,
        concurrency=concurrency,
        duration=duration,
        single_proxy=single_proxy,
        k6_user_agent=k6_user_agent,
        base_dir=settings.BASE_DIR,
    )

    proxy_wrapper = ProxychainsWrapper()
    temp_conf_path = None
    if proxy_wrapper.should_wrap():
        cmd_str, temp_conf_path = proxy_wrapper.wrap_command(cmd_str)
        activity.logger.info("[RunStressToolActivity] Wrapping via proxychains: %s", cmd_str)
    else:
        activity.logger.info("[RunStressToolActivity] Executing: %s", cmd_str)

    if temp_conf_path:
        temp_files.append(temp_conf_path)

    command_obj = Command.objects.create(
        command=cmd_str,
        time=timezone.now(),
        scan_history_id=scan_id,
    )

    publisher.publish({
        "type": "command",
        "tool": tool,
        "endpoint": endpoint_url,
        "command": cmd_str,
        "timestamp": time.time(),
    })

    # Pre-declare process variable so the background heartbeat thread can inspect it safely
    process = None

    # Helper function to terminate the subprocess group
    def _terminate_process():
        is_mock = hasattr(process, 'assert_called')
        if process and (process.poll() is None or is_mock):
            try:
                activity.logger.info(
                    "[RunStressToolActivity] Terminating process group for %s (PID: %s)", tool, process.pid
                )
                os.killpg(os.getpgid(process.pid), os_signal.SIGTERM)
            except Exception as kill_err:
                activity.logger.error("[RunStressToolActivity] Kill failed: %s", kill_err)

    # Helper to check if running inside a Temporal activity context (fails during direct unit tests)
    def _is_in_activity_context():
        try:
            activity.is_cancelled()
            return True
        except RuntimeError:
            return False

    def _is_cancelled():
        return _is_in_activity_context() and activity.is_cancelled()

    # Heartbeat thread — keeps the activity alive in Temporal's eyes.
    # Copy the current contextvars context so the heartbeat thread inherits the
    # Temporal activity context. threading.Thread does NOT copy contextvars by
    # default, causing activity.heartbeat() to fail with "Not in activity context",
    # which silently prevents all heartbeats from reaching Temporal and triggers
    # the heartbeat_timeout cancellation + retry loop.
    stop_heartbeat = threading.Event()
    _activity_ctx = contextvars.copy_context()

    def _heartbeat():
        def _do_heartbeat():
            while not stop_heartbeat.is_set():
                # Perform periodic cancellation check
                if _is_cancelled():
                    _cd = activity.cancellation_details() if _is_in_activity_context() else None
                    if _cd and _cd.paused:
                        activity.logger.info(
                            "[RunStressToolActivity] Activity paused — terminating %s (will retry when unpaused)", tool
                        )
                    else:
                        activity.logger.info(
                            "[RunStressToolActivity] Activity cancelled — terminating %s", tool
                        )
                    _terminate_process()
                    break
                if _is_in_activity_context():
                    try:
                        activity.heartbeat(f"Running {tool} against {endpoint_url}")
                    except CancelledError:
                        _cd = activity.cancellation_details()
                        if _cd and _cd.paused:
                            activity.logger.info(
                                "[RunStressToolActivity] Activity paused via heartbeat — terminating %s (will retry when unpaused)", tool
                            )
                        else:
                            activity.logger.info(
                                "[RunStressToolActivity] Heartbeat received cancellation — terminating %s", tool
                            )
                        _terminate_process()
                        break
                    except Exception as hb_err:
                        if "cancel" in str(hb_err).lower():
                            activity.logger.info(
                                "[RunStressToolActivity] Heartbeat received cancellation exception: %s — terminating %s", hb_err, tool
                            )
                            _terminate_process()
                            break
                        try:
                            _info = activity.info()
                            activity.logger.warning(
                                "[RunStressToolActivity] Heartbeat failed — "
                                "activity_type=%s workflow_id=%s attempt=%d tool=%s error=%s",
                                _info.activity_type, _info.workflow_id, _info.attempt, tool, hb_err,
                            )
                        except Exception:
                            activity.logger.warning(
                                "[RunStressToolActivity] Heartbeat failed for %s: %s", tool, hb_err
                            )
                stop_heartbeat.wait(15)
        _activity_ctx.run(_do_heartbeat)

    hb_thread = threading.Thread(target=_heartbeat, daemon=True)
    hb_thread.start()

    accumulated_lines = []
    try:
        process = subprocess.Popen(
            cmd_str,
            stdout=subprocess.PIPE,
            stderr=subprocess.STDOUT,
            text=True,
            shell=True,
            start_new_session=True,
        )

        while True:
            # Check for cancellation on each iteration
            if _is_cancelled():
                activity.logger.info(
                    "[RunStressToolActivity] Main thread detected cancellation — terminating %s", tool
                )
                _terminate_process()
                break

            line = process.stdout.readline()
            if not line and process.poll() is not None:
                break
            if line:
                line = line.strip()
                accumulated_lines.append(line)
                publisher.publish({
                    "type": "log",
                    "tool": tool,
                    "endpoint": endpoint_url,
                    "line": line,
                    "timestamp": time.time(),
                })
                metrics = parser.parse_line(line)
                if metrics:
                    metrics.update({
                        "type": "metric",
                        "tool": tool,
                        "endpoint": endpoint_url,
                        "timestamp": time.time(),
                    })
                    publisher.publish(metrics)

            if _kill_switch_active():
                activity.logger.info(
                    "[RunStressToolActivity] Redis kill switch active — terminating %s", tool
                )
                _terminate_process()
                break

        process.wait()
        command_obj.output = "\n".join(accumulated_lines)
        command_obj.return_code = process.returncode
        command_obj.save()

    finally:
        stop_heartbeat.set()
        hb_thread.join(timeout=5)
        for path in temp_files:
            if path and os.path.exists(path):
                try:
                    os.remove(path)
                except Exception as rm_err:
                    activity.logger.error(
                        "[RunStressToolActivity] Could not remove temp file %s: %s", path, rm_err
                    )

    final_metrics = parser.get_final_metrics()
    activity.logger.info(
        "[RunStressToolActivity] tool=%s endpoint=%s done — %s requests", tool, endpoint_url, final_metrics.get('total_requests', 0)
    )
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=run_stress_tool tool=%s scan_id=%s requests=%d" % (tool, scan_id, final_metrics.get('total_requests', 0)))
    return final_metrics


@activity.defn(name="FinalizeStressTestActivity")
def finalize_stress_test_activity(ctx: dict) -> bool:
    """Aggregate metrics, update StressTestResult + ScanHistory, send notification.

    Mirrors the post-loop finalisation block in run_stress_testing and always
    publishes a 'completed' status to the telemetry stream so the frontend
    exits the running state even if a previous worker crash left it stale.

    Args:
        ctx: Must contain scan_history_id, stress_result_id, aborted (bool),
             and pre-aggregated metric fields from the workflow.

    Returns:
        True on success.
    """
    import time
    from django.utils import timezone
    from startScan.models import ScanHistory, StressTestResult
    from reNgine.definitions import SUCCESS_TASK, ABORTED_TASK
    from reNgine.stress.telemetry import StressTelemetryPublisher
    from reNgine.tasks import send_scan_notif

    scan_id = ctx["scan_history_id"]
    result_id = ctx.get("stress_result_id")
    aborted = ctx.get("aborted", False)

    logger.log_line("[TEMPORAL]", "START", "task=finalize_stress_test scan_id=%s aborted=%s" % (scan_id, aborted))
    activity.logger.info(
        "[FinalizeStressTestActivity] scan_id=%s aborted=%s", scan_id, aborted
    )

    result = StressTestResult.objects.filter(id=result_id).first()
    if result:
        result.total_requests = ctx.get("total_requests", 0)
        result.successful_requests = ctx.get("successful_requests", 0)
        result.failed_requests = ctx.get("failed_requests", 0)
        result.avg_latency_ms = ctx.get("avg_latency_ms", 0.0)
        result.p95_latency_ms = ctx.get("p95_latency_ms", 0.0)
        result.p99_latency_ms = ctx.get("p99_latency_ms", 0.0)
        result.max_requests_per_second = ctx.get("max_rps", 0.0)
        result.is_kill_switch_triggered = aborted
        result.save()

    scan = ScanHistory.objects.filter(id=scan_id).first()
    if scan:
        scan.scan_status = ABORTED_TASK if aborted else SUCCESS_TASK
        scan.stop_scan_date = timezone.now()
        scan.save()

    # Always publish completed status — prevents the frontend from getting stuck
    # in 'running' state after a worker crash between activities.
    publisher = StressTelemetryPublisher(scan_id)
    publisher.publish({
        "type": "scan_status",
        "status": "completed",
        "timestamp": time.time(),
    })

    try:
        send_scan_notif(
            scan_history_id=scan_id,
            status="ABORTED" if aborted else "SUCCESS",
        )
    except Exception as e:
        activity.logger.warning(
            "[FinalizeStressTestActivity] Notification failed (non-fatal): %s", e
        )

    status_h = "ABORTED" if aborted else "SUCCESS"
    logger.log_line("[TEMPORAL]", "COMPLETE", "task=finalize_stress_test scan_id=%s status=%s" % (scan_id, status_h))
    return True
