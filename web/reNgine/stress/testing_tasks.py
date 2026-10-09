from django.conf import settings
import subprocess
import os
import signal
import redis
import logging
import time
from startScan.models import ScanHistory, EndPoint, StressTestResult, Command
from targetApp.models import Domain
from reNgine.utils.graph import Neo4jManager
from django.utils import timezone
from reNgine.parsers import K6Parser, WrkParser, Hping3Parser, LocustParser, TAStressorParser
from reNgine.stress.telemetry import StressTelemetryPublisher
from reNgine.stress.cmd_builder import build_stress_command
from reNgine.definitions import SUCCESS_TASK, FAILED_TASK, RUNNING_TASK, ABORTED_TASK

logger = logging.getLogger(__name__)

# Redis for kill switch
try:
    redis_client = redis.StrictRedis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        password=settings.REDIS_PASSWORD,
        db=0
    )
except:
    redis_client = None


class StressTestTask:
    """Task proxy for stress testing with specialized cleanup logic."""
    def on_failure(self, exc, task_id, args, kwargs, einfo=None):
        scan_id = getattr(self, 'scan_id', None)
        if not scan_id and args:
            scan_id = args[0]
        if scan_id:
            self.terminate_processes(scan_id)

    def terminate_processes(self, scan_id):
        """Logic to kill all processes related to this scan."""
        if redis_client:
            redis_client.set(f"kill_switch_{scan_id}", "1", ex=3600)
        logger.warning("Termination requested for stress test on scan %s", scan_id)


def is_kill_switch_active(scan_id):
    """Check if the kill switch for this scan has been flipped in Redis."""
    if redis_client:
        return redis_client.get(f"kill_switch_{scan_id}") == b"1"
    return False


def run_stress_testing(self, scan_history_id, target_domain_name, yaml_config, **kwargs):
    # Extract config
    stress_config = yaml_config.get("stress_test", {})
    if not stress_config:
        return {"status": "success", "message": "No stress test config provided"}

    concurrency = stress_config.get("concurrency", 50)
    duration = stress_config.get("duration", "30s")

    # Validate duration is not empty
    if not duration or duration == "":
        duration = "30s"
        logger.warning("Empty duration received for scan %s, defaulting to 30s", scan_history_id)

    tools = stress_config.get("uses_tools", ["k6"])
    
    # Initialize Telemetry — clear any stale stream from a previous run first
    publisher = StressTelemetryPublisher(scan_history_id)
    publisher.clear_stream()

    # Publish initial running status
    publisher.publish({
        "type": "scan_status",
        "status": "running",
        "timestamp": time.time()
    })

    try:
        # Target Profiling
        try:
            scan = ScanHistory.objects.get(id=scan_history_id)
            domain = Domain.objects.get(name=target_domain_name)
            scan.scan_status = RUNNING_TASK
            scan.save()
        except Exception as e:
            logger.error("Stress test error: %s", e)
            return {"status": "failed"}

        selected_endpoints = stress_config.get('selected_endpoints', [])
        
        if selected_endpoints:
            # Filter specifically on selected endpoints matching the list of URLs
            endpoints = EndPoint.objects.filter(
                scan_history_id=scan_history_id,
                http_url__in=selected_endpoints
            )
        else:
            crawl_targets = yaml_config.get('crawl_targets', False)
            if not crawl_targets:
                # Only take the root target.
                endpoints = EndPoint.objects.filter(
                    scan_history_id=scan_history_id, 
                    subdomain__name=target_domain_name
                ).order_by('id')[:1]
            else:
                # Take up to 5 endpoints on the target domain
                endpoints = EndPoint.objects.filter(
                    scan_history_id=scan_history_id, 
                    subdomain__name=target_domain_name
                )[:5]
        if not endpoints:
            logger.warning("No endpoints found for scan %s to stress test.", scan_history_id)
            try:
                scan.scan_status = SUCCESS_TASK
                scan.stop_scan_date = timezone.now()
                scan.save()
            except Exception as e:
                logger.error("Failed to update scan status: %s", e)
            return {"status": "success", "message": "No endpoints to stress test"}

        neo4j = Neo4jManager()

        overall_result = StressTestResult.objects.create(
            scan_history=scan,
            target_domain=domain,
            tool_used=",".join(tools),
            concurrency_used=concurrency,
            duration=duration,
        )

        from reNgine.utils.opsec import ProxychainsWrapper
        from reNgine.common_func import get_random_proxy, get_random_user_agent
        
        proxy_wrapper = ProxychainsWrapper()
        single_proxy = get_random_proxy()
        # Fetch a user agent from OpSec settings (rotates if enable_random_ua is on)
        k6_user_agent = get_random_user_agent()

        # Initialize aggregate metric accumulators across all tools and endpoints
        total_requests = 0
        successful_requests = 0
        failed_requests = 0
        
        avg_latencies = []
        p95_latencies = []
        p99_latencies = []
        max_rps_values = []

        task_aborted = False

        for endpoint in endpoints:
            if is_kill_switch_active(scan_history_id):
                logger.warning("Kill switch activated for scan %s. Aborting.", scan_history_id)
                overall_result.is_kill_switch_triggered = True
                overall_result.save()
                task_aborted = True
                break

            for tool in tools:
                if is_kill_switch_active(scan_history_id):
                    logger.warning("Kill switch activated for scan %s. Aborting tool %s.", scan_history_id, tool)
                    overall_result.is_kill_switch_triggered = True
                    overall_result.save()
                    task_aborted = True
                    break

                tool_config = stress_config.get(f"{tool}_config", {})

                parsers = {
                    "k6": K6Parser,
                    "wrk": WrkParser,
                    "hping3": Hping3Parser,
                    "locust": LocustParser,
                    "stressor": TAStressorParser,
                }
                parser_cls = parsers.get(tool)
                if not parser_cls:
                    logger.warning("Unknown stress tool %r — skipping.", tool)
                    continue
                parser = parser_cls()
                temp_conf_path = None

                try:
                    cmd_str, temp_files = build_stress_command(
                        tool=tool,
                        tool_config=tool_config,
                        endpoint_url=endpoint.http_url,
                        target_domain=target_domain_name,
                        scan_id=scan_history_id,
                        concurrency=concurrency,
                        duration=duration,
                        single_proxy=single_proxy,
                        k6_user_agent=k6_user_agent,
                        base_dir=settings.BASE_DIR,
                    )
                except Exception as build_err:
                    logger.error("Failed to build command for tool=%s: %s", tool, build_err)
                    continue

                if proxy_wrapper.should_wrap():
                    cmd_str, temp_conf_path = proxy_wrapper.wrap_command(cmd_str)
                    if temp_conf_path:
                        temp_files.append(temp_conf_path)
                    logger.info("Wrapping execution via proxychains: %s", cmd_str)
                else:
                    logger.info("Executing %s: %s", tool, cmd_str)
                
                command_obj = Command.objects.create(
                    command=cmd_str,
                    time=timezone.now(),
                    scan_history_id=scan_history_id
                )

                publisher.publish({
                    "type": "command",
                    "tool": tool,
                    "endpoint": endpoint.http_url,
                    "command": cmd_str,
                    "timestamp": time.time()
                })

                accumulated_lines = []
                
                try:
                    process = subprocess.Popen(
                        cmd_str, 
                        stdout=subprocess.PIPE, 
                        stderr=subprocess.STDOUT, 
                        text=True,
                        shell=True,
                        start_new_session=True
                    )

                    while True:
                        line = process.stdout.readline()
                        if not line and process.poll() is not None:
                            break
                        
                        if line:
                            line = line.strip()
                            accumulated_lines.append(line)

                            publisher.publish({
                                "type": "log",
                                "tool": tool,
                                "endpoint": endpoint.http_url,
                                "line": line,
                                "timestamp": time.time()
                            })

                            metrics = parser.parse_line(line)
                            if metrics:
                                metrics["type"] = "metric"
                                metrics["tool"] = tool
                                metrics["endpoint"] = endpoint.http_url
                                metrics["timestamp"] = time.time()
                                publisher.publish(metrics)

                        if is_kill_switch_active(scan_history_id):
                            import signal
                            try:
                                os.killpg(os.getpgid(process.pid), signal.SIGTERM)
                            except Exception as kill_err:
                                logger.error("Failed to kill process group: %s", kill_err)
                            break

                    process.wait()

                    command_obj.output = "\n".join(accumulated_lines)
                    command_obj.return_code = process.returncode
                    command_obj.save()

                    # Extract final metrics from the parser after process completes and add them to totals
                    if parser:
                        final_metrics = parser.get_final_metrics()
                        total_requests += final_metrics.get("total_requests", 0)
                        successful_requests += final_metrics.get("successful_requests", 0)
                        failed_requests += final_metrics.get("failed_requests", 0)
                        
                        if final_metrics.get("avg_latency_ms", 0.0) > 0:
                            avg_latencies.append(final_metrics["avg_latency_ms"])
                        if final_metrics.get("p95_latency_ms", 0.0) > 0:
                            p95_latencies.append(final_metrics["p95_latency_ms"])
                        if final_metrics.get("p99_latency_ms", 0.0) > 0:
                            p99_latencies.append(final_metrics["p99_latency_ms"])
                        if final_metrics.get("max_requests_per_second", 0.0) > 0:
                            max_rps_values.append(final_metrics["max_requests_per_second"])
                    
                except Exception as e:
                    logger.error("Execution of %s failed: %s", tool, e)
                finally:
                    for _path in temp_files:
                        if _path and os.path.exists(_path):
                            try:
                                os.remove(_path)
                            except Exception as rm_err:
                                logger.error("Failed to remove temp file %s: %s", _path, rm_err)
            
            if task_aborted:
                break

        # Compute averages and maximums across all runs, then persist to the database model
        overall_result.total_requests = total_requests
        overall_result.successful_requests = successful_requests
        overall_result.failed_requests = failed_requests
        overall_result.avg_latency_ms = sum(avg_latencies) / len(avg_latencies) if avg_latencies else 0.0
        overall_result.p95_latency_ms = sum(p95_latencies) / len(p95_latencies) if p95_latencies else 0.0
        overall_result.p99_latency_ms = sum(p99_latencies) / len(p99_latencies) if p99_latencies else 0.0
        overall_result.max_requests_per_second = max(max_rps_values) if max_rps_values else 0.0
        overall_result.save()

        neo4j.close()

        # Update ScanHistory status
        is_aborted = is_kill_switch_active(scan_history_id) or overall_result.is_kill_switch_triggered
        if is_aborted:
            scan.scan_status = ABORTED_TASK
            status_notif = 'ABORTED'
        else:
            scan.scan_status = SUCCESS_TASK
            status_notif = 'SUCCESS'
            
        scan.stop_scan_date = timezone.now()
        scan.save()

        # Final notification
        from reNgine.tasks import send_scan_notif
        send_scan_notif(
            scan_history_id=scan_history_id,
            status=status_notif
        )

        return {"status": "success"}

    except Exception as exc:
        logger.error("Stress test failed: %s", exc)
        try:
            scan = ScanHistory.objects.get(id=scan_history_id)
            scan.scan_status = FAILED_TASK
            scan.stop_scan_date = timezone.now()
            scan.save()
            from reNgine.tasks import send_scan_notif
            send_scan_notif(
                scan_history_id=scan_history_id,
                status='FAILED'
            )
        except Exception as db_err:
            logger.error("Failed to update scan status: %s", db_err)
        raise exc

    finally:
        # Publish final completed status to telemetry
        publisher.publish({
            "type": "scan_status",
            "status": "completed",
            "timestamp": time.time()
        })
