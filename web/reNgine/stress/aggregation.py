"""
Aggregation tasks for stress test telemetry data.
Converts real-time Redis stream data to persistent database records.
"""
import json
import logging
import redis
from django.conf import settings
from django.utils import timezone
from startScan.models import ScanHistory, StressTestResult, StressTelemetryPoint, StressToolConfiguration, EndPoint

logger = logging.getLogger(__name__)


def aggregate_stress_telemetry(stress_result_id):
    """
    Aggregates real-time Redis stream data into persistent database records.
    Called after stress test completion.

    Args:
        stress_result_id: ID of StressTestResult to aggregate data for
    """
    try:
        stress_result = StressTestResult.objects.get(id=stress_result_id)
        scan_id = stress_result.scan_history_id

        logger.info("Starting telemetry aggregation for stress result %s", stress_result_id)

        # Connect to Redis
        try:
            redis_client = redis.StrictRedis(
                host=settings.REDIS_HOST,
                port=settings.REDIS_PORT,
                password=settings.REDIS_PASSWORD,
                db=0,
                decode_responses=True
            )
        except Exception as e:
            logger.error("Failed to connect to Redis: %s", e)
            return {"status": "failed", "error": "Redis connection failed"}

        stream_key = f"stress:telemetry:{scan_id}"

        # Read all data from Redis stream
        try:
            stream_data = redis_client.xrange(stream_key)
        except Exception as e:
            logger.error("Failed to read Redis stream %s: %s", stream_key, e)
            return {"status": "failed", "error": "Failed to read stream"}

        if not stream_data:
            logger.warning("No telemetry data found in stream for scan %s", scan_id)
            return {"status": "success", "message": "No telemetry data to aggregate"}

        # Parse and persist telemetry points
        telemetry_points_created = 0
        endpoints_set = set()
        status_codes = {}
        error_breakdown = {}

        for msg_id, data in stream_data:
            try:
                payload = json.loads(data['data'])

                # Only process metric and log types, skip commands
                if payload.get('type') not in ['metric', 'log']:
                    continue

                if payload.get('type') == 'metric':
                    # Get endpoint reference if exists
                    endpoint = None
                    endpoint_url = payload.get('endpoint')
                    if endpoint_url:
                        endpoints_set.add(endpoint_url)
                        try:
                            endpoint = EndPoint.objects.get(
                                http_url=endpoint_url,
                                scan_history_id=scan_id
                            )
                        except EndPoint.DoesNotExist:
                            pass

                    # Create telemetry point
                    try:
                        timestamp = timezone.datetime.fromtimestamp(
                            payload.get('timestamp', timezone.now().timestamp()),
                            tz=timezone.utc
                        )
                    except (ValueError, TypeError):
                        timestamp = timezone.now()

                    point = StressTelemetryPoint.objects.create(
                        stress_result=stress_result,
                        endpoint=endpoint,
                        tool=payload.get('tool', 'unknown'),
                        timestamp=timestamp,
                        latency_ms=payload.get('latency_ms') or payload.get('avg_latency'),
                        throughput=payload.get('throughput_rps'),
                        error_rate=payload.get('error_rate'),
                        tool_specific_metrics=payload,
                    )
                    telemetry_points_created += 1

                    # Aggregate response codes
                    if 'status_codes' in payload:
                        for code, count in payload['status_codes'].items():
                            status_codes[code] = status_codes.get(code, 0) + count

                    # Aggregate error breakdown
                    if 'error_types' in payload:
                        for error_type, count in payload['error_types'].items():
                            error_breakdown[error_type] = error_breakdown.get(error_type, 0) + count

            except json.JSONDecodeError as e:
                logger.warning("Failed to parse telemetry data: %s", e)
                continue
            except Exception as e:
                logger.warning("Failed to create telemetry point: %s", e)
                continue

        # Calculate percentiles
        points = StressTelemetryPoint.objects.filter(
            stress_result=stress_result,
            latency_ms__isnull=False
        ).order_by('latency_ms')

        if points.exists():
            latency_values = list(points.values_list('latency_ms', flat=True))

            if latency_values:
                latency_values.sort()
                n = len(latency_values)

                # Calculate percentiles manually
                def percentile(data, percentile_value):
                    if not data:
                        return 0.0
                    idx = int((percentile_value / 100.0) * (len(data) - 1))
                    return data[idx]

                stress_result.p50_latency_ms = percentile(latency_values, 50)
                stress_result.p75_latency_ms = percentile(latency_values, 75)
                stress_result.p90_latency_ms = percentile(latency_values, 90)
                stress_result.p95_latency_ms = percentile(latency_values, 95)
                stress_result.p99_latency_ms = percentile(latency_values, 99)
                stress_result.p999_latency_ms = percentile(latency_values, 99.9)

                # Store full percentile distribution
                stress_result.percentile_latencies = {
                    "p50": stress_result.p50_latency_ms,
                    "p75": stress_result.p75_latency_ms,
                    "p90": stress_result.p90_latency_ms,
                    "p95": stress_result.p95_latency_ms,
                    "p99": stress_result.p99_latency_ms,
                    "p999": stress_result.p999_latency_ms,
                    "min": latency_values[0],
                    "max": latency_values[-1],
                }

        # Update stress result with aggregated data
        stress_result.endpoints_tested = list(endpoints_set)
        stress_result.response_code_distribution = status_codes
        stress_result.error_breakdown = error_breakdown
        stress_result.end_time = timezone.now()

        # Generate findings
        findings = generate_findings(stress_result)
        stress_result.findings = findings

        # Generate recommendations
        recommendations = generate_recommendations(stress_result)
        stress_result.recommendations = recommendations

        stress_result.save()

        logger.info("Aggregation complete: %s points created", telemetry_points_created)

        # Clean up Redis stream
        try:
            redis_client.delete(stream_key)
            logger.info("Cleaned up Redis stream %s", stream_key)
        except Exception as e:
            logger.warning("Failed to clean Redis stream: %s", e)

        return {
            "status": "success",
            "points_created": telemetry_points_created,
            "message": f"Successfully aggregated {telemetry_points_created} telemetry points"
        }

    except StressTestResult.DoesNotExist:
        logger.error("StressTestResult %s not found", stress_result_id)
        return {"status": "failed", "error": "Stress result not found"}
    except Exception as e:
        logger.error("Aggregation failed: %s", e, exc_info=True)
        return {"status": "failed", "error": str(e)}


def generate_findings(stress_result):
    """Auto-generate key findings from stress test metrics."""
    findings = []

    try:
        # Latency analysis
        if stress_result.p99_latency_ms > 0 and stress_result.avg_latency_ms > 0:
            variance_ratio = stress_result.p99_latency_ms / stress_result.avg_latency_ms
            if variance_ratio > 5:
                findings.append(
                    f"High latency variance detected: P99 latency ({stress_result.p99_latency_ms:.2f}ms) "
                    f"is {variance_ratio:.1f}x higher than average ({stress_result.avg_latency_ms:.2f}ms). "
                    "This indicates inconsistent response times under load."
                )

        # Error rate analysis
        if stress_result.total_requests > 0:
            error_rate = (stress_result.failed_requests / stress_result.total_requests) * 100
            if error_rate > 5:
                findings.append(
                    f"Elevated error rate detected: {error_rate:.2f}% of requests failed. "
                    f"Out of {stress_result.total_requests} total requests, {stress_result.failed_requests} failed. "
                    "This may indicate performance degradation under load."
                )
            elif error_rate > 0:
                findings.append(
                    f"Error rate: {error_rate:.2f}% ({stress_result.failed_requests}/{stress_result.total_requests}). "
                    "Some requests failed during the test."
                )

        # Peak throughput
        if stress_result.max_requests_per_second > 0:
            if stress_result.max_requests_per_second > stress_result.total_requests / 10:
                findings.append(
                    f"Peak throughput reached: {stress_result.max_requests_per_second:.2f} RPS. "
                    "System maintained good request processing speed."
                )

        # Endpoint coverage
        if stress_result.endpoints_tested:
            findings.append(
                f"Tested {len(stress_result.endpoints_tested)} endpoint(s). "
                f"URLs: {', '.join(stress_result.endpoints_tested[:3])}"
                + (f" and {len(stress_result.endpoints_tested)-3} more" if len(stress_result.endpoints_tested) > 3 else "")
            )

        # Response code distribution
        if stress_result.response_code_distribution:
            total_codes = sum(stress_result.response_code_distribution.values())
            if total_codes > 0:
                errors_4xx = sum(v for k, v in stress_result.response_code_distribution.items() if k.startswith('4'))
                errors_5xx = sum(v for k, v in stress_result.response_code_distribution.items() if k.startswith('5'))
                if errors_5xx > 0:
                    findings.append(
                        f"Server errors detected: {errors_5xx} 5xx responses. "
                        "This indicates backend issues during stress testing."
                    )
                if errors_4xx > 0:
                    findings.append(
                        f"Client errors detected: {errors_4xx} 4xx responses. "
                        "This may indicate validation or routing issues."
                    )

    except Exception as e:
        logger.warning("Error generating findings: %s", e)

    return " | ".join(findings) if findings else "Stress test completed. No anomalies detected."


def generate_recommendations(stress_result):
    """Auto-generate actionable recommendations based on test results."""
    recommendations = []

    try:
        # Latency recommendations
        if stress_result.p99_latency_ms > 500:
            recommendations.append(
                "❌ P99 latency exceeds 500ms: Implement caching, optimize database queries, "
                "or scale infrastructure to reduce latency variance."
            )
        elif stress_result.p99_latency_ms > 200:
            recommendations.append(
                "⚠️ P99 latency is elevated (>200ms): Review slow queries and consider implementing caching strategies."
            )

        # Error rate recommendations
        if stress_result.total_requests > 0:
            error_rate = (stress_result.failed_requests / stress_result.total_requests) * 100
            if error_rate > 5:
                recommendations.append(
                    "❌ High error rate (>5%): Implement circuit breakers, add retry logic, "
                    "and investigate error types to improve reliability."
                )

        # Throughput recommendations
        if stress_result.max_requests_per_second > 0 and stress_result.concurrency_used > 0:
            throughput_ratio = stress_result.max_requests_per_second / stress_result.concurrency_used
            if throughput_ratio < 10:
                recommendations.append(
                    "⚠️ Low throughput relative to concurrency: Each concurrent user generated <10 RPS. "
                    "Consider optimizing endpoint performance or increasing server resources."
                )

        # Response code recommendations
        if stress_result.response_code_distribution:
            if any(k.startswith('5') for k in stress_result.response_code_distribution.keys()):
                recommendations.append(
                    "❌ Server errors (5xx) detected: Review application logs to identify and fix backend issues. "
                    "Consider adding health checks and auto-scaling policies."
                )

        # General scalability
        if not recommendations:
            recommendations.append(
                "✅ Stress test completed successfully with acceptable metrics. "
                "Maintain current infrastructure and monitor performance in production."
            )

    except Exception as e:
        logger.warning("Error generating recommendations: %s", e)

    return " | ".join(recommendations) if recommendations else "Review test results for optimization opportunities."
