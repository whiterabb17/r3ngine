import asyncio
import logging
import threading

import redis
from django.conf import settings
from django.shortcuts import get_object_or_404
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView
from startScan.models import ScanHistory, ScanReport

logger = logging.getLogger(__name__)

try:
    redis_client = redis.StrictRedis(
        host=settings.REDIS_HOST,
        port=settings.REDIS_PORT,
        password=settings.REDIS_PASSWORD,
        db=0
    )
except Exception:
    redis_client = None


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

async def _start_stress_workflow(ctx: dict, scan_id: int) -> None:
    """Start a StressTestWorkflow via the Temporal client."""
    from reNgine.temporal_client import TemporalClientProvider
    client = await TemporalClientProvider.get_client()
    await client.start_workflow(
        "StressTestWorkflow",
        ctx,
        id=f"stress-test-{scan_id}",
        task_queue="python-orchestrator-queue",
    )


async def _signal_stress_workflow(scan_id: int) -> None:
    """Send the kill_switch signal to a running StressTestWorkflow."""
    from reNgine.temporal_client import TemporalClientProvider
    client = await TemporalClientProvider.get_client()
    handle = client.get_workflow_handle(f"stress-test-{scan_id}")
    await handle.signal("kill_switch")


# ---------------------------------------------------------------------------
# API Views
# ---------------------------------------------------------------------------

class StressTestControlAPI(APIView):
    """Start or stop a stress test for a given scan.

    POST action='start' — launches a StressTestWorkflow via Temporal.
                          Falls back to the legacy Celery task if Temporal
                          is unreachable (dual-run migration period).
    POST action='stop'  — sends a Temporal kill_switch signal and sets the
                          Redis kill-switch key as a belt-and-braces fallback.
    """

    permission_classes = [IsAuthenticated]

    def post(self, request, scan_id):
        action = request.data.get("action")

        if action == "stop":
            # Primary: Temporal signal
            try:
                asyncio.run(_signal_stress_workflow(scan_id))
                logger.info(f"[StressTestControlAPI] Temporal kill_switch sent for scan {scan_id}")
            except Exception as e:
                logger.warning(
                    f"[StressTestControlAPI] Temporal signal failed for scan {scan_id}: {e} "
                    "— falling back to Redis kill switch only."
                )

            # Secondary: Redis key checked by both the Celery task and RunStressToolActivity
            if redis_client:
                redis_client.set(f"kill_switch_{scan_id}", "1", ex=3600)

            return Response({"status": "stopping"}, status=status.HTTP_200_OK)

        elif action == "start":
            config = request.data.get("config", {})
            scan = ScanHistory.objects.filter(id=scan_id).first()
            if not scan:
                return Response({"error": "Scan not found"}, status=status.HTTP_404_NOT_FOUND)

            # Clear any stale kill switch so a fresh test is not immediately aborted
            if redis_client:
                redis_client.delete(f"kill_switch_{scan_id}")

            ctx = {
                "scan_history_id": scan.id,
                "target_domain_name": scan.domain.name,
                "stress_config": config,
            }

            # Primary: Temporal workflow
            try:
                asyncio.run(_start_stress_workflow(ctx, scan_id))
                logger.info(
                    f"[StressTestControlAPI] StressTestWorkflow started for scan {scan_id}"
                )
                return Response({"status": "started"}, status=status.HTTP_200_OK)
            except Exception as e:
                logger.error(
                    f"[StressTestControlAPI] Temporal start failed for scan {scan_id}: {e}"
                )
                return Response(
                    {"error": "Failed to start stress test"},
                    status=status.HTTP_500_INTERNAL_SERVER_ERROR,
                )

        return Response({"error": "Invalid action"}, status=status.HTTP_400_BAD_REQUEST)


class StressTestStatusAPI(APIView):
    """Return the current stress test status for a scan."""

    permission_classes = [IsAuthenticated]

    def get(self, request, scan_id):
        is_killed = False
        if redis_client:
            is_killed = redis_client.get(f"kill_switch_{scan_id}") == b"1"

        return Response(
            {"scan_id": scan_id, "kill_switch_active": is_killed},
            status=status.HTTP_200_OK,
        )


class StressReportGenerationAPI(APIView):
    """Generate a stress test report in PDF format."""

    permission_classes = [IsAuthenticated]

    def post(self, request, scan_id):
        try:
            report_template = request.data.get("report_template", "stress_modern")
            include_endpoints = request.data.get("include_endpoints", True)
            include_timeline = request.data.get("include_timeline", True)

            scan = get_object_or_404(ScanHistory, id=scan_id)

            report_obj = ScanReport.objects.create(
                scan_history=scan,
                report_type="stress_test",
                report_template=report_template,
                status=-1,  # Initiated
                params={
                    "include_endpoints": include_endpoints,
                    "include_timeline": include_timeline,
                },
            )

            from reNgine.tasks.report import generate_report_task
            threading.Thread(
                target=generate_report_task,
                args=(report_obj.id,),
                daemon=True
            ).start()

            return Response(
                {
                    "status": True,
                    "report_id": report_obj.id,
                    "message": "Report generation initiated",
                },
                status=status.HTTP_201_CREATED,
            )

        except Exception as e:
            logger.error(f"[StressReportGenerationAPI] Error initiating report: {e}")
            return Response(
                {"status": False, "error": str(e)},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR,
            )

    def get(self, request, scan_id):
        try:
            report_id = request.query_params.get("report_id")
            if not report_id:
                return Response(
                    {"error": "report_id parameter required"},
                    status=status.HTTP_400_BAD_REQUEST,
                )

            report = get_object_or_404(ScanReport, id=report_id)
            return Response(
                {
                    "status": report.status,
                    "error_message": report.error_message,
                    "report_url": report.report_file.url if report.report_file else None,
                    "completed_at": report.completed_at,
                },
                status=status.HTTP_200_OK,
            )

        except Exception as e:
            logger.error(f"[StressReportGenerationAPI] Error getting report status: {e}")
            return Response({"error": str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)
