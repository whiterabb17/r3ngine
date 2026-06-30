"""Identity Infrastructure REST API views."""

import logging
from collections import defaultdict
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

from .permissions import IsAuditor

logger = logging.getLogger(__name__)


class IdentityInfraView(APIView):
    """
    GET /api/identity/?scan_id=<id>[&project=<slug>]

    Returns all IdentityInfraDiscovery records for a scan.
    Response includes a summary dict keyed by infra_type.
    Requires Auditor role or above.
    """
    permission_classes = [IsAuditor]

    def get(self, request):
        from startScan.models import IdentityInfraDiscovery

        scan_id = request.query_params.get("scan_id")
        project_slug = request.query_params.get("project")

        if not scan_id:
            return Response(
                {"error": "scan_id query parameter is required"},
                status=status.HTTP_400_BAD_REQUEST,
            )
        try:
            scan_id = int(scan_id)
        except (ValueError, TypeError):
            return Response(
                {"error": "scan_id must be an integer"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        qs = IdentityInfraDiscovery.objects.filter(scan_history_id=scan_id)

        # Scope to project when provided — prevents cross-project IDOR for callers that
        # supply a project slug.  Without it, IsAuditor is the only guard (same posture as
        # apme_views.py and cert_views.py).  TODO: make project_slug required once all
        # frontend callers are confirmed to pass it.
        if project_slug:
            qs = qs.filter(scan_history__domain__project__slug=project_slug)
        else:
            logger.warning(
                "identity_views: scan_id=%s requested without project scoping",
                scan_id,
            )

        qs = qs.order_by("-confidence_score", "infra_type", "host")

        summary: dict = defaultdict(int)
        results = []
        for rec in qs:
            summary[rec.infra_type] += 1
            results.append({
                "id": rec.id,
                "host": rec.host,
                "url": rec.url,
                "infra_type": rec.infra_type,
                "detection_method": rec.detection_method,
                "confidence_score": round(rec.confidence_score, 3),
                "is_externally_accessible": rec.is_externally_accessible,
                "additional_signals": rec.additional_signals,
            })

        return Response({
            "count": len(results),
            "summary": dict(summary),
            "results": results,
        })
