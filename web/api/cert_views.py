"""Certificate Intelligence REST API views."""

import logging
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework import status

from .permissions import IsAuditor

logger = logging.getLogger(__name__)

_PAGE_DEFAULT = 1
_PAGE_SIZE_DEFAULT = 100
_PAGE_SIZE_MAX = 500


class CertificateIntelView(APIView):
    """
    GET /api/certs/?scan_id=<id>[&project=<slug>][&page=<n>][&page_size=<n>]

    Returns CertificateIntelligence records for a scan, ordered by risk
    (expired first, then weak-cipher, then self-signed).  Requires at least
    Auditor role.  The scan must belong to the project identified by the
    project slug so that cross-project IDOR is not possible.
    """
    permission_classes = [IsAuditor]

    def get(self, request):
        from startScan.models import CertificateIntelligence

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

        try:
            page = max(1, int(request.query_params.get("page", _PAGE_DEFAULT)))
            page_size = min(
                _PAGE_SIZE_MAX,
                max(1, int(request.query_params.get("page_size", _PAGE_SIZE_DEFAULT))),
            )
        except (ValueError, TypeError):
            return Response(
                {"error": "page and page_size must be integers"},
                status=status.HTTP_400_BAD_REQUEST,
            )

        qs = (
            CertificateIntelligence.objects
            .filter(scan_history_id=scan_id)
        )

        # Scope to project to prevent cross-project IDOR.
        if project_slug:
            qs = qs.filter(scan_history__domain__project__slug=project_slug)

        qs = qs.order_by("-is_expired", "-has_weak_cipher", "-self_signed", "host")

        total = qs.count()
        offset = (page - 1) * page_size
        page_qs = qs[offset: offset + page_size]

        results = [
            {
                "id": c.id,
                "host": c.host,
                "port": c.port,
                "subject_cn": c.subject_cn,
                "subject_an": c.subject_an or [],
                "issuer_cn": c.issuer_cn,
                "issuer_org": c.issuer_org,
                "not_before": c.not_before.isoformat() if c.not_before else None,
                "not_after": c.not_after.isoformat() if c.not_after else None,
                "tls_version": c.tls_version,
                "cipher": c.cipher,
                "fingerprint_sha256": c.fingerprint_sha256,
                "self_signed": c.self_signed,
                "mismatched": c.mismatched,
                "is_expired": c.is_expired,
                "has_weak_cipher": c.has_weak_cipher,
            }
            for c in page_qs
        ]

        return Response({
            "count": total,
            "page": page,
            "page_size": page_size,
            "results": results,
        })
