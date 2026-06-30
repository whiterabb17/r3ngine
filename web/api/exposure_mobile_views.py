"""Mobile-specific Exposure API views for r3ngine-mobile v1.5.0+."""
import logging
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

logger = logging.getLogger(__name__)

_VALID_STATUSES = {'open', 'verified', 'accepted', 'false_positive', 'remediated', 'resolved'}


def _risk_to_severity(score) -> str:
    if score is None:
        return 'info'
    s = float(score)
    if s >= 9.0:
        return 'critical'
    if s >= 7.0:
        return 'high'
    if s >= 4.0:
        return 'medium'
    if s >= 1.0:
        return 'low'
    return 'info'


def _serialize_exposure(obj) -> dict:
    subdomain = obj.subdomain
    hostname = subdomain.name if subdomain else None
    ip = None
    if subdomain and hasattr(subdomain, 'ip_addresses'):
        ips = list(subdomain.ip_addresses.values_list('address', flat=True)[:1])
        ip = ips[0] if ips else None

    types = obj.type or []
    service = types[0] if types else None

    title = hostname or (obj.endpoint.http_url if obj.endpoint_id else None) or f'Exposure #{obj.id}'

    ev = obj.evidence.order_by('id').first()
    evidence_data = ev.evidence_data if ev else {}

    vuln_ids = list(obj.vulnerabilities.values_list('id', flat=True))

    return {
        'id': obj.id,
        'title': title,
        'status': obj.status,
        'severity': _risk_to_severity(obj.risk_score),
        'asset_summary': {
            'hostname': hostname,
            'ip': ip,
            'port': None,
            'service': service,
        },
        'evidence_data': evidence_data if isinstance(evidence_data, dict) else {},
        'evidence_timestamps': {
            'first_seen': obj.first_seen.isoformat() if obj.first_seen else None,
            'last_seen': obj.last_seen.isoformat() if obj.last_seen else None,
        } if obj.first_seen else None,
        'linked_vulnerability_ids': vuln_ids,
        'scan_id': obj.scan_history_id,
        'created_at': obj.first_seen.isoformat() if obj.first_seen else '',
    }


class ExposureMobileListView(APIView):
    """GET /mapi/exposures/?scan_id=<id>[&status=<status>]"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from startScan.models import Exposure
        scan_id = request.query_params.get('scan_id')
        filter_status = request.query_params.get('status')

        qs = Exposure.objects.select_related('subdomain', 'endpoint').prefetch_related(
            'evidence', 'vulnerabilities', 'subdomain__ip_addresses'
        )

        if scan_id:
            try:
                qs = qs.filter(scan_history_id=int(scan_id))
            except (ValueError, TypeError):
                return Response(
                    {'error': 'scan_id must be an integer'},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        if filter_status:
            if filter_status not in _VALID_STATUSES:
                return Response(
                    {'error': f'Invalid status: {filter_status}'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
            qs = qs.filter(status=filter_status)

        return Response([_serialize_exposure(e) for e in qs.order_by('-first_seen')[:200]])


class ExposureMobileDetailView(APIView):
    """GET /mapi/exposures/<int:pk>/"""
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        from startScan.models import Exposure
        try:
            obj = (
                Exposure.objects
                .select_related('subdomain', 'endpoint')
                .prefetch_related('evidence', 'vulnerabilities', 'subdomain__ip_addresses')
                .get(pk=pk)
            )
        except Exposure.DoesNotExist:
            return Response({'error': 'Exposure not found'}, status=status.HTTP_404_NOT_FOUND)
        return Response(_serialize_exposure(obj))


class ExposureStatsMobileView(APIView):
    """GET /mapi/exposures/stats/?scan_id=<id>"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from startScan.models import Exposure
        from django.db.models import Count
        scan_id = request.query_params.get('scan_id')

        qs = Exposure.objects.all()
        if scan_id:
            try:
                qs = qs.filter(scan_history_id=int(scan_id))
            except (ValueError, TypeError):
                return Response(
                    {'error': 'scan_id must be an integer'},
                    status=status.HTTP_400_BAD_REQUEST,
                )

        total = qs.count()
        by_status = {row['status']: row['cnt'] for row in qs.values('status').annotate(cnt=Count('id'))}

        sev_counts = {'critical': 0, 'high': 0, 'medium': 0, 'low': 0, 'info': 0}
        for score in qs.values_list('risk_score', flat=True):
            sev_counts[_risk_to_severity(score)] += 1

        return Response({
            'total': total,
            'open': by_status.get('open', 0),
            'accepted': by_status.get('accepted', 0) + by_status.get('verified', 0),
            'false_positive': by_status.get('false_positive', 0),
            'resolved': by_status.get('resolved', 0) + by_status.get('remediated', 0),
            'by_severity': sev_counts,
        })


class ExposureStatusUpdateView(APIView):
    """PATCH /mapi/exposures/<int:pk>/status/  body: {status, note?}"""
    permission_classes = [IsAuthenticated]

    def patch(self, request, pk):
        from startScan.models import Exposure
        new_status = request.data.get('status')
        note = (request.data.get('note') or '')[:1000]

        if not new_status:
            return Response({'error': 'status is required'}, status=status.HTTP_400_BAD_REQUEST)
        if new_status not in _VALID_STATUSES:
            return Response(
                {'error': f'Invalid status: {new_status}'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            obj = (
                Exposure.objects
                .select_related('subdomain', 'endpoint')
                .prefetch_related('evidence', 'vulnerabilities', 'subdomain__ip_addresses')
                .get(pk=pk)
            )
        except Exposure.DoesNotExist:
            return Response({'error': 'Exposure not found'}, status=status.HTTP_404_NOT_FOUND)

        obj.status = new_status
        obj.status_note = note
        obj.save(update_fields=['status', 'status_note'])
        logger.info('ExposureStatusUpdateView: exposure %s set to %s', pk, new_status)
        return Response(_serialize_exposure(obj))


class ExposureBulkStatusView(APIView):
    """POST /mapi/exposures/bulk-status/  body: {ids: [], status}"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        from startScan.models import Exposure
        ids = request.data.get('ids', [])
        new_status = request.data.get('status')

        if not isinstance(ids, list) or not ids:
            return Response({'error': 'ids must be a non-empty list'}, status=status.HTTP_400_BAD_REQUEST)
        if not new_status:
            return Response({'error': 'status is required'}, status=status.HTTP_400_BAD_REQUEST)
        if new_status not in _VALID_STATUSES:
            return Response({'error': f'Invalid status: {new_status}'}, status=status.HTTP_400_BAD_REQUEST)
        if len(ids) > 100:
            return Response({'error': 'Maximum 100 IDs per request'}, status=status.HTTP_400_BAD_REQUEST)

        try:
            int_ids = [int(i) for i in ids]
        except (ValueError, TypeError):
            return Response({'error': 'ids must be integers'}, status=status.HTTP_400_BAD_REQUEST)

        exists_ids = set(Exposure.objects.filter(pk__in=int_ids).values_list('id', flat=True))
        Exposure.objects.filter(pk__in=exists_ids).update(status=new_status)
        updated = list(exists_ids)
        rejected = [i for i in int_ids if i not in exists_ids]

        logger.info('ExposureBulkStatusView: updated=%s rejected=%s', len(updated), len(rejected))
        return Response({'updated': updated, 'rejected': rejected})
