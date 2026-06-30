"""Mobile-specific Certificate Intelligence views for r3ngine-mobile v1.5.0+."""
import logging
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

logger = logging.getLogger(__name__)

_VALID_FLAGS = {'expired-not-revoked', 'weak-key', 'suspicious-san', 'other'}


def _serialize_cert(c) -> dict:
    return {
        'id': c.id,
        'subject_cn': c.subject_cn or '',
        'issuer_cn': c.issuer_cn or '',
        'san': c.subject_an or [],
        'not_before': c.not_before.isoformat() if c.not_before else None,
        'not_after': c.not_after.isoformat() if c.not_after else None,
        'sha256_fingerprint': c.fingerprint_sha256 or '',
        'sha1_fingerprint': None,  # not stored in model
        'chain': c.trust_chain if isinstance(c.trust_chain, list) else [],
        'scan_id': c.scan_history_id,
        'is_self_signed': bool(c.self_signed),
        'is_expired': bool(c.is_expired),
        'flag_type': c.flag_type,
        'flag_note': c.flag_note,
    }


class CertificateMobileListView(APIView):
    """GET /mapi/certificates/?scan_id=<id> (scan_id optional)"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from startScan.models import CertificateIntelligence
        scan_id = request.query_params.get('scan_id')
        qs = CertificateIntelligence.objects.order_by('-is_expired', '-has_weak_cipher', 'host')
        if scan_id:
            try:
                qs = qs.filter(scan_history_id=int(scan_id))
            except (ValueError, TypeError):
                return Response(
                    {'error': 'scan_id must be an integer'},
                    status=status.HTTP_400_BAD_REQUEST,
                )
        return Response([_serialize_cert(c) for c in qs[:200]])


class CertificateMobileDetailView(APIView):
    """GET /mapi/certificates/<int:pk>/"""
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        from startScan.models import CertificateIntelligence
        try:
            c = CertificateIntelligence.objects.get(pk=pk)
        except CertificateIntelligence.DoesNotExist:
            return Response({'error': 'Certificate not found'}, status=status.HTTP_404_NOT_FOUND)
        return Response(_serialize_cert(c))


class CertificateResyncView(APIView):
    """POST /mapi/certificates/<int:pk>/resync/"""
    permission_classes = [IsAuthenticated]

    def post(self, request, pk):
        from startScan.models import CertificateIntelligence
        try:
            c = CertificateIntelligence.objects.get(pk=pk)
        except CertificateIntelligence.DoesNotExist:
            return Response({'error': 'Certificate not found'}, status=status.HTTP_404_NOT_FOUND)

        from reNgine.job_tracker import create_job, update_job
        from reNgine.temporal_client import TemporalClientProvider
        import asyncio

        job_id = create_job()

        async def _start():
            client = await TemporalClientProvider.get_client()
            await client.start_workflow(
                "CertificateResyncWorkflow",
                args=[c.id, job_id],
                id=f"cert-resync-{c.id}-{job_id}",
                task_queue="python-orchestrator-queue",
            )

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(_start())
        except Exception as e:
            update_job(job_id, "FAILED", 100, f"Failed to start resync: {e}")
            logger.warning(
                "CertificateResyncView: workflow start failed for cert %s: %s", pk, e
            )
        finally:
            loop.close()

        return Response({'queued': True, 'job_id': job_id}, status=status.HTTP_202_ACCEPTED)


class CertificateFlagView(APIView):
    """PATCH /mapi/certificates/<int:pk>/flag/  body: {flag, note?}"""
    permission_classes = [IsAuthenticated]

    def patch(self, request, pk):
        from startScan.models import CertificateIntelligence
        flag = request.data.get('flag')
        note = (request.data.get('note') or '')[:1000]

        if not flag:
            return Response({'error': 'flag is required'}, status=status.HTTP_400_BAD_REQUEST)
        if flag not in _VALID_FLAGS:
            return Response(
                {'error': f'Invalid flag. Must be one of: {", ".join(sorted(_VALID_FLAGS))}'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            c = CertificateIntelligence.objects.get(pk=pk)
        except CertificateIntelligence.DoesNotExist:
            return Response({'error': 'Certificate not found'}, status=status.HTTP_404_NOT_FOUND)

        c.flag_type = flag
        c.flag_note = note or None
        c.save(update_fields=['flag_type', 'flag_note'])
        logger.info('CertificateFlagView: cert %s flagged as %s', pk, flag)
        return Response(_serialize_cert(c))
