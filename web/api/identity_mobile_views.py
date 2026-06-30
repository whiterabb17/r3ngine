"""Mobile-specific Identity Infrastructure views for r3ngine-mobile v1.5.0+."""
import logging
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

logger = logging.getLogger(__name__)

_INFRA_TYPE_TO_PROVIDER = {
    'okta': 'okta',
    'azure': 'azure_ad',
    'azure_ad': 'azure_ad',
    'auth0': 'auth0',
    'ping': 'ping',
    'onelogin': 'onelogin',
    'jumpcloud': 'jumpcloud',
    'adfs': 'adfs',
    'owa': 'owa',
    'exchange': 'exchange',
    'ldap': 'ldap',
    'sso': 'sso',
    'saml_idp': 'saml_idp',
    'vpn_portal': 'vpn_portal',
    'ntlm_endpoint': 'ntlm_endpoint',
    'generic_auth_portal': 'generic_auth_portal',
}


def _map_provider(infra_type: str) -> str:
    return _INFRA_TYPE_TO_PROVIDER.get((infra_type or '').lower(), 'other')


def _confidence_to_strength(score) -> str:
    s = float(score or 0)
    if s >= 0.7:
        return 'high'
    if s >= 0.4:
        return 'medium'
    return 'low'


def _serialize_identity(rec) -> dict:
    signals = rec.additional_signals or {}
    return {
        'id': rec.id,
        'provider': _map_provider(rec.infra_type),
        'match_strength': _confidence_to_strength(rec.confidence_score),
        'detection_signals': {
            'matched_urls': [rec.url] if rec.url else [],
            'matched_titles': [],
            'matched_headers': signals if isinstance(signals, dict) else {},
        },
        'target_id': rec.target_domain_id,
        'scan_id': rec.scan_history_id,
        'first_seen': str(rec.id),  # proxy — no timestamp field on model
        'confirmed': rec.confirmed,
        'dismissed': rec.dismissed,
    }


class IdentityMobileDetailView(APIView):
    """GET /mapi/identity/<int:pk>/"""
    permission_classes = [IsAuthenticated]

    def get(self, request, pk):
        from startScan.models import IdentityInfraDiscovery
        try:
            rec = IdentityInfraDiscovery.objects.get(pk=pk)
        except IdentityInfraDiscovery.DoesNotExist:
            return Response(
                {'error': 'Identity discovery not found'},
                status=status.HTTP_404_NOT_FOUND,
            )
        return Response(_serialize_identity(rec))


class IdentityConfirmView(APIView):
    """PATCH /mapi/identity/<int:pk>/confirm/  body: {"confirmed": bool}"""
    permission_classes = [IsAuthenticated]

    def patch(self, request, pk):
        from startScan.models import IdentityInfraDiscovery
        confirmed = request.data.get('confirmed')
        if confirmed is None:
            return Response(
                {'error': 'confirmed field is required'},
                status=status.HTTP_400_BAD_REQUEST,
            )

        try:
            rec = IdentityInfraDiscovery.objects.get(pk=pk)
        except IdentityInfraDiscovery.DoesNotExist:
            return Response(
                {'error': 'Identity discovery not found'},
                status=status.HTTP_404_NOT_FOUND,
            )

        rec.confirmed = bool(confirmed)
        rec.save(update_fields=['confirmed'])
        logger.info('IdentityConfirmView: pk=%s confirmed=%s', pk, rec.confirmed)
        return Response(_serialize_identity(rec))


class IdentityDismissView(APIView):
    """PATCH /mapi/identity/<int:pk>/dismiss/  body: {"reason"?: str}"""
    permission_classes = [IsAuthenticated]

    def patch(self, request, pk):
        from startScan.models import IdentityInfraDiscovery
        reason = (request.data.get('reason') or '')[:1000]

        try:
            rec = IdentityInfraDiscovery.objects.get(pk=pk)
        except IdentityInfraDiscovery.DoesNotExist:
            return Response(
                {'error': 'Identity discovery not found'},
                status=status.HTTP_404_NOT_FOUND,
            )

        rec.dismissed = True
        rec.dismiss_reason = reason
        rec.save(update_fields=['dismissed', 'dismiss_reason'])
        logger.info('IdentityDismissView: pk=%s dismissed', pk)
        return Response(_serialize_identity(rec))
