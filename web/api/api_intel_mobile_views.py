"""
Mobile API views for APIIntelligenceProfile.

GET /mapi/api-intel/          — paginated list; optional ?scan_id=<int>
GET /mapi/api-intel/<pk>/     — single profile detail
"""
import logging
from rest_framework import serializers
from rest_framework.generics import ListAPIView, RetrieveAPIView
from rest_framework.permissions import IsAuthenticated
from startScan.models import APIIntelligenceProfile

logger = logging.getLogger(__name__)


class APIIntelProfileSerializer(serializers.ModelSerializer):
    class Meta:
        model = APIIntelligenceProfile
        fields = [
            'id', 'scan_history', 'target_domain', 'subdomain',
            'base_url', 'api_type', 'endpoint_count', 'requires_auth',
            'auth_scheme', 'parameters_sample', 'graphql_schema_snippet',
            'raw_endpoints',
        ]


class APIIntelMobileListView(ListAPIView):
    """
    GET /mapi/api-intel/
    Returns APIIntelligenceProfile list. Filter by scan_id query param.
    """
    permission_classes = [IsAuthenticated]
    serializer_class = APIIntelProfileSerializer
    pagination_class = None

    def get_queryset(self):
        qs = APIIntelligenceProfile.objects.select_related('subdomain', 'scan_history', 'target_domain')
        scan_id = self.request.query_params.get('scan_id')
        if scan_id:
            try:
                qs = qs.filter(scan_history_id=int(scan_id))
            except (ValueError, TypeError):
                pass
        return qs.order_by('api_type', 'base_url')


class APIIntelMobileDetailView(RetrieveAPIView):
    """GET /mapi/api-intel/<pk>/"""
    permission_classes = [IsAuthenticated]
    serializer_class = APIIntelProfileSerializer
    queryset = APIIntelligenceProfile.objects.all()
