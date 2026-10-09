from rest_framework import serializers, viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from rest_framework.permissions import IsAuthenticated

from startScan.models import TemporalSchedule
from .permissions import HasPermission
from reNgine.definitions import PERM_INITATE_SCANS_SUBSCANS, PERM_MODIFY_SCAN_RESULTS

import logging

logger = logging.getLogger(__name__)


class TemporalScheduleSerializer(serializers.ModelSerializer):
    """Serializes TemporalSchedule with field names compatible with the legacy
    PeriodicTaskSerializer so the frontend requires no changes."""

    # Legacy-compatible aliases
    enabled = serializers.BooleanField(source='is_active')
    kwargs = serializers.JSONField(source='workflow_args')
    date_changed = serializers.DateTimeField(source='updated_at', read_only=True)
    task = serializers.SerializerMethodField()
    description = serializers.SerializerMethodField()
    frequency = serializers.SerializerMethodField()

    class Meta:
        model = TemporalSchedule
        fields = [
            'id', 'name', 'task', 'description', 'frequency',
            'enabled', 'last_run_at', 'total_run_count',
            'one_off', 'kwargs', 'date_changed',
        ]

    def get_task(self, obj):
        return obj.workflow_type

    def get_description(self, obj):
        if ':' in obj.name:
            return obj.name.split(':')[0]
        return obj.name

    def get_frequency(self, obj):
        if obj.interval_seconds:
            s = obj.interval_seconds
            if s % (30 * 86400) == 0:
                n = s // (30 * 86400)
                return f"Every {n} month{'s' if n > 1 else ''}"
            if s % (7 * 86400) == 0:
                n = s // (7 * 86400)
                return f"Every {n} week{'s' if n > 1 else ''}"
            if s % 86400 == 0:
                n = s // 86400
                return f"Every {n} day{'s' if n > 1 else ''}"
            if s % 3600 == 0:
                n = s // 3600
                return f"Every {n} hour{'s' if n > 1 else ''}"
            if s % 60 == 0:
                n = s // 60
                return f"Every {n} minute{'s' if n > 1 else ''}"
            return f"Every {s}s"
        if obj.clocked_time:
            return f"Once at {obj.clocked_time}"
        if obj.cron_expression:
            return f"Cron: {obj.cron_expression}"
        return "N/A"


class ScheduledScanViewSet(viewsets.ModelViewSet):
    """ViewSet for TemporalSchedule CRUD + toggle/bulk_delete actions.

    Named ScheduledScanViewSet (not TemporalScheduleViewSet) so existing
    URL router registrations require no changes.
    """
    queryset = TemporalSchedule.objects.all().order_by('-created_at')
    serializer_class = TemporalScheduleSerializer
    permission_classes = [IsAuthenticated, HasPermission]
    permission_required = PERM_INITATE_SCANS_SUBSCANS

    @action(detail=True, methods=['post'])
    def toggle(self, request, pk=None):
        from reNgine.temporal_schedule_utils import (
            _pause_temporal_schedule,
            _unpause_temporal_schedule,
        )
        ts = self.get_object()
        ts.is_active = not ts.is_active
        ts.save(update_fields=['is_active', 'updated_at'])
        try:
            if ts.is_active:
                _unpause_temporal_schedule(ts.schedule_id)
            else:
                _pause_temporal_schedule(ts.schedule_id)
        except Exception as e:
            logger.error("[ScheduledScanViewSet.toggle] Temporal call failed for '%s': %s", ts.schedule_id, e)
        return Response({'status': True, 'enabled': ts.is_active})

    @action(detail=False, methods=['post'])
    def bulk_delete(self, request):
        from reNgine.temporal_schedule_utils import _delete_temporal_schedule_by_id
        ids = request.data.get('ids', [])
        if not ids:
            return Response(
                {'status': False, 'message': 'No IDs provided'},
                status=status.HTTP_400_BAD_REQUEST,
            )
        records = TemporalSchedule.objects.filter(id__in=ids)
        deleted = 0
        for ts in records:
            try:
                _delete_temporal_schedule_by_id(ts.schedule_id)
            except Exception as e:
                logger.error("[ScheduledScanViewSet.bulk_delete] Temporal delete failed for '%s': %s", ts.schedule_id, e)
            ts.delete()
            deleted += 1
        return Response({'status': True, 'message': f'Deleted {deleted} scheduled scans'})
