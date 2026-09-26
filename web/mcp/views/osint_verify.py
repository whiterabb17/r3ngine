"""MCP write path for agent OSINT staging verification badges."""
from django.utils import timezone
from rest_framework.response import Response

from api.permissions import IsPenetrationTester
from mcp.views.base import McpDataView
from startScan.models import OsintStaging, ScanHistory

VERIFY_BATCH_CAP = 100


class McpVerifyOsintStagingView(McpDataView):
    """Set agent_verified True/False on staging rows. Does not promote or delete."""

    http_method_names = ['post', 'options']
    permission_classes = [IsPenetrationTester]

    def post(self, request):
        scan_id = request.data.get('scan_id')
        if scan_id is None:
            return Response({'error': 'scan_id is required'}, status=400)
        try:
            scan_id = int(scan_id)
        except (TypeError, ValueError):
            return Response({'error': 'scan_id must be an integer'}, status=400)
        if not ScanHistory.objects.filter(pk=scan_id).exists():
            return Response({'error': 'Not found'}, status=404)

        updates = request.data.get('updates') or []
        if not isinstance(updates, list) or not updates:
            return Response({'error': 'updates must be a non-empty list'}, status=400)
        if len(updates) > VERIFY_BATCH_CAP:
            return Response(
                {'error': f'max {VERIFY_BATCH_CAP} updates per request'},
                status=400,
            )

        now = timezone.now()
        user = request.user if getattr(request.user, 'is_authenticated', False) else None
        updated = []
        errors = []

        for i, item in enumerate(updates):
            if not isinstance(item, dict):
                errors.append({'index': i, 'error': 'each update must be an object'})
                continue
            row_id = item.get('id')
            flag = item.get('agent_verified')
            if row_id is None:
                errors.append({'index': i, 'error': 'id is required'})
                continue
            if flag is not True and flag is not False:
                errors.append({'index': i, 'id': row_id, 'error': 'agent_verified must be true or false'})
                continue
            # Scope every update to the requested scan so ids from other scans cannot be mutated.
            row = OsintStaging.objects.filter(pk=int(row_id), scan_history_id=scan_id).first()
            if not row:
                errors.append({'index': i, 'id': row_id, 'error': 'not found'})
                continue
            row.agent_verified = bool(flag)
            row.agent_verified_at = now
            row.agent_verified_by = user
            row.save(update_fields=['agent_verified', 'agent_verified_at', 'agent_verified_by'])
            updated.append({'id': row.id, 'agent_verified': row.agent_verified})

        return Response({
            'status': True,
            'scan_id': scan_id,
            'updated': updated,
            'updated_count': len(updated),
            'errors': errors,
        })
