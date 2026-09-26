from rest_framework import viewsets, status
from rest_framework.decorators import action
from rest_framework.response import Response
from startScan.models import SubScan
from .serializers import SubScanSerializer
from .permissions import HasPermission
from reNgine.definitions import PERM_INITATE_SCANS_SUBSCANS, ABORTED_TASK
class SubScanViewSet(viewsets.ModelViewSet):
    queryset = SubScan.objects.all().order_by('-start_scan_date')
    serializer_class = SubScanSerializer
    permission_classes = [HasPermission]
    permission_required = PERM_INITATE_SCANS_SUBSCANS

    def get_queryset(self):
        project_slug = self.request.query_params.get('project')
        if project_slug:
            return self.queryset.filter(scan_history__domain__project__slug=project_slug)
        return self.queryset

    @action(detail=False, methods=['post'])
    def bulk_delete(self, request):
        ids = request.data.get('ids', [])
        if not ids:
            return Response({'status': False, 'message': 'No IDs provided'}, status=status.HTTP_400_BAD_REQUEST)

        from reNgine.utils.scan_cancellation import abort_subscan
        subscans = SubScan.objects.filter(id__in=ids)
        count = subscans.count()
        for subscan in subscans:
            try:
                abort_subscan(subscan)
            except Exception:
                pass
            subscan.delete()
        return Response({'status': True, 'message': f'Successfully deleted {count} subscans'})

    @action(detail=False, methods=['post'])
    def bulk_stop(self, request):
        ids = request.data.get('ids', [])
        if not ids:
            return Response({'status': False, 'message': 'No IDs provided'}, status=status.HTTP_400_BAD_REQUEST)

        from reNgine.utils.scan_cancellation import abort_subscan
        from reNgine.definitions import SUCCESS_TASK

        subscans = SubScan.objects.filter(id__in=ids)
        stopped = 0
        for subscan in subscans:
            if subscan.status in (SUCCESS_TASK, ABORTED_TASK):
                continue
            result = abort_subscan(subscan)
            if result.get('status'):
                stopped += 1
        return Response({'status': True, 'message': f'Stopped {stopped} subscans'})
