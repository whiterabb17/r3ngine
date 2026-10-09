from django.shortcuts import get_object_or_404
from rest_framework.response import Response

from api.permissions import IsPenetrationTester
from dashboard.models import Project
from mcp.pagination import page_queryset
from mcp.views.base import McpDataView
from recon_note.models import TodoNote
from startScan.models import ScanHistory, Subdomain


def serialize_note(row):
    return {
        'id': row.id,
        'title': row.title or '',
        'description': row.description or '',
        'project_slug': row.project.slug if row.project_id else None,
        'scan_id': row.scan_history_id,
        'domain_name': (
            row.scan_history.domain.name
            if row.scan_history_id and row.scan_history.domain_id
            else None
        ),
        'subdomain_id': row.subdomain_id,
        'subdomain_name': row.subdomain.name if row.subdomain_id else None,
        'is_done': bool(row.is_done),
        'is_important': bool(row.is_important),
    }


class McpNotesListCreateView(McpDataView):
    """GET list (any MCP key) + POST create (pentester/sys-admin)."""
    http_method_names = ['get', 'post', 'head', 'options']

    def get_permissions(self):
        if self.request.method == 'POST':
            return [IsPenetrationTester()]
        return super().get_permissions()

    def get(self, request):
        qs = TodoNote.objects.select_related(
            'project', 'scan_history__domain', 'subdomain'
        ).order_by('-id')
        project = request.query_params.get('project')
        if project:
            qs = qs.filter(project__slug=project)
        scan_id = request.query_params.get('scan_id')
        if scan_id:
            try:
                qs = qs.filter(scan_history_id=int(scan_id))
            except (TypeError, ValueError):
                pass
        target_id = request.query_params.get('target_id')
        if target_id:
            try:
                qs = qs.filter(scan_history__domain_id=int(target_id))
            except (TypeError, ValueError):
                pass
        subdomain_id = request.query_params.get('subdomain_id')
        if subdomain_id:
            try:
                qs = qs.filter(subdomain_id=int(subdomain_id))
            except (TypeError, ValueError):
                pass
        todo_id = request.query_params.get('todo_id')
        if todo_id:
            try:
                qs = qs.filter(id=int(todo_id))
            except (TypeError, ValueError):
                pass
        return Response(page_queryset(qs, request, serialize_note))

    def post(self, request):
        title = (request.data.get('title') or '').strip()
        description = (request.data.get('description') or '').strip()
        project_slug = (request.data.get('project') or '').strip()
        if not title:
            return Response({'error': 'title is required'}, status=400)
        if not project_slug:
            return Response({'error': 'project is required'}, status=400)
        project = get_object_or_404(Project, slug=project_slug)
        note = TodoNote(title=title, description=description, project=project)
        if 'is_important' in request.data:
            note.is_important = bool(request.data.get('is_important'))

        subdomain_id = request.data.get('subdomain_id')
        scan_id = request.data.get('scan_id')
        if subdomain_id is not None and subdomain_id != '':
            try:
                subdomain_id = int(subdomain_id)
            except (TypeError, ValueError):
                return Response({'error': 'subdomain_id must be an integer'}, status=400)
            subdomain = get_object_or_404(
                Subdomain.objects.select_related('scan_history__domain__project'),
                pk=subdomain_id,
            )
            scan = subdomain.scan_history
            if not scan or not scan.domain_id or scan.domain.project_id != project.id:
                return Response(
                    {'error': 'subdomain does not belong to the given project'},
                    status=400,
                )
            note.subdomain = subdomain
            note.scan_history = scan
        elif scan_id is not None and scan_id != '':
            try:
                scan_id = int(scan_id)
            except (TypeError, ValueError):
                return Response({'error': 'scan_id must be an integer'}, status=400)
            scan = get_object_or_404(
                ScanHistory.objects.select_related('domain__project'),
                pk=scan_id,
            )
            if not scan.domain_id or scan.domain.project_id != project.id:
                return Response(
                    {'error': 'scan does not belong to the given project'},
                    status=400,
                )
            note.scan_history = scan

        note.save()
        return Response(serialize_note(note), status=201)


class McpNoteDetailView(McpDataView):
    """GET one note (any MCP key) + PATCH update (pentester/sys-admin). No DELETE."""
    http_method_names = ['get', 'patch', 'head', 'options']

    def get_permissions(self):
        if self.request.method == 'PATCH':
            return [IsPenetrationTester()]
        return super().get_permissions()

    def _get_note(self, pk):
        return get_object_or_404(
            TodoNote.objects.select_related('project', 'scan_history__domain', 'subdomain'),
            pk=pk,
        )

    def get(self, request, pk):
        return Response(serialize_note(self._get_note(pk)))

    def patch(self, request, pk):
        note = self._get_note(pk)
        changed = False
        if 'is_done' in request.data:
            note.is_done = bool(request.data['is_done'])
            changed = True
        if 'is_important' in request.data:
            note.is_important = bool(request.data['is_important'])
            changed = True
        if 'title' in request.data:
            note.title = (request.data.get('title') or '').strip()
            if not note.title:
                return Response({'error': 'title cannot be empty'}, status=400)
            changed = True
        if 'description' in request.data:
            note.description = (request.data.get('description') or '').strip()
            changed = True
        if changed:
            note.save()
        return Response(serialize_note(note))
