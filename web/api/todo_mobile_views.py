"""
Mobile API views for TodoNote CRUD.

GET  /mapi/todos/          — list; optional ?project=<slug>&scan_id=<int>
POST /mapi/todos/          — create; body {title, description, project, scan_id?}
GET  /mapi/todos/<pk>/     — retrieve single note
PATCH /mapi/todos/<pk>/    — partial update; body {is_done?, is_important?, title?, description?}
DELETE /mapi/todos/<pk>/   — delete; returns 204
"""
import logging

from django.shortcuts import get_object_or_404
from rest_framework import status as http_status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

from dashboard.models import Project
from recon_note.models import TodoNote
from startScan.models import ScanHistory

from .serializers import ReconNoteSerializer

logger = logging.getLogger(__name__)


class TodoMobileListCreateView(APIView):
    """GET + POST /mapi/todos/"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        notes = TodoNote.objects.select_related(
            'project', 'scan_history__domain', 'subdomain'
        ).order_by('-id')

        project_slug = request.query_params.get('project')
        if project_slug:
            notes = notes.filter(project__slug=project_slug)

        scan_id = request.query_params.get('scan_id')
        if scan_id:
            try:
                notes = notes.filter(scan_history__id=int(scan_id))
            except (ValueError, TypeError):
                pass

        return Response({'todos': ReconNoteSerializer(notes, many=True).data})

    def post(self, request):
        title = request.data.get('title', '').strip()
        description = request.data.get('description', '').strip()
        project_slug = request.data.get('project', '').strip()

        if not title:
            return Response(
                {'error': 'title is required'},
                status=http_status.HTTP_400_BAD_REQUEST,
            )
        if not project_slug:
            return Response(
                {'error': 'project is required'},
                status=http_status.HTTP_400_BAD_REQUEST,
            )

        project = get_object_or_404(Project, slug=project_slug)
        note = TodoNote(title=title, description=description, project=project)

        scan_id = request.data.get('scan_id')
        if scan_id:
            scan = get_object_or_404(ScanHistory, id=scan_id)
            note.scan_history = scan

        note.save()
        logger.info("TodoNote created: id=%s project=%s", note.id, project_slug)
        return Response(ReconNoteSerializer(note).data, status=http_status.HTTP_201_CREATED)


class TodoMobileDetailView(APIView):
    """GET + PATCH + DELETE /mapi/todos/<pk>/"""
    permission_classes = [IsAuthenticated]

    def _get_note(self, pk: int) -> TodoNote:
        return get_object_or_404(
            TodoNote.objects.select_related('project', 'scan_history__domain', 'subdomain'),
            pk=pk,
        )

    def get(self, request, pk: int):
        return Response(ReconNoteSerializer(self._get_note(pk)).data)

    def patch(self, request, pk: int):
        note = self._get_note(pk)
        changed = False

        if 'is_done' in request.data:
            note.is_done = bool(request.data['is_done'])
            changed = True
        if 'is_important' in request.data:
            note.is_important = bool(request.data['is_important'])
            changed = True
        if 'title' in request.data:
            note.title = request.data['title'].strip()
            changed = True
        if 'description' in request.data:
            note.description = request.data['description'].strip()
            changed = True

        if changed:
            note.save()

        return Response(ReconNoteSerializer(note).data)

    def delete(self, request, pk: int):
        self._get_note(pk).delete()
        return Response(status=http_status.HTTP_204_NO_CONTENT)
