import logging

from rest_framework.response import Response
from rest_framework.views import APIView

from api.permissions import IsPenetrationTester
from api.serializers import ReconNoteSerializer
from recon_note.models import TodoNote
from reNgine.definitions import INTERNAL_ERROR_MESSAGE
from startScan.models import ScanHistory

logger = logging.getLogger(__name__)


class ListTodoNotes(APIView):
	permission_classes = [IsPenetrationTester]
	def get(self, request, format=None):
		req = self.request
		notes = TodoNote.objects.all().order_by('-id')
		scan_id = req.query_params.get('scan_id')
		project = req.query_params.get('project')
		if project:
			notes = notes.filter(project__slug=project)
		target_id = req.query_params.get('target_id')
		todo_id = req.query_params.get('todo_id')
		subdomain_id = req.query_params.get('subdomain_id')
		if target_id:
			notes = notes.filter(scan_history__in=ScanHistory.objects.filter(domain__id=target_id))
		elif scan_id:
			notes = notes.filter(scan_history__id=scan_id)
		if todo_id:
			notes = notes.filter(id=todo_id)
		if subdomain_id:
			notes = notes.filter(subdomain__id=subdomain_id)
		notes = ReconNoteSerializer(notes, many=True)
		return Response({'notes': notes.data})


class ToggleTodoStatus(APIView):
	permission_classes = [IsPenetrationTester]
	def post(self, request):
		todo_id = request.data.get('id')
		try:
			note = TodoNote.objects.get(id=todo_id)
			note.is_done = not note.is_done
			note.save()
			return Response({'status': True, 'is_done': note.is_done})
		except TodoNote.DoesNotExist:
			return Response({'status': False, 'message': 'Note not found'}, status=404)


class ToggleNoteImportance(APIView):
	permission_classes = [IsPenetrationTester]
	def post(self, request):
		todo_id = request.data.get('id')
		try:
			note = TodoNote.objects.get(id=todo_id)
			note.is_important = not note.is_important
			note.save()
			return Response({'status': True, 'is_important': note.is_important})
		except TodoNote.DoesNotExist:
			return Response({'status': False, 'message': 'Note not found'}, status=404)


class DeleteReconNote(APIView):
	permission_classes = [IsPenetrationTester]
	def post(self, request):
		todo_id = request.data.get('id')
		try:
			TodoNote.objects.filter(id=todo_id).delete()
			return Response({'status': True})
		except Exception:
			logger.exception('Failed to delete todo note')
			return Response({'status': False, 'message': INTERNAL_ERROR_MESSAGE}, status=500)
