"""Evidence Platform REST API views.

All views require authentication. Evidence files are served via a signed URL
redirect (never directly) so they are protected by Django's permission system.

Endpoints:
  GET    /api/evidence/collections/
  POST   /api/evidence/collections/
  GET    /api/evidence/collections/{uuid}/
  GET    /api/evidence/collections/{uuid}/items/
  DELETE /api/evidence/collections/{uuid}/archive/

  GET    /api/evidence/{uuid}/
  POST   /api/evidence/upload/
  GET    /api/evidence/{uuid}/download/
  POST   /api/evidence/{uuid}/verify/
  POST   /api/evidence/{uuid}/archive/
  DELETE /api/evidence/{uuid}/purge/
  POST   /api/evidence/{uuid}/annotations/
"""
import logging

from django.http import HttpResponseRedirect, Http404
from django.shortcuts import get_object_or_404
from rest_framework import permissions, status
from rest_framework.decorators import action
from rest_framework.parsers import MultiPartParser, FormParser, JSONParser
from rest_framework.response import Response
from rest_framework.views import APIView
from rest_framework.viewsets import GenericViewSet
from rest_framework.mixins import RetrieveModelMixin, ListModelMixin, CreateModelMixin

from .models import Evidence, EvidenceCollection, EvidenceAnnotation
from .serializers import (
    EvidenceSerializer, EvidenceListSerializer, EvidenceCollectionSerializer,
    EvidenceUploadSerializer, EvidenceAnnotationSerializer,
)
from .services import EvidenceService

logger = logging.getLogger(__name__)


class EvidenceCollectionViewSet(RetrieveModelMixin, ListModelMixin, CreateModelMixin, GenericViewSet):
    """CRUD for EvidenceCollection records.

    GET /api/evidence/collections/ — list all collections for authenticated user
    POST /api/evidence/collections/ — create a new collection
    GET /api/evidence/collections/{uuid}/ — retrieve a single collection
    GET /api/evidence/collections/{uuid}/items/ — list evidence items in collection
    POST /api/evidence/collections/{uuid}/archive/ — archive the collection
    """
    serializer_class = EvidenceCollectionSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'uuid'

    def get_queryset(self):
        """Return collections filtered by assessment if provided."""
        qs = EvidenceCollection.objects.prefetch_related('evidence_items', 'retention_policy').order_by('-created_at')
        assessment_id = self.request.query_params.get('assessment')
        if assessment_id:
            qs = qs.filter(assessment__uuid=assessment_id)
        return qs

    @action(detail=True, methods=['get'])
    def items(self, request, uuid=None):
        """List evidence items in this collection.

        Supports filtering by status and evidence_type.
        GET /api/evidence/collections/{uuid}/items/?status=Active&type=Screenshot
        """
        collection = self.get_object()
        qs = collection.evidence_items.all().order_by('-collected_at')

        item_status = request.query_params.get('status')
        if item_status:
            qs = qs.filter(status=item_status)

        evidence_type = request.query_params.get('type')
        if evidence_type:
            qs = qs.filter(evidence_type=evidence_type)

        serializer = EvidenceListSerializer(qs, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['post'])
    def archive(self, request, uuid=None):
        """Archive all active evidence in this collection.

        POST /api/evidence/collections/{uuid}/archive/
        """
        collection = self.get_object()
        try:
            EvidenceService.archive_collection(collection, actor=request.user)
            return Response({'status': 'Collection archived', 'uuid': str(collection.uuid)})
        except Exception as e:
            logger.error(f"[EVIDENCE] Archive collection {uuid} failed: {e}")
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)


class EvidenceViewSet(RetrieveModelMixin, ListModelMixin, GenericViewSet):
    """Retrieve and manage individual Evidence items.

    GET /api/evidence/ — list (supports ?collection=<uuid> filter)
    GET /api/evidence/{uuid}/ — get detail
    GET /api/evidence/{uuid}/download/ — get signed download URL or redirect
    POST /api/evidence/{uuid}/verify/ — verify integrity
    POST /api/evidence/{uuid}/archive/ — archive item
    DELETE /api/evidence/{uuid}/purge/ — purge item
    POST /api/evidence/{uuid}/annotations/ — add annotation
    GET /api/evidence/{uuid}/annotations/ — list annotations
    """
    serializer_class = EvidenceSerializer
    permission_classes = [permissions.IsAuthenticated]
    lookup_field = 'uuid'

    def get_queryset(self):
        qs = Evidence.objects.prefetch_related(
            'events', 'annotations', 'vulnerabilities', 'scopes'
        ).order_by('-collected_at')
        collection_uuid = self.request.query_params.get('collection')
        if collection_uuid:
            qs = qs.filter(collection__uuid=collection_uuid)
        return qs

    def get_serializer_class(self):
        if self.action == 'list':
            return EvidenceListSerializer
        return EvidenceSerializer

    @action(detail=True, methods=['get'])
    def download(self, request, uuid=None):
        """Return a signed download URL for an evidence file.

        Returns a redirect to the signed URL, or a JSON object with the URL.
        GET /api/evidence/{uuid}/download/

        Query params:
            redirect=1 — redirect to URL instead of returning JSON.
        """
        evidence = self.get_object()
        if not evidence.file_path:
            raise Http404("No file associated with this evidence item.")

        try:
            url = EvidenceService.get_download_url(evidence)
        except Exception as e:
            return Response({'error': str(e)}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        if request.query_params.get('redirect') == '1':
            return HttpResponseRedirect(url)
        return Response({'url': url, 'uuid': str(evidence.uuid)})

    @action(detail=True, methods=['post'])
    def verify(self, request, uuid=None):
        """Verify the SHA-256 integrity of an evidence file.

        POST /api/evidence/{uuid}/verify/

        Returns:
            {"passed": true/false, "sha256_hash": "...", "uuid": "..."}
        """
        evidence = self.get_object()
        passed = EvidenceService.verify_integrity(evidence, actor=request.user)
        return Response({
            'passed': passed,
            'sha256_hash': evidence.sha256_hash,
            'uuid': str(evidence.uuid),
        })

    @action(detail=True, methods=['post'])
    def archive(self, request, uuid=None):
        """Archive an evidence item.

        POST /api/evidence/{uuid}/archive/
        Body: {"note": "Optional reason"}
        """
        evidence = self.get_object()
        if evidence.status != 'Active':
            return Response(
                {'error': f"Cannot archive evidence in status '{evidence.status}'."},
                status=status.HTTP_400_BAD_REQUEST,
            )
        note = request.data.get('note', '')
        EvidenceService.archive_evidence(evidence, actor=request.user, note=note)
        return Response({'status': 'Archived', 'uuid': str(evidence.uuid)})

    @action(detail=True, methods=['delete'])
    def purge(self, request, uuid=None):
        """Purge an evidence item.

        DELETE /api/evidence/{uuid}/purge/
        Body: {"delete_file": false}
        """
        evidence = self.get_object()
        delete_file = bool(request.data.get('delete_file', False))
        EvidenceService.purge_evidence(evidence, actor=request.user, delete_file=delete_file)
        return Response({'status': 'Purged', 'uuid': str(evidence.uuid)})

    @action(detail=True, methods=['get', 'post'])
    def annotations(self, request, uuid=None):
        """List or create annotations for an evidence item.

        GET  /api/evidence/{uuid}/annotations/ — list annotations
        POST /api/evidence/{uuid}/annotations/ — create annotation
        Body: {"annotation_type": "Note", "content": "...", "region": null}
        """
        evidence = self.get_object()

        if request.method == 'GET':
            annotations = evidence.annotations.all().order_by('created_at')
            serializer = EvidenceAnnotationSerializer(annotations, many=True)
            return Response(serializer.data)

        # POST — create annotation
        serializer = EvidenceAnnotationSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        annotation = EvidenceAnnotation.objects.create(
            evidence=evidence,
            author=request.user,
            **serializer.validated_data,
        )

        from evidence.models import EvidenceEvent
        from django.utils import timezone
        EvidenceEvent.objects.create(
            evidence=evidence,
            event_type='Annotated',
            actor=request.user,
            note=f"{annotation.annotation_type}: {annotation.content[:100]}",
            timestamp=timezone.now(),
        )
        return Response(EvidenceAnnotationSerializer(annotation).data, status=status.HTTP_201_CREATED)


class EvidenceUploadView(APIView):
    """Upload a new evidence file.

    POST /api/evidence/upload/
    Content-Type: multipart/form-data
    Fields: file, title, description, evidence_type, collection_uuid, vulnerability_ids, scope_ids
    """
    permission_classes = [permissions.IsAuthenticated]
    parser_classes = [MultiPartParser, FormParser, JSONParser]

    def post(self, request):
        """Handle evidence file upload, validate, hash, store, and return the created item."""
        serializer = EvidenceUploadSerializer(data=request.data)
        serializer.is_valid(raise_exception=True)
        data = serializer.validated_data

        collection = get_object_or_404(EvidenceCollection, uuid=data['collection_uuid'])

        uploaded_file = data['file']
        content = uploaded_file.read()
        filename = uploaded_file.name

        try:
            evidence = EvidenceService.create_evidence(
                collection=collection,
                content=content,
                filename=filename,
                evidence_type=data['evidence_type'],
                title=data['title'],
                description=data.get('description', ''),
                collected_by=request.user,
                vulnerability_ids=data.get('vulnerability_ids', []),
                scope_ids=data.get('scope_ids', []),
            )
        except ValueError as e:
            return Response({'error': str(e)}, status=status.HTTP_400_BAD_REQUEST)
        except Exception as e:
            logger.error(f"[EVIDENCE] Upload failed: {e}", exc_info=True)
            return Response({'error': 'Upload failed. See server logs.'}, status=status.HTTP_500_INTERNAL_SERVER_ERROR)

        return Response(EvidenceSerializer(evidence).data, status=status.HTTP_201_CREATED)
