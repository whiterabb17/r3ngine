from rest_framework import viewsets, permissions
from rest_framework.decorators import action
from rest_framework.response import Response
from .models import Client, Engagement, Assessment, AssessmentScope, AssessmentAsset
from .serializers import (
    ClientSerializer, EngagementSerializer, AssessmentSerializer,
    AssessmentScopeSerializer, AssessmentAssetSerializer
)
from api.serializers import ScanHistorySerializer

class ClientViewSet(viewsets.ModelViewSet):
    queryset = Client.objects.all().order_by('-created_at')
    serializer_class = ClientSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

class EngagementViewSet(viewsets.ModelViewSet):
    queryset = Engagement.objects.all().order_by('-created_at')
    serializer_class = EngagementSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

class AssessmentViewSet(viewsets.ModelViewSet):
    queryset = Assessment.objects.all().order_by('-created_at')
    serializer_class = AssessmentSerializer
    permission_classes = [permissions.IsAuthenticated]

    def perform_create(self, serializer):
        serializer.save(created_by=self.request.user)

    @action(detail=True, methods=['get'])
    def assets(self, request, pk=None):
        assessment = self.get_object()
        assets = AssessmentAsset.objects.filter(assessment=assessment)
        serializer = AssessmentAssetSerializer(assets, many=True)
        return Response(serializer.data)

    @action(detail=True, methods=['get'])
    def scans(self, request, pk=None):
        assessment = self.get_object()
        scans = assessment.scan_histories.all()
        serializer = ScanHistorySerializer(scans, many=True)
        return Response(serializer.data)

class AssessmentScopeViewSet(viewsets.ModelViewSet):
    queryset = AssessmentScope.objects.all()
    serializer_class = AssessmentScopeSerializer
    permission_classes = [permissions.IsAuthenticated]

class AssessmentAssetViewSet(viewsets.ModelViewSet):
    queryset = AssessmentAsset.objects.all()
    serializer_class = AssessmentAssetSerializer
    permission_classes = [permissions.IsAuthenticated]
