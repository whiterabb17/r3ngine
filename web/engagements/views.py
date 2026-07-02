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

    @action(detail=True, methods=['post'])
    def start(self, request, pk=None):
        from asgiref.sync import async_to_sync
        from reNgine.temporal_client import TemporalClientProvider
        from reNgine.temporal.workflows.assessment_workflow import AssessmentWorkflow, AssessmentInput
        from .services.state_machine import AssessmentStateMachine

        assessment = self.get_object()
        
        try:
            AssessmentStateMachine.transition_to(assessment, 'Ready', user=request.user)
            
            client = async_to_sync(TemporalClientProvider.get_client)()
            
            workflow_id = f"assessment-{assessment.uuid}"
            
            # Start the Temporal Workflow
            async_to_sync(client.start_workflow)(
                AssessmentWorkflow.run,
                AssessmentInput(
                    assessment_id=str(assessment.uuid),
                    engagement_id=str(assessment.engagement.uuid),
                    assessment_type=assessment.assessment_type,
                    scope_ids=[str(scope.uuid) for scope in assessment.scopes.all()]
                ),
                id=workflow_id,
                task_queue="rengine-tasks"
            )
            
            # Save workflow ID in state
            from .models import AssessmentWorkflowState
            state, _ = AssessmentWorkflowState.objects.get_or_create(assessment=assessment)
            state.workflow_id = workflow_id
            state.save()
            
            return Response({'status': 'Assessment started', 'workflow_id': workflow_id})
        except Exception as e:
            return Response({'error': str(e)}, status=400)

    @action(detail=True, methods=['post'])
    def pause(self, request, pk=None):
        from asgiref.sync import async_to_sync
        from reNgine.temporal_client import TemporalClientProvider
        
        assessment = self.get_object()
        try:
            client = async_to_sync(TemporalClientProvider.get_client)()
            workflow_id = f"assessment-{assessment.uuid}"
            handle = client.get_workflow_handle(workflow_id)
            async_to_sync(handle.signal)("pause_assessment")
            return Response({'status': 'Assessment pause signal sent'})
        except Exception as e:
            return Response({'error': str(e)}, status=400)

    @action(detail=True, methods=['post'])
    def resume(self, request, pk=None):
        from asgiref.sync import async_to_sync
        from reNgine.temporal_client import TemporalClientProvider
        
        assessment = self.get_object()
        try:
            client = async_to_sync(TemporalClientProvider.get_client)()
            workflow_id = f"assessment-{assessment.uuid}"
            handle = client.get_workflow_handle(workflow_id)
            async_to_sync(handle.signal)("resume_assessment")
            return Response({'status': 'Assessment resume signal sent'})
        except Exception as e:
            return Response({'error': str(e)}, status=400)

    @action(detail=True, methods=['post'])
    def cancel(self, request, pk=None):
        from asgiref.sync import async_to_sync
        from reNgine.temporal_client import TemporalClientProvider
        from .services.state_machine import AssessmentStateMachine
        
        assessment = self.get_object()
        try:
            AssessmentStateMachine.transition_to(assessment, 'Cancelled', user=request.user)
            
            client = async_to_sync(TemporalClientProvider.get_client)()
            workflow_id = f"assessment-{assessment.uuid}"
            handle = client.get_workflow_handle(workflow_id)
            async_to_sync(handle.signal)("cancel_assessment")
            return Response({'status': 'Assessment cancel signal sent'})
        except Exception as e:
            return Response({'error': str(e)}, status=400)

class AssessmentScopeViewSet(viewsets.ModelViewSet):
    queryset = AssessmentScope.objects.all()
    serializer_class = AssessmentScopeSerializer
    permission_classes = [permissions.IsAuthenticated]

class AssessmentAssetViewSet(viewsets.ModelViewSet):
    queryset = AssessmentAsset.objects.all()
    serializer_class = AssessmentAssetSerializer
    permission_classes = [permissions.IsAuthenticated]
