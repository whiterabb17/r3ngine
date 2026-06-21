"""
APME API Views

Exposes attack paths stored in ImpactAssessment to the frontend.
"""

import logging

from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

logger = logging.getLogger(__name__)


class AttackPathsAPIView(APIView):
    """
    GET /api/apme/paths/?scan_id=<id>

    Returns top attack paths computed by the APME for a given scan.
    Paths are ordered by score descending (highest risk first).
    Each step is tagged as 'validated' or 'inferred'.
    """
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from startScan.models import ImpactAssessment
        scan_id = request.query_params.get('scan_id')
        project_slug = request.query_params.get('project')

        if not scan_id and not project_slug:
            return Response(
                {'error': 'scan_id or project query parameter is required'},
                status=status.HTTP_400_BAD_REQUEST
            )

        assessments = ImpactAssessment.objects.all()

        if scan_id:
            try:
                scan_id = int(scan_id)
                assessments = assessments.filter(scan_history_id=scan_id)
            except (ValueError, TypeError):
                return Response({'error': 'scan_id must be an integer'}, status=status.HTTP_400_BAD_REQUEST)
        
        if project_slug:
            assessments = assessments.filter(scan_history__domain__project__slug=project_slug)

        # Fetch ImpactAssessments that have APME path data
        assessments = (
            assessments
            .exclude(potential_attack_chain__isnull=True)
            .exclude(potential_attack_chain={})
            .order_by('-remediation_priority', '-scan_history__start_scan_date')
        )

        paths = []
        for a in assessments:
            chain = a.potential_attack_chain or {}
            if not chain.get('apme_path_id'):
                continue

            paths.append({
                'path_id': chain.get('apme_path_id'),
                'risk': chain.get('risk', 'unknown'),
                'score': chain.get('score', 0.0),
                'step_count': len(chain.get('steps', [])),
                'steps': chain.get('steps', []),
                'potential_impact': a.potential_impact,
                'remediation_priority': a.remediation_priority,
                'vulnerability_id': a.vulnerability_id,
            })

        return Response({
            'total_paths': len(paths),
            'paths': paths,
        }, status=status.HTTP_200_OK)


class TriggerLLMAPMEAPIView(APIView):
    """
    POST /api/apme/trigger/
    Body: { "scan_id": <id> }

    Triggers an on-demand LLM-assisted attack path modeling task.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        scan_id = request.data.get('scan_id')
        if not scan_id:
            return Response(
                {'error': 'scan_id is required in request body'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            from startScan.models import ScanHistory
            scan = ScanHistory.objects.get(id=scan_id)
        except ScanHistory.DoesNotExist:
            return Response({'error': 'Scan not found'}, status=status.HTTP_404_NOT_FOUND)

        from reNgine.job_tracker import create_job
        from reNgine.temporal_client import TemporalClientProvider
        import asyncio
        
        job_id = create_job()
        
        async def _start():
            client = await TemporalClientProvider.get_client()
            await client.start_workflow(
                "ApmeTaskWorkflow",
                args=[scan_id, job_id],
                id=f"apme-modeling-{scan_id}-{job_id}",
                task_queue="python-orchestrator-queue"
            )

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(_start())
        except Exception as e:
            from reNgine.job_tracker import update_job
            update_job(job_id, "FAILED", 100, f"Failed to start workflow: {e}")
        finally:
            loop.close()

        return Response({
            'status': 'triggered',
            'task_id': job_id,
            'message': 'AI Attack Path Modeling task has been initiated.'
        }, status=status.HTTP_202_ACCEPTED)


class RecalculateAttackPathsAPIView(APIView):
    """
    POST /api/apme/recalculate/
    Body: { "scan_id": <id> }

    Triggers an on-demand algorithmic attack path modeling recalculation task (via Temporal).
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        scan_id = request.data.get('scan_id')
        if not scan_id:
            return Response(
                {'error': 'scan_id is required in request body'},
                status=status.HTTP_400_BAD_REQUEST
            )

        try:
            from startScan.models import ScanHistory
            scan = ScanHistory.objects.get(id=scan_id)
        except ScanHistory.DoesNotExist:
            return Response({'error': 'Scan not found'}, status=status.HTTP_404_NOT_FOUND)

        from reNgine.job_tracker import create_job
        from reNgine.temporal_client import TemporalClientProvider
        import asyncio

        job_id = create_job()

        async def _start():
            client = await TemporalClientProvider.get_client()
            await client.start_workflow(
                "RecalculateApmeWorkflow",
                args=[scan_id, job_id],
                id=f"apme-recalculate-{scan_id}-{job_id}",
                task_queue="python-orchestrator-queue"
            )

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(_start())
        except Exception as e:
            from reNgine.job_tracker import update_job
            update_job(job_id, "FAILED", 100, f"Failed to start workflow: {e}")
        finally:
            loop.close()

        return Response({
            'status': 'triggered',
            'task_id': job_id,
            'message': 'Algorithmic Attack Path Recalculation has been initiated.'
        }, status=status.HTTP_202_ACCEPTED)


class AttackPathExplanationAPIView(APIView):
    """
    POST /api/apme/explain/
    Body: { "path_id": "<apme_path_id>" }

    Generates and persists an in-depth tactical explanation of an attack path.
    """
    permission_classes = [IsAuthenticated]

    def post(self, request):
        path_id = request.data.get('path_id')
        if not path_id:
            return Response(
                {'error': 'path_id is required in request body'},
                status=status.HTTP_400_BAD_REQUEST
            )

        from startScan.models import ImpactAssessment
        # Find the ImpactAssessment containing this path ID
        assessment = ImpactAssessment.objects.filter(
            potential_attack_chain__apme_path_id=path_id
        ).first()

        if not assessment:
            return Response(
                {'error': f'Attack path {path_id} not found'},
                status=status.HTTP_404_NOT_FOUND
            )

        chain = assessment.potential_attack_chain or {}
        
        # Return persisted explanation if it already exists
        if 'explanation' in chain and chain['explanation']:
            return Response({
                'status': 'success',
                'path_id': path_id,
                'explanation': chain['explanation']
            }, status=status.HTTP_200_OK)

        # Build details string from nodes and steps to feed to the LLM
        steps = chain.get('steps', [])
        steps_str_list = []
        for i, step in enumerate(steps):
            from_node = step.get('from_node') or {}
            to_node = step.get('to_node') or {}
            from_name = from_node.get('name') or step.get('from')
            to_name = to_node.get('name') or step.get('to')
            action = step.get('action') or 'Exploit transition'
            confidence = step.get('confidence', 1.0)
            status_val = step.get('status') or 'inferred'
            steps_str_list.append(
                f"Step {i+1}: Node [{from_name}] -> Node [{to_name}] via action [{action}] "
                f"(confidence: {confidence * 100}%, status: {status_val})"
            )

        steps_details = "\n".join(steps_str_list)
        path_details_str = (
            f"Risk Level: {chain.get('risk', 'unknown').upper()}\n"
            f"Score: {chain.get('score', 0.0)}\n"
            f"Executive Summary of Impact: {assessment.potential_impact}\n\n"
            f"Steps:\n{steps_details}"
        )

        # Invoke the masked LLM explainer
        from reNgine.llm import LLMAttackPathExplainer
        explainer = LLMAttackPathExplainer(logger=logger)
        try:
            explanation = explainer.explain_path(path_id, path_details_str)
        except Exception as e:
            return Response(
                {'error': f'Failed to generate explanation: {str(e)}'},
                status=status.HTTP_500_INTERNAL_SERVER_ERROR
            )

        # Persist explanation in the JSON field
        chain['explanation'] = explanation
        assessment.potential_attack_chain = chain
        assessment.save(update_fields=['potential_attack_chain'])

        return Response({
            'status': 'success',
            'path_id': path_id,
            'explanation': explanation
        }, status=status.HTTP_200_OK)

