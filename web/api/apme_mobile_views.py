"""Mobile-specific APME API views for r3ngine-mobile v1.5.0+."""
import logging
from rest_framework import status
from rest_framework.permissions import IsAuthenticated
from rest_framework.response import Response
from rest_framework.views import APIView

logger = logging.getLogger(__name__)


def _score_to_priority(score: float) -> str:
    if score >= 90: return 'P0'
    if score >= 70: return 'P1'
    if score >= 50: return 'P2'
    return 'P3'


class RiskSummaryMobileView(APIView):
    """GET /api/apme/risk-summary/?scan_id=<id>"""
    permission_classes = [IsAuthenticated]

    def get(self, request):
        from startScan.models import ImpactAssessment
        scan_id = request.query_params.get('scan_id')
        if not scan_id:
            return Response({'error': 'scan_id is required'}, status=status.HTTP_400_BAD_REQUEST)
        try:
            scan_id = int(scan_id)
        except (ValueError, TypeError):
            return Response({'error': 'scan_id must be an integer'}, status=status.HTTP_400_BAD_REQUEST)

        qs = (
            ImpactAssessment.objects
            .filter(scan_history_id=scan_id)
            .exclude(potential_attack_chain__isnull=True)
            .exclude(potential_attack_chain={})
        )
        assessments = list(qs)
        paths = [a for a in assessments if (a.potential_attack_chain or {}).get('apme_path_id')]

        scores = [float((a.potential_attack_chain or {}).get('score', 0)) for a in paths]
        top_score = max(scores, default=0.0)
        speculative = sum(1 for a in paths if (a.potential_attack_chain or {}).get('is_speculative', False))

        risk_factors = []
        for a in paths[:3]:
            chain = a.potential_attack_chain or {}
            for step in (chain.get('steps') or []):
                action = step.get('action', '')
                if action and action not in risk_factors:
                    risk_factors.append(action)
                    if len(risk_factors) >= 5:
                        break

        return Response({
            'score': round(top_score, 1),
            'priority': _score_to_priority(top_score),
            'path_count': len(paths),
            'speculative_count': speculative,
            'top_risk_factors': risk_factors[:5],
        })


class ImpactDetailMobileView(APIView):
    """GET /api/apme/impact/<str:path_id>/"""
    permission_classes = [IsAuthenticated]

    def get(self, request, path_id):
        from startScan.models import ImpactAssessment
        assessment = ImpactAssessment.objects.select_related('subdomain').filter(
            potential_attack_chain__apme_path_id=path_id
        ).first()
        if not assessment:
            return Response({'error': 'Attack path not found'}, status=status.HTTP_404_NOT_FOUND)

        chain = assessment.potential_attack_chain or {}
        mitre = []
        for step in (chain.get('steps') or []):
            tech = step.get('mitre_technique')
            tactic = step.get('mitre_tactic', '')
            if tech:
                mitre.append({'id': tech, 'name': step.get('mitre_technique_name', tech), 'tactic': tactic})

        affected = []
        if assessment.subdomain_id:
            sub = assessment.subdomain
            affected.append({'id': sub.id, 'name': sub.name})

        return Response({
            'business_impact': assessment.potential_impact or '',
            'technical_impact': chain.get('risk', 'unknown'),
            'affected_assets': affected,
            'mitre_techniques': mitre,
        })


class RegenerateImpactMobileView(APIView):
    """POST /api/apme/impact/regenerate/  body: {path_id}"""
    permission_classes = [IsAuthenticated]

    def post(self, request):
        path_id = request.data.get('path_id')
        if not path_id:
            return Response({'error': 'path_id is required'}, status=status.HTTP_400_BAD_REQUEST)

        from startScan.models import ImpactAssessment
        assessment = ImpactAssessment.objects.filter(
            potential_attack_chain__apme_path_id=path_id
        ).first()
        if not assessment:
            return Response({'error': 'Attack path not found'}, status=status.HTTP_404_NOT_FOUND)

        from reNgine.job_tracker import create_job
        from reNgine.temporal_client import TemporalClientProvider
        import asyncio

        scan_id = assessment.scan_history_id
        job_id = create_job()

        async def _start():
            client = await TemporalClientProvider.get_client()
            await client.start_workflow(
                'ApmeTaskWorkflow',
                args=[scan_id, job_id],
                id=f'apme-regen-{scan_id}-{job_id}',
                task_queue='python-orchestrator-queue',
            )

        loop = asyncio.new_event_loop()
        try:
            loop.run_until_complete(_start())
        except Exception as exc:
            from reNgine.job_tracker import update_job
            logger.error('RegenerateImpactMobileView: workflow start failed: %s', exc)
            update_job(job_id, 'FAILED', 100, 'Workflow start failed')
        finally:
            loop.close()

        return Response({'queued': True}, status=status.HTTP_202_ACCEPTED)


class AttackTreeMobileView(APIView):
    """GET /api/apme/tree/<str:target_id>/  (URL-encoded target_id)"""
    permission_classes = [IsAuthenticated]

    def get(self, request, target_id):
        from startScan.models import ImpactAssessment
        from urllib.parse import unquote
        target_id_decoded = unquote(target_id)

        qs = (
            ImpactAssessment.objects
            .exclude(potential_attack_chain__isnull=True)
            .exclude(potential_attack_chain={})
            .filter(subdomain__name__icontains=target_id_decoded)
            .order_by('-remediation_priority')
        )

        paths = []
        for a in qs:
            chain = a.potential_attack_chain or {}
            if not chain.get('apme_path_id'):
                continue
            score = float(chain.get('score', 0))
            paths.append({
                'path_id': chain.get('apme_path_id', 'unknown'),
                'risk': chain.get('risk', 'unknown'),
                'score': score,
                'step_count': len(chain.get('steps', [])),
                'potential_impact': a.potential_impact or '',
                'mitre_tactics': list({
                    step.get('mitre_tactic', '')
                    for step in chain.get('steps', [])
                    if step.get('mitre_tactic')
                }),
                'priority': _score_to_priority(score),
                'is_speculative': bool(chain.get('is_speculative', False)),
                'score_breakdown': chain.get('score_breakdown'),
                'leaf_detectability': chain.get('leaf_detectability'),
            })

        return Response({'paths': paths})


class DismissPathMobileView(APIView):
    """PATCH /api/apme/path/<str:path_id>/dismiss/  body: {reason?}"""
    permission_classes = [IsAuthenticated]

    def patch(self, request, path_id):
        from startScan.models import ImpactAssessment
        assessment = ImpactAssessment.objects.filter(
            potential_attack_chain__apme_path_id=path_id
        ).first()
        if not assessment:
            return Response({'error': 'Attack path not found'}, status=status.HTTP_404_NOT_FOUND)

        reason = (request.data.get('reason') or '')[:1000]
        assessment.dismissed = True
        assessment.dismiss_reason = reason
        assessment.save(update_fields=['dismissed', 'dismiss_reason'])
        logger.info('DismissPathMobileView: path %s dismissed', path_id)
        return Response({'status': 'dismissed'})
