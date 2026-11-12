"""Assessment Copilot gateway tests (no sidecar required for approve remediations)."""
from __future__ import annotations

from django.contrib.auth.models import User
from django.utils import timezone
from rest_framework.test import APIClient
from django.test import TestCase

from copilot.models import CopilotActionProposal, CopilotSession
from copilot.service import approve_proposal, create_proposal, reject_proposal
from dashboard.models import Project
from rolepermissions.roles import assign_role
from scanEngine.models import EngineType
from startScan.models import Domain, ScanHistory, Vulnerability
from reNgine.definitions import SUCCESS_TASK


class CopilotGatewayTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='copilot-op', password='x')
        assign_role(self.user, 'penetration_tester')
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        self.client.force_login(self.user)
        self.project = Project.objects.create(
            name='Copilot', slug='copilot-project', insert_date=timezone.now(),
        )
        self.engine = EngineType.objects.create(engine_name='CE', yaml_configuration='')
        self.domain = Domain.objects.create(
            name='copilot.example.com', project=self.project, insert_date=timezone.now(),
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=SUCCESS_TASK,
            start_scan_date=timezone.now(),
        )
        self.vuln = Vulnerability.objects.create(
            name='Reflected XSS',
            severity=2,
            http_url='https://copilot.example.com/search?q=1',
            scan_history=self.scan,
            target_domain=self.domain,
        )

    def test_settings_get_patch(self):
        res = self.client.get('/api/copilot/settings/', {'project_slug': 'copilot-project'})
        self.assertEqual(res.status_code, 200, res.content)
        self.assertTrue(res.json()['enabled'])
        res = self.client.patch(
            '/api/copilot/settings/',
            {'project_slug': 'copilot-project', 'memory_scope': 'org', 'enabled': True},
            format='json',
        )
        self.assertEqual(res.status_code, 200, res.content)
        self.assertEqual(res.json()['memory_scope'], 'org')

    def test_session_crud(self):
        res = self.client.post('/api/copilot/sessions/', {
            'project_slug': 'copilot-project',
            'scan_id': self.scan.id,
            'title': 'Engagement chat',
        }, format='json')
        self.assertEqual(res.status_code, 201, res.content)
        sid = res.json()['id']
        res = self.client.get(f'/api/copilot/sessions/{sid}/')
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['title'], 'Engagement chat')
        res = self.client.get('/api/copilot/sessions/', {'project_slug': 'copilot-project'})
        self.assertEqual(res.status_code, 200)
        self.assertGreaterEqual(len(res.json()['sessions']), 1)

    def test_remediation_approve_persists(self):
        proposal = create_proposal(
            project_slug='copilot-project',
            action_type=CopilotActionProposal.TYPE_REMEDIATION,
            summary='Patch XSS',
            rationale='Reflect encoding',
            vulnerability_id=self.vuln.id,
            payload={
                'short': 'Encode output immediately.',
                'long': 'Adopt contextual output encoding and CSP long-term.',
            },
            user=self.user,
        )
        approved = approve_proposal(proposal, user=self.user)
        self.assertEqual(approved.status, CopilotActionProposal.STATUS_APPROVED)
        self.vuln.refresh_from_db()
        self.assertIn('Encode output', self.vuln.remediation or '')
        rem = (self.vuln.agent_enrichment or {}).get('remediation') or {}
        self.assertEqual(rem.get('short'), 'Encode output immediately.')
        self.assertIn('CSP', rem.get('long') or '')

    def test_validate_approve_never_auto_verified(self):
        proposal = create_proposal(
            project_slug='copilot-project',
            action_type=CopilotActionProposal.TYPE_VALIDATE,
            vulnerability_id=self.vuln.id,
            payload={
                'validation_status': 'verified',
                'validation_verdict': 'likely_tp',
                'confidence': 0.95,
            },
            user=self.user,
        )
        approve_proposal(proposal, user=self.user)
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.validation_status, 'needs_review')

    def test_validate_rejects_cross_project_vuln(self):
        other = Project.objects.create(
            name='Other', slug='other-project', insert_date=timezone.now(),
        )
        other_domain = Domain.objects.create(
            name='other.example.com', project=other, insert_date=timezone.now(),
        )
        other_scan = ScanHistory.objects.create(
            domain=other_domain,
            scan_type=self.engine,
            scan_status=SUCCESS_TASK,
            start_scan_date=timezone.now(),
        )
        other_vuln = Vulnerability.objects.create(
            name='Other finding',
            severity=2,
            http_url='https://other.example.com/',
            scan_history=other_scan,
            target_domain=other_domain,
        )
        proposal = create_proposal(
            project_slug='copilot-project',
            action_type=CopilotActionProposal.TYPE_VALIDATE,
            vulnerability_id=other_vuln.id,
            payload={'validation_status': 'needs_review'},
            user=self.user,
        )
        from copilot.service import CopilotError
        with self.assertRaises(CopilotError):
            approve_proposal(proposal, user=self.user)

    def test_session_requires_project_slug(self):
        session = CopilotSession.objects.create(
            project_slug='copilot-project', title='Scoped',
        )
        res = self.client.get(f'/api/copilot/sessions/{session.id}/')
        self.assertEqual(res.status_code, 400)
        res = self.client.get(
            f'/api/copilot/sessions/{session.id}/',
            {'project_slug': 'copilot-project'},
        )
        self.assertEqual(res.status_code, 200)
        res = self.client.get(
            f'/api/copilot/sessions/{session.id}/',
            {'project_slug': 'wrong-project'},
        )
        self.assertEqual(res.status_code, 404)

    def test_reject_proposal(self):
        proposal = create_proposal(
            project_slug='copilot-project',
            action_type=CopilotActionProposal.TYPE_VALIDATE,
            vulnerability_id=self.vuln.id,
            payload={},
            user=self.user,
        )
        rejected = reject_proposal(proposal, user=self.user)
        self.assertEqual(rejected.status, CopilotActionProposal.STATUS_REJECTED)

    def test_proposals_list_api(self):
        create_proposal(
            project_slug='copilot-project',
            action_type=CopilotActionProposal.TYPE_VALIDATE,
            vulnerability_id=self.vuln.id,
            payload={},
            user=self.user,
        )
        res = self.client.get('/api/copilot/proposals/', {'project_slug': 'copilot-project'})
        self.assertEqual(res.status_code, 200, res.content)
        self.assertGreaterEqual(len(res.json()['proposals']), 1)

    def test_status_endpoint(self):
        res = self.client.get('/api/copilot/status/', {'project_slug': 'copilot-project'})
        self.assertEqual(res.status_code, 200, res.content)
        body = res.json()
        self.assertIn('health', body)
        self.assertIn('pending_proposals', body)
