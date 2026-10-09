from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role
from unittest.mock import patch

from dashboard.models import Project
from mcp.keys import display_prefix, generate_mcp_secret, hash_mcp_secret
from mcp.models import AttackPathProposal, McpApiKey
from mcp.tool_map import tool_name_for
from scanEngine.models import EngineType
from startScan.models import ImpactAssessment, ScanHistory, Vulnerability
from targetApp.models import Domain

User = get_user_model()


def mcp_client_with_session(user, transport='stdio'):
    secret = generate_mcp_secret()
    McpApiKey.objects.create(
        user=user,
        name=f'k-{user.username}',
        prefix=display_prefix(secret),
        key_hash=hash_mcp_secret(secret),
    )
    client = APIClient()
    client.credentials(HTTP_AUTHORIZATION=f'Bearer {secret}')
    sid = client.post('/api/mcp/sessions/', {
        'transport': transport,
        'client_name': 'test',
        'client_version': '0',
        'agent_id': hash_mcp_secret(secret),
        'provider': 'test',
        'ide': 'test',
        'device_id': 'test-device',
        'hostname': 'test-host',
        'username': user.username,
    }, format='json').json()['session_id']
    client.credentials(
        HTTP_AUTHORIZATION=f'Bearer {secret}',
        HTTP_X_MCP_SESSION_ID=str(sid),
    )
    return client


class McpAttackPathProposalTests(TestCase):
    def setUp(self):
        self.project = Project.objects.create(
            name='Path Project',
            slug='path-project',
            insert_date=timezone.now(),
        )
        self.engine = EngineType.objects.create(engine_name='Default', yaml_configuration='')
        self.domain = Domain.objects.create(
            name='path.example.com',
            project=self.project,
            insert_date=timezone.now(),
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=2,
            start_scan_date=timezone.now(),
        )
        self.vuln = Vulnerability.objects.create(
            name='SQL Injection',
            severity=3,
            scan_history=self.scan,
            target_domain=self.domain,
            http_url='https://path.example.com/api',
            validation_status='new',
        )
        self.path_id = 'APT-TEST-PATH-1'
        self.impact = ImpactAssessment.objects.create(
            scan_history=self.scan,
            vulnerability=self.vuln,
            potential_impact='Data exposure',
            remediation_priority=2,
            potential_attack_chain={
                'apme_path_id': self.path_id,
                'risk': 'high',
                'score': 0.8,
                'steps': [{'action': 'abuse_sqli', 'from': 'internet', 'to': 'api'}],
            },
        )
        self.pentester = User.objects.create_user(username='path-pt', password='x')
        assign_role(self.pentester, 'penetration_tester')
        self.pt = mcp_client_with_session(self.pentester)

    def test_tool_map_routes(self):
        self.assertEqual(
            tool_name_for('GET', f'/api/mcp/attack-paths/{self.path_id}/'),
            'r3ngine_get_attack_path',
        )
        self.assertEqual(
            tool_name_for('POST', '/api/mcp/attack-path-proposals/propose/'),
            'r3ngine_propose_attack_path',
        )
        self.assertEqual(
            tool_name_for('POST', '/api/mcp/attack-path-proposals/1/approve/'),
            'r3ngine_approve_attack_path_proposal',
        )

    def test_direct_enrich_returns_410(self):
        before = self.impact.potential_attack_chain
        res = self.pt.patch(
            f'/api/mcp/attack-paths/{self.path_id}/enrich/',
            {'feasibility': 'plausible', 'confidence': 0.9},
            format='json',
        )
        self.assertEqual(res.status_code, 410)
        self.impact.refresh_from_db()
        self.assertEqual(self.impact.potential_attack_chain, before)

    def test_direct_trigger_apme_returns_410(self):
        res = self.pt.post('/api/mcp/apme/trigger/', {'scan_id': self.scan.id}, format='json')
        self.assertEqual(res.status_code, 410)

    def test_get_attack_path_detail(self):
        res = self.pt.get(f'/api/mcp/attack-paths/{self.path_id}/')
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body['path_id'], self.path_id)
        self.assertIn('chain', body)
        self.assertEqual(body['vulnerability']['id'], self.vuln.id)

    def test_propose_does_not_mutate(self):
        res = self.pt.post(
            '/api/mcp/attack-path-proposals/propose/',
            {
                'project_slug': 'path-project',
                'scan_id': self.scan.id,
                'operation': 'enrich',
                'target_path_id': self.path_id,
                'agent_id': 'r3ngine-attack-path',
                'rationale': 'Auth gate unclear',
                'payload': {
                    'feasibility': 'stretched',
                    'confidence': 0.55,
                    'blocked_reasons': ['auth gate unclear'],
                    'missing_prereqs': ['valid session'],
                    'impact_classes': ['data_leakage'],
                    'rationale': 'Chain assumes auth',
                },
            },
            format='json',
        )
        self.assertEqual(res.status_code, 201)
        body = res.json()
        self.assertEqual(body['status'], 'proposed')
        self.impact.refresh_from_db()
        self.assertIsNone(
            (self.impact.potential_attack_chain or {}).get('agent_path_review')
        )

    def test_approve_applies_enrich(self):
        proposed = self.pt.post(
            '/api/mcp/attack-path-proposals/propose/',
            {
                'project_slug': 'path-project',
                'scan_id': self.scan.id,
                'operation': 'enrich',
                'target_path_id': self.path_id,
                'payload': {
                    'feasibility': 'stretched',
                    'confidence': 0.55,
                    'blocked_reasons': ['auth'],
                    'impact_classes': ['data_leakage'],
                },
            },
            format='json',
        ).json()
        res = self.pt.post(
            f'/api/mcp/attack-path-proposals/{proposed["id"]}/approve/',
            {},
            format='json',
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['status'], 'applied')
        self.impact.refresh_from_db()
        review = self.impact.potential_attack_chain['agent_path_review']
        self.assertEqual(review['feasibility'], 'stretched')
        self.assertEqual(review['confidence'], 0.55)

    def test_abort_leaves_db_unchanged(self):
        proposed = self.pt.post(
            '/api/mcp/attack-path-proposals/propose/',
            {
                'project_slug': 'path-project',
                'scan_id': self.scan.id,
                'operation': 'enrich',
                'target_path_id': self.path_id,
                'payload': {'feasibility': 'fantasy', 'confidence': 0.1},
            },
            format='json',
        ).json()
        res = self.pt.post(
            f'/api/mcp/attack-path-proposals/{proposed["id"]}/abort/',
            {},
            format='json',
        )
        self.assertEqual(res.status_code, 200)
        self.assertEqual(res.json()['status'], 'aborted')
        self.impact.refresh_from_db()
        self.assertIsNone(
            (self.impact.potential_attack_chain or {}).get('agent_path_review')
        )

    def test_forbidden_keys_rejected(self):
        res = self.pt.post(
            '/api/mcp/attack-path-proposals/propose/',
            {
                'project_slug': 'path-project',
                'scan_id': self.scan.id,
                'operation': 'enrich',
                'target_path_id': self.path_id,
                'payload': {'feasibility': 'plausible', 'payload': 'SELECT 1'},
            },
            format='json',
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn('forbidden', res.json()['error'])

    def test_create_and_unique_vuln_conflict(self):
        create = self.pt.post(
            '/api/mcp/attack-path-proposals/propose/',
            {
                'project_slug': 'path-project',
                'scan_id': self.scan.id,
                'operation': 'create',
                'payload': {
                    'chain': {
                        'risk': 'medium',
                        'score': 0.4,
                        'steps': [{'action': 'recon', 'from': 'internet', 'to': 'edge'}],
                    },
                    'potential_impact': 'Alternate narrated path',
                },
            },
            format='json',
        )
        self.assertEqual(create.status_code, 201)
        applied = self.pt.post(
            f'/api/mcp/attack-path-proposals/{create.json()["id"]}/approve/',
            {},
            format='json',
        )
        self.assertEqual(applied.status_code, 200)
        path_id = applied.json()['result']['path_id']
        self.assertTrue(str(path_id).startswith('APT-AGENT-'))
        self.assertTrue(
            ImpactAssessment.objects.filter(
                potential_attack_chain__apme_path_id=path_id
            ).exists()
        )

        conflict = self.pt.post(
            '/api/mcp/attack-path-proposals/propose/',
            {
                'project_slug': 'path-project',
                'scan_id': self.scan.id,
                'operation': 'create',
                'payload': {
                    'vulnerability_id': self.vuln.id,
                    'chain': {'steps': [{'action': 'dup'}]},
                },
            },
            format='json',
        )
        self.assertEqual(conflict.status_code, 201)
        deny = self.pt.post(
            f'/api/mcp/attack-path-proposals/{conflict.json()["id"]}/approve/',
            {},
            format='json',
        )
        self.assertEqual(deny.status_code, 409)

    def test_dismiss_on_approve(self):
        proposed = self.pt.post(
            '/api/mcp/attack-path-proposals/propose/',
            {
                'project_slug': 'path-project',
                'scan_id': self.scan.id,
                'operation': 'dismiss',
                'target_path_id': self.path_id,
                'payload': {'dismiss_reason': 'Fantasy chain'},
            },
            format='json',
        ).json()
        res = self.pt.post(
            f'/api/mcp/attack-path-proposals/{proposed["id"]}/approve/',
            {},
            format='json',
        )
        self.assertEqual(res.status_code, 200)
        self.impact.refresh_from_db()
        self.assertTrue(self.impact.dismissed)
        self.assertEqual(self.impact.dismiss_reason, 'Fantasy chain')

    @patch('mcp.attack_path_proposals._queue_apme')
    def test_trigger_apme_only_on_approve(self, mock_queue):
        mock_queue.return_value = {
            'status': 'triggered',
            'task_id': 'job-1',
            'workflow_id': 'wf-1',
            'recalculate': False,
        }
        proposed = self.pt.post(
            '/api/mcp/attack-path-proposals/propose/',
            {
                'project_slug': 'path-project',
                'scan_id': self.scan.id,
                'operation': 'trigger_apme',
                'rationale': 'Operator asked to remodel',
            },
            format='json',
        ).json()
        self.assertFalse(mock_queue.called)
        res = self.pt.post(
            f'/api/mcp/attack-path-proposals/{proposed["id"]}/approve/',
            {},
            format='json',
        )
        self.assertEqual(res.status_code, 200)
        mock_queue.assert_called_once_with(self.scan.id, recalculate=False)
        self.assertEqual(AttackPathProposal.objects.get(pk=proposed['id']).status, 'applied')

    def test_cross_project_path_rejected(self):
        other = Project.objects.create(
            name='Other',
            slug='other-project',
            insert_date=timezone.now(),
        )
        other_domain = Domain.objects.create(
            name='other.example.com',
            project=other,
            insert_date=timezone.now(),
        )
        other_scan = ScanHistory.objects.create(
            domain=other_domain,
            scan_type=self.engine,
            scan_status=2,
            start_scan_date=timezone.now(),
        )
        other_path = 'APT-OTHER-PATH'
        ImpactAssessment.objects.create(
            scan_history=other_scan,
            potential_impact='x',
            potential_attack_chain={
                'apme_path_id': other_path,
                'steps': [{'action': 'x'}],
            },
        )
        res = self.pt.post(
            '/api/mcp/attack-path-proposals/propose/',
            {
                'project_slug': 'path-project',
                'scan_id': self.scan.id,
                'operation': 'enrich',
                'target_path_id': other_path,
                'payload': {'feasibility': 'plausible', 'confidence': 0.9},
            },
            format='json',
        )
        self.assertEqual(res.status_code, 403)

    def test_mcp_update_does_not_claim_operator(self):
        """MCP agents must not set operator_edited (body operator=true ignored)."""
        proposed = self.pt.post(
            '/api/mcp/attack-path-proposals/propose/',
            {
                'project_slug': 'path-project',
                'scan_id': self.scan.id,
                'operation': 'enrich',
                'target_path_id': self.path_id,
                'payload': {'feasibility': 'stretched', 'confidence': 0.4},
            },
            format='json',
        ).json()
        res = self.pt.post(
            f'/api/mcp/attack-path-proposals/{proposed["id"]}/update/',
            {
                'operator': True,  # forged — must not elevate
                'payload': {'feasibility': 'plausible', 'confidence': 0.8},
            },
            format='json',
        )
        self.assertEqual(res.status_code, 200)
        self.assertFalse(res.json()['operator_edited'])
        row = AttackPathProposal.objects.get(pk=proposed['id'])
        self.assertFalse(row.operator_edited)

        # After a real operator lock, MCP agent cannot overwrite.
        row.operator_edited = True
        row.save(update_fields=['operator_edited'])
        locked = self.pt.post(
            f'/api/mcp/attack-path-proposals/{proposed["id"]}/update/',
            {'payload': {'feasibility': 'fantasy', 'confidence': 0.1}},
            format='json',
        )
        self.assertEqual(locked.status_code, 403)

    @patch('mcp.attack_path_proposals._apply_enrich')
    def test_approve_unexpected_error_rolls_back(self, mock_enrich):
        mock_enrich.side_effect = RuntimeError('db blew up')
        proposed = self.pt.post(
            '/api/mcp/attack-path-proposals/propose/',
            {
                'project_slug': 'path-project',
                'scan_id': self.scan.id,
                'operation': 'enrich',
                'target_path_id': self.path_id,
                'payload': {'feasibility': 'plausible', 'confidence': 0.9},
            },
            format='json',
        ).json()
        res = self.pt.post(
            f'/api/mcp/attack-path-proposals/{proposed["id"]}/approve/',
            {},
            format='json',
        )
        self.assertEqual(res.status_code, 500)
        row = AttackPathProposal.objects.get(pk=proposed['id'])
        self.assertEqual(row.status, 'proposed')
        self.assertIsNone(row.approved_at)
