"""Tests for capability registry, follow-up plans, and MCP enrichment."""
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role
from unittest.mock import AsyncMock, MagicMock, patch

from dashboard.models import Project
from mcp.followups import FollowupError, normalize_steps, propose_plan, update_plan_steps
from mcp.keys import display_prefix, generate_mcp_secret, hash_mcp_secret
from mcp.models import FollowupPlan, McpApiKey
from reNgine.capabilities import list_capabilities, serialize_engine_detail
from reNgine.definitions import FAILED_TASK, SUCCESS_TASK
from scanEngine.models import EngineType
from startScan.models import ScanActivity, ScanHistory, Subdomain
from targetApp.models import Domain

User = get_user_model()


def mcp_client_with_session(user, transport='stdio'):
    secret = generate_mcp_secret()
    McpApiKey.objects.create(
        user=user,
        name='k',
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
    return client, sid


class CapabilitiesTests(TestCase):
    def test_list_capabilities_shape(self):
        caps = list_capabilities()
        self.assertIn('pipeline_tasks', caps)
        self.assertIn('workflows', caps)
        self.assertEqual(caps['max_followup_steps'], 5)
        names = {t['name'] for t in caps['pipeline_tasks']}
        self.assertIn('port_scan', names)
        self.assertIn('nuclei_scan', names)

    def test_engine_detail_exposes_tasks(self):
        engine = EngineType.objects.create(
            engine_name='CapEngine',
            yaml_configuration='port_scan:\n  enabled: true\nfetch_url:\n  enabled: true\n',
        )
        detail = serialize_engine_detail(engine)
        self.assertIn('port_scan', detail['tasks'])
        self.assertIn('port_scan', detail['known_followup_tasks'])


class FollowupPlanServiceTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='fu-user', password='x')
        assign_role(self.user, 'penetration_tester')
        self.project = Project.objects.create(
            name='FU', slug='fu-project', insert_date=timezone.now(),
        )
        self.engine = EngineType.objects.create(engine_name='E', yaml_configuration='port_scan: {}\n')
        self.domain = Domain.objects.create(
            name='fu.example.com', project=self.project, insert_date=timezone.now(),
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=SUCCESS_TASK,
            start_scan_date=timezone.now(),
            tasks=['port_scan'],
        )
        self.sub = Subdomain.objects.create(
            name='fu.example.com',
            target_domain=self.domain,
            scan_history=self.scan,
        )

    def test_normalize_rejects_more_than_five(self):
        steps = [
            {
                'kind': 'run_tool',
                'tool': 'port_scan',
                'asset_type': 'subdomain',
                'asset_id': self.sub.id,
                'scan_history_id': self.scan.id,
            }
        ] * 6
        with self.assertRaises(FollowupError):
            normalize_steps(steps)

    def test_propose_and_operator_lock(self):
        steps = [
            {
                'kind': 'run_tool',
                'tool': 'port_scan',
                'asset_type': 'subdomain',
                'asset_id': self.sub.id,
                'scan_history_id': self.scan.id,
            }
        ]
        plan = propose_plan(
            project_slug='fu-project',
            steps=steps,
            rationale='test',
            scan_id=self.scan.id,
            user=self.user,
        )
        self.assertEqual(plan.status, FollowupPlan.STATUS_PROPOSED)
        self.assertEqual(len(plan.steps), 1)

        update_plan_steps(plan, steps, user=self.user, is_operator=True)
        plan.refresh_from_db()
        self.assertTrue(plan.operator_edited)
        with self.assertRaises(FollowupError):
            update_plan_steps(plan, steps, user=self.user, is_operator=False)

    @patch('mcp.followups._cancel_plan_workflows')
    @patch('mcp.followups._start_plan_workflow', return_value='followup-plan-1')
    def test_approve_abort_retry(self, _mock_start, _mock_cancel):
        from mcp.followups import abort_plan, approve_plan, retry_plan

        steps = [
            {
                'kind': 'run_tool',
                'tool': 'port_scan',
                'asset_type': 'subdomain',
                'asset_id': self.sub.id,
                'scan_history_id': self.scan.id,
            }
        ]
        plan = propose_plan(
            project_slug='fu-project',
            steps=steps,
            scan_id=self.scan.id,
            user=self.user,
        )
        plan = approve_plan(plan, user=self.user)
        self.assertEqual(plan.status, FollowupPlan.STATUS_RUNNING)
        plan = abort_plan(plan, user=self.user)
        self.assertEqual(plan.status, FollowupPlan.STATUS_ABORTED)
        plan = retry_plan(plan, user=self.user)
        self.assertEqual(plan.status, FollowupPlan.STATUS_RUNNING)
        self.assertEqual(plan.retry_count, 1)

    def test_url_step_must_match_scan_domain(self):
        from mcp.followups import _validate_scope

        with self.assertRaises(FollowupError):
            _validate_scope(
                [
                    {
                        'kind': 'run_tool',
                        'tool': 'nuclei_scan',
                        'asset_type': 'url',
                        'url': 'https://evil.example.net/admin',
                        'scan_history_id': self.scan.id,
                    }
                ],
                'fu-project',
                self.scan.id,
            )
        # In-scope host is accepted
        _validate_scope(
            [
                {
                    'kind': 'run_tool',
                    'tool': 'nuclei_scan',
                    'asset_type': 'url',
                    'url': 'https://api.fu.example.com/v1',
                    'scan_history_id': self.scan.id,
                }
            ],
            'fu-project',
            self.scan.id,
        )

    @patch('reNgine.temporal_client.run_and_close')
    @patch('reNgine.utils.scan_cancellation.abort_scan_history')
    def test_abort_does_not_abort_parent_scan(self, mock_abort_scan, mock_run):
        from reNgine.definitions import RUNNING_TASK
        from mcp.followups import _cancel_plan_workflows

        mock_run.side_effect = lambda loop, coro: None
        self.scan.scan_status = RUNNING_TASK
        self.scan.save(update_fields=['scan_status'])
        plan = FollowupPlan.objects.create(
            project_slug='fu-project',
            scan_id=self.scan.id,
            status=FollowupPlan.STATUS_RUNNING,
            steps=[
                {
                    'id': 's1',
                    'kind': 'run_tool',
                    'status': 'running',
                    'workflow_id': 'tool-wf-1',
                }
            ],
            temporal_workflow_ids=['followup-plan-1'],
            created_by=self.user,
        )
        _cancel_plan_workflows(plan)
        mock_abort_scan.assert_not_called()
        self.scan.refresh_from_db()
        self.assertEqual(self.scan.scan_status, SUCCESS_TASK)


class McpCapabilitiesApiTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='mcp-cap', password='x')
        assign_role(self.user, 'penetration_tester')
        self.client, _ = mcp_client_with_session(self.user)
        self.project = Project.objects.create(
            name='Cap', slug='cap-project', insert_date=timezone.now(),
        )
        self.engine = EngineType.objects.create(
            engine_name='CapE',
            yaml_configuration='port_scan:\n  x: 1\n',
        )
        self.domain = Domain.objects.create(
            name='cap.example.com', project=self.project, insert_date=timezone.now(),
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=SUCCESS_TASK,
            start_scan_date=timezone.now(),
            tasks=['port_scan'],
        )
        self.sub = Subdomain.objects.create(
            name='cap.example.com',
            target_domain=self.domain,
            scan_history=self.scan,
        )

    def test_list_capabilities(self):
        res = self.client.get('/api/mcp/capabilities/')
        self.assertEqual(res.status_code, 200)
        self.assertIn('pipeline_tasks', res.json())

    def test_engine_detail(self):
        res = self.client.get(f'/api/mcp/engines/{self.engine.id}/')
        self.assertEqual(res.status_code, 200)
        self.assertIn('tasks', res.json())

    def test_subdomain_detail_suggestions(self):
        res = self.client.get(f'/api/mcp/subdomains/{self.sub.id}/detail/')
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertIn('suggested_followups', body)
        self.assertTrue(len(body['suggested_followups']) >= 1)

    def test_propose_followups(self):
        res = self.client.post('/api/mcp/followups/propose/', {
            'project_slug': 'cap-project',
            'scan_id': self.scan.id,
            'rationale': 'mcp test',
            'steps': [
                {
                    'kind': 'run_tool',
                    'tool': 'port_scan',
                    'asset_type': 'subdomain',
                    'asset_id': self.sub.id,
                    'scan_history_id': self.scan.id,
                }
            ],
        }, format='json')
        self.assertEqual(res.status_code, 201, res.content)
        plan = res.json()['plan']
        self.assertEqual(plan['status'], 'proposed')
        get_res = self.client.get(f"/api/mcp/followups/{plan['id']}/")
        self.assertEqual(get_res.status_code, 200)


class SubscanRetryParityTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='retry-sub', password='x')
        assign_role(self.user, 'penetration_tester')
        self.client = APIClient()
        self.client.force_authenticate(user=self.user)
        self.client.force_login(self.user)
        self.project = Project.objects.create(
            name='RS', slug='rs-project', insert_date=timezone.now(),
        )
        self.engine = EngineType.objects.create(engine_name='RSE', yaml_configuration='')
        self.domain = Domain.objects.create(
            name='rs.example.com', project=self.project, insert_date=timezone.now(),
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=SUCCESS_TASK,
            start_scan_date=timezone.now(),
            tasks=['port_scan'],
            results_dir='/tmp/rs',
        )
        self.sub = Subdomain.objects.create(
            name='rs.example.com',
            target_domain=self.domain,
            scan_history=self.scan,
        )
        from startScan.models import SubScan
        self.subscan = SubScan.objects.create(
            scan_history=self.scan,
            subdomain=self.sub,
            status=FAILED_TASK,
            type='port_scan',
            start_scan_date=timezone.now(),
        )
        self.activity = ScanActivity.objects.create(
            scan_of=self.scan,
            name='port_scan',
            title='Port Scan',
            status=FAILED_TASK,
            time=timezone.now(),
            time_started=timezone.now(),
            subscan=self.subscan,
        )

    def test_subscan_activity_retry_allowed(self):
        start_workflow = AsyncMock(return_value=MagicMock(id='wf'))
        client = MagicMock()
        client.start_workflow = start_workflow
        with patch(
            'reNgine.temporal_client.TemporalClientProvider.get_client',
            new_callable=AsyncMock,
            return_value=client,
        ):
            res = self.client.post(f'/api/action/retry/task/{self.activity.id}/')
        self.assertEqual(res.status_code, 200, res.content)
        self.assertTrue(res.json().get('status'))
        self.assertTrue(start_workflow.called)
