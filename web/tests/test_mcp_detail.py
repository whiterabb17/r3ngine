from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role

from dashboard.models import Project
from mcp.keys import display_prefix, generate_mcp_secret, hash_mcp_secret
from mcp.models import McpApiKey, McpAuditEvent
from reNgine.definitions import (
    ABORTED_TASK,
    FAILED_TASK,
    INITIATED_TASK,
    RUNNING_TASK,
    SUCCESS_TASK,
)
from scanEngine.models import EngineType
from startScan.models import (
    EndPoint,
    Exposure,
    ScanActivity,
    ScanHistory,
    Subdomain,
    SubScan,
    Vulnerability,
)
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


def _activity(scan, name, status, tier=1, subscan=None, traceback=None):
    return ScanActivity.objects.create(
        scan_of=scan,
        title=name,
        name=name,
        status=status,
        tier=tier,
        time=timezone.now(),
        time_started=timezone.now(),
        subscan=subscan,
        error_message='boom' if status == FAILED_TASK else None,
        traceback=traceback,
    )


class McpDetailTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='mcp-detail', password='x')
        assign_role(self.user, 'auditor')
        self.project = Project.objects.create(
            name='Detail Project',
            slug='detail-project',
            insert_date=timezone.now(),
        )
        self.engine = EngineType.objects.create(engine_name='Full', yaml_configuration='')
        self.domain = Domain.objects.create(
            name='detail.example.com',
            project=self.project,
            insert_date=timezone.now(),
            description='Acme corp',
            h1_team_handle='acme',
            excluded_paths=['/admin', '/private'],
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=1,
            start_scan_date=timezone.now(),
            tasks=['subdomain_discovery', 'port_scan'],
            error_message=None,
        )
        self.subdomain = Subdomain.objects.create(
            name='www.detail.example.com',
            scan_history=self.scan,
            target_domain=self.domain,
            http_status=200,
            http_url='https://www.detail.example.com',
            page_title='Home',
        )
        self.endpoint = EndPoint.objects.create(
            http_url='https://www.detail.example.com/login',
            scan_history=self.scan,
            target_domain=self.domain,
            subdomain=self.subdomain,
            http_status=200,
        )
        self.exposure = Exposure.objects.create(
            scan_history=self.scan,
            target_domain=self.domain,
            subdomain=self.subdomain,
            endpoint=self.endpoint,
            type=['VPN Gateway'],
            status='open',
            risk_score=7.5,
        )
        self.vuln = Vulnerability.objects.create(
            name='XSS',
            severity=3,
            scan_history=self.scan,
            target_domain=self.domain,
            subdomain=self.subdomain,
            endpoint=self.endpoint,
            exposure=self.exposure,
            http_url=self.endpoint.http_url,
            description='reflected xss',
            impact='account takeover',
            remediation='encode output',
            request='GET /login',
            response='<html>',
            curl_command='curl http://x',
            extracted_results=['a', 'b'],
        )
        self.subscan = SubScan.objects.create(
            type='port_scan',
            status=RUNNING_TASK,
            start_scan_date=timezone.now(),
            scan_history=self.scan,
            subdomain=self.subdomain,
            engine=self.engine,
        )
        _activity(self.scan, 'queued_task', INITIATED_TASK, tier=1)
        _activity(self.scan, 'running_task', RUNNING_TASK, tier=2)
        _activity(self.scan, 'done_task', SUCCESS_TASK, tier=2)
        _activity(self.scan, 'fail_task', FAILED_TASK, tier=3, traceback='SECRET_TRACE')
        _activity(self.scan, 'abort_task', ABORTED_TASK, tier=3)
        _activity(self.scan, 'sub_task', RUNNING_TASK, tier=1, subscan=self.subscan)
        self.client, self.sid = mcp_client_with_session(self.user)

    def test_thin_get_scan_unchanged(self):
        res = self.client.get(f'/api/mcp/scans/{self.scan.id}/')
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertNotIn('tasks', body)
        self.assertNotIn('task_summary', body)
        self.assertNotIn('counts', body)
        self.assertEqual(body['id'], self.scan.id)

    def test_scan_detail_buckets_counts_and_audit(self):
        res = self.client.get(f'/api/mcp/scans/{self.scan.id}/detail/')
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body['engine_name'], 'Full')
        self.assertEqual(body['tasks_planned'], ['subdomain_discovery', 'port_scan'])
        self.assertEqual(body['counts']['subdomains'], 1)
        self.assertEqual(body['counts']['endpoints'], 1)
        self.assertEqual(body['counts']['vulnerabilities'], 1)
        self.assertEqual(body['counts']['exposures'], 1)
        self.assertEqual(body['counts']['subscans'], 1)
        self.assertEqual(body['severity_counts']['high'], 1)
        self.assertEqual(body['task_summary']['initiated'], 1)
        self.assertEqual(body['task_summary']['running'], 2)
        self.assertEqual(body['task_summary']['success'], 1)
        self.assertEqual(body['task_summary']['failed'], 1)
        self.assertEqual(body['task_summary']['aborted'], 1)
        running_names = [t['name'] for t in body['tasks']['running']]
        self.assertIn('running_task', running_names)
        self.assertIn('sub_task', running_names)
        failed = body['tasks']['failed'][0]
        self.assertEqual(failed['error_message'], 'boom')
        self.assertNotIn('traceback', failed)
        self.assertNotIn('SECRET_TRACE', str(body))
        self.assertTrue(
            McpAuditEvent.objects.filter(
                session_id=self.sid,
                tool_name='r3ngine_get_scan_detail',
            ).exists()
        )

    def test_scan_detail_404(self):
        res = self.client.get('/api/mcp/scans/999999/detail/')
        self.assertEqual(res.status_code, 404)

    def test_export_scan_for_ai_bundle_and_audit(self):
        res = self.client.get(f'/api/mcp/scans/{self.scan.id}/export-ai/')
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body['format_version'], 'ai-export.v1')
        self.assertEqual(body['preset'], 'analyst_assist')
        self.assertIn('markdown', body)
        self.assertIn('prompt', body)
        self.assertIn('bundle', body)
        self.assertIn('manifest', body)
        self.assertNotIn('files', body)
        self.assertEqual(body['bundle']['metadata']['scan_id'], self.scan.id)
        self.assertEqual(body['manifest']['goal'], 'analyst_assist')
        self.assertIn('detail.example.com', body['markdown'])
        self.assertTrue(
            McpAuditEvent.objects.filter(
                session_id=self.sid,
                tool_name='r3ngine_export_scan_for_ai',
            ).exists()
        )

        with_files = self.client.get(
            f'/api/mcp/scans/{self.scan.id}/export-ai/',
            {'include_files': 'true', 'include_timeline': 'false'},
        )
        self.assertEqual(with_files.status_code, 200)
        files_body = with_files.json()
        self.assertIn('files', files_body)
        self.assertIn('ai_bundle.md', files_body['files'])
        self.assertEqual(files_body['options']['include_timeline'], False)

    def test_export_scan_for_ai_404(self):
        res = self.client.get('/api/mcp/scans/999999/export-ai/')
        self.assertEqual(res.status_code, 404)

    def test_target_detail(self):
        res = self.client.get(f'/api/mcp/targets/{self.domain.id}/detail/')
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body['description'], 'Acme corp')
        self.assertEqual(body['h1_team_handle'], 'acme')
        self.assertEqual(body['excluded_paths']['count'], 2)
        self.assertEqual(len(body['recent_scans']), 1)
        self.assertEqual(body['counts']['vulnerabilities'], 1)
        self.assertNotIn('request_headers', body)

    def test_vulnerability_detail_omits_blobs(self):
        res = self.client.get(f'/api/mcp/vulnerabilities/{self.vuln.id}/detail/')
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body['description'], 'reflected xss')
        self.assertEqual(body['impact'], 'account takeover')
        self.assertEqual(body['scan']['id'], self.scan.id)
        self.assertEqual(body['extracted_results'], ['a', 'b'])
        self.assertNotIn('request', body)
        self.assertNotIn('response', body)
        self.assertNotIn('curl_command', body)

    def test_subdomain_endpoint_exposure_detail(self):
        sub = self.client.get(f'/api/mcp/subdomains/{self.subdomain.id}/detail/')
        self.assertEqual(sub.status_code, 200)
        self.assertEqual(sub.json()['page_title'], 'Home')
        self.assertEqual(sub.json()['counts']['endpoints'], 1)

        ep = self.client.get(f'/api/mcp/endpoints/{self.endpoint.id}/detail/')
        self.assertEqual(ep.status_code, 200)
        self.assertEqual(ep.json()['subdomain_id'], self.subdomain.id)
        self.assertEqual(len(ep.json()['recent_vulnerabilities']), 1)

        exp = self.client.get(f'/api/mcp/exposures/{self.exposure.id}/detail/')
        self.assertEqual(exp.status_code, 200)
        self.assertEqual(exp.json()['type'], ['VPN Gateway'])
        self.assertEqual(len(exp.json()['vulnerabilities']), 1)

    def test_subscan_detail_activities(self):
        res = self.client.get(f'/api/mcp/subscans/{self.subscan.id}/detail/')
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body['subdomain_name'], 'www.detail.example.com')
        self.assertEqual(body['engine_name'], 'Full')
        self.assertEqual(body['scan']['id'], self.scan.id)
        self.assertEqual(body['task_summary']['running'], 1)
        self.assertEqual(body['tasks']['running'][0]['name'], 'sub_task')

    def test_subscan_detail_falls_back_to_type_window(self):
        """Activities reused from the parent scan without subscan_id still appear."""
        orphan = SubScan.objects.create(
            type='port_scan',
            status=RUNNING_TASK,
            start_scan_date=timezone.now(),
            scan_history=self.scan,
            subdomain=self.subdomain,
            engine=self.engine,
        )
        ScanActivity.objects.create(
            scan_of=self.scan,
            title='port_scan',
            name='port_scan',
            status=RUNNING_TASK,
            tier=1,
            time=timezone.now(),
            time_started=timezone.now(),
            subscan=None,
        )
        res = self.client.get(f'/api/mcp/subscans/{orphan.id}/detail/')
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertEqual(body['task_summary']['running'], 1)
        self.assertEqual(body['tasks']['running'][0]['name'], 'port_scan')
