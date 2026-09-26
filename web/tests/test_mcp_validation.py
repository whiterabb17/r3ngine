from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role

from dashboard.models import Project
from mcp.keys import display_prefix, generate_mcp_secret, hash_mcp_secret
from mcp.models import McpApiKey, McpAuditEvent
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


class McpValidationTests(TestCase):
    def setUp(self):
        self.project = Project.objects.create(
            name='Val Project',
            slug='val-project',
            insert_date=timezone.now(),
        )
        self.engine = EngineType.objects.create(engine_name='Default', yaml_configuration='')
        self.domain = Domain.objects.create(
            name='val.example.com',
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
            http_url='https://val.example.com/api',
            validation_status='new',
        )
        self.path_id = 'apme-test-path-1'
        self.impact = ImpactAssessment.objects.create(
            scan_history=self.scan,
            vulnerability=self.vuln,
            potential_impact='Data exposure',
            remediation_priority=2,
            potential_attack_chain={
                'apme_path_id': self.path_id,
                'risk': 'high',
                'score': 0.8,
                'steps': [{'action': 'exploit_sqli'}],
            },
        )
        self.pentester = User.objects.create_user(username='val-pt', password='x')
        assign_role(self.pentester, 'penetration_tester')
        self.auditor = User.objects.create_user(username='val-aud', password='x')
        assign_role(self.auditor, 'auditor')
        self.pt = mcp_client_with_session(self.pentester)
        self.aud = mcp_client_with_session(self.auditor)

    def test_tool_map_routes(self):
        self.assertEqual(
            tool_name_for('GET', f'/api/mcp/vulnerabilities/{self.vuln.id}/analyze/'),
            'r3ngine_analyze_vulnerability',
        )
        self.assertEqual(
            tool_name_for('PATCH', f'/api/mcp/vulnerabilities/{self.vuln.id}/enrich/'),
            'r3ngine_enrich_vulnerability',
        )
        self.assertEqual(
            tool_name_for('PATCH', f'/api/mcp/vulnerabilities/{self.vuln.id}/validation/'),
            'r3ngine_validate_vulnerability',
        )
        self.assertEqual(
            tool_name_for('PATCH', f'/api/mcp/attack-paths/{self.path_id}/enrich/'),
            'r3ngine_enrich_attack_path',
        )

    def test_analyze_is_readonly_for_auditor(self):
        res = self.aud.get(f'/api/mcp/vulnerabilities/{self.vuln.id}/analyze/')
        self.assertEqual(res.status_code, 200)
        body = res.json()
        self.assertIn('vulnerability', body)
        self.assertIn('cve_signals', body)
        self.assertIn('safety', body)
        self.assertEqual(body['safety']['mode'], 'interpret_enrich_only')

    def test_enrich_writes_agent_enrichment(self):
        res = self.pt.patch(
            f'/api/mcp/vulnerabilities/{self.vuln.id}/enrich/',
            {
                'impact_classes': ['data_leakage', 'auth_bypass'],
                'validation_verdict': 'likely_tp',
                'confidence': 0.7,
                'rationale': 'Template match with neighbor findings',
                'attck_techniques': ['T1190'],
                'agent_id': 'r3ngine-vuln-validator',
            },
            format='json',
        )
        self.assertEqual(res.status_code, 200)
        body = res.json()
        enrichment = body['agent_enrichment']
        self.assertEqual(enrichment['validation_verdict'], 'likely_tp')
        self.assertEqual(enrichment['impact_classes'], ['data_leakage', 'auth_bypass'])
        self.assertEqual(enrichment['confidence'], 0.7)
        self.assertIn('enriched_at', enrichment)
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.agent_enrichment['validation_verdict'], 'likely_tp')

    def test_enrich_rejects_forbidden_payload_key(self):
        res = self.pt.patch(
            f'/api/mcp/vulnerabilities/{self.vuln.id}/enrich/',
            {'rationale': 'x', 'payload': 'SELECT 1'},
            format='json',
        )
        self.assertEqual(res.status_code, 400)
        self.assertIn('forbidden', res.json()['error'])

    def test_auditor_cannot_enrich(self):
        res = self.aud.patch(
            f'/api/mcp/vulnerabilities/{self.vuln.id}/enrich/',
            {'validation_verdict': 'uncertain'},
            format='json',
        )
        self.assertIn(res.status_code, (403, 401))

    def test_verified_requires_confirm_and_confidence(self):
        denied = self.pt.patch(
            f'/api/mcp/vulnerabilities/{self.vuln.id}/validation/',
            {
                'validation_status': 'verified',
                'validation_confidence': 0.9,
                'validation_reason': 'looks real',
            },
            format='json',
        )
        self.assertEqual(denied.status_code, 400)
        self.assertIn('confirm_verified', denied.json()['error'])

        low = self.pt.patch(
            f'/api/mcp/vulnerabilities/{self.vuln.id}/validation/',
            {
                'validation_status': 'verified',
                'confirm_verified': True,
                'validation_confidence': 0.5,
                'validation_reason': 'looks real',
            },
            format='json',
        )
        self.assertEqual(low.status_code, 400)

        ok = self.pt.patch(
            f'/api/mcp/vulnerabilities/{self.vuln.id}/validation/',
            {
                'validation_status': 'verified',
                'confirm_verified': True,
                'validation_confidence': 0.85,
                'validation_reason': 'Confirmed against corroborating neighbors',
            },
            format='json',
        )
        self.assertEqual(ok.status_code, 200)
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.validation_status, 'verified')
        self.assertEqual(self.vuln.validation_confidence, 0.85)

    def test_needs_review_without_confirm(self):
        res = self.pt.patch(
            f'/api/mcp/vulnerabilities/{self.vuln.id}/validation/',
            {
                'validation_status': 'needs_review',
                'validation_confidence': 0.4,
                'validation_reason': 'Ambiguous template',
            },
            format='json',
        )
        self.assertEqual(res.status_code, 200)
        self.vuln.refresh_from_db()
        self.assertEqual(self.vuln.validation_status, 'needs_review')

    def test_enrich_attack_path_by_apme_id(self):
        res = self.pt.patch(
            f'/api/mcp/attack-paths/{self.path_id}/enrich/',
            {
                'feasibility': 'stretched',
                'confidence': 0.55,
                'blocked_reasons': ['auth gate unclear'],
                'missing_prereqs': ['valid session token'],
                'impact_classes': ['data_leakage'],
                'rationale': 'Chain assumes authenticated SQLi without evidence',
                'agent_id': 'r3ngine-vuln-validator',
            },
            format='json',
        )
        self.assertEqual(res.status_code, 200)
        body = res.json()
        review = body['agent_path_review']
        self.assertEqual(review['feasibility'], 'stretched')
        self.assertEqual(review['missing_prereqs'], ['valid session token'])
        self.impact.refresh_from_db()
        nested = self.impact.potential_attack_chain['agent_path_review']
        self.assertEqual(nested['feasibility'], 'stretched')

    def test_attack_paths_list_includes_review(self):
        self.impact.potential_attack_chain = {
            **self.impact.potential_attack_chain,
            'agent_path_review': {'feasibility': 'plausible', 'confidence': 0.9},
        }
        self.impact.save(update_fields=['potential_attack_chain'])
        res = self.aud.get(f'/api/mcp/attack-paths/?scan_id={self.scan.id}')
        self.assertEqual(res.status_code, 200)
        paths = res.json()['paths']
        self.assertTrue(paths)
        self.assertEqual(paths[0]['agent_path_review']['feasibility'], 'plausible')

    def test_analyze_related_ignores_null_endpoint_fk(self):
        """Null endpoint_id must not OR-match every null-endpoint vuln on the scan."""
        other = Vulnerability.objects.create(
            name='Unrelated TLS',
            severity=1,
            scan_history=self.scan,
            target_domain=self.domain,
            http_url='https://other.example.com/',
            validation_status='new',
            # subdomain_id and endpoint_id remain null
        )
        scoped = Vulnerability.objects.create(
            name='Host SQLi',
            severity=3,
            scan_history=self.scan,
            target_domain=self.domain,
            http_url='https://val.example.com/x',
            validation_status='new',
        )
        from startScan.models import Subdomain
        host = Subdomain.objects.create(
            name='app.val.example.com',
            scan_history=self.scan,
            target_domain=self.domain,
        )
        scoped.subdomain = host
        scoped.save(update_fields=['subdomain'])

        res = self.aud.get(f'/api/mcp/vulnerabilities/{scoped.id}/analyze/')
        self.assertEqual(res.status_code, 200)
        related_ids = [item['id'] for item in res.json()['related_vulnerabilities']]
        self.assertNotIn(other.id, related_ids)
        self.assertNotIn(self.vuln.id, related_ids)  # different host, also no subdomain
    def test_enrich_is_audited(self):
        before = McpAuditEvent.objects.count()
        res = self.pt.patch(
            f'/api/mcp/vulnerabilities/{self.vuln.id}/enrich/',
            {'validation_verdict': 'uncertain', 'confidence': 0.3},
            format='json',
        )
        self.assertEqual(res.status_code, 200)
        self.assertGreater(McpAuditEvent.objects.count(), before)
        latest = McpAuditEvent.objects.order_by('-id').first()
        self.assertEqual(latest.tool_name, 'r3ngine_enrich_vulnerability')
