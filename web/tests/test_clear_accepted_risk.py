"""Clear accepted-risk vulnerabilities for a single scan."""
from django.contrib.auth import get_user_model
from django.test import TestCase
from django.utils import timezone
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role

from dashboard.models import Project
from reNgine.definitions import SUCCESS_TASK
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Vulnerability
from targetApp.models import Domain

User = get_user_model()


class ClearAcceptedRiskVulnerabilitiesTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='clear-ar', password='x')
        assign_role(self.user, 'penetration_tester')
        self.auditor = User.objects.create_user(username='clear-ar-aud', password='x')
        assign_role(self.auditor, 'auditor')
        self.project = Project.objects.create(
            name='ClearAR', slug='clear-ar', insert_date=timezone.now(),
        )
        self.other_project = Project.objects.create(
            name='OtherAR', slug='other-ar', insert_date=timezone.now(),
        )
        self.engine = EngineType.objects.create(engine_name='CAR', yaml_configuration='')
        self.domain = Domain.objects.create(
            name='clear-ar.example.com', project=self.project, insert_date=timezone.now(),
        )
        self.other_domain = Domain.objects.create(
            name='other-ar.example.com', project=self.other_project, insert_date=timezone.now(),
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=SUCCESS_TASK,
            start_scan_date=timezone.now(),
            tasks=['vulnerability_scan'],
        )
        self.other_scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=SUCCESS_TASK,
            start_scan_date=timezone.now(),
            tasks=['vulnerability_scan'],
        )
        self.foreign_scan = ScanHistory.objects.create(
            domain=self.other_domain,
            scan_type=self.engine,
            scan_status=SUCCESS_TASK,
            start_scan_date=timezone.now(),
            tasks=['vulnerability_scan'],
        )
        self.accepted = Vulnerability.objects.create(
            scan_history=self.scan,
            name='Accepted Risk Vuln',
            severity=2,
            validation_status='accepted_risk',
        )
        self.accepted_other = Vulnerability.objects.create(
            scan_history=self.other_scan,
            name='Other Scan Accepted',
            severity=2,
            validation_status='accepted_risk',
        )
        self.accepted_foreign = Vulnerability.objects.create(
            scan_history=self.foreign_scan,
            name='Foreign Project Accepted',
            severity=2,
            validation_status='accepted_risk',
        )
        self.verified = Vulnerability.objects.create(
            scan_history=self.scan,
            name='Verified Vuln',
            severity=3,
            validation_status='verified',
        )

    def _client(self, user=None):
        client = APIClient()
        user = user or self.user
        client.force_authenticate(user=user)
        client.force_login(user)
        return client

    def test_requires_scan_id_and_project(self):
        client = self._client()
        res = client.post('/api/action/vulnerability/clear_accepted_risk/', {}, format='json')
        self.assertEqual(res.status_code, 400, res.content)
        res = client.post(
            '/api/action/vulnerability/clear_accepted_risk/',
            {'scan_id': self.scan.id},
            format='json',
        )
        self.assertEqual(res.status_code, 400, res.content)

    def test_unauthenticated_denied(self):
        client = APIClient()
        res = client.post(
            '/api/action/vulnerability/clear_accepted_risk/',
            {'scan_id': self.scan.id, 'project': self.project.slug},
            format='json',
        )
        # Session auth redirects; DRF JWT-style clients may get 401/403.
        self.assertIn(res.status_code, (302, 401, 403), res.content)

    def test_auditor_denied(self):
        client = self._client(self.auditor)
        res = client.post(
            '/api/action/vulnerability/clear_accepted_risk/',
            {'scan_id': self.scan.id, 'project': self.project.slug},
            format='json',
        )
        self.assertEqual(res.status_code, 403, res.content)
        self.assertTrue(Vulnerability.objects.filter(pk=self.accepted.id).exists())

    def test_unknown_or_cross_project_scan_returns_404(self):
        client = self._client()
        res = client.post(
            '/api/action/vulnerability/clear_accepted_risk/',
            {'scan_id': 999999, 'project': self.project.slug},
            format='json',
        )
        self.assertEqual(res.status_code, 404, res.content)
        res = client.post(
            '/api/action/vulnerability/clear_accepted_risk/',
            {'scan_id': self.foreign_scan.id, 'project': self.project.slug},
            format='json',
        )
        self.assertEqual(res.status_code, 404, res.content)
        self.assertTrue(Vulnerability.objects.filter(pk=self.accepted_foreign.id).exists())

    def test_clears_only_accepted_risk_for_scan(self):
        client = self._client()
        res = client.post(
            '/api/action/vulnerability/clear_accepted_risk/',
            {'scan_id': self.scan.id, 'project': self.project.slug},
            format='json',
        )
        self.assertEqual(res.status_code, 200, res.content)
        body = res.json()
        self.assertTrue(body['status'])
        self.assertEqual(body['deleted'], 1)
        self.assertFalse(Vulnerability.objects.filter(pk=self.accepted.id).exists())
        self.assertTrue(Vulnerability.objects.filter(pk=self.verified.id).exists())
        self.assertTrue(Vulnerability.objects.filter(pk=self.accepted_other.id).exists())
        self.assertTrue(Vulnerability.objects.filter(pk=self.accepted_foreign.id).exists())
