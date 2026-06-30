import shutil
import tempfile
from unittest.mock import AsyncMock, MagicMock, patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role

from dashboard.models import Project
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Subdomain
from targetApp.models import Domain

User = get_user_model()


class ManualSubdomainPersistenceAPITests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='manual-subdomain-user',
            password='testpassword',
            email='manual@example.com',
            is_staff=True,
            is_superuser=True,
        )
        assign_role(self.user, 'sys_admin')
        self.client.force_authenticate(user=self.user)
        self.client.force_login(self.user)

        self.project = Project.objects.create(
            name='Manual Subdomain Project',
            slug='manual-subdomain-project',
            insert_date=timezone.now(),
        )
        self.domain = Domain.objects.create(
            name='example.com',
            project=self.project,
            insert_date=timezone.now(),
            target_type='domain',
        )
        self.engine = EngineType.objects.create(
            engine_name='Manual Subdomain Engine',
            yaml_configuration='subdomain_discovery: {}\nhttp_crawl: {}',
        )
        self.scan = ScanHistory.objects.create(
            start_scan_date=timezone.now(),
            scan_status=1,
            results_dir='',
            domain=self.domain,
            scan_type=self.engine,
            tasks=[],
        )

    def test_add_manual_subdomain_persists_to_target_and_latest_scan(self):
        response = self.client.post(
            reverse('api:add_manual_subdomain'),
            {
                'target_id': self.domain.id,
                'subdomain_name': 'App.Example.com app.example.com bad.test',
            },
            format='json',
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data['status'])

        self.domain.refresh_from_db()
        self.assertEqual(self.domain.get_manual_subdomains(), ['app.example.com'])
        self.assertEqual(response.data['added_count'], 1)
        self.assertEqual(response.data['duplicate_count'], 1)
        self.assertEqual(response.data['out_of_scope_count'], 1)
        self.assertTrue(
            Subdomain.objects.filter(
                scan_history=self.scan,
                target_domain=self.domain,
                name='app.example.com',
            ).exists()
        )

    def test_add_manual_subdomain_with_scan_id_only_still_persists_to_target(self):
        response = self.client.post(
            reverse('api:add_manual_subdomain'),
            {
                'scan_id': self.scan.id,
                'subdomain_name': 'api.example.com',
            },
            format='json',
        )

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data['status'])

        self.domain.refresh_from_db()
        self.assertEqual(self.domain.get_manual_subdomains(), ['api.example.com'])


class ManualSubdomainScanBootstrapTests(TestCase):
    def setUp(self):
        self.project = Project.objects.create(
            name='Bootstrap Project',
            slug='bootstrap-project',
            insert_date=timezone.now(),
        )
        self.domain = Domain.objects.create(
            name='example.com',
            project=self.project,
            insert_date=timezone.now(),
            target_type='domain',
            manual_subdomains='persisted.example.com\nshared.example.com',
        )
        self.engine = EngineType.objects.create(
            engine_name='Bootstrap Engine',
            yaml_configuration='subdomain_discovery: {}\nhttp_crawl: {}',
        )
        self.scan = ScanHistory.objects.create(
            start_scan_date=timezone.now(),
            scan_status=1,
            results_dir='',
            domain=self.domain,
            scan_type=self.engine,
            tasks=[],
        )
        self.results_dir = tempfile.mkdtemp(prefix='codex-manual-subdomains-')

    def tearDown(self):
        shutil.rmtree(self.results_dir, ignore_errors=True)

    @patch('reNgine.temporal_client.TemporalClientProvider.get_client', new_callable=AsyncMock)
    @patch('reNgine.tasks.scan_init.save_endpoint')
    @patch('reNgine.tasks.scan_init.send_scan_notif')
    def test_initiate_scan_temporal_merges_target_manual_subdomains(
        self,
        mock_send_notif,
        mock_save_endpoint,
        mock_get_client,
    ):
        from reNgine.tasks import initiate_scan_temporal

        mock_handle = MagicMock()
        mock_handle.id = 'manual-subdomain-workflow-id'
        mock_client = AsyncMock()
        mock_client.start_workflow.return_value = mock_handle
        mock_get_client.return_value = mock_client

        mock_endpoint = MagicMock(is_alive=True)
        mock_endpoint.http_url = 'http://example.com'
        mock_endpoint.http_status = 200
        mock_endpoint.response_time = 0.5
        mock_endpoint.page_title = 'Example'
        mock_endpoint.content_type = 'text/html'
        mock_endpoint.content_length = 1234
        mock_endpoint.techs.all.return_value = []
        mock_save_endpoint.return_value = (mock_endpoint, True)

        result = initiate_scan_temporal(
            scan_history_id=self.scan.id,
            domain_id=self.domain.id,
            engine_id=self.engine.id,
            results_dir=self.results_dir,
            imported_subdomains=['new.example.com', 'shared.example.com'],
        )

        self.assertTrue(result['success'])

        self.scan.refresh_from_db()
        self.assertEqual(
            self.scan.cfg_imported_subdomains,
            ['persisted.example.com', 'shared.example.com', 'new.example.com'],
        )
        self.assertTrue(
            Subdomain.objects.filter(
                scan_history=self.scan,
                target_domain=self.domain,
                name='persisted.example.com',
            ).exists()
        )
        self.assertTrue(
            Subdomain.objects.filter(
                scan_history=self.scan,
                target_domain=self.domain,
                name='new.example.com',
            ).exists()
        )
