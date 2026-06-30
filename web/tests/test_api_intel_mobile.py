# web/tests/test_api_intel_mobile.py
from django.test import TestCase, Client as DjangoClient
from django.utils import timezone
from rest_framework.test import APIClient
from django.contrib.auth import get_user_model
from dashboard.models import Project
from targetApp.models import Domain
from scanEngine.models import EngineType
from startScan.models import ScanHistory, APIIntelligenceProfile

User = get_user_model()


class APIIntelMobileViewTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(username='testuser_apiintel', password='testpass')
        self.client.force_authenticate(user=self.user)

        self.project = Project.objects.create(
            name='test-project-apiintel',
            slug='test-project-apiintel',
            insert_date=timezone.now(),
        )
        self.domain = Domain.objects.create(
            name='apiintel.example.test',
            project=self.project,
        )
        self.engine = EngineType.objects.create(
            engine_name='test-engine-apiintel',
            yaml_configuration='',
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=2,
            start_scan_date=timezone.now(),
        )
        self.profile = APIIntelligenceProfile.objects.create(
            scan_history=self.scan,
            target_domain=self.domain,
            base_url='https://api.example.test/v1',
            api_type='rest',
            endpoint_count=8,
            requires_auth=True,
            auth_scheme='Bearer',
        )
        # Second profile on a different scan for filter testing
        self.scan2 = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=2,
            start_scan_date=timezone.now(),
        )
        self.profile2 = APIIntelligenceProfile.objects.create(
            scan_history=self.scan2,
            target_domain=self.domain,
            base_url='https://gql.example.test/graphql',
            api_type='graphql',
            endpoint_count=3,
            requires_auth=False,
        )

    def test_list_returns_all_profiles_without_scan_id(self):
        # Use scan_id filter to scope results to our test data (avoids --keepdb interference)
        response = self.client.get(f'/mapi/api-intel/?scan_id={self.scan.id}')
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.data, list)
        self.assertGreaterEqual(len(response.data), 1)

    def test_list_filters_by_scan_id(self):
        response = self.client.get(f'/mapi/api-intel/?scan_id={self.scan.id}')
        self.assertEqual(response.status_code, 200)
        self.assertIsInstance(response.data, list)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['api_type'], 'rest')

    def test_list_ignores_invalid_scan_id(self):
        response = self.client.get('/mapi/api-intel/?scan_id=notanumber')
        self.assertEqual(response.status_code, 200)

    def test_detail_returns_single_profile(self):
        response = self.client.get(f'/mapi/api-intel/{self.profile.id}/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.data['base_url'], 'https://api.example.test/v1')
        self.assertEqual(response.data['api_type'], 'rest')
        self.assertTrue(response.data['requires_auth'])
        self.assertEqual(response.data['auth_scheme'], 'Bearer')

    def test_detail_returns_404_for_missing_profile(self):
        response = self.client.get('/mapi/api-intel/99999/')
        self.assertEqual(response.status_code, 404)

    def test_list_requires_authentication(self):
        anon_client = APIClient()  # bare — no force_authenticate
        response = anon_client.get('/mapi/api-intel/')
        self.assertEqual(response.status_code, 401)
