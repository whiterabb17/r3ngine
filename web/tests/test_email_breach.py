from django.test import TestCase, TransactionTestCase
from django.utils import timezone
from rest_framework.test import APIClient
from django.contrib.auth import get_user_model
from unittest.mock import patch, MagicMock
import threading

from dashboard.models import Project
from targetApp.models import Domain
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Email, EmailBreach

User = get_user_model()

class EmailBreachAPITests(TestCase):
    def setUp(self):
        # Clear existing data to prevent --keepdb contamination
        EmailBreach.objects.all().delete()
        Email.objects.all().delete()

        self.client = APIClient()
        self.user = User.objects.create_superuser(username='testadmin', password='testpassword', email='admin@example.test')
        self.client.force_login(self.user)
        self.client.force_authenticate(user=self.user)

        self.project = Project.objects.create(
            name='Test Project',
            slug='test-project',
            insert_date=timezone.now()
        )
        self.domain = Domain.objects.create(
            name='example.com',
            project=self.project
        )
        self.engine = EngineType.objects.create(
            engine_name='test-engine',
            yaml_configuration=''
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=2,
            start_scan_date=timezone.now()
        )
        self.email = Email.objects.create(
            address='testuser@example.com'
        )
        self.scan.emails.add(self.email)

        self.breach = EmailBreach.objects.create(
            scan_history=self.scan,
            email=self.email,
            email_address='testuser@example.com',
            breach_name='Adobe',
            breach_date='October 2013',
            description='In October 2013, Adobe suffered a data breach.',
            compromised_data=['Email addresses', 'Passwords']
        )

    def test_list_breaches(self):
        response = self.client.get('/api/emailBreaches/')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 1)
        self.assertEqual(response.data[0]['breach_name'], 'Adobe')

    def test_filter_by_scan_id(self):
        # Create second scan
        scan2 = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=2,
            start_scan_date=timezone.now()
        )
        response = self.client.get(f'/api/emailBreaches/?scan_id={scan2.id}')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 0)

        response = self.client.get(f'/api/emailBreaches/?scan_id={self.scan.id}')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 1)

    def test_filter_by_email_id(self):
        email2 = Email.objects.create(
            address='other@example.com'
        )
        self.scan.emails.add(email2)
        response = self.client.get(f'/api/emailBreaches/?email_id={email2.id}')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 0)

        response = self.client.get(f'/api/emailBreaches/?email_id={self.email.id}')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 1)

    def test_filter_by_project(self):
        response = self.client.get('/api/emailBreaches/?project=non-existent')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 0)

        response = self.client.get('/api/emailBreaches/?project=test-project')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 1)

    def test_filter_by_target_id(self):
        response = self.client.get(f'/api/emailBreaches/?target_id={self.domain.id}')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 1)

        response = self.client.get('/api/emailBreaches/?target_id=9999')
        self.assertEqual(response.status_code, 200)
        self.assertEqual(len(response.data), 0)

    @patch('api.views.threading.Thread')
    @patch('api.views.save_email')
    def test_check_email_breach_success(self, mock_save_email, mock_thread_cls):
        mock_save_email.return_value = (self.email, False)
        mock_thread_instance = MagicMock()
        mock_thread_cls.return_value = mock_thread_instance

        payload = {
            'email_address': 'testuser@example.com',
            'scan_id': self.scan.id
        }
        response = self.client.post('/api/emails/check_breach/', payload, format='json')
        
        self.assertEqual(response.status_code, 202)
        self.assertEqual(response.data['status'], 'checking')
        self.assertEqual(response.data['email']['address'], 'testuser@example.com')
        
        # Verify that check_hibp_for_email_task was launched in a thread
        from reNgine.osint.hibp_scraper import check_hibp_for_email_task
        thread_calls = [
            call for call in mock_thread_cls.call_args_list
            if (call[1].get('target') == check_hibp_for_email_task or 
                (call[0] and call[0][0] == check_hibp_for_email_task))
        ]
        self.assertEqual(len(thread_calls), 1)

    def test_check_email_breach_missing_params(self):
        response = self.client.post('/api/emails/check_breach/', {}, format='json')
        self.assertEqual(response.status_code, 400)
        self.assertIn('error', response.data)

    def test_check_email_breach_not_found_scan(self):
        payload = {
            'email_address': 'testuser@example.com',
            'scan_id': 99999
        }
        response = self.client.post('/api/emails/check_breach/', payload, format='json')
        self.assertEqual(response.status_code, 404)


class HIBPScraperTaskTests(TransactionTestCase):
    def setUp(self):
        # Clear existing data to prevent --keepdb contamination
        EmailBreach.objects.all().delete()
        Email.objects.all().delete()

        self.project = Project.objects.create(
            name='Test Project Scraper',
            slug='test-project-scraper',
            insert_date=timezone.now()
        )
        self.domain = Domain.objects.create(
            name='example.com',
            project=self.project
        )
        self.engine = EngineType.objects.create(
            engine_name='test-engine-scraper',
            yaml_configuration=''
        )
        self.scan = ScanHistory.objects.create(
            domain=self.domain,
            scan_type=self.engine,
            scan_status=2,
            start_scan_date=timezone.now()
        )
        self.email = Email.objects.create(
            address='testuser@example.com'
        )
        self.scan.emails.add(self.email)

    @patch('reNgine.osint.hibp_scraper.scrape_email_breaches_with_retries')
    def test_check_hibp_for_email_task_pwned(self, mock_scrape):
        mock_scrape.return_value = {
            'success': True,
            'pwned': True,
            'breaches': [
                {
                    'name': 'Canva',
                    'date': 'May 2019',
                    'description': 'In May 2019, Canva suffered a breach.',
                    'compromised_data': ['Email addresses', 'Passwords', 'Names']
                }
            ]
        }

        from reNgine.osint.hibp_scraper import check_hibp_for_email_task
        count = check_hibp_for_email_task('testuser@example.com', self.scan.id, self.email.id)
        
        self.assertEqual(count, 1)
        db_breaches = EmailBreach.objects.filter(email_address='testuser@example.com')
        self.assertEqual(db_breaches.count(), 1)
        breach = db_breaches.first()
        self.assertEqual(breach.breach_name, 'Canva')
        self.assertEqual(breach.breach_date, 'May 2019')
        self.assertEqual(breach.compromised_data, ['Email addresses', 'Passwords', 'Names'])

    @patch('reNgine.osint.hibp_scraper.scrape_email_breaches_with_retries')
    def test_check_hibp_for_email_task_not_pwned(self, mock_scrape):
        mock_scrape.return_value = {
            'success': True,
            'pwned': False,
            'breaches': []
        }

        from reNgine.osint.hibp_scraper import check_hibp_for_email_task
        count = check_hibp_for_email_task('testuser@example.com', self.scan.id, self.email.id)
        
        self.assertEqual(count, 0)
        self.assertEqual(EmailBreach.objects.filter(email_address='testuser@example.com').count(), 0)

    def test_check_hibp_live_with_provided_email(self):
        # Live unmocked check to test haveibeenpwned page request and parsing logic
        from reNgine.osint.hibp_scraper import check_hibp_for_email_task
        
        count = check_hibp_for_email_task('testuser@example.com', self.scan.id, self.email.id)
        print(f"Live breach count for testuser@example.com: {count}")
        self.assertGreater(count, 0)
        
        db_breaches = EmailBreach.objects.filter(email_address='testuser@example.com')
        self.assertEqual(db_breaches.count(), count)
        for breach in db_breaches:
            print(f"Live parsed breach: {breach.breach_name} - Date: {breach.breach_date}")
            self.assertIsNotNone(breach.breach_name)
            self.assertIsNotNone(breach.description)
