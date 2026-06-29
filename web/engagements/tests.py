from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from django.contrib.auth.models import User
from .models import Client, Engagement, Assessment

class EngagementAppTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(username='testuser', password='testpassword')
        self.client = APIClient()
        self.client.login(username='testuser', password='testpassword')
        # DRF forces authentication on the client if it's token based, 
        # let's just force authenticate the user.
        self.client.force_authenticate(user=self.user)

        self.client_obj = Client.objects.create(
            name='Test Client',
            description='Test Client Description',
            created_by=self.user
        )

        self.engagement_obj = Engagement.objects.create(
            client=self.client_obj,
            name='Test Engagement',
            status='Draft',
            start_date='2026-01-01',
            end_date='2026-12-31',
            created_by=self.user
        )

        self.assessment_obj = Assessment.objects.create(
            engagement=self.engagement_obj,
            name='Test Assessment',
            assessment_type='Web',
            status='Draft',
            created_by=self.user
        )

    def test_client_model(self):
        self.assertEqual(self.client_obj.name, 'Test Client')

    def test_engagement_model(self):
        self.assertEqual(self.engagement_obj.name, 'Test Engagement')
        self.assertEqual(self.engagement_obj.client, self.client_obj)

    def test_assessment_model(self):
        self.assertEqual(self.assessment_obj.name, 'Test Assessment')
        self.assertEqual(self.assessment_obj.engagement, self.engagement_obj)

    def test_get_clients(self):
        response = self.client.get('/api/engagements/clients/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['name'], 'Test Client')

    def test_create_client(self):
        data = {
            'name': 'New Client',
            'description': 'New Client Description'
        }
        response = self.client.post('/api/engagements/clients/', data)
        self.assertEqual(response.status_code, status.HTTP_201_CREATED)
        self.assertEqual(Client.objects.count(), 2)
        self.assertEqual(Client.objects.get(id=response.data['id']).created_by, self.user)

    def test_get_engagements(self):
        response = self.client.get('/api/engagements/engagements/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['name'], 'Test Engagement')

    def test_get_assessments(self):
        response = self.client.get('/api/engagements/assessments/')
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(len(response.data['results']), 1)
        self.assertEqual(response.data['results'][0]['name'], 'Test Assessment')
