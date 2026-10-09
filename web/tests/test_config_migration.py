from django.test import TestCase
from django.urls import reverse
from rest_framework.test import APIClient
from rest_framework import status
from django.contrib.auth import get_user_model
import json
import zipfile
import io
import os
import shutil
import tempfile
from unittest.mock import patch
from dashboard.models import OpenAiAPIKey
from scanEngine.models import EngineType
from rolepermissions.roles import assign_role

User = get_user_model()

class ConfigMigrationTests(TestCase):
    def setUp(self):
        self.client = APIClient()
        self.user = User.objects.create_user(
            username='testuser', 
            password='testpassword',
            email='test@example.com',
            is_staff=True,
            is_superuser=True
        )
        self.client.force_authenticate(user=self.user)
        self.client.force_login(self.user)
        
        # Assign admin role to pass HasPermission checks
        assign_role(self.user, 'sys_admin')

        # Keep the import/export off the container paths the runner cannot write.
        root = tempfile.mkdtemp(prefix='rengine_test_config_')
        self.addCleanup(shutil.rmtree, root, ignore_errors=True)
        self.wordlist_dir = os.path.join(root, 'wordlist') + os.sep
        tool_configs = {
            'tool_configs/theharvester_api-keys.yaml': os.path.join(root, 'theHarvester', 'api-keys.yaml'),
            'tool_configs/spiderfoot.cfg': os.path.join(root, 'spiderfoot', 'spiderfoot.cfg'),
        }
        for target, value in (('WORDLIST_DIR', self.wordlist_dir), ('TOOL_CONFIG_FILES', tool_configs)):
            patcher = patch(f'api.config_migration_views.{target}', value)
            patcher.start()
            self.addCleanup(patcher.stop)

        # Create some test data
        OpenAiAPIKey.objects.create(key='sk-testkey')
        EngineType.objects.create(engine_name='TestEngine', yaml_configuration='test: true')

    def test_export_config(self):
        url = reverse('api:settings_export')
        response = self.client.get(url)
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertEqual(response['Content-Type'], 'application/zip')
        
        # Read the zip from response
        zip_buffer = io.BytesIO(b"".join(response.streaming_content))
        with zipfile.ZipFile(zip_buffer, 'r') as zip_file:
            self.assertIn('dashboard_models.json', zip_file.namelist())
            self.assertIn('scanengine_models.json', zip_file.namelist())
            
            dashboard_data = json.loads(zip_file.read('dashboard_models.json'))
            self.assertIn('OpenAiAPIKey', dashboard_data)
            self.assertEqual(len(dashboard_data['OpenAiAPIKey']), 1)
            self.assertEqual(dashboard_data['OpenAiAPIKey'][0]['fields']['key'], 'sk-testkey')

            scanengine_data = json.loads(zip_file.read('scanengine_models.json'))
            self.assertIn('EngineType', scanengine_data)
            self.assertEqual(len(scanengine_data['EngineType']), 1)
            self.assertEqual(scanengine_data['EngineType'][0]['fields']['engine_name'], 'TestEngine')

    def test_import_config(self):
        # First, export to get a valid zip
        url_export = reverse('api:settings_export')
        export_resp = self.client.get(url_export)
        
        # Now clear the DB
        OpenAiAPIKey.objects.all().delete()
        EngineType.objects.all().delete()
        
        self.assertEqual(OpenAiAPIKey.objects.count(), 0)
        
        url_import = reverse('api:settings_import')
        zip_buffer = io.BytesIO(b"".join(export_resp.streaming_content))
        zip_buffer.name = 'r3ngine_config_backup.zip' # Mock file name
        
        response = self.client.post(url_import, {
            'file': zip_buffer,
            'overwrite_existing': 'false'
        }, format='multipart')
        
        self.assertEqual(response.status_code, status.HTTP_200_OK)
        self.assertTrue(response.data['status'])
        
        # Verify data is restored
        self.assertEqual(OpenAiAPIKey.objects.count(), 1)
        self.assertEqual(EngineType.objects.count(), 1)
        self.assertEqual(EngineType.objects.first().engine_name, 'TestEngine')
