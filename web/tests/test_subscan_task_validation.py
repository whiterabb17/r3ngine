"""Only tasks SubScanWorkflow can run may be started as a subscan.

An engine's task list is every top-level YAML key, which includes settings-only
sections (tier_7, email_security, ...). Starting a subscan with one of those used
to raise a plain exception inside the workflow, which Temporal retries forever,
leaving the subscan RUNNING.
"""
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase
from django.urls import reverse

from api.serializers import EngineSerializer
from reNgine.temporal.workflows.subscan import is_subscan_task
from scanEngine.models import EngineType


class IsSubscanTaskTests(TestCase):

    def test_settings_only_sections_are_not_subscan_tasks(self) -> None:
        for name in ('tier_7', 'email_security', 'stress_test', 'leaks_and_secrets', 'wordpress'):
            self.assertFalse(is_subscan_task(name), name)

    def test_pipeline_steps_are(self) -> None:
        for name in ('port_scan', 'vulnerability_scan', 'run_acunetix', 'url_crawl', 'secret_scanning'):
            self.assertTrue(is_subscan_task(name), name)


class InitiateSubTaskValidationTests(TestCase):

    def setUp(self) -> None:
        self.client.force_login(User.objects.create_superuser('admin', 'admin@example.test', 'pw'))
        self.url = reverse('api:initiate_subscan')

    @patch('api.views.scan.initiate_subscan_temporal')
    def test_an_unsupported_task_is_rejected_before_anything_starts(self, mock_start) -> None:
        resp = self.client.post(
            self.url, {'tasks': ['port_scan', 'tier_7'], 'subdomain_ids': [1]}, content_type='application/json',
        )

        self.assertEqual(resp.status_code, 400)
        self.assertIn('tier_7', resp.json()['message'])
        self.assertNotIn('port_scan', resp.json()['message'])
        mock_start.assert_not_called()

    @patch('api.views.scan.initiate_subscan_temporal', return_value={'success': True})
    def test_supported_tasks_start(self, mock_start) -> None:
        resp = self.client.post(
            self.url, {'tasks': ['port_scan'], 'subdomain_ids': [1]}, content_type='application/json',
        )

        self.assertEqual(resp.status_code, 200)
        self.assertEqual(mock_start.call_args.kwargs['scan_type'], ['port_scan'])


class EngineSubscanTasksTests(TestCase):

    def test_the_serializer_lists_only_runnable_subscan_tasks(self) -> None:
        engine = EngineType.objects.create(
            engine_name='subscan-tasks',
            yaml_configuration='port_scan: {}\ntier_7: {}\nemail_security: {}\nvulnerability_scan: {}\n',
        )

        data = EngineSerializer(engine).data

        self.assertEqual(data['subscan_tasks'], ['port_scan', 'vulnerability_scan'])
        self.assertIn('tier_7', data['tasks'], 'the full list is unchanged for other callers')
