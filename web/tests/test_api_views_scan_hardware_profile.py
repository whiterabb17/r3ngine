"""POST /api/action/scan/<scan_id>/hardware-profile/ — switch the profile of a scan.

All domains and users here are anonymised (RFC 2606).
"""
from unittest.mock import patch

from django.contrib.auth import get_user_model
from django.test import TestCase
from django.urls import reverse
from django.utils import timezone
from rest_framework.test import APIClient
from rolepermissions.roles import assign_role

from reNgine.definitions import INTERNAL_ERROR_MESSAGE, RUNNING_TASK
from scanEngine.models import EngineType, HardwareProfile
from startScan.models import ScanHistory
from targetApp.models import Domain

User = get_user_model()


class SetScanHardwareProfileTests(TestCase):

    def setUp(self) -> None:
        self.client = APIClient()
        self.weak = HardwareProfile.objects.create(name='api-hp-weak', threads=4, rate_limit=50)
        self.strong = HardwareProfile.objects.create(name='api-hp-strong', threads=64, rate_limit=1000)
        self.retired = HardwareProfile.objects.create(name='api-hp-retired', threads=99, is_active=False)
        engine = EngineType.objects.create(engine_name='api-hp-engine', yaml_configuration='')
        domain = Domain.objects.create(name='api-hp.test.example', insert_date=timezone.now())
        self.scan = ScanHistory.objects.create(
            domain=domain,
            scan_type=engine,
            scan_status=RUNNING_TASK,
            start_scan_date=timezone.now(),
            hardware_profile=self.weak,
        )

    def _login(self, role: str) -> None:
        user = User.objects.create_user(username=f'hp-{role}', password='pass', email=f'{role}@test.example')
        assign_role(user, role)
        self.client.force_authenticate(user=user)
        self.client.force_login(user)

    def _post(self, profile_id, scan_id: int | None = None):
        url = reverse('api:set_scan_hardware_profile', kwargs={'scan_id': scan_id or self.scan.id})
        return self.client.post(url, {'hardware_profile_id': profile_id}, format='json')

    def _profile_id(self) -> int | None:
        return ScanHistory.objects.values_list('hardware_profile_id', flat=True).get(pk=self.scan.pk)

    def test_running_scan_is_switched(self) -> None:
        self._login('penetration_tester')

        response = self._post(self.strong.id)

        self.assertEqual(response.status_code, 200)
        self.assertTrue(response.data['status'])
        self.assertEqual(response.data['hardware_profile'], {'id': self.strong.id, 'name': 'api-hp-strong'})
        self.assertEqual(self._profile_id(), self.strong.id)

    def test_role_without_scan_permission_is_denied(self) -> None:
        self._login('auditor')

        response = self._post(self.strong.id)

        self.assertEqual(response.status_code, 403)
        self.assertEqual(self._profile_id(), self.weak.id)

    def test_anonymous_is_denied(self) -> None:
        response = self._post(self.strong.id)

        # The login-required middleware redirects before DRF answers 401/403.
        self.assertIn(response.status_code, (302, 401, 403))
        self.assertEqual(self._profile_id(), self.weak.id)

    def test_unknown_profile_is_rejected(self) -> None:
        self._login('penetration_tester')

        response = self._post(987654)

        self.assertEqual(response.status_code, 400)
        self.assertFalse(response.data['status'])
        self.assertEqual(self._profile_id(), self.weak.id)

    def test_inactive_profile_is_rejected(self) -> None:
        self._login('penetration_tester')

        response = self._post(self.retired.id)

        self.assertEqual(response.status_code, 400)
        self.assertEqual(self._profile_id(), self.weak.id)

    def test_malformed_profile_id_is_rejected(self) -> None:
        self._login('penetration_tester')

        for bad in (None, 'abc', ''):
            with self.subTest(bad=bad):
                self.assertEqual(self._post(bad).status_code, 400)

    def test_unknown_scan_is_404(self) -> None:
        self._login('penetration_tester')

        self.assertEqual(self._post(self.strong.id, scan_id=987654).status_code, 404)

    def test_save_failure_returns_a_generic_message(self) -> None:
        self._login('penetration_tester')

        with patch.object(ScanHistory, 'save', side_effect=RuntimeError('db detail /secret/path')), \
                self.assertLogs('api.views.scan', level='ERROR'):
            response = self._post(self.strong.id)

        self.assertEqual(response.status_code, 500)
        self.assertEqual(response.data['message'], INTERNAL_ERROR_MESSAGE)
        self.assertNotIn('secret', str(response.data))
