"""Tool update/uninstall/version endpoints: method, input and filesystem safety."""
import os
import shutil
import tempfile
from unittest.mock import patch

from django.contrib.auth.models import User
from django.test import TestCase
from rest_framework.test import APIClient
from rest_framework_simplejwt.tokens import RefreshToken
from rolepermissions.roles import assign_role

from scanEngine.models import InstalledExternalTool


def _tool(**overrides) -> InstalledExternalTool:
    fields = {
        'name': 'sometool',
        'description': 'test tool',
        'github_url': 'https://github.com/example/sometool',
        'install_command': 'go install -v github.com/example/sometool@latest',
        'update_command': 'go install -v github.com/example/sometool@latest',
    }
    fields.update(overrides)
    return InstalledExternalTool.objects.create(**fields)


class ToolCommandViewTests(TestCase):

    def setUp(self):
        self.admin = User.objects.create_user(username='tool-admin', password='x')
        assign_role(self.admin, 'sys_admin')
        self.client = APIClient()
        self.client.force_login(self.admin)

        base = tempfile.mkdtemp(prefix='rengine_tool_views_')
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        self.bin_dir = os.path.join(base, 'bin')
        self.github_dir = os.path.join(base, 'github')
        os.makedirs(self.bin_dir)
        os.makedirs(self.github_dir)
        for name, value in (('GO_BIN_DIR', self.bin_dir), ('GITHUB_TOOLS_DIR', self.github_dir)):
            patcher = patch(f'api.views.tools.{name}', value)
            patcher.start()
            self.addCleanup(patcher.stop)

    def test_session_get_is_refused_without_running_anything(self):
        tool = _tool()
        with patch('api.views.tools.run_command') as run:
            resp = self.client.get('/api/tool/update/', {'tool_id': tool.id})
        self.assertEqual(resp.status_code, 405)
        run.assert_not_called()

    def test_post_update_runs_the_update_command(self):
        tool = _tool()
        with patch('api.views.tools.run_command', return_value=(0, '')) as run:
            resp = self.client.post('/api/tool/update/', {'tool_id': tool.id}, format='json')
        self.assertEqual(resp.status_code, 200)
        self.assertTrue(resp.data['status'])
        run.assert_called_once()

    def test_token_client_may_still_use_get(self):
        """The mobile app authenticates with a JWT, which carries no ambient credentials."""
        tool = _tool()
        token = str(RefreshToken.for_user(self.admin).access_token)
        client = APIClient()
        client.credentials(HTTP_AUTHORIZATION=f'Bearer {token}')
        with patch('api.views.tools.run_command', return_value=(0, '')):
            resp = client.get('/mapi/tool/update/', {'tool_id': tool.id})
        self.assertEqual(resp.status_code, 200)

    def test_missing_tool_reference_is_bad_request(self):
        self.assertEqual(self.client.post('/api/tool/uninstall/', {}, format='json').status_code, 400)
        self.assertEqual(self.client.get('/api/external/tool/get_current_release/').status_code, 400)

    def test_unknown_tool_is_not_found(self):
        resp = self.client.post('/api/tool/uninstall/', {'tool_id': 999999}, format='json')
        self.assertEqual(resp.status_code, 404)

    def test_uninstall_go_tool_removes_only_its_binary(self):
        tool = _tool()
        binary = os.path.join(self.bin_dir, 'sometool')
        other = os.path.join(self.bin_dir, 'othertool')
        for path in (binary, other):
            open(path, 'w').close()

        resp = self.client.post('/api/tool/uninstall/', {'tool_id': tool.id}, format='json')

        self.assertEqual(resp.status_code, 200, resp.data)
        self.assertFalse(os.path.exists(binary))
        self.assertTrue(os.path.exists(other))
        self.assertFalse(InstalledExternalTool.objects.filter(pk=tool.pk).exists())

    def test_uninstall_git_tool_removes_its_checkout(self):
        checkout = os.path.join(self.github_dir, 'sometool')
        os.makedirs(checkout)
        tool = _tool(install_command='git clone https://github.com/example/sometool', github_clone_path=checkout)

        resp = self.client.post('/api/tool/uninstall/', {'tool_id': tool.id}, format='json')

        self.assertEqual(resp.status_code, 200, resp.data)
        self.assertFalse(os.path.exists(checkout))

    def test_uninstall_refuses_checkout_outside_tools_dir(self):
        outside = tempfile.mkdtemp(prefix='rengine_outside_')
        self.addCleanup(shutil.rmtree, outside, ignore_errors=True)
        for clone_path in (outside, self.github_dir, os.path.join(self.github_dir, '..')):
            tool = _tool(install_command='git clone https://github.com/example/x', github_clone_path=clone_path)
            resp = self.client.post('/api/tool/uninstall/', {'tool_id': tool.id}, format='json')
            self.assertEqual(resp.status_code, 400, clone_path)
            self.assertTrue(InstalledExternalTool.objects.filter(pk=tool.pk).exists())
        self.assertTrue(os.path.isdir(outside))
        self.assertTrue(os.path.isdir(self.github_dir))

    def test_uninstall_refuses_odd_binary_names(self):
        tool = _tool(install_command='go install github.com/example/..@latest')
        resp = self.client.post('/api/tool/uninstall/', {'tool_id': tool.id}, format='json')
        self.assertEqual(resp.status_code, 400)

    def test_default_tool_cannot_be_uninstalled(self):
        tool = _tool(is_default=True)
        resp = self.client.post('/api/tool/uninstall/', {'tool_id': tool.id}, format='json')
        self.assertEqual(resp.status_code, 400)
        self.assertTrue(InstalledExternalTool.objects.filter(pk=tool.pk).exists())

    def test_penetration_tester_cannot_uninstall(self):
        user = User.objects.create_user(username='pentester', password='x')
        assign_role(user, 'penetration_tester')
        client = APIClient()
        client.force_login(user)
        tool = _tool()
        resp = client.post('/api/tool/uninstall/', {'tool_id': tool.id}, format='json')
        self.assertEqual(resp.status_code, 403)
