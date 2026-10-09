"""Scan result deletion must stay inside RENGINE_RESULTS."""
import os
import shutil
import tempfile

from django.contrib.auth.models import User
from django.test import SimpleTestCase, TestCase, override_settings
from django.utils import timezone
from rolepermissions.roles import assign_role

from reNgine.utils.results_fs import delete_screenshot_files, remove_results_dir
from scanEngine.models import EngineType
from startScan.models import ScanHistory, Screenshot, Subdomain
from targetApp.models import Domain


def _touch(path: str) -> None:
    os.makedirs(os.path.dirname(path), exist_ok=True)
    with open(path, 'w') as fh:
        fh.write('x')


class _ResultsRootMixin:
    """Points RENGINE_RESULTS at a fresh temp dir, next to an 'outside' dir."""

    def setUp(self):
        super().setUp()
        base = tempfile.mkdtemp(prefix='rengine_results_fs_')
        self.addCleanup(shutil.rmtree, base, ignore_errors=True)
        self.root = os.path.join(base, 'scan_results')
        self.outside = os.path.join(base, 'outside')
        os.makedirs(self.root)
        os.makedirs(self.outside)
        override = override_settings(RENGINE_RESULTS=self.root)
        override.enable()
        self.addCleanup(override.disable)


class RemoveResultsDirTests(_ResultsRootMixin, SimpleTestCase):

    def test_removes_directory_inside_root(self):
        scan_dir = os.path.join(self.root, 'example.test_1')
        _touch(os.path.join(scan_dir, 'subdomains.txt'))

        self.assertTrue(remove_results_dir(scan_dir))
        self.assertFalse(os.path.exists(scan_dir))

    def test_refuses_the_root_itself(self):
        _touch(os.path.join(self.root, 'keep.txt'))

        self.assertFalse(remove_results_dir(self.root))
        self.assertFalse(remove_results_dir(self.root + '/'))
        self.assertTrue(os.path.exists(os.path.join(self.root, 'keep.txt')))

    def test_refuses_paths_outside_root(self):
        _touch(os.path.join(self.outside, 'keep.txt'))

        self.assertFalse(remove_results_dir(self.outside))
        self.assertFalse(remove_results_dir(os.path.join(self.root, '..', 'outside')))
        self.assertTrue(os.path.exists(os.path.join(self.outside, 'keep.txt')))

    def test_refuses_symlink_escaping_root(self):
        _touch(os.path.join(self.outside, 'keep.txt'))
        link = os.path.join(self.root, 'escape')
        os.symlink(self.outside, link)

        self.assertFalse(remove_results_dir(link))
        self.assertTrue(os.path.exists(os.path.join(self.outside, 'keep.txt')))

    def test_empty_or_missing_path_is_a_no_op(self):
        self.assertFalse(remove_results_dir(''))
        self.assertFalse(remove_results_dir(None))
        self.assertFalse(remove_results_dir(os.path.join(self.root, 'missing')))
        self.assertFalse(remove_results_dir(self.root + '/a\x00b'))

    def test_delete_screenshot_files_keeps_other_results(self):
        scan_dir = os.path.join(self.root, 'example.test_1')
        _touch(os.path.join(scan_dir, 'screenshots', '1', 'a.png'))
        _touch(os.path.join(scan_dir, 'subdomains.txt'))
        _touch(os.path.join(self.root, 'screenshots', '2', 'b.png'))

        self.assertEqual(delete_screenshot_files(), 2)
        self.assertFalse(os.path.exists(os.path.join(scan_dir, 'screenshots')))
        self.assertFalse(os.path.exists(os.path.join(self.root, 'screenshots')))
        self.assertTrue(os.path.exists(os.path.join(scan_dir, 'subdomains.txt')))


class ScanDeletionTests(_ResultsRootMixin, TestCase):

    def setUp(self):
        super().setUp()
        self.domain = Domain.objects.create(name='example.test')
        self.engine = EngineType.objects.create(engine_name='Deletion Test Engine')
        user = User.objects.create_user(username='admin-user', password='x')
        assign_role(user, 'sys_admin')
        self.client.force_login(user)

    def _scan(self, results_dir: str) -> ScanHistory:
        return ScanHistory.objects.create(
            domain=self.domain, scan_type=self.engine, scan_status=2,
            start_scan_date=timezone.now(), results_dir=results_dir,
        )

    def test_deleting_a_scan_removes_its_results(self):
        scan_dir = os.path.join(self.root, 'example.test_1')
        _touch(os.path.join(scan_dir, 'subdomains.txt'))
        scan = self._scan(scan_dir)

        resp = self.client.post(f'/scan/delete/scan/{scan.id}')

        self.assertEqual(resp.status_code, 200)
        self.assertFalse(ScanHistory.objects.filter(pk=scan.pk).exists())
        self.assertFalse(os.path.exists(scan_dir))

    def test_results_dir_outside_root_is_left_alone(self):
        _touch(os.path.join(self.outside, 'keep.txt'))
        scan = self._scan(self.outside)

        scan.delete()

        self.assertTrue(os.path.exists(os.path.join(self.outside, 'keep.txt')))

    def test_delete_all_screenshots_keeps_scan_results(self):
        scan_dir = os.path.join(self.root, 'example.test_1')
        _touch(os.path.join(scan_dir, 'subdomains.txt'))
        _touch(os.path.join(scan_dir, 'screenshots', '1', 'a.png'))
        scan = self._scan(scan_dir)
        subdomain = Subdomain.objects.create(
            name='app.example.test', scan_history=scan, target_domain=self.domain,
            screenshot_path='screenshots/1/a.png',
        )
        Screenshot.objects.create(
            subdomain=subdomain, scan_history=scan, url='https://app.example.test/',
            screenshot_path='screenshots/1/a.png',
        )

        resp = self.client.post('/scan/delete/screenshots/')

        self.assertEqual(resp.status_code, 200)
        self.assertTrue(os.path.exists(os.path.join(scan_dir, 'subdomains.txt')))
        self.assertFalse(os.path.exists(os.path.join(scan_dir, 'screenshots')))
        self.assertFalse(Screenshot.objects.exists())
        subdomain.refresh_from_db()
        self.assertIsNone(subdomain.screenshot_path)
