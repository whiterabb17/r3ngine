from django.test import TestCase
from dashboard.models import GitHubAPIKey, LeakSearchAPIKey


class TestNewAPIKeyModels(TestCase):
    def test_github_api_key_create(self):
        obj = GitHubAPIKey.objects.create(key='ghp_testtoken123456789')
        self.assertEqual(GitHubAPIKey.objects.count(), 1)
        self.assertIn('GitHub API Key', str(obj))

    def test_leaksearch_api_key_create(self):
        obj = LeakSearchAPIKey.objects.create(key='ls_testtoken123456789')
        self.assertEqual(LeakSearchAPIKey.objects.count(), 1)
        self.assertIn('LeakSearch API Key', str(obj))

    def test_github_api_key_str_truncates(self):
        obj = GitHubAPIKey.objects.create(key='ghp_abcdefghijklmnop')
        self.assertIn('ghp_abcd', str(obj))

    def test_leaksearch_api_key_str_truncates(self):
        obj = LeakSearchAPIKey.objects.create(key='ls_xyzxyzxyzxyzxyz')
        self.assertIn('ls_xyzxy', str(obj))
