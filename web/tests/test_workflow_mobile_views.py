from django.test import TestCase
from django.contrib.auth import get_user_model

User = get_user_model()

EXPECTED_SLUGS = {
    'user-hunt', 'url-bypass', 'wordpress', 'host-recon', 'cidr-recon',
    'code-scan', 'domain-recon', 'subdomain-recon', 'url-crawl',
    'url-dirsearch', 'url-fuzz', 'url-params-fuzz', 'url-vuln',
}


class WorkflowMobileListTests(TestCase):
    def setUp(self):
        self.user = User.objects.create_user(
            username='wfuser', password='testpass123'
        )
        self.client.force_login(self.user)

    def test_list_requires_auth(self):
        from django.test import Client
        anon_client = Client()
        resp = anon_client.get('/mapi/workflows/')
        self.assertIn(resp.status_code, [401, 403])

    def test_list_returns_all_slugs(self):
        resp = self.client.get('/mapi/workflows/')
        self.assertEqual(resp.status_code, 200)
        data = resp.json()
        self.assertIn('workflows', data)
        returned_slugs = {w['slug'] for w in data['workflows']}
        self.assertEqual(returned_slugs, EXPECTED_SLUGS)

    def test_each_workflow_has_required_keys(self):
        resp = self.client.get('/mapi/workflows/')
        for wf in resp.json()['workflows']:
            self.assertIn('slug', wf)
            self.assertIn('name', wf)
            self.assertIn('description', wf)
            self.assertIn('required_fields', wf)
            self.assertIsInstance(wf['required_fields'], list)
