"""save_endpoint only accepts URLs whose host is the scanned domain or one of its subdomains."""
from unittest.mock import patch

from django.test import TestCase
from django.utils import timezone

from reNgine.utils.task import save_endpoint
from scanEngine.models import EngineType
from startScan.models import EndPoint, ScanHistory
from targetApp.models import Domain


class SaveEndpointScopeTests(TestCase):

    def setUp(self) -> None:
        self.domain = Domain.objects.create(name='example.test')
        self.scan = ScanHistory.objects.create(
            scan_status=0,
            domain=self.domain,
            scan_type=EngineType.objects.create(engine_name='Endpoint scope test'),
            start_scan_date=timezone.now(),
        )
        self.ctx = {'scan_history_id': self.scan.id, 'domain_id': self.domain.id}

    def test_urls_that_only_contain_the_domain_name_are_rejected(self) -> None:
        for url in (
            'https://example.test.attacker.test/login',
            'https://attacker.test/?next=example.test',
            'https://notexample.test/',
            'https://attacker.test/example.test/',
        ):
            with self.subTest(url=url):
                self.assertEqual(save_endpoint(url, ctx=dict(self.ctx)), (None, False))
        self.assertFalse(EndPoint.objects.exists())

    def test_the_domain_and_its_subdomains_are_accepted(self) -> None:
        for url in ('https://example.test/a', 'https://api.example.test:8443/v1', 'https://API.Example.test/b'):
            with self.subTest(url=url):
                endpoint, _ = save_endpoint(url, ctx=dict(self.ctx))
                self.assertIsNotNone(endpoint)

    @patch('reNgine.temporal_activities.TemporalTaskProxy')
    @patch('reNgine.tasks.http_crawl', return_value=[])
    def test_a_bare_subdomain_is_crawled_like_before(self, mock_crawl, _proxy) -> None:
        # The subscan starter passes 'host[/path]' with no scheme and lets http_crawl probe it.
        save_endpoint('api.example.test/app', ctx=dict(self.ctx), crawl=True)
        self.assertEqual(mock_crawl.call_args.kwargs['urls'], ['api.example.test/app'])

    @patch('reNgine.temporal_activities.TemporalTaskProxy')
    @patch('reNgine.tasks.http_crawl', return_value=[])
    def test_a_bare_foreign_host_is_not_crawled(self, mock_crawl, _proxy) -> None:
        for url in ('attacker.test', 'example.test.attacker.test:8080/x', 'http://[bad/'):
            with self.subTest(url=url):
                self.assertEqual(save_endpoint(url, ctx=dict(self.ctx), crawl=True), (None, False))
        mock_crawl.assert_not_called()

    def test_a_domain_stored_with_a_trailing_dot_still_matches(self) -> None:
        Domain.objects.filter(pk=self.domain.pk).update(name='Example.test.')
        endpoint, _ = save_endpoint('https://www.example.test/', ctx=dict(self.ctx))
        self.assertIsNotNone(endpoint)
