"""Tests for authenticated-proxy handling (socks5://user:pass@host:port).

Covers the three things that made credentialed proxies unusable or unsafe:
credentials leaking into persisted commands and logs, the pool auto-deleting a
paid endpoint after one failed health check, and proxychains mis-parsing the
line so the proxy never worked at all.
"""
from django.test import SimpleTestCase, TestCase

from reNgine.common_func import (
    proxy_has_credentials,
    redact_proxy_credentials,
    remove_proxy_from_pool,
)
from reNgine.utils.opsec import ProxychainsWrapper
from reNgine.utils.task import sanitize_command_for_db
from scanEngine.models import Proxy


class RedactProxyCredentialsTests(SimpleTestCase):
    def test_masks_password_and_keeps_username(self):
        self.assertEqual(
            redact_proxy_credentials('socks5://user:pass@host.com:1234'),
            'socks5://user:***@host.com:1234',
        )

    def test_masks_inside_a_full_command(self):
        self.assertEqual(
            redact_proxy_credentials(
                'nuclei -l /tmp/u.txt -proxy socks5://acct7:s3cr3t@px.io:1080'
            ),
            'nuclei -l /tmp/u.txt -proxy socks5://acct7:***@px.io:1080',
        )

    def test_percent_encoded_password_is_masked(self):
        self.assertEqual(
            redact_proxy_credentials('socks5://user:p%40ss%3Aword@host.com:1234'),
            'socks5://user:***@host.com:1234',
        )

    def test_leaves_proxy_without_credentials_alone(self):
        self.assertEqual(
            redact_proxy_credentials('socks5://host.com:1234'),
            'socks5://host.com:1234',
        )

    def test_none_passes_through(self):
        self.assertIsNone(redact_proxy_credentials(None))


class ProxyHasCredentialsTests(SimpleTestCase):
    def test_true_for_userinfo(self):
        self.assertTrue(proxy_has_credentials('socks5://user:pass@host.com:1234'))

    def test_false_for_plain_forms(self):
        self.assertFalse(proxy_has_credentials('socks5://host.com:1234'))
        self.assertFalse(proxy_has_credentials('1.2.3.4:8080'))
        self.assertFalse(proxy_has_credentials(''))

    def test_at_sign_in_path_is_not_userinfo(self):
        self.assertFalse(proxy_has_credentials('http://host.com:80/a@b'))


class SanitizeCommandForDbTests(SimpleTestCase):
    def test_persisted_command_carries_no_password(self):
        self.assertEqual(
            sanitize_command_for_db('httpx -proxy socks5://acct7:s3cr3t@px.io:1080'),
            'httpx -proxy socks5://acct7:***@px.io:1080',
        )

    def test_still_strips_export_prefix(self):
        self.assertEqual(
            sanitize_command_for_db("export HTTP_PROXY='http://u:p@h:1' && curl http://x"),
            'curl http://x',
        )

    def test_still_strips_proxychains_wrapper(self):
        self.assertEqual(
            sanitize_command_for_db('/usr/bin/proxychains4 -f /tmp/pc.conf nuclei -u https://x'),
            'nuclei -u https://x',
        )


class RemoveProxyFromPoolTests(TestCase):
    def test_credentialed_proxy_is_never_auto_removed(self):
        """One failed health check must not delete a paid endpoint."""
        proxy = Proxy.objects.create(
            use_proxy=True,
            proxies='socks5://acct7:s3cr3t@px.io:1080\nhttp://free.com:8080',
        )
        self.assertFalse(
            remove_proxy_from_pool('socks5://acct7:s3cr3t@px.io:1080', proxy)
        )
        proxy.refresh_from_db()
        self.assertIn('socks5://acct7:s3cr3t@px.io:1080', proxy.proxies)

    def test_plain_proxy_is_still_removed(self):
        proxy = Proxy.objects.create(
            use_proxy=True,
            proxies='socks5://acct7:s3cr3t@px.io:1080\nhttp://free.com:8080',
        )
        self.assertTrue(remove_proxy_from_pool('http://free.com:8080', proxy))
        proxy.refresh_from_db()
        self.assertEqual(proxy.proxies, 'socks5://acct7:s3cr3t@px.io:1080')


class ProxychainsLineTests(TestCase):
    """proxychains takes 'type host port [user pass]'.

    The old parser split the line on ':' and read host='acct7',
    port='s3cr3t@px.io', so an authenticated proxy could never connect.
    """

    def _lines(self, stored):
        Proxy.objects.create(use_proxy=True, proxies=stored)
        return ProxychainsWrapper()._fetch_proxies()

    def test_authenticated_socks5(self):
        self.assertEqual(
            self._lines('socks5://acct7:s3cr3t@px.io:1080'),
            ['socks5 px.io 1080 acct7 s3cr3t'],
        )

    def test_socks5h_collapses_to_socks5_keeping_credentials(self):
        self.assertEqual(
            self._lines('socks5h://acct7:s3cr3t@px.io:1080'),
            ['socks5 px.io 1080 acct7 s3cr3t'],
        )

    def test_percent_encoded_password_is_decoded(self):
        self.assertEqual(
            self._lines('socks5://acct7:p%40ss@px.io:1080'),
            ['socks5 px.io 1080 acct7 p@ss'],
        )

    def test_plain_forms_are_unchanged(self):
        self.assertEqual(self._lines('http://1.2.3.4:8080'), ['http 1.2.3.4 8080'])

    def test_bare_host_port_defaults_to_socks5(self):
        self.assertEqual(self._lines('1.2.3.4:1080'), ['socks5 1.2.3.4 1080'])
