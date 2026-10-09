"""Unit tests for marketplace plugin metadata, including public-repo icons."""

from unittest.mock import MagicMock, patch

from django.test import TestCase


class TestMarketplaceIconUrl(TestCase):
    def test_default_icon_png_for_valid_slug(self):
        from plugins.utils import MarketplaceManager

        url = MarketplaceManager._marketplace_icon_url('active_directory')
        self.assertEqual(
            url,
            'https://raw.githubusercontent.com/whiterabb17/r3ngine-plugins/refs/heads/master/active_directory/icon.png',
        )

    def test_yaml_icon_filename_is_used_when_safe(self):
        from plugins.utils import MarketplaceManager

        url = MarketplaceManager._marketplace_icon_url('burpsuite_integration', 'logo.svg')
        self.assertEqual(
            url,
            'https://raw.githubusercontent.com/whiterabb17/r3ngine-plugins/refs/heads/master/burpsuite_integration/logo.svg',
        )

    def test_invalid_slug_returns_none(self):
        from plugins.utils import MarketplaceManager

        self.assertIsNone(MarketplaceManager._marketplace_icon_url(None))
        self.assertIsNone(MarketplaceManager._marketplace_icon_url(''))
        self.assertIsNone(MarketplaceManager._marketplace_icon_url('../etc'))
        self.assertIsNone(MarketplaceManager._marketplace_icon_url('Active-Directory'))

    def test_unsafe_icon_field_falls_back_to_icon_png(self):
        from plugins.utils import MarketplaceManager

        url = MarketplaceManager._marketplace_icon_url('active_directory', 'icon.exe')
        self.assertEqual(
            url,
            'https://raw.githubusercontent.com/whiterabb17/r3ngine-plugins/refs/heads/master/active_directory/icon.png',
        )

    def test_icon_field_url_is_not_used_as_src(self):
        from plugins.utils import MarketplaceManager

        url = MarketplaceManager._marketplace_icon_url(
            'active_directory',
            'https://evil.example/payload.png',
        )
        self.assertEqual(
            url,
            'https://raw.githubusercontent.com/whiterabb17/r3ngine-plugins/refs/heads/master/active_directory/icon.png',
        )

    def test_get_available_plugins_attaches_icon_url(self):
        from plugins.utils import MarketplaceManager

        mock_resp = MagicMock()
        mock_resp.status_code = 200
        mock_resp.text = (
            'marketplace:\n'
            '  - slug: active_directory\n'
            '    name: Active Directory\n'
            '    version: "1.1.1"\n'
            '    icon: icon.png\n'
        )
        with patch('plugins.utils.requests.get', return_value=mock_resp), \
             patch('plugins.utils.cache.get', return_value=None), \
             patch('plugins.utils.cache.set') as mock_cache_set, \
             patch('plugins.utils.Plugin.objects') as mock_objects:
            mock_objects.all.return_value = []
            plugins = MarketplaceManager.get_available_plugins(force_refresh=True)

        self.assertEqual(len(plugins), 1)
        self.assertEqual(
            plugins[0]['icon_url'],
            'https://raw.githubusercontent.com/whiterabb17/r3ngine-plugins/refs/heads/master/active_directory/icon.png',
        )
        mock_cache_set.assert_called_once()
