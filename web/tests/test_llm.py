from django.test import TestCase
from unittest.mock import patch, MagicMock


class TestLLMSSLAndSecurity(TestCase):

    def _make_generator(self, provider_const):
        from unittest.mock import MagicMock
        from reNgine.llm import LLMBaseGenerator
        gen = LLMBaseGenerator.__new__(LLMBaseGenerator)
        gen.logger = MagicMock()
        gen.gate = MagicMock()
        gen.gate.anonymize = lambda x: x
        gen.gate.deanonymize = lambda x: x
        gen.model_name = "test-model"
        gen.provider = provider_const
        gen.api_key = "test-api-key"
        gen.base_url = None
        return gen

    def test_openai_ssl_verification_enabled(self):
        """OpenAI call must use SSL verification (no verify=False)."""
        from reNgine.definitions import OPENAI
        gen = self._make_generator(OPENAI)
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "choices": [{"message": {"content": "test"}}]
        }
        with patch("requests.post", return_value=mock_response) as mock_post:
            gen._call_openai("sys", "user")
        mock_response.raise_for_status.assert_called_once()
        call_kwargs = mock_post.call_args.kwargs
        self.assertNotIn("verify", call_kwargs,
                         "verify=False must not be passed — default (True) must apply")
        self.assertNotIn("proxies", call_kwargs,
                         "proxies override must not be set")

    def test_openai_fallback_to_max_completion_tokens(self):
        """OpenAI call must fallback to max_completion_tokens when max_tokens returns 400 error."""
        from reNgine.definitions import OPENAI
        gen = self._make_generator(OPENAI)

        # Mock initial 400 response for max_tokens
        mock_400 = MagicMock()
        mock_400.status_code = 400
        mock_400.text = "Unsupported parameter: 'max_tokens' is not supported with this model. Use 'max_completion_tokens' instead."

        # Mock second 200 response for max_completion_tokens
        mock_200 = MagicMock()
        mock_200.status_code = 200
        mock_200.json.return_value = {
            "choices": [{"message": {"content": "fallback success"}}]
        }

        with patch("requests.post", side_effect=[mock_400, mock_200]) as mock_post:
            result = gen._call_openai("sys", "user", max_tokens=100)

        self.assertEqual(result, "fallback success")
        self.assertEqual(mock_post.call_count, 2)

        # Verify second call used max_completion_tokens instead of max_tokens
        second_call_json = mock_post.call_args_list[1].kwargs["json"]
        self.assertNotIn("max_tokens", second_call_json)
        self.assertEqual(second_call_json.get("max_completion_tokens"), 100)

    def test_anthropic_system_field_separate(self):
        """Anthropic call must send system_message as top-level 'system' field, not in messages."""
        from reNgine.definitions import ANTHROPIC
        gen = self._make_generator(ANTHROPIC)
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "content": [{"type": "text", "text": "test"}]
        }
        with patch("requests.post", return_value=mock_response) as mock_post:
            gen._call_anthropic("my system prompt", "my user message")
        mock_response.raise_for_status.assert_called_once()
        payload = mock_post.call_args.kwargs["json"]
        self.assertIn("system", payload, "Anthropic payload must have top-level 'system' key")
        self.assertEqual(payload["system"], "my system prompt")
        self.assertEqual(payload["messages"], [{"role": "user", "content": "my user message"}])

    def test_anthropic_ssl_verification_enabled(self):
        """Anthropic call must use SSL verification."""
        from reNgine.definitions import ANTHROPIC
        gen = self._make_generator(ANTHROPIC)
        mock_response = MagicMock()
        mock_response.json.return_value = {"content": [{"type": "text", "text": "test"}]}
        with patch("requests.post", return_value=mock_response) as mock_post:
            gen._call_anthropic("sys", "user")
        mock_response.raise_for_status.assert_called_once()
        call_kwargs = mock_post.call_args.kwargs
        self.assertNotIn("verify", call_kwargs)
        self.assertNotIn("proxies", call_kwargs)

    def test_gemini_api_key_in_header_not_url(self):
        """Gemini API key must be in x-goog-api-key header, NOT in the URL query string."""
        from reNgine.definitions import GEMINI
        gen = self._make_generator(GEMINI)
        mock_response = MagicMock()
        mock_response.json.return_value = {
            "candidates": [{"content": {"parts": [{"text": "test"}]}}]
        }
        with patch("requests.post", return_value=mock_response) as mock_post:
            gen._call_gemini("sys", "user")
        mock_response.raise_for_status.assert_called_once()
        url = mock_post.call_args.args[0]
        headers = mock_post.call_args.kwargs.get("headers", {})
        self.assertNotIn("key=", url, "API key must not appear in URL query string")
        self.assertIn("x-goog-api-key", headers, "API key must be in x-goog-api-key header")
        self.assertEqual(headers["x-goog-api-key"], "test-api-key")


class TestOpenAICompatibleProvider(TestCase):

    def _make_generator(self, base_url):
        from reNgine.definitions import OPENAI_COMPATIBLE
        from reNgine.llm import LLMBaseGenerator
        gen = LLMBaseGenerator.__new__(LLMBaseGenerator)
        gen.logger = MagicMock()
        gen.model_name = "claude-opus-4-8"
        gen.provider = OPENAI_COMPATIBLE
        gen.api_key = "gateway-key"
        gen.base_url = base_url
        return gen

    def test_chat_goes_to_the_configured_base_url(self):
        gen = self._make_generator("https://gateway.example.test/v1/")
        ok = MagicMock(status_code=200)
        ok.json.return_value = {"choices": [{"message": {"content": "hello"}}]}
        with patch("requests.post", return_value=ok) as mock_post:
            result = gen._call_openai_compatible("sys", "user")
        self.assertEqual(result, "hello")
        self.assertEqual(mock_post.call_args.args[0], "https://gateway.example.test/v1/chat/completions")
        self.assertEqual(mock_post.call_args.kwargs["headers"]["Authorization"], "Bearer gateway-key")
        self.assertEqual(mock_post.call_args.kwargs["json"]["model"], "claude-opus-4-8")

    def test_missing_base_url_is_reported_without_a_request(self):
        gen = self._make_generator(None)
        with patch("requests.post") as mock_post:
            result = gen._call_openai_compatible("sys", "user")
        self.assertTrue(result.startswith("Error:"))
        mock_post.assert_not_called()

    def test_base_url_validation(self):
        from reNgine.llm_client import normalize_base_url
        self.assertEqual(normalize_base_url(" https://gw.example.test/v1/ "), "https://gw.example.test/v1")
        self.assertEqual(normalize_base_url("http://10.0.0.5:8000/v1"), "http://10.0.0.5:8000/v1")
        for bad in ("", "gw.example.test/v1", "file:///etc/passwd", "javascript:alert(1)",
                    "https://user:pw@gw.example.test/v1", "https://gw.example.test/v1?x=1"):
            with self.assertRaises(ValueError, msg=bad):
                normalize_base_url(bad)

    def test_model_list_keeps_non_gpt_ids(self):
        from reNgine.utils.llm import LLMModelManager
        listing = MagicMock(status_code=200)
        listing.json.return_value = {"data": [{"id": "gpt-5.5"}, {"id": "claude-opus-4-8"}, {"id": "gemma-3-27b-it"}]}
        with patch("requests.get", return_value=listing) as mock_get:
            models = LLMModelManager().get_models("openai_compatible", "k", base_url="https://gw.example.test/v1")
        self.assertEqual(mock_get.call_args.args[0], "https://gw.example.test/v1/models")
        self.assertEqual([m["name"] for m in models], ["claude-opus-4-8", "gemma-3-27b-it", "gpt-5.5"])

    def test_model_list_without_base_url_is_empty(self):
        from reNgine.utils.llm import LLMModelManager
        with patch("requests.get") as mock_get:
            self.assertEqual(LLMModelManager().get_models("openai_compatible", "k"), [])
        mock_get.assert_not_called()

    def test_connection_test_uses_the_base_url(self):
        from scanEngine.views import _test_llm_provider
        ok = MagicMock(status_code=200)
        ok.json.return_value = {"choices": [{"message": {"content": "CONNECTED"}}]}
        with patch("requests.post", return_value=ok) as mock_post:
            result = _test_llm_provider("openai_compatible", "k", "gpt-oss-20b", "https://gw.example.test/v1")
        self.assertEqual(result["status"], "success")
        self.assertEqual(result["response"], "CONNECTED")
        self.assertEqual(mock_post.call_args.args[0], "https://gw.example.test/v1/chat/completions")

    def test_connection_test_rejects_a_bad_base_url_and_a_missing_model(self):
        from scanEngine.views import _test_llm_provider
        with patch("requests.post") as mock_post:
            bad_url = _test_llm_provider("openai_compatible", "k", "m", "ftp://gw.example.test")
            no_model = _test_llm_provider("openai", "k", "", "")
        self.assertEqual(bad_url["status"], "error")
        self.assertEqual(no_model["status"], "error")
        mock_post.assert_not_called()


class TestLLMSettingsSwitch(TestCase):
    def setUp(self):
        from django.contrib.auth import get_user_model
        from django.utils import timezone
        from rolepermissions.roles import assign_role
        from dashboard.models import Project

        User = get_user_model()
        self.user = User.objects.create_user(username='llm-admin', password='x')
        assign_role(self.user, 'sys_admin')
        self.project = Project.objects.create(
            name='LLM Project',
            slug='llm-project',
            insert_date=timezone.now(),
        )

    def test_llm_enabled_follows_settings_row(self):
        from dashboard.models import LLMSettings
        from reNgine.llm import llm_enabled

        settings_row = LLMSettings.get_solo()
        self.assertFalse(settings_row.enabled)
        self.assertFalse(llm_enabled())

        settings_row.enabled = True
        settings_row.save(update_fields=['enabled'])
        self.assertTrue(llm_enabled())

    def test_toggle_endpoint_updates_settings(self):
        from dashboard.models import LLMSettings

        self.client.force_login(self.user)
        res = self.client.post(
            f'/scanEngine/{self.project.slug}/update_llm_settings',
            {'action': 'toggle_enabled', 'llm_enabled': 'true'},
            HTTP_ACCEPT='application/json',
        )
        self.assertEqual(res.status_code, 200)
        payload = res.json()
        self.assertTrue(payload['llm_enabled'])
        self.assertTrue(LLMSettings.get_solo().enabled)

        toolkit = self.client.get(
            f'/scanEngine/{self.project.slug}/llm_toolkit',
            HTTP_ACCEPT='application/json',
        )
        self.assertEqual(toolkit.status_code, 200)
        self.assertTrue(toolkit.json()['llm_enabled'])

    def test_saving_an_openai_compatible_provider_stores_the_base_url(self):
        from dashboard.models import LLMConfig

        self.client.force_login(self.user)
        res = self.client.post(
            f'/scanEngine/{self.project.slug}/update_llm_settings',
            {
                'action': 'save', 'provider': 'openai_compatible', 'api_key': 'k',
                'base_url': 'https://gw.example.test/v1/', 'selected_model': 'claude-opus-4-8', 'is_active': 'true',
            },
            HTTP_ACCEPT='application/json',
        )
        self.assertEqual(res.status_code, 200)
        config = LLMConfig.objects.get(provider='openai_compatible')
        self.assertEqual(config.base_url, 'https://gw.example.test/v1')
        self.assertTrue(config.is_active)

        toolkit = self.client.get(f'/scanEngine/{self.project.slug}/llm_toolkit', HTTP_ACCEPT='application/json')
        saved = [c for c in toolkit.json()['llm_configs'] if c['provider'] == 'openai_compatible'][0]
        self.assertEqual(saved['base_url'], 'https://gw.example.test/v1')

    def test_saving_rejects_a_bad_base_url_and_an_unknown_provider(self):
        from dashboard.models import LLMConfig

        self.client.force_login(self.user)
        url = f'/scanEngine/{self.project.slug}/update_llm_settings'
        bad_url = self.client.post(url, {
            'action': 'save', 'provider': 'openai_compatible', 'api_key': 'k',
            'base_url': 'javascript:alert(1)', 'selected_model': 'm',
        }, HTTP_ACCEPT='application/json')
        unknown = self.client.post(url, {
            'action': 'save', 'provider': 'not-a-provider', 'api_key': 'k', 'selected_model': 'm',
        }, HTTP_ACCEPT='application/json')
        self.assertEqual(bad_url.status_code, 400)
        self.assertEqual(unknown.status_code, 400)
        self.assertFalse(LLMConfig.objects.exists())



def _http_response(status, body=None, headers=None):
    import requests
    response = requests.Response()
    response.status_code = status
    response._content = __import__('json').dumps(body or {}).encode()
    response.headers.update(headers or {})
    response.url = 'https://llm.example.test'
    return response


class TestLLMClientRetries(TestCase):
    OK = {"choices": [{"message": {"content": "done"}}]}

    def _complete(self, **kwargs):
        from reNgine.llm_client import complete
        return complete('openai', api_key='k', model='m', system='s', user='u', **kwargs)

    @patch('reNgine.llm_client.time.sleep')
    def test_rate_limit_is_retried_after_the_advertised_delay(self, mock_sleep):
        responses = [_http_response(429, headers={'Retry-After': '3'}), _http_response(200, self.OK)]
        with patch('requests.post', side_effect=responses) as mock_post:
            self.assertEqual(self._complete(), 'done')
        self.assertEqual(mock_post.call_count, 2)
        mock_sleep.assert_called_once_with(3.0)

    @patch('reNgine.llm_client.time.sleep')
    def test_long_retry_after_is_capped(self, mock_sleep):
        responses = [_http_response(529, headers={'Retry-After': '600'}), _http_response(200, self.OK)]
        with patch('requests.post', side_effect=responses):
            self._complete()
        mock_sleep.assert_called_once_with(20)

    @patch('reNgine.llm_client.time.sleep')
    def test_gives_up_after_the_retry_budget(self, mock_sleep):
        import requests
        with patch('requests.post', return_value=_http_response(503)) as mock_post:
            with self.assertRaises(requests.exceptions.HTTPError):
                self._complete()
        self.assertEqual(mock_post.call_count, 3)
        self.assertEqual([c.args[0] for c in mock_sleep.call_args_list], [2.0, 4.0])

    @patch('reNgine.llm_client.time.sleep')
    def test_connection_failure_is_retried(self, _sleep):
        import requests
        responses = [requests.exceptions.ConnectionError('reset'), _http_response(200, self.OK)]
        with patch('requests.post', side_effect=responses) as mock_post:
            self.assertEqual(self._complete(), 'done')
        self.assertEqual(mock_post.call_count, 2)

    @patch('reNgine.llm_client.time.sleep')
    def test_client_errors_and_read_timeouts_are_not_retried(self, mock_sleep):
        import requests
        with patch('requests.post', return_value=_http_response(401)) as mock_post:
            with self.assertRaises(requests.exceptions.HTTPError):
                self._complete()
        self.assertEqual(mock_post.call_count, 1)
        with patch('requests.post', side_effect=requests.exceptions.ReadTimeout()) as mock_post:
            with self.assertRaises(requests.exceptions.ReadTimeout):
                self._complete()
        self.assertEqual(mock_post.call_count, 1)
        mock_sleep.assert_not_called()

    @patch('reNgine.llm_client.time.sleep')
    def test_connection_test_reports_a_rate_limit_at_once(self, mock_sleep):
        from scanEngine.views import _test_llm_provider
        with patch('requests.post', return_value=_http_response(429)) as mock_post:
            result = _test_llm_provider('openai', 'k', 'm')
        self.assertEqual(result['status'], 'error')
        self.assertIn('Rate limit', result['message'])
        self.assertEqual(mock_post.call_count, 1)
        mock_sleep.assert_not_called()

    def test_anthropic_asks_for_4096_tokens_unless_told_otherwise(self):
        from reNgine.llm_client import complete
        body = {"content": [{"type": "text", "text": "ok"}]}
        with patch('requests.post', return_value=_http_response(200, body)) as mock_post:
            complete('anthropic', api_key='k', model='m', system='s', user='u')
            complete('anthropic', api_key='k', model='m', system='s', user='u', max_tokens=20)
        self.assertEqual(mock_post.call_args_list[0].kwargs['json']['max_tokens'], 4096)
        self.assertEqual(mock_post.call_args_list[1].kwargs['json']['max_tokens'], 20)
