# web/tests/test_temporal_client.py
import asyncio
from unittest.mock import AsyncMock, MagicMock, patch
from django.test import TestCase
from reNgine.temporal_client import TemporalClientProvider


class TestTemporalClientProvider(TestCase):

    @patch("reNgine.temporal_client.Client.connect", new_callable=AsyncMock)
    def test_get_client_creates_fresh_connection_each_call(self, mock_connect):
        """Each call to get_client must connect fresh — no caching across event loops."""
        mock_connect.return_value = MagicMock()
        asyncio.run(TemporalClientProvider.get_client())
        asyncio.run(TemporalClientProvider.get_client())
        self.assertEqual(mock_connect.call_count, 2)

    def test_reset_method_no_longer_exists(self):
        """reset() existed only to defeat the cache. With caching gone it must not exist."""
        self.assertFalse(
            hasattr(TemporalClientProvider, "reset"),
            "TemporalClientProvider.reset() must be removed along with the cache",
        )

    @patch("reNgine.temporal_client.Client.connect", new_callable=AsyncMock)
    def test_cancel_workflow_uses_correct_env_vars(self, mock_connect):
        """cancel_workflow must connect to TEMPORAL_HOST / TEMPORAL_NAMESPACE env vars."""
        import os
        mock_handle = AsyncMock()
        mock_client = MagicMock()
        mock_client.get_workflow_handle.return_value = mock_handle
        mock_connect.return_value = mock_client

        with patch.dict(os.environ, {"TEMPORAL_HOST": "myhost:7233", "TEMPORAL_NAMESPACE": "mynamespace"}):
            TemporalClientProvider.cancel_workflow("wf-123")

        mock_connect.assert_called_once_with("myhost:7233", namespace="mynamespace")
        mock_client.get_workflow_handle.assert_called_once_with("wf-123")
        mock_handle.cancel.assert_awaited_once()

    @patch("reNgine.temporal_client.asyncio.wait_for", side_effect=asyncio.TimeoutError)
    @patch("reNgine.temporal_client.Client.connect", new_callable=AsyncMock)
    def test_get_client_timeout_raises_temporal_connection_error(self, mock_connect, mock_wait):
        """A timeout must raise TemporalConnectionError, not the built-in ConnectionError."""
        from reNgine.temporal_client import TemporalConnectionError
        with self.assertRaises(TemporalConnectionError):
            asyncio.run(TemporalClientProvider.get_client())

    @patch("reNgine.temporal_client.asyncio.wait_for", side_effect=asyncio.TimeoutError)
    @patch("reNgine.temporal_client.Client.connect", new_callable=AsyncMock)
    def test_get_client_timeout_not_builtin_connection_error(self, mock_connect, mock_wait):
        """TemporalConnectionError must NOT be a subclass of the built-in ConnectionError."""
        from reNgine.temporal_client import TemporalConnectionError
        with self.assertRaises(TemporalConnectionError) as cm:
            asyncio.run(TemporalClientProvider.get_client())
        self.assertNotIsInstance(cm.exception, ConnectionError)
