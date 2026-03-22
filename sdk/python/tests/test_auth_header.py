"""Tests for auth header in Agentity clients."""

import asyncio
import unittest
from unittest import mock

from agentity.client import AgentityClient, AsyncAgentityClient


class TestAuthHeaderSync(unittest.TestCase):
    """Test that AgentityClient sends correct Authorization header."""

    def test_sync_client_authorization_header(self):
        """Verify sync client passes 'Authorization: Bearer {api_key}' to httpx.Client constructor."""
        api_key = "test-admin-key-12345"
        base_url = "http://localhost:8080"

        with mock.patch("httpx.Client") as mock_client_class:
            AgentityClient(base_url=base_url, api_key=api_key)

            mock_client_class.assert_called_once()
            call_kwargs = mock_client_class.call_args[1]
            headers = call_kwargs.get("headers", {})

            self.assertIn("Authorization", headers, "Authorization header not found")
            self.assertEqual(headers["Authorization"], f"Bearer {api_key}")

    def test_sync_client_no_x_admin_api_key_header(self):
        """Verify sync client does NOT send deprecated X-Admin-API-Key header."""
        api_key = "test-admin-key-12345"
        base_url = "http://localhost:8080"

        with mock.patch("httpx.Client") as mock_client_class:
            AgentityClient(base_url=base_url, api_key=api_key)

            mock_client_class.assert_called_once()
            call_kwargs = mock_client_class.call_args[1]
            headers = call_kwargs.get("headers", {})

            self.assertNotIn(
                "X-Admin-API-Key",
                headers,
                "Deprecated X-Admin-API-Key header must not be present",
            )


class TestAuthHeaderAsync(unittest.TestCase):
    """Test that AsyncAgentityClient sends correct Authorization header."""

    def test_async_client_authorization_header(self):
        """Verify async client passes 'Authorization: Bearer {api_key}' to httpx.AsyncClient."""
        api_key = "test-async-key-67890"
        base_url = "http://localhost:8080"

        async def run():
            with mock.patch("httpx.AsyncClient") as mock_async_class:
                mock_instance = mock.AsyncMock()
                mock_async_class.return_value = mock_instance

                client = AsyncAgentityClient(base_url=base_url, api_key=api_key)
                await client._get_client()  # triggers lazy init

                mock_async_class.assert_called_once()
                call_kwargs = mock_async_class.call_args[1]
                headers = call_kwargs.get("headers", {})

                assert "Authorization" in headers, "Authorization header not found"
                assert headers["Authorization"] == f"Bearer {api_key}"

        asyncio.run(run())

    def test_async_client_no_x_admin_api_key_header(self):
        """Verify async client does NOT send deprecated X-Admin-API-Key header."""
        api_key = "test-async-key-67890"
        base_url = "http://localhost:8080"

        async def run():
            with mock.patch("httpx.AsyncClient") as mock_async_class:
                mock_instance = mock.AsyncMock()
                mock_async_class.return_value = mock_instance

                client = AsyncAgentityClient(base_url=base_url, api_key=api_key)
                await client._get_client()

                mock_async_class.assert_called_once()
                call_kwargs = mock_async_class.call_args[1]
                headers = call_kwargs.get("headers", {})

                assert "X-Admin-API-Key" not in headers, \
                    "Deprecated X-Admin-API-Key header must not be present"

        asyncio.run(run())


if __name__ == "__main__":
    unittest.main()
