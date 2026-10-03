"""Tests for Evergy."""

import unittest
from typing import Any
from unittest.mock import AsyncMock, patch

from opower.utilities.evergy import Evergy, EvergyLoginHandler

CUSTOM_HTML_TEMPLATE = "customHTMLTemplate"
SET_COOKIE = "setCookieWithoutUser"


class _MockResponse:
    """Minimal stand-in for aiohttp.ClientResponse."""

    def __init__(self, payload: dict[str, Any]) -> None:
        self._payload = payload

    async def json(self, **kwargs: Any) -> dict[str, Any]:
        return self._payload

    async def __aenter__(self) -> "_MockResponse":
        return self

    async def __aexit__(self, *args: object) -> None:
        return None


class _MockSession:
    """Answers the davinci capability endpoints and records which were called."""

    def __init__(self, template_payload: dict[str, Any]) -> None:
        self._template_payload = template_payload
        self.capabilities: list[str] = []

    def post(self, url: str, **kwargs: Any) -> _MockResponse:
        capability = url.rsplit("/", 1)[1]
        self.capabilities.append(capability)
        if capability == CUSTOM_HTML_TEMPLATE:
            return _MockResponse(self._template_payload)
        return _MockResponse({"id": "id-2", "access_token": "token-from-set-cookie"})


class TestEvergy(unittest.TestCase):
    """Test public methods inherited from UtilityBase."""

    def test_name(self) -> None:
        """Test name."""
        self.assertEqual("Evergy", Evergy().name())

    def test_timezone(self) -> None:
        """Test timezone."""
        self.assertEqual("America/Chicago", Evergy().timezone())


class TestEvergyLoginHandler(unittest.IsolatedAsyncioTestCase):
    """Test the end of the davinci login flow, after the login form is submitted."""

    async def _login(self, template_payload: dict[str, Any]) -> tuple[EvergyLoginHandler, _MockSession]:
        session = _MockSession(template_payload)
        handler = EvergyLoginHandler(session)  # type: ignore[arg-type]
        handler.auth_data = {"api_root": "https://auth.example.com", "company_id": "company"}
        handler.connectionId = "connection-1"
        handler.id = "id-1"
        handler.access_token = "sdk-token"  # noqa: S105
        with (
            patch.object(handler, "get_auth_data", AsyncMock()),
            patch.object(handler, "get_sdktoken", AsyncMock()),
            patch.object(handler, "start_flow", AsyncMock()),
            patch.object(handler, "get_login_form", AsyncMock()),
            patch.object(handler, "submit_login_form", AsyncMock()),
            patch.object(handler, "postprocessing_api", AsyncMock()) as postprocessing_api,
        ):
            await handler.login("user", "pw")
        postprocessing_api.assert_awaited_once()
        return handler, session

    async def test_token_from_custom_html_template_skips_set_cookie(self) -> None:
        """Since Sept 2026 customHTMLTemplate can return the token directly."""
        handler, session = await self._login(
            {"id": "id-2", "connectionId": "connection-2", "access_token": "token-from-template"}
        )
        self.assertEqual(handler.access_token, "token-from-template")
        self.assertEqual(session.capabilities, [CUSTOM_HTML_TEMPLATE])

    async def test_no_token_from_custom_html_template_runs_set_cookie_twice(self) -> None:
        """Without a token the older flow calls setCookieWithoutUser twice."""
        handler, session = await self._login({"id": "id-2", "connectionId": "connection-2"})
        self.assertEqual(handler.access_token, "token-from-set-cookie")
        self.assertEqual(session.capabilities, [CUSTOM_HTML_TEMPLATE, SET_COOKIE, SET_COOKIE])

    async def test_empty_token_from_custom_html_template_runs_set_cookie_twice(self) -> None:
        """An empty token is not treated as the shorter flow."""
        handler, session = await self._login({"id": "id-2", "connectionId": "connection-2", "access_token": ""})
        self.assertEqual(handler.access_token, "token-from-set-cookie")
        self.assertEqual(session.capabilities, [CUSTOM_HTML_TEMPLATE, SET_COOKIE, SET_COOKIE])
