"""Tests for Evergy."""

import json
import unittest
from typing import Any
from unittest.mock import AsyncMock, patch

from opower.exceptions import CannotConnect
from opower.utilities.evergy import Evergy, EvergyLoginHandler

CUSTOM_HTML_TEMPLATE = "customHTMLTemplate"
SET_COOKIE = "setCookieWithoutUser"

# Trimmed from the screen Evergy shows after the password when MFA is not set up.
MFA_PROMPT = {
    "id": "id-2",
    "connectionId": "connection-2",
    "capabilityName": "customHTMLTemplate",
    "screen": {
        "name": "HTTP",
        "properties": {
            "formFieldsList": {
                "value": [
                    {"propertyName": "buttonValue"},
                    {"propertyName": "secure-account-option", "value": ""},
                ]
            },
            "customHTML": {
                "value": '<input type="radio" id="secure" name="secure-account-option" value="Yes" required checked>'
                '<input type="radio" id="dont-secure" name="secure-account-option" value="No">'
            },
        },
    },
}


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

    def __init__(self, template_payload: dict[str, Any] | list[dict[str, Any]]) -> None:
        payloads = template_payload if isinstance(template_payload, list) else [template_payload]
        self._template_payloads = list(payloads)
        self.capabilities: list[str] = []
        self.bodies: list[dict[str, Any]] = []

    def post(self, url: str, **kwargs: Any) -> _MockResponse:
        capability = url.rsplit("/", 1)[1]
        self.capabilities.append(capability)
        self.bodies.append(json.loads(kwargs.get("data") or "{}"))
        if capability == CUSTOM_HTML_TEMPLATE:
            payload = self._template_payloads[0]
            if len(self._template_payloads) > 1:
                self._template_payloads.pop(0)
            return _MockResponse(payload)
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

    async def _login(self, template_payload: dict[str, Any] | list[dict[str, Any]]) -> tuple[EvergyLoginHandler, _MockSession]:
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

    async def test_mfa_enrollment_prompt_is_declined(self) -> None:
        """The "set up MFA?" screen is answered No, and its reply carries the token."""
        handler, session = await self._login(
            [MFA_PROMPT, {"id": "id-3", "connectionId": "connection-3", "access_token": "token-after-no"}]
        )
        self.assertEqual(handler.access_token, "token-after-no")
        self.assertEqual(session.capabilities, [CUSTOM_HTML_TEMPLATE, CUSTOM_HTML_TEMPLATE])
        self.assertEqual(session.bodies[1]["parameters"]["secure-account-option"], "No")
        self.assertEqual(session.bodies[1]["id"], "id-2")

    async def test_mfa_enrollment_prompt_then_older_flow(self) -> None:
        """If declining returns no token, the setCookieWithoutUser steps still run."""
        handler, session = await self._login([MFA_PROMPT, {"id": "id-3", "connectionId": "connection-3"}])
        self.assertEqual(handler.access_token, "token-from-set-cookie")
        self.assertEqual(session.capabilities, [CUSTOM_HTML_TEMPLATE, CUSTOM_HTML_TEMPLATE, SET_COOKIE, SET_COOKIE])

    async def test_mfa_enrollment_prompt_repeated_raises(self) -> None:
        """A prompt that comes back after "No" fails clearly instead of looping."""
        with self.assertRaises(CannotConnect):
            await self._login([MFA_PROMPT, MFA_PROMPT])
