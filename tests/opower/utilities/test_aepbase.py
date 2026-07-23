"""Tests for the shared AEP login flow, especially the ValidToken retry behavior."""

import unittest
from typing import Any
from unittest.mock import patch

from opower.exceptions import InvalidAuth
from opower.utilities.aepbase import _VALID_TOKEN_ATTEMPTS
from opower.utilities.aepohio import AEPOHio

USAGE_URL = "https://www.aepohio.com/account/usage/"
VALID_TOKEN_URL = "https://www.aepohio.com/account/oauth/ValidToken"  # noqa: S105
LOGIN_HTML = '<html><body>Redirecting to https://aepo.opower.com/</body></html>'


class _MockResponse:
    """Minimal stand-in for aiohttp.ClientResponse."""

    def __init__(self, *, text: str = "", payload: Any = None) -> None:
        self.status = 200
        self._text = text
        self._payload = payload

    async def text(self) -> str:
        return self._text

    async def json(self) -> Any:
        return self._payload

    async def __aenter__(self) -> "_MockResponse":
        return self

    async def __aexit__(self, *args: object) -> None:
        return None


class _MockSession:
    """Returns queued responses per URL; each GET/POST pops the next one."""

    def __init__(self, responses: dict[str, list[_MockResponse]]) -> None:
        self._responses = responses
        self.cookie_jar = _MockCookieJar()

    def get(self, url: str, **kwargs: Any) -> _MockResponse:
        return self._responses[url].pop(0)

    def post(self, url: str, **kwargs: Any) -> _MockResponse:
        return self._responses[url].pop(0)


class _MockCookieJar:
    def clear(self, predicate: Any) -> None:
        return None


class TestAEPBaseValidTokenRetry(unittest.IsolatedAsyncioTestCase):
    """Test the ValidToken retry loop added for the intermittent empty-token race."""

    async def test_retries_until_access_token_present_then_succeeds(self) -> None:
        """A transiently empty AccessToken must be retried, not fail the login."""
        responses = {
            USAGE_URL: [
                _MockResponse(text=LOGIN_HTML),
                _MockResponse(text=LOGIN_HTML),
            ],
            VALID_TOKEN_URL: [
                _MockResponse(payload=[{"data": {"AccessToken": ""}}]),
                _MockResponse(payload=[{"data": {"AccessToken": "real_token"}}]),
            ],
        }
        session = _MockSession(responses)

        with patch("opower.utilities.aepbase.asyncio.sleep") as mock_sleep:
            token = await AEPOHio().async_login(session, "user", "pass", {})  # type: ignore[arg-type]

        self.assertEqual(token, "real_token")
        mock_sleep.assert_called_once()

    async def test_raises_invalid_auth_after_exhausting_retries(self) -> None:
        """If AEP never mints a token within the retry budget, raise InvalidAuth."""
        responses = {
            USAGE_URL: [
                _MockResponse(text=LOGIN_HTML),
                _MockResponse(text=LOGIN_HTML),
            ],
            VALID_TOKEN_URL: [_MockResponse(payload=[{"data": {"AccessToken": ""}}]) for _ in range(_VALID_TOKEN_ATTEMPTS)],
        }
        session = _MockSession(responses)

        with patch("opower.utilities.aepbase.asyncio.sleep"), self.assertRaises(InvalidAuth):
            await AEPOHio().async_login(session, "user", "pass", {})  # type: ignore[arg-type]
