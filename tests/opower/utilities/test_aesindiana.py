"""Tests for AES Indiana."""

import os
import unittest
from typing import TYPE_CHECKING, Any, Self, cast

import aiohttp
from dotenv import load_dotenv
from yarl import URL

from opower.exceptions import InvalidAuth
from opower.utilities.aesindiana import AESIndiana

if TYPE_CHECKING:
    from collections.abc import Mapping

ENV_SECRET_PATH = os.path.join(os.path.dirname(__file__), "../../../.env.secret")


class _FakeResponse:
    """Minimal asynchronous response context manager for login tests."""

    def __init__(self, status: int, body: str = "", location: str | None = None) -> None:
        self.status = status
        self.body = body
        self.headers: Mapping[str, str] = {"Location": location} if location else {}

    async def __aenter__(self) -> Self:
        return self

    async def __aexit__(self, *args: object) -> None:
        return None

    async def text(self) -> str:
        """Return the configured response body."""
        return self.body


class _FakeSession:
    """Return configured responses while recording outgoing requests."""

    def __init__(self, responses: list[_FakeResponse]) -> None:
        self.responses = responses
        self.requests: list[tuple[str, str, dict[str, str] | None]] = []

    def request(
        self,
        method: str,
        url: URL,
        *,
        data: dict[str, str] | None,
        **kwargs: Any,
    ) -> _FakeResponse:
        """Record a request and return the next response."""
        self.requests.append((method, str(url), data))
        return self.responses.pop(0)


class TestAESIndiana(unittest.IsolatedAsyncioTestCase):
    """Test AES Indiana metadata and login flow behavior."""

    def test_metadata(self) -> None:
        """Return the expected utility metadata."""
        utility = AESIndiana()

        self.assertEqual("AES Indiana", utility.name())
        self.assertEqual("aesi", utility.subdomain())
        self.assertEqual("America/Indiana/Indianapolis", utility.timezone())

    async def test_307_redirect_preserves_post_and_form_data(self) -> None:
        """Preserve the request method and body across 307 redirects."""
        login_form = """
        <form action="/login">
          <input type="hidden" name="__VIEWSTATE" value="state">
          <input type="text" name="ctl00$phMainColumn$ctl00$iplLogin$UserName">
        </form>
        """
        session = _FakeSession(
            [
                _FakeResponse(200, login_form),
                _FakeResponse(307, location="/continue"),
                _FakeResponse(200, "unexpected page"),
            ]
        )

        with self.assertRaises(InvalidAuth):
            await AESIndiana.async_login(cast("aiohttp.ClientSession", session), "user", "password", {})

        login_request = session.requests[1]
        redirected_request = session.requests[2]
        self.assertEqual("POST", redirected_request[0])
        self.assertEqual(login_request[2], redirected_request[2])

    async def test_authentication_query_is_redacted_from_logs(self) -> None:
        """Do not expose OAuth credentials in debug logs."""
        authorization_code = "top-secret-authorization-code"
        session = _FakeSession(
            [
                _FakeResponse(302, location=f"https://aesi.opower.com/ei/x/dashboard?code={authorization_code}"),
                _FakeResponse(200),
            ]
        )

        with self.assertLogs("opower.utilities.aesindiana", level="DEBUG") as logs:
            token = await AESIndiana.async_login(cast("aiohttp.ClientSession", session), "user", "password", {})

        self.assertEqual("", token)
        self.assertNotIn(authorization_code, "\n".join(logs.output))

    async def test_unexpected_opower_page_is_not_success(self) -> None:
        """Reject an OPower error page that is not the dashboard."""
        session = _FakeSession(
            [
                _FakeResponse(302, location="https://aesi.opower.com/ei/app/api/authenticate?error=invalid_request"),
                _FakeResponse(200, "OAuth error"),
            ]
        )

        with self.assertRaises(InvalidAuth):
            await AESIndiana.async_login(cast("aiohttp.ClientSession", session), "user", "password", {})

    async def test_real_login(self) -> None:
        """Perform an optional live login against AES Indiana and OPower."""
        load_dotenv(dotenv_path=ENV_SECRET_PATH)

        username = os.getenv("AES_INDIANA_USERNAME")
        password = os.getenv("AES_INDIANA_PASSWORD")
        if username is None or password is None:
            self.skipTest(
                "Add `AES_INDIANA_USERNAME=` and `AES_INDIANA_PASSWORD=` to `.env.secret` to run the live AES Indiana test."
            )

        session = aiohttp.ClientSession()
        self.addCleanup(session.close)

        token = await AESIndiana.async_login(session, username, password, {})

        self.assertEqual("", token)
        cookies = session.cookie_jar.filter_cookies(URL("https://aesi.opower.com"))
        self.assertTrue(cookies, "Expected authenticated OPower cookies to be set")


if __name__ == "__main__":
    unittest.main()
