"""Tests for Lafayette Utilities System (LUS)."""

import unittest
from typing import Any

from opower import get_supported_utility_names, select_utility
from opower.exceptions import InvalidAuth
from opower.utilities.lus import LUS


class _FakeResponse:
    """Minimal stand-in for an aiohttp response."""

    def __init__(self, status: int, body: Any) -> None:
        self.status = status
        self._body = body

    async def json(self) -> Any:
        return self._body

    def raise_for_status(self) -> None:
        if self.status >= 400:
            raise AssertionError(f"unexpected raise_for_status for {self.status}")

    async def __aenter__(self) -> "_FakeResponse":
        return self

    async def __aexit__(self, *args: object) -> bool:
        return False


class _FakeCookieJar:
    def __init__(self) -> None:
        self.cookies: dict[str, str] = {}

    def clear(self, predicate: Any = None) -> None:
        self.cookies.clear()

    def update_cookies(self, cookies: dict[str, str]) -> None:
        self.cookies.update(cookies)


class _FakeSession:
    """Session that answers the login POST with a fixed status and body."""

    def __init__(self, status: int, body: Any) -> None:
        self._status = status
        self._body = body
        self.cookie_jar = _FakeCookieJar()
        self.posts: list[tuple[str, dict[str, Any]]] = []

    def post(self, url: str, **kwargs: Any) -> _FakeResponse:
        self.posts.append((url, kwargs))
        return _FakeResponse(self._status, self._body)


class TestLUS(unittest.IsolatedAsyncioTestCase):
    """Test Lafayette Utilities System (LUS)."""

    def test_name(self) -> None:
        """Test name."""
        self.assertEqual("Lafayette Utilities System (LUS)", LUS().name())

    def test_subdomain(self) -> None:
        """Test subdomain."""
        self.assertEqual("lus", LUS().subdomain())

    def test_timezone(self) -> None:
        """Test timezone."""
        self.assertEqual("America/Chicago", LUS().timezone())

    def test_is_dss(self) -> None:
        """LUS uses the DSS portal at dss-lus.opower.com."""
        self.assertTrue(LUS().is_dss())

    def test_selectable_by_name(self) -> None:
        """Test the utility is listed and can be selected."""
        self.assertIn("Lafayette Utilities System (LUS)", get_supported_utility_names())
        self.assertIs(select_utility("Lafayette Utilities System (LUS)"), LUS)

    async def test_login_returns_session_token(self) -> None:
        """The login API's sessionToken is the bearer token."""
        session = _FakeSession(200, {"sessionToken": "abc-123"})

        token = await LUS().async_login(session, "user", "pw", {})  # type: ignore[arg-type]

        self.assertEqual("abc-123", token)
        url, kwargs = session.posts[0]
        self.assertEqual(
            "https://dss-lus.opower.com/webcenter/edge/apis/identity-management-v1/cws/v1/lus/login",
            url,
        )
        self.assertEqual({"username": "user", "password": "pw", "rememberMe": "true"}, kwargs["data"])
        self.assertEqual({"dssPortalCW": "1"}, session.cookie_jar.cookies)

    async def test_rejected_credentials_raise_invalid_auth(self) -> None:
        """A 401 is a credential rejection."""
        session = _FakeSession(401, {"error": {"serviceErrorCode": "INVALID_CREDENTIALS"}})
        with self.assertRaises(InvalidAuth):
            await LUS().async_login(session, "user", "bad", {})  # type: ignore[arg-type]

    async def test_missing_token_raises_invalid_auth(self) -> None:
        """A 200 without a sessionToken is not a usable login."""
        session = _FakeSession(200, {})
        with self.assertRaises(InvalidAuth):
            await LUS().async_login(session, "user", "pw", {})  # type: ignore[arg-type]
