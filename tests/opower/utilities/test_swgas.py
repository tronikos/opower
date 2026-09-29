"""Tests for Southwest Gas."""

import unittest
from typing import Any

from opower.exceptions import InvalidAuth
from opower.utilities.swgas import SouthwestGas


class _FakeResponse:
    """Minimal stand-in for an aiohttp response."""

    def __init__(self, status: int) -> None:
        self.status = status

    async def text(self) -> str:
        return ""

    async def json(self) -> Any:
        return {}

    def raise_for_status(self) -> None:
        if self.status >= 400:
            raise AssertionError(f"unexpected raise_for_status for {self.status}")

    async def __aenter__(self) -> "_FakeResponse":
        return self

    async def __aexit__(self, *args: object) -> bool:
        return False


class _FakeSession:
    """Session that answers the sign-in POST with a fixed status."""

    def __init__(self, status: int) -> None:
        self._status = status

    def get(self, *args: Any, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse(200)

    def post(self, *args: Any, **kwargs: Any) -> _FakeResponse:
        return _FakeResponse(self._status)


class TestSouthwestGas(unittest.IsolatedAsyncioTestCase):
    """Test the Southwest Gas login."""

    def test_name(self) -> None:
        """Test name."""
        self.assertEqual("Southwest Gas", SouthwestGas().name())

    def test_subdomain(self) -> None:
        """Test subdomain."""
        self.assertEqual("swg", SouthwestGas().subdomain())

    def test_timezone(self) -> None:
        """Test timezone."""
        self.assertEqual("America/Phoenix", SouthwestGas().timezone())

    async def test_cookie_auth_returns_no_token(self) -> None:
        """A 204 means the session cookie carries the auth, so there is no token.

        Returning a placeholder string instead would be sent as
        "Authorization: Bearer <placeholder>" on every subsequent API call.
        """
        token = await SouthwestGas().async_login(_FakeSession(204), "user", "pw", {})  # type: ignore[arg-type]

        self.assertIsNone(token)

    async def test_rejected_credentials_raise_invalid_auth(self) -> None:
        """A 401 is a genuine credential rejection."""
        with self.assertRaises(InvalidAuth):
            await SouthwestGas().async_login(_FakeSession(401), "user", "pw", {})  # type: ignore[arg-type]
