"""Tests for Washington Gas."""

import os
import unittest
from typing import Any

import aiohttp
import pytest
from dotenv import load_dotenv

from opower.exceptions import CannotConnect, InvalidAuth
from opower.utilities.washingtongas import WashingtonGas

ENV_SECRET_PATH = os.path.join(os.path.dirname(__file__), "../../../.env.secret")


class _Response:
    def __init__(self, status: int) -> None:
        self.status = status

    async def __aenter__(self) -> "_Response":
        return self

    async def __aexit__(self, *args: Any) -> None:
        pass

    def raise_for_status(self) -> None:
        if self.status >= 400:
            request_info: Any = None
            raise aiohttp.ClientResponseError(request_info, (), status=self.status)


class _Session:
    def __init__(self, status: int) -> None:
        self.status = status
        self.kwargs: dict[str, Any] = {}

    def post(self, _url: str, **kwargs: Any) -> _Response:
        self.kwargs = kwargs
        return _Response(self.status)


class TestWashingtonGas(unittest.IsolatedAsyncioTestCase):
    """Test public methods inherited from UtilityBase."""

    def test_metadata(self) -> None:
        """Test name, subdomain and timezone."""
        wgl = WashingtonGas()
        self.assertEqual("Washington Gas", wgl.name())
        self.assertEqual("wgl", wgl.subdomain())
        self.assertEqual("America/New_York", wgl.timezone())

    async def test_login_status(self) -> None:
        """Test how sign-in statuses are handled."""
        session: Any = _Session(204)
        wgl: Any = WashingtonGas()
        self.assertIsNone(await wgl.async_login(session, "a", "b", {}))
        self.assertFalse(session.kwargs["allow_redirects"])
        self.assertFalse(session.kwargs["raise_for_status"])
        for status in (401, 403):
            session = _Session(status)
            with self.assertRaises(InvalidAuth):
                await WashingtonGas().async_login(session, "a", "b", {})
        for status in (400, 429, 500, 503):
            session = _Session(status)
            with self.assertRaises(aiohttp.ClientResponseError) as ctx:
                await WashingtonGas().async_login(session, "a", "b", {})
            self.assertEqual(status, ctx.exception.status)
        session = _Session(307)
        with self.assertRaises(CannotConnect):
            await WashingtonGas().async_login(session, "a", "b", {})

    @pytest.mark.network
    async def test_real_login(self) -> None:
        """Perform a live test against the Washington Gas Opower website."""
        load_dotenv(dotenv_path=ENV_SECRET_PATH)
        username = os.getenv("WASHINGTON_GAS_USERNAME")
        password = os.getenv("WASHINGTON_GAS_PASSWORD")
        if username is None or password is None:
            self.skipTest("Add `WASHINGTON_GAS_USERNAME=` and `WASHINGTON_GAS_PASSWORD=` to `.env.secret` to run.")
        async with aiohttp.ClientSession() as session:
            await WashingtonGas().async_login(session, username, password, {})
