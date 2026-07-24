"""Tests for Clark Public Utilities."""

import os
import unittest

import aiohttp
from dotenv import load_dotenv

from opower.utilities.clarkpublicutilities import ClarkPublicUtilities

ENV_SECRET_PATH = os.path.join(os.path.dirname(__file__), "../../../.env.secret")


class TestClarkPublicUtilities(unittest.IsolatedAsyncioTestCase):
    """Test public methods inherited from UtilityBase."""

    def test_name(self) -> None:
        """Test name."""
        clark = ClarkPublicUtilities()

        self.assertEqual("Clark Public Utilities", clark.name())

    def test_subdomain(self) -> None:
        """Test subdomain."""
        clark = ClarkPublicUtilities()

        self.assertEqual("clrk", clark.subdomain())

    def test_timezone(self) -> None:
        """Test timezone."""
        clark = ClarkPublicUtilities()

        self.assertEqual("America/Los_Angeles", clark.timezone())

    async def test_real_login(self) -> None:
        """Perform a live test against the Clark Public Utilities Opower website."""
        load_dotenv(dotenv_path=ENV_SECRET_PATH)

        username = os.getenv("CLARK_PUBLIC_UTILITIES_USERNAME")
        password = os.getenv("CLARK_PUBLIC_UTILITIES_PASSWORD")

        if username is None or password is None:
            self.skipTest(
                "Add `CLARK_PUBLIC_UTILITIES_USERNAME=` and `CLARK_PUBLIC_UTILITIES_PASSWORD=` "
                "to `.env.secret` to run live Clark Public Utilities test."
            )

        clark = ClarkPublicUtilities()
        session = aiohttp.ClientSession()
        self.addCleanup(session.close)

        # Clark authorizes via a session cookie set by the signin endpoint and
        # returns no bearer token, so async_login returns None on success. This
        # should simply not raise an exception with valid credentials.
        await clark.async_login(session, username, password, {})
