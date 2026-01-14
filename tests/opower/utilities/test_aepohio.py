"""Tests for AEP Ohio."""

import os
import unittest

import aiohttp
from dotenv import load_dotenv
from yarl import URL

from opower.utilities.aepohio import AEPOHio

ENV_SECRET_PATH = os.path.join(os.path.dirname(__file__), "../../../.env.secret")


class TestAEPOhio(unittest.IsolatedAsyncioTestCase):
    """Test public methods inherited from UtilityBase."""

    def test_name(self) -> None:
        """Test name."""
        aep = AEPOHio()

        self.assertEqual("AEP Ohio", aep.name())

    def test_hostname(self) -> None:
        """Test hostname."""
        aep = AEPOHio()

        self.assertEqual("aepohio.com", aep.hostname())

    def test_timezone(self) -> None:
        """Test timezone."""
        aep = AEPOHio()

        self.assertEqual("America/New_York", aep.timezone())

    async def test_real_login(self) -> None:
        """Perform a live test against the AEP Ohio and Opower websites."""
        load_dotenv(dotenv_path=ENV_SECRET_PATH)

        username = os.getenv("AEP_OHIO_USERNAME")
        password = os.getenv("AEP_OHIO_PASSWORD")

        if username is None or password is None:
            self.skipTest("Add `AEP_OHIO_USERNAME=` and `AEP_OHIO_PASSWORD=` to `.env.secret` to run live AEP Ohio test.")

        aep = AEPOHio()
        session = aiohttp.ClientSession()
        self.addCleanup(session.close)

        # This should not raise an exception with valid credentials
        access_token = await aep.async_login(session, username, password, {})

        # Verify we got a non-empty access token
        self.assertIsNotNone(access_token)
        self.assertTrue(len(access_token) > 0)
        print(f"Successfully obtained access token: {access_token[:20]}...")

        # Verify subdomain was set
        subdomain = aep.subdomain()
        self.assertIsNotNone(subdomain)
        self.assertTrue(len(subdomain) > 0)
        print(f"Subdomain: {subdomain}")

        # Confirm opower cookies have been set
        opower_url = f"https://{subdomain}.opower.com"
        cookies = session.cookie_jar.filter_cookies(URL(opower_url))
        self.assertTrue(len(cookies) > 0, "Expected opower cookies to be set")
        print(f"Opower cookies set: {len(cookies)} cookies found")
