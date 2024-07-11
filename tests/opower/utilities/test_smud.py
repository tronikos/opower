"""Tests for SMUD."""

import os
import unittest

import aiohttp
from dotenv import load_dotenv
from yarl import URL

from opower.utilities.smud import (
    SMUD,
    SMUDLoginParser,
    SMUDOktaResponseSamlResponseValueParser,
)

REQUEST_VERIFICATION_TOKEN_HTML_FILENAME = os.path.join(
    os.path.dirname(__file__), "smud/myAccountResponse.html"
)
OKTA_SAML_RESPONSE_HTML_FILENAME = os.path.join(
    os.path.dirname(__file__), "smud/smudOkta.html"
)
ENV_SECRET_PATH = os.path.join(os.path.dirname(__file__), "../../../.env.secret")


class TestSMUD(unittest.IsolatedAsyncioTestCase):
    """Test public methods inherited from UtilityBase."""

    def test_name(self) -> None:
        """Test name."""
        smud = SMUD()

        self.assertEqual("Sacramento Municipal Utility District (SMUD)", smud.name())

    def test_subdomain(self) -> None:
        """Test subdomain."""
        smud = SMUD()

        self.assertEqual("smud", smud.subdomain())

    def test_timezone(self) -> None:
        """Test timezone."""
        smud = SMUD()

        self.assertEqual("America/Los_Angeles", smud.timezone())

    async def test_real_login(self) -> None:
        """Perform a live test against the SMUD, OKTA and Opower websites."""
        load_dotenv(dotenv_path=ENV_SECRET_PATH)

        username = os.getenv("SMUD_USERNAME")
        password = os.getenv("SMUD_PASSWORD")

        if username is None or password is None:
            self.skipTest(
                "Add `SMUD_USERNAME=` and `SMUD_PASSWORD=` to `.env.secret` to run live SMUD test."
            )

        smud = SMUD()
        session = aiohttp.ClientSession()
        self.addCleanup(session.close)

        await smud.async_login(session, username, password, None)

        # Confirm opower cookies have been set.
        self.assertTrue(
            len(session.cookie_jar.filter_cookies(URL("https://smud.opower.com/ei")))
            > 0
        )


class TestSMUDLoginParser(unittest.TestCase):
    """Test parsing the Request Verification Token from the SMUD login page."""

    def test_parse(self) -> None:
        """Test finding the input __RequestVerificationToken value."""
        loginParser = SMUDLoginParser()
        html = open(REQUEST_VERIFICATION_TOKEN_HTML_FILENAME).read()
        loginParser.feed(html)
        result = loginParser.verification_token
        assert result is not None
        self.assertEqual("O04jy", result[0:5])
        self.assertEqual("5fWQ1", result[-5:])


class TestSMUDOktaResponseSamlResponseValueParser(unittest.TestCase):
    """Test parsing the SamlResponse input value from the OKTA HTML."""

    def test_parse(self) -> None:
        """Test parsing the input SamlResponse value."""
        samlResponseParser = SMUDOktaResponseSamlResponseValueParser()
        html = open(OKTA_SAML_RESPONSE_HTML_FILENAME).read()
        samlResponseParser.feed(html)
        result = samlResponseParser.saml_response
        assert result is not None
        self.assertEqual("PD94b", result[0:5])
        self.assertEqual("uc2U+", result[-5:])
