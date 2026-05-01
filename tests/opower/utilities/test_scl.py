"""Tests for Seattle City Light (SCL)."""

import os
import unittest

import aiohttp
from dotenv import load_dotenv
from yarl import URL

from opower.utilities.helpers import get_form_action_url_and_hidden_inputs
from opower.utilities.scl import SCL, _get_session_storage_values, _get_user_token_from_url

SSOLOGIN_HTML_FILENAME = os.path.join(os.path.dirname(__file__), "scl/ssologin_response.html")
LOGIN_PAGE_HTML_FILENAME = os.path.join(os.path.dirname(__file__), "scl/login_page.html")
IDCS_SESSION_HTML_FILENAME = os.path.join(os.path.dirname(__file__), "scl/idcs_session_response.html")
SAML_RESPONSE_HTML_FILENAME = os.path.join(os.path.dirname(__file__), "scl/saml_response.html")
ENV_SECRET_PATH = os.path.join(os.path.dirname(__file__), "../../../.env.secret")


class TestSCL(unittest.IsolatedAsyncioTestCase):
    """Test public methods inherited from UtilityBase."""

    def test_name(self) -> None:
        """Test name."""
        scl = SCL()
        self.assertEqual("Seattle City Light (SCL)", scl.name())

    def test_subdomain(self) -> None:
        """Test subdomain."""
        scl = SCL()
        self.assertEqual("scl", scl.subdomain())

    def test_timezone(self) -> None:
        """Test timezone."""
        scl = SCL()
        self.assertEqual("America/Los_Angeles", scl.timezone())

    async def test_real_login(self) -> None:
        """Perform a live test against SCL and Opower websites."""
        load_dotenv(dotenv_path=ENV_SECRET_PATH)

        username = os.getenv("SCL_USERNAME")
        password = os.getenv("SCL_PASSWORD")

        if username is None or password is None:
            self.skipTest("Add `SCL_USERNAME=` and `SCL_PASSWORD=` to `.env.secret` to run live SCL test.")

        scl = SCL()
        session = aiohttp.ClientSession()
        self.addCleanup(session.close)

        access_token = await scl.async_login(session, username, password, {})

        self.assertIsNotNone(access_token)
        self.assertTrue(len(access_token) > 0)

        cookies = session.cookie_jar.filter_cookies(URL("https://scl.opower.com"))
        self.assertTrue(len(cookies) > 0, "Expected opower cookies to be set")


class TestSCLSessionStorageParser(unittest.TestCase):
    """Test parsing sessionStorage values from the login page."""

    def test_parse_session_storage(self) -> None:
        """Test extracting sessionStorage items from HTML."""
        with open(LOGIN_PAGE_HTML_FILENAME) as f:
            html = f.read()
        items = _get_session_storage_values(html)
        self.assertIn("initialState", items)
        self.assertIn("signinAT", items)
        self.assertEqual(items["signinAT"], "test_signin_at_token")

    def test_parse_session_storage_empty(self) -> None:
        """Test parsing HTML with no sessionStorage calls."""
        items = _get_session_storage_values("<html><body></body></html>")
        self.assertEqual(items, {})

    def test_parse_session_storage_multiple(self) -> None:
        """Test that all sessionStorage items are captured."""
        with open(LOGIN_PAGE_HTML_FILENAME) as f:
            html = f.read()
        items = _get_session_storage_values(html)
        self.assertEqual(len(items), 3)
        self.assertIn("otherItem", items)


class TestSCLUserTokenExtraction(unittest.TestCase):
    """Test extracting user token from redirect URL."""

    def test_valid_url(self) -> None:
        """Test extracting token from a valid redirect URL."""
        url = "https://myutilities.seattle.gov/eportal/#/ssohome/abc123xyz"
        token = _get_user_token_from_url(url)
        self.assertEqual(token, "abc123xyz")

    def test_invalid_url(self) -> None:
        """Test that an unrelated URL returns empty string."""
        token = _get_user_token_from_url("https://example.com/other")
        self.assertEqual(token, "")

    def test_empty_url(self) -> None:
        """Test that an empty string returns empty string."""
        token = _get_user_token_from_url("")
        self.assertEqual(token, "")

    def test_url_with_long_token(self) -> None:
        """Test extracting a long UUID-style token."""
        url = "https://myutilities.seattle.gov/eportal/#/ssohome/550e8400-e29b-41d4-a716-446655440000"
        token = _get_user_token_from_url(url)
        self.assertEqual(token, "550e8400-e29b-41d4-a716-446655440000")


class TestSCLFormParsing(unittest.TestCase):
    """Test parsing HTML forms from SSO flow responses."""

    def test_ssologin_form(self) -> None:
        """Test parsing the SSO login form."""
        with open(SSOLOGIN_HTML_FILENAME) as f:
            html = f.read()
        action_url, hidden_inputs = get_form_action_url_and_hidden_inputs(html)
        self.assertEqual(
            action_url,
            "https://login.seattle.gov/#/login?appName=EPORTAL_PROD",
        )
        self.assertEqual(set(hidden_inputs.keys()), {"signature", "state", "loginCtx"})
        self.assertEqual(hidden_inputs["signature"], "test_signature_value")

    def test_idcs_session_form(self) -> None:
        """Test parsing the Oracle IDCS session form."""
        with open(IDCS_SESSION_HTML_FILENAME) as f:
            html = f.read()
        action_url, hidden_inputs = get_form_action_url_and_hidden_inputs(html)
        self.assertEqual(
            action_url,
            "https://idcs-3359adb31e35415e8c1729c5c8098c6d.identity.oraclecloud.com/fed/v1/user/response/login",
        )
        self.assertEqual(set(hidden_inputs.keys()), {"OCIS_REQ"})

    def test_saml_response_form(self) -> None:
        """Test parsing the SAML response form."""
        with open(SAML_RESPONSE_HTML_FILENAME) as f:
            html = f.read()
        action_url, hidden_inputs = get_form_action_url_and_hidden_inputs(html)
        self.assertEqual(
            action_url,
            "https://myutilities.seattle.gov/rest/auth/samlresp",
        )
        self.assertEqual(set(hidden_inputs.keys()), {"RelayState", "SAMLResponse"})
