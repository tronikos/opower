"""Tests for Seattle City Light (SCL)."""

import os
import unittest

import aiohttp
import pytest
from dotenv import load_dotenv

from opower.const import USER_AGENT
from opower.exceptions import CannotConnect, InvalidAuth
from opower.utilities.helpers import get_form_action_url_and_hidden_inputs
from opower.utilities.scl import REQUEST_TIMEOUT, SCL, _get_session_storage_values, _get_user_token_from_url
from tests.mock_http import MockResponse, MockSession

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

    @pytest.mark.network
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

        # SCL returns the Opower token directly; unlike the cookie/SAML based
        # utilities it never contacts *.opower.com during login, so only the
        # returned token can be asserted here.
        self.assertIsNotNone(access_token)
        self.assertTrue(len(access_token) > 0)


def _read_fixture(filename: str) -> str:
    with open(os.path.join(os.path.dirname(__file__), "scl", filename)) as f:
        return f.read()


def _login_responses() -> dict[str, MockResponse]:
    return {
        "https://myutilities.seattle.gov/rest/auth/ssologin": MockResponse(text=_read_fixture("ssologin_response.html")),
        "https://login.seattle.gov/#/login?appName=EPORTAL_PROD": MockResponse(text=_read_fixture("login_page.html")),
        # Bot defense serves the JSON body as text/html.
        "https://login.seattle.gov/authenticate": MockResponse(
            payload={"authnToken": "test_authn_token"}, content_type="text/html"
        ),
        "https://idcs-3359adb31e35415e8c1729c5c8098c6d.identity.oraclecloud.com/sso/v1/sdk/session": MockResponse(
            text=_read_fixture("idcs_session_response.html")
        ),
        "https://idcs-3359adb31e35415e8c1729c5c8098c6d.identity.oraclecloud.com/fed/v1/user/response/login": MockResponse(
            text=_read_fixture("saml_response.html")
        ),
        "https://myutilities.seattle.gov/rest/auth/samlresp": MockResponse(
            real_url="https://myutilities.seattle.gov/eportal/#/ssohome/test_user_token"
        ),
        "https://myutilities.seattle.gov/rest/auth/token": MockResponse(
            payload={"access_token": "test_access_token", "user": {"customerId": "test_customer"}}
        ),
        "https://myutilities.seattle.gov/rest/account/list/some": MockResponse(
            payload={
                "account": [
                    {
                        "accountNumber": "1",
                        "personId": "2",
                        "companyCd": "SCL",
                        "serviceAddress": "addr",
                    }
                ]
            }
        ),
        "https://myutilities.seattle.gov/rest/usage/token": MockResponse(payload={"token": "opower_token"}),
    }


class TestSCLLoginFlow(unittest.IsolatedAsyncioTestCase):
    """Test the full SSO login flow with mocked HTTP responses."""

    async def test_login_sends_bot_defense_headers_and_parses_html_json(self) -> None:
        """Authenticate must send Origin/Referer and parse its text/html JSON body."""
        responses = _login_responses()
        session = MockSession(responses)

        token = await SCL().async_login(session, "user", "pass", {})  # type: ignore[arg-type]

        self.assertEqual(token, "opower_token")
        authenticate = next(r for r in session.requests if r["url"] == "https://login.seattle.gov/authenticate")
        headers = authenticate["headers"]
        self.assertEqual(headers["Origin"], "https://login.seattle.gov")
        self.assertEqual(headers["Referer"], "https://login.seattle.gov/")

    async def test_login_passes_timeout_to_every_request(self) -> None:
        """Test that every login request has a timeout."""
        session = MockSession(_login_responses())

        await SCL().async_login(session, "user", "pass", {})  # type: ignore[arg-type]

        self.assertEqual(len(session.requests), 9)
        for request in session.requests:
            self.assertEqual(request.get("timeout"), REQUEST_TIMEOUT, request["url"])

    async def test_unexpected_ssologin_page_raises_cannot_connect(self) -> None:
        """Test that an unexpected ssologin page raises CannotConnect."""
        responses = _login_responses()
        responses["https://myutilities.seattle.gov/rest/auth/ssologin"] = MockResponse(text="<html>challenge</html>")
        session = MockSession(responses)

        with self.assertRaises(CannotConnect):
            await SCL().async_login(session, "user", "pass", {})  # type: ignore[arg-type]

    async def test_login_page_without_session_storage_raises_cannot_connect(self) -> None:
        """Test that a login page without sessionStorage raises CannotConnect."""
        responses = _login_responses()
        responses["https://login.seattle.gov/#/login?appName=EPORTAL_PROD"] = MockResponse(text="<html>challenge</html>")
        session = MockSession(responses)

        with self.assertRaises(CannotConnect):
            await SCL().async_login(session, "user", "pass", {})  # type: ignore[arg-type]

    async def test_unexpected_idcs_session_page_raises_cannot_connect(self) -> None:
        """Test that an unexpected IDCS session page raises CannotConnect."""
        responses = _login_responses()
        responses["https://idcs-3359adb31e35415e8c1729c5c8098c6d.identity.oraclecloud.com/sso/v1/sdk/session"] = MockResponse(
            text="<html>challenge</html>"
        )
        session = MockSession(responses)

        with self.assertRaises(CannotConnect):
            await SCL().async_login(session, "user", "pass", {})  # type: ignore[arg-type]

    async def test_rejected_credentials_raise_invalid_auth(self) -> None:
        """Test that rejected credentials raise InvalidAuth."""
        responses = _login_responses()
        responses["https://login.seattle.gov/authenticate"] = MockResponse(status=400)
        session = MockSession(responses)

        with self.assertRaises(InvalidAuth):
            await SCL().async_login(session, "user", "pass", {})  # type: ignore[arg-type]

    async def test_authenticate_error_description_raises_invalid_auth(self) -> None:
        """Test that an authenticate error description raises InvalidAuth."""
        responses = _login_responses()
        responses["https://login.seattle.gov/authenticate"] = MockResponse(
            payload={"error_description": "Invalid username or password"}, content_type="text/html"
        )
        session = MockSession(responses)

        with self.assertRaises(InvalidAuth):
            await SCL().async_login(session, "user", "pass", {})  # type: ignore[arg-type]

    async def test_ssologin_get_sends_user_agent_and_raises_for_status(self) -> None:
        """Test that the ssologin GET sends the User-Agent and raises for status."""
        session = MockSession(_login_responses())

        await SCL().async_login(session, "user", "pass", {})  # type: ignore[arg-type]

        ssologin = session.requests[0]
        self.assertEqual(ssologin["url"], "https://myutilities.seattle.gov/rest/auth/ssologin")
        self.assertEqual(ssologin["headers"]["User-Agent"], USER_AGENT)
        self.assertTrue(ssologin["raise_for_status"])

    async def test_ssologin_form_missing_fields_raises_cannot_connect(self) -> None:
        """Test that a login form missing fields raises CannotConnect."""
        responses = _login_responses()
        responses["https://myutilities.seattle.gov/rest/auth/ssologin"] = MockResponse(
            text='<html><body><form action="https://login.seattle.gov/#/login?appName=EPORTAL_PROD">'
            '<input type="hidden" name="signature" value="sig"></form></body></html>'
        )
        session = MockSession(responses)

        with self.assertRaisesRegex(CannotConnect, "Unexpected SSO login form fields"):
            await SCL().async_login(session, "user", "pass", {})  # type: ignore[arg-type]

    async def test_unexpected_saml_url_after_ssologin_names_step(self) -> None:
        """Test that the SAML URL error after ssologin names the step."""
        responses = _login_responses()
        responses["https://myutilities.seattle.gov/rest/auth/ssologin"] = MockResponse(text="<html>challenge</html>")
        session = MockSession(responses)

        with self.assertRaisesRegex(CannotConnect, "after initial ssologin GET: no form"):
            await SCL().async_login(session, "user", "pass", {})  # type: ignore[arg-type]

    async def test_unexpected_saml_url_after_sso_login_is_sanitized(self) -> None:
        """Test that the SAML URL error after SSO login strips query and fragment."""
        responses = _login_responses()
        responses["https://idcs-3359adb31e35415e8c1729c5c8098c6d.identity.oraclecloud.com/fed/v1/user/response/login"] = (
            MockResponse(text='<html><form action="https://user:pw@login.seattle.gov/error?code=secret#frag"></form></html>')
        )
        session = MockSession(responses)

        with self.assertRaises(CannotConnect) as ctx:
            await SCL().async_login(session, "user", "pass", {})  # type: ignore[arg-type]

        self.assertEqual(str(ctx.exception), "Unexpected SAML response URL after SSO login: https://login.seattle.gov/error")

    async def test_authenticate_unexpected_status_raises_cannot_connect(self) -> None:
        """Test that an unexpected authenticate status raises CannotConnect."""
        for status in (401, 403, 429, 502, 503, 504):
            with self.subTest(status=status):
                responses = _login_responses()
                responses["https://login.seattle.gov/authenticate"] = MockResponse(
                    status=status, payload={"message": "busy"}, content_type="text/html"
                )
                session = MockSession(responses)

                with self.assertRaises(CannotConnect):
                    await SCL().async_login(session, "user", "pass", {})  # type: ignore[arg-type]

    async def test_authenticate_non_json_body_raises_cannot_connect(self) -> None:
        """Test that a non-JSON authenticate body raises CannotConnect."""
        responses = _login_responses()
        responses["https://login.seattle.gov/authenticate"] = MockResponse(
            raw_json="<html>challenge</html>", content_type="text/html"
        )
        session = MockSession(responses)

        with self.assertRaises(CannotConnect):
            await SCL().async_login(session, "user", "pass", {})  # type: ignore[arg-type]

    async def test_authenticate_non_object_json_raises_cannot_connect(self) -> None:
        """Test that non-object authenticate JSON raises CannotConnect."""
        responses = _login_responses()
        responses["https://login.seattle.gov/authenticate"] = MockResponse(payload=["unexpected"], content_type="text/html")
        session = MockSession(responses)

        with self.assertRaises(CannotConnect):
            await SCL().async_login(session, "user", "pass", {})  # type: ignore[arg-type]

    async def test_invalid_initial_state_raises_cannot_connect(self) -> None:
        """Test that an unparsable initialState raises CannotConnect."""
        responses = _login_responses()
        responses["https://login.seattle.gov/#/login?appName=EPORTAL_PROD"] = MockResponse(
            text="<script>sessionStorage.setItem(\"initialState\", '{not json');"
            "sessionStorage.setItem(\"signinAT\", 'token');</script>"
        )
        session = MockSession(responses)

        with self.assertRaises(CannotConnect):
            await SCL().async_login(session, "user", "pass", {})  # type: ignore[arg-type]

    async def test_post_sso_failures_raise_cannot_connect(self) -> None:
        """Test that failures after SSO login raise CannotConnect."""
        cases = {
            "Failed to extract user token": (
                "https://myutilities.seattle.gov/rest/auth/samlresp",
                MockResponse(real_url="https://myutilities.seattle.gov/eportal/#/error"),
            ),
            "Failed to retrieve access token": (
                "https://myutilities.seattle.gov/rest/auth/token",
                MockResponse(payload={"user": {"customerId": "test_customer"}}),
            ),
            "No accounts found": (
                "https://myutilities.seattle.gov/rest/account/list/some",
                MockResponse(payload={"account": []}),
            ),
            "Failed to retrieve Opower token": (
                "https://myutilities.seattle.gov/rest/usage/token",
                MockResponse(payload={}),
            ),
        }
        for message, (url, response) in cases.items():
            with self.subTest(message=message):
                responses = _login_responses()
                responses[url] = response
                session = MockSession(responses)

                with self.assertRaisesRegex(CannotConnect, message):
                    await SCL().async_login(session, "user", "pass", {})  # type: ignore[arg-type]


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
