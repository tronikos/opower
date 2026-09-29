"""Tests for AES Indiana."""

import unittest
from typing import Any

import aiohttp
from yarl import URL

from opower.exceptions import CannotConnect, InvalidAuth
from opower.utilities.aesindiana import AESIndiana, _complete_sso, _is_allowed_sso_host

DASHBOARD_URL = "https://aesi.opower.com/ei/x/dashboard"
CUSTOMERS_URL = "https://aesi.opower.com/ei/edge/apis/multi-account-v1/cws/aesi/customers"
LOGIN_URL = "https://myaccount.aesindiana.com/SAML/ssoservice.aspx?SAMLRequest=abc"
# Where the login form's relative action ("./?ReturnURL=...") resolves to.
LOGIN_POST_URL = "https://myaccount.aesindiana.com/SAML/?ReturnURL=%2fSAML%2fssoservice.aspx"
IDCS_SSO_URL = "https://idcs-abc.identity.oraclecloud.com/fed/v1/sp/sso"

LOGIN_PAGE_HTML = """
<form method="post" action="./?ReturnURL=%2fSAML%2fssoservice.aspx" id="Form1">
  <input type="hidden" name="__VIEWSTATE" value="viewstate123" />
  <input type="text" name="ctl00$phMainColumn$ctl00$iplLogin$UserName" />
  <input type="password" name="ctl00$phMainColumn$ctl00$iplLogin$Password" />
  <input type="submit" name="ctl00$phMainColumn$ctl00$iplLogin$LoginButton" value="Log In" />
</form>
"""

SAML_AUTOSUBMIT_HTML = f"""
<html><body onload="document.forms[0].submit()">
<form method="post" action="{IDCS_SSO_URL}">
  <input type="hidden" name="SAMLResponse" value="c2FtbA==" />
  <input type="hidden" name="RelayState" value="xyz" />
</form>
</body></html>
"""

SAML_TO_UNEXPECTED_HOST_HTML = """
<form method="post" action="https://evil.example.com/sso">
  <input type="hidden" name="SAMLResponse" value="c2FtbA==" />
</form>
"""

EVIL_ACTION_LOGIN_HTML = """
<form method="post" action="https://evil.example.com/login">
  <input type="text" name="ctl00$iplLogin$UserName" />
  <input type="password" name="ctl00$iplLogin$Password" />
</form>
"""

RENAMED_FIELDS_LOGIN_HTML = """
<form method="post" action="">
  <input type="text" name="ctl00$login$Account" />
  <input type="password" name="ctl00$login$Secret" />
</form>
"""


class FakeResponse:
    """A canned aiohttp-like response usable as an async context manager."""

    def __init__(self, url: str, status: int = 200, body: str = "", location: str | None = None) -> None:
        """Initialize."""
        self.real_url = URL(url)
        self.status = status
        self._body = body
        self.headers = {"Location": location} if location else {}
        self.raise_on_enter = False

    async def text(self) -> str:
        """Return the canned body."""
        return self._body

    def raise_for_status(self) -> None:
        """Raise like aiohttp for error statuses."""
        if self.status >= 400:
            raise aiohttp.ClientResponseError(request_info=None, history=(), status=self.status)  # type: ignore[arg-type]

    async def __aenter__(self) -> "FakeResponse":
        """Enter, raising for status if requested at the session level."""
        if self.raise_on_enter:
            self.raise_for_status()
        return self

    async def __aexit__(self, *args: object) -> None:
        """Exit."""


class FakeCookieJar:
    """Cookie jar stub that records clears."""

    def __init__(self) -> None:
        """Initialize."""
        self.cleared = False

    def clear(self, predicate: Any = None) -> None:
        """Record that cookies were cleared."""
        self.cleared = True


class FakeSession:
    """aiohttp.ClientSession stub serving scripted responses per (method, url)."""

    def __init__(self, responses: dict[tuple[str, str], list[FakeResponse]]) -> None:
        """Initialize."""
        self._responses = responses
        self.requests: list[tuple[str, str, dict[str, str] | None]] = []
        self.cookie_jar = FakeCookieJar()

    def request(self, method: str, url: Any, data: Any = None, raise_for_status: bool = False, **kwargs: Any) -> FakeResponse:
        """Serve the next scripted response for this method and URL."""
        self.requests.append((method, str(url), data))
        responses = self._responses.get((method, str(url)))
        assert responses, f"Unexpected request: {method} {url}"
        response = responses.pop(0)
        response.raise_on_enter = raise_for_status
        return response

    def get(self, url: Any, **kwargs: Any) -> FakeResponse:
        """Serve a GET request."""
        return self.request("GET", url, **kwargs)


class TestAESIndiana(unittest.TestCase):
    """Test public methods inherited from UtilityBase."""

    def test_name(self) -> None:
        """Test name."""
        self.assertEqual("AES Indiana", AESIndiana.name())

    def test_subdomain(self) -> None:
        """Test subdomain."""
        self.assertEqual("aesi", AESIndiana().subdomain())

    def test_timezone(self) -> None:
        """Test timezone."""
        self.assertEqual("America/Indiana/Indianapolis", AESIndiana.timezone())


class TestAllowedSSOHosts(unittest.TestCase):
    """Test the allow-list guarding where SAML assertions may be posted."""

    def test_allowed_hosts(self) -> None:
        """The three legitimate hosts of the SSO chain are allowed."""
        self.assertTrue(_is_allowed_sso_host(URL("https://myaccount.aesindiana.com/SAML/ssoservice.aspx")))
        self.assertTrue(_is_allowed_sso_host(URL(IDCS_SSO_URL)))
        self.assertTrue(_is_allowed_sso_host(URL(DASHBOARD_URL)))

    def test_disallowed_hosts(self) -> None:
        """Lookalike and unrelated hosts are rejected."""
        self.assertFalse(_is_allowed_sso_host(URL("https://evil.example.com/sso")))
        self.assertFalse(_is_allowed_sso_host(URL("https://identity.oraclecloud.com/sso")))
        self.assertFalse(_is_allowed_sso_host(URL("https://aesi.opower.com.evil.com/sso")))
        self.assertFalse(_is_allowed_sso_host(URL("https://notmyaccount.aesindiana.com/sso")))

    def test_non_https_disallowed(self) -> None:
        """Plain-http targets are rejected even on otherwise allowed hosts."""
        self.assertFalse(_is_allowed_sso_host(URL("http://myaccount.aesindiana.com/SAML/ssoservice.aspx")))
        self.assertFalse(_is_allowed_sso_host(URL("http://idcs-abc.identity.oraclecloud.com/fed/v1/sp/sso")))


class TestLoginFlow(unittest.IsolatedAsyncioTestCase):
    """Test async_login and _complete_sso against a fake session with canned pages."""

    async def test_full_login(self) -> None:
        """A fresh login walks the whole chain: login form, SAML post, back to opower."""
        session = FakeSession(
            {
                ("GET", DASHBOARD_URL): [
                    FakeResponse(DASHBOARD_URL, 302, location=LOGIN_URL),
                    # Requested again by the redirect after the SAML post.
                    FakeResponse(DASHBOARD_URL, body="<html>usage</html>"),
                ],
                ("GET", LOGIN_URL): [FakeResponse(LOGIN_URL, body=LOGIN_PAGE_HTML)],
                ("POST", LOGIN_POST_URL): [FakeResponse(LOGIN_URL, body=SAML_AUTOSUBMIT_HTML)],
                ("POST", IDCS_SSO_URL): [FakeResponse(IDCS_SSO_URL, 302, location=DASHBOARD_URL)],
            }
        )

        await AESIndiana().async_login(session, "user@example.com", "hunter2", {})  # type: ignore[arg-type]

        login_post = next(data for method, url, data in session.requests if method == "POST" and url == LOGIN_POST_URL)
        assert login_post is not None
        self.assertEqual("user@example.com", login_post["ctl00$phMainColumn$ctl00$iplLogin$UserName"])
        self.assertEqual("hunter2", login_post["ctl00$phMainColumn$ctl00$iplLogin$Password"])
        self.assertEqual("viewstate123", login_post["__VIEWSTATE"])
        saml_post = next(data for method, url, data in session.requests if method == "POST" and url == IDCS_SSO_URL)
        assert saml_post is not None
        self.assertEqual("c2FtbA==", saml_post["SAMLResponse"])

    async def test_valid_existing_session_skips_sso(self) -> None:
        """A still-valid opower session is verified with an API call and reused."""
        session = FakeSession(
            {
                ("GET", DASHBOARD_URL): [FakeResponse(DASHBOARD_URL, body="<html>usage</html>")],
                ("GET", CUSTOMERS_URL): [FakeResponse(CUSTOMERS_URL, body="{}")],
            }
        )
        await AESIndiana().async_login(session, "user@example.com", "hunter2", {})  # type: ignore[arg-type]
        self.assertEqual(2, len(session.requests))
        self.assertFalse(session.cookie_jar.cleared)

    async def test_stale_session_clears_cookies_and_relogs(self) -> None:
        """A stale opower session fails the API check, clears cookies, and logs in again."""
        session = FakeSession(
            {
                ("GET", DASHBOARD_URL): [
                    FakeResponse(DASHBOARD_URL, body="<html>stale</html>"),
                    FakeResponse(DASHBOARD_URL, 302, location=LOGIN_URL),
                    FakeResponse(DASHBOARD_URL, body="<html>usage</html>"),
                ],
                ("GET", CUSTOMERS_URL): [FakeResponse(CUSTOMERS_URL, 401)],
                ("GET", LOGIN_URL): [FakeResponse(LOGIN_URL, body=LOGIN_PAGE_HTML)],
                ("POST", LOGIN_POST_URL): [FakeResponse(LOGIN_URL, body=SAML_AUTOSUBMIT_HTML)],
                ("POST", IDCS_SSO_URL): [FakeResponse(IDCS_SSO_URL, 302, location=DASHBOARD_URL)],
            }
        )
        await AESIndiana().async_login(session, "user@example.com", "hunter2", {})  # type: ignore[arg-type]
        self.assertTrue(session.cookie_jar.cleared)

    async def test_invalid_credentials(self) -> None:
        """Re-serving the login page after the credential post raises InvalidAuth."""
        session = FakeSession(
            {
                ("GET", DASHBOARD_URL): [FakeResponse(DASHBOARD_URL, 302, location=LOGIN_URL)],
                ("GET", LOGIN_URL): [FakeResponse(LOGIN_URL, body=LOGIN_PAGE_HTML)],
                ("POST", LOGIN_POST_URL): [FakeResponse(LOGIN_URL, body=LOGIN_PAGE_HTML)],
            }
        )
        with self.assertRaises(InvalidAuth):
            await AESIndiana().async_login(session, "user@example.com", "wrong", {})  # type: ignore[arg-type]

    async def test_renamed_credential_fields(self) -> None:
        """Unrecognized credential field names fail fast instead of posting empty values."""
        session = FakeSession(
            {
                ("GET", DASHBOARD_URL): [FakeResponse(DASHBOARD_URL, 302, location=LOGIN_URL)],
                ("GET", LOGIN_URL): [FakeResponse(LOGIN_URL, body=RENAMED_FIELDS_LOGIN_HTML)],
            }
        )
        with self.assertRaises(CannotConnect):
            await AESIndiana().async_login(session, "user@example.com", "hunter2", {})  # type: ignore[arg-type]

    async def test_login_form_to_unexpected_host(self) -> None:
        """A login form targeting a host outside the allow-list never receives credentials."""
        session = FakeSession(
            {
                ("GET", DASHBOARD_URL): [FakeResponse(DASHBOARD_URL, 302, location=LOGIN_URL)],
                ("GET", LOGIN_URL): [FakeResponse(LOGIN_URL, body=EVIL_ACTION_LOGIN_HTML)],
            }
        )
        with self.assertRaises(CannotConnect):
            await AESIndiana().async_login(session, "user@example.com", "hunter2", {})  # type: ignore[arg-type]
        self.assertFalse(any(method == "POST" for method, _, _ in session.requests))

    async def test_login_post_not_forwarded_offhost(self) -> None:
        """A 307 redirect of the credential POST to an off-list host is refused."""
        session = FakeSession(
            {
                ("GET", DASHBOARD_URL): [FakeResponse(DASHBOARD_URL, 302, location=LOGIN_URL)],
                ("GET", LOGIN_URL): [FakeResponse(LOGIN_URL, body=LOGIN_PAGE_HTML)],
                ("POST", LOGIN_POST_URL): [FakeResponse(LOGIN_POST_URL, 307, location="https://evil.example.com/sink")],
            }
        )
        with self.assertRaises(CannotConnect):
            await AESIndiana().async_login(session, "user@example.com", "hunter2", {})  # type: ignore[arg-type]
        self.assertFalse(any("evil.example.com" in url for _, url, _ in session.requests))

    async def test_sso_form_to_unexpected_host(self) -> None:
        """An SSO form targeting a host outside the allow-list is not posted."""
        session = FakeSession({})
        with self.assertRaises(CannotConnect):
            await _complete_sso(session, URL(LOGIN_URL), SAML_TO_UNEXPECTED_HOST_HTML)  # type: ignore[arg-type]
        self.assertEqual(0, len(session.requests))

    async def test_sso_unexpected_page(self) -> None:
        """A page with neither an SSO form nor a login form raises CannotConnect."""
        session = FakeSession({})
        with self.assertRaises(CannotConnect):
            await _complete_sso(session, URL(LOGIN_URL), "<html><body>maintenance</body></html>")  # type: ignore[arg-type]

    async def test_sso_never_reaches_opower(self) -> None:
        """An SSO loop that never lands on opower gives up with CannotConnect."""
        looping_html = f"""
        <form method="post" action="{IDCS_SSO_URL}">
          <input type="hidden" name="SAMLResponse" value="c2FtbA==" />
        </form>
        """
        session = FakeSession({("POST", IDCS_SSO_URL): [FakeResponse(IDCS_SSO_URL, body=looping_html) for _ in range(5)]})
        with self.assertRaises(CannotConnect):
            await _complete_sso(session, URL(LOGIN_URL), looping_html)  # type: ignore[arg-type]
