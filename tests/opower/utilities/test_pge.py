"""Tests for Pacific Gas & Electric (PG&E)."""

import json
import os
import unittest
from pathlib import Path
from typing import Any
from urllib.parse import parse_qs

import aiohttp
import pytest
from dotenv import dotenv_values

from opower.exceptions import CannotConnect, InvalidAuth, MfaChallenge
from opower.utilities.pge import PGE, PgeMfaHandler

REPO_ROOT = Path(__file__).parents[3]

AURA_URL = "https://myaccount.pge.com/myaccount/s/sfsites/aura?aura.ApexAction.execute=1"
FRONTDOOR_URL = "https://myaccount.pge.com/myaccount/secur/frontdoor.jsp?sid=00Dtest%21TESTSESSIONID&retURL=%2Fmyaccount"
MY_ACCOUNT_URL = "https://myaccount.pge.com/myaccount/s/"
DATA_BROWSER_URL = "https://myaccount.pge.com/myaccount/apex/MyAcct_VF_BillInsights_OpowerDataBrowser"

# The page embeds the Opower token in a script tag.
DATA_BROWSER_PAGE = """<html><body><script>
    let userId = '005000000000000000';
    let tokenFromApex = 'test-opower-token';
    let opowerUrl = 'https://pge.opower.com/ei/x/e/';
</script></body></html>"""

AURA_TOKEN_COOKIE = "__Host-ERIC_PROD_0000000000"  # noqa: S105


def _login_response(return_value: dict[str, Any]) -> dict[str, Any]:
    """Wrap an Apex return value the way the Aura endpoint does."""
    return {
        "actions": [
            {
                "state": "SUCCESS",
                "returnValue": {"returnValue": return_value, "cacheable": False},
                "error": [],
            },
            # Aura appends this warning to most responses.
            {"id": "COOSE", "state": "warning", "coos": "This page has changes since the last refresh."},
        ],
        "context": {"mode": "PROD", "app": "siteforce:loginApp2"},
    }


class _FakeCookie:
    """Minimal stand-in for an aiohttp cookie."""

    def __init__(self, key: str, value: str) -> None:
        """Initialize with the cookie name and value."""
        self.key = key
        self.value = value


class _FakeResponse:
    """Minimal stand-in for aiohttp.ClientResponse."""

    def __init__(self, payload: Any = None, text: str = "") -> None:
        """Initialize with the JSON payload and/or body text to serve."""
        self._payload = payload
        self._text = text

    async def json(self) -> Any:
        """Return the canned payload."""
        return self._payload

    async def text(self) -> str:
        """Return the canned body."""
        return self._text


class _FakeSession:
    """Serves canned PG&E responses and records the requests made.

    Aura POSTs are routed by the Apex method they invoke, GETs by URL. A route
    value may be an exception to raise instead of a response.
    """

    def __init__(
        self,
        aura: dict[str, Any] | None = None,
        pages: dict[str, Any] | None = None,
        cookies: list[_FakeCookie] | None = None,
    ) -> None:
        """Initialize with the Apex, page and cookie fixtures to serve."""
        self._aura = aura or {}
        self._pages = pages or {}
        self.cookie_jar = cookies if cookies is not None else [_FakeCookie(AURA_TOKEN_COOKIE, "test-aura-token")]
        self.aura_requests: list[dict[str, Any]] = []
        self.get_requests: list[str] = []

    async def post(self, url: str, **kwargs: Any) -> _FakeResponse:
        """Serve an Aura POST, routed by the Apex method it invokes."""
        assert url == AURA_URL
        form = {key: value[0] for key, value in parse_qs(kwargs["data"]).items()}
        params = json.loads(form["message"])["actions"][0]["params"]
        self.aura_requests.append({"form": form, "params": params})
        route = self._aura[params["method"]]
        if isinstance(route, Exception):
            raise route
        return _FakeResponse(payload=route)

    async def get(self, url: str, **kwargs: Any) -> _FakeResponse:
        """Serve a page GET."""
        self.get_requests.append(url)
        route = self._pages.get(url, "")
        if isinstance(route, Exception):
            raise route
        return _FakeResponse(text=route)


def _session_for_successful_login(**overrides: Any) -> _FakeSession:
    """Return a session that serves a complete, successful login."""
    aura = {
        "login": _login_response(
            {
                "cookieExpiryDays": "180.0",
                "cscodeattempt": "5.0",
                "cslockattempt": "3.0",
                "PGE_USER_FIRST": "TESTUSER",
                "retencrUsrname": "encrypted-username",
                "retMessage": FRONTDOOR_URL,
            }
        ),
        "generateToken": _login_response({"retMessage": "success"}),
        "copyToSessionCacheForUser": _login_response({"retMessage": "success"}),
    }
    pages = {FRONTDOOR_URL: "", MY_ACCOUNT_URL: "", DATA_BROWSER_URL: DATA_BROWSER_PAGE}
    return _FakeSession(aura=aura, pages=pages, **overrides)


class TestPGE(unittest.TestCase):
    """Test the public methods inherited from UtilityBase."""

    def test_name(self) -> None:
        """Test name."""
        self.assertEqual("Pacific Gas and Electric Company (PG&E)", PGE.name())

    def test_subdomain(self) -> None:
        """Test subdomain."""
        self.assertEqual("pge", PGE().subdomain())

    def test_timezone(self) -> None:
        """Test timezone."""
        self.assertEqual("America/Los_Angeles", PGE.timezone())

    def test_does_not_accept_totp_secret(self) -> None:
        """PG&E uses interactive MFA, not TOTP."""
        self.assertFalse(PGE.accepts_totp_secret())

    def test_is_not_dss(self) -> None:
        """PG&E uses the classic opower.com endpoints."""
        self.assertFalse(PGE.is_dss())


class TestPGELogin(unittest.IsolatedAsyncioTestCase):
    """Test the login flow with mocked HTTP responses."""

    async def test_login_returns_opower_token(self) -> None:
        """A successful login extracts the Opower token from the data browser page."""
        session = _session_for_successful_login()

        token = await PGE().async_login(session, "user@example.com", "password", {})  # type: ignore[arg-type]

        self.assertEqual("test-opower-token", token)
        # The redirect is followed, then the pages that set the session cookies.
        self.assertEqual([FRONTDOOR_URL, MY_ACCOUNT_URL, DATA_BROWSER_URL], session.get_requests)
        self.assertEqual(
            ["login", "generateToken", "copyToSessionCacheForUser"],
            [request["params"]["method"] for request in session.aura_requests],
        )

    async def test_login_sends_credentials_and_saved_cookies(self) -> None:
        """Login posts the credentials, and the saved MFA cookies when there are any."""
        session = _session_for_successful_login()

        await PGE().async_login(
            session,  # type: ignore[arg-type]
            "user@example.com",
            "password",
            {"browsercookie": "saved-browsercookie", "validationCookie": "saved-validation-cookie"},
        )

        login = session.aura_requests[0]
        self.assertEqual("MyAcct_customLoginLWCController", login["params"]["classname"])
        self.assertEqual(
            {
                "username": "user@example.com",
                "password": "password",
                "browsercookie": "saved-browsercookie",
                "validationCookie": "saved-validation-cookie",
            },
            login["params"]["params"],
        )
        self.assertEqual("/myaccount/s/login/", login["form"]["aura.pageURI"])
        # The dict form fields are urlencoded compact JSON, without whitespace.
        self.assertNotIn(", ", login["form"]["message"])
        self.assertEqual('{"app":"siteforce:loginApp2"}', login["form"]["aura.context"])

    async def test_login_without_saved_login_data_sends_null_cookies(self) -> None:
        """Without saved MFA data the cookies are sent as the string "null"."""
        session = _session_for_successful_login()

        await PGE().async_login(session, "user@example.com", "password", {})  # type: ignore[arg-type]

        params = session.aura_requests[0]["params"]["params"]
        self.assertEqual("null", params["browsercookie"])
        self.assertEqual("null", params["validationCookie"])

    async def test_post_login_actions_use_the_aura_token_cookie(self) -> None:
        """The actions run after login authenticate with the Aura token cookie."""
        session = _session_for_successful_login()

        await PGE().async_login(session, "user@example.com", "password", {})  # type: ignore[arg-type]

        self.assertEqual("null", session.aura_requests[0]["form"]["aura.token"])
        for request in session.aura_requests[1:]:
            self.assertEqual("test-aura-token", request["form"]["aura.token"])
            self.assertEqual("/myaccount/s/", request["form"]["aura.pageURI"])

    async def test_invalid_username_raises_invalid_auth(self) -> None:
        """PG&E reports a bad username in retMessage of an otherwise successful action."""
        session = _FakeSession(aura={"login": _login_response({"retMessage": "invalid username."})})

        with self.assertRaises(InvalidAuth) as context:
            await PGE().async_login(session, "user@example.com", "wrong", {})  # type: ignore[arg-type]
        self.assertIn("invalid username.", str(context.exception))

    async def test_no_actions_raises_invalid_auth(self) -> None:
        """A response without actions cannot be interpreted as a login."""
        session = _FakeSession(aura={"login": {"actions": []}})

        with self.assertRaises(InvalidAuth):
            await PGE().async_login(session, "user@example.com", "password", {})  # type: ignore[arg-type]

    async def test_failed_action_raises_invalid_auth(self) -> None:
        """An action that did not succeed raises with its error."""
        session = _FakeSession(
            aura={"login": {"actions": [{"state": "ERROR", "error": [{"message": "An internal server error"}]}]}}
        )

        with self.assertRaises(InvalidAuth) as context:
            await PGE().async_login(session, "user@example.com", "password", {})  # type: ignore[arg-type]
        self.assertIn("An internal server error", str(context.exception))

    async def test_missing_aura_token_cookie_raises_invalid_auth(self) -> None:
        """Without the Aura token cookie the session is not really logged in."""
        session = _session_for_successful_login(cookies=[_FakeCookie("some-other-cookie", "value")])

        with self.assertRaises(InvalidAuth) as context:
            await PGE().async_login(session, "user@example.com", "password", {})  # type: ignore[arg-type]
        self.assertIn("Aura token", str(context.exception))

    async def test_missing_opower_token_raises_invalid_auth(self) -> None:
        """A data browser page without the token means the login did not stick."""
        session = _session_for_successful_login()
        session._pages[DATA_BROWSER_URL] = "<html><body>Session expired</body></html>"

        with self.assertRaises(InvalidAuth):
            await PGE().async_login(session, "user@example.com", "password", {})  # type: ignore[arg-type]

    async def test_empty_opower_token_raises_cannot_connect(self) -> None:
        """An empty token is treated as a temporary failure, so it is retried."""
        session = _session_for_successful_login()
        session._pages[DATA_BROWSER_URL] = "<script>let tokenFromApex = '';</script>"

        with self.assertRaises(CannotConnect):
            await PGE().async_login(session, "user@example.com", "password", {})  # type: ignore[arg-type]


class TestPGEMfa(unittest.IsolatedAsyncioTestCase):
    """Test the interactive MFA flow with mocked HTTP responses."""

    async def _challenge(self, return_value: dict[str, Any] | None = None, **kwargs: Any) -> PgeMfaHandler:
        """Log in against a session that answers with an MFA challenge."""
        if return_value is None:
            return_value = {
                "retMessage": "verifymfa :",
                "retencrUsrname": "encrypted-username",
                "encryptedTFT": "encrypted-tft",
                "EmailVal": "t***@example.com",
                "PhoneVal": "***-***-1234",
            }
        session = _FakeSession(aura={"login": _login_response(return_value)}, **kwargs)
        with self.assertRaises(MfaChallenge) as context:
            await PGE().async_login(session, "user@example.com", "password", {})  # type: ignore[arg-type]
        handler = context.exception.handler
        assert isinstance(handler, PgeMfaHandler)
        return handler

    async def test_login_raises_mfa_challenge_with_options(self) -> None:
        """An account with MFA offers the delivery options from the login response."""
        handler = await self._challenge()

        self.assertEqual({"Email": "t***@example.com", "Phone": "***-***-1234"}, await handler.async_get_mfa_options())

    async def test_mfa_options_can_be_empty(self) -> None:
        """Some accounts get the code without being asked where to send it."""
        handler = await self._challenge({"retMessage": "verifymfa :", "retencrUsrname": "encrypted-username"})

        self.assertEqual({}, await handler.async_get_mfa_options())

    async def test_select_mfa_option_requests_the_code(self) -> None:
        """Selecting an option asks PG&E to send the code there."""
        session = _FakeSession(aura={"handleChoiceofMFA": _login_response({"retMessage": "Success"})})
        handler = PgeMfaHandler(session, "password", {"retencrUsrname": "encrypted-username"})  # type: ignore[arg-type]

        await handler.async_select_mfa_option("Email")

        params = session.aura_requests[0]["params"]["params"]
        self.assertEqual("MyAcct_Apex_CustomMFAController", session.aura_requests[0]["params"]["classname"])
        self.assertEqual("encrypted-username", params["username"])
        self.assertEqual("Email", params["selectedChoice"])
        self.assertFalse(params["isforgotpassword"])

    async def test_select_mfa_option_failure_raises_cannot_connect(self) -> None:
        """A rejected selection is retryable, not an authentication failure."""
        session = _FakeSession(aura={"handleChoiceofMFA": _login_response({"retMessage": "Max attempts reached"})})
        handler = PgeMfaHandler(session, "password", {})  # type: ignore[arg-type]

        with self.assertRaises(CannotConnect) as context:
            await handler.async_select_mfa_option("Email")
        self.assertIn("Max attempts reached", str(context.exception))

    async def test_select_mfa_option_network_error_raises_cannot_connect(self) -> None:
        """A network error while selecting an option is retryable."""
        session = _FakeSession(aura={"handleChoiceofMFA": aiohttp.ClientConnectionError("boom")})
        handler = PgeMfaHandler(session, "password", {})  # type: ignore[arg-type]

        with self.assertRaises(CannotConnect):
            await handler.async_select_mfa_option("Email")

    async def test_submit_mfa_code_returns_login_data(self) -> None:
        """A valid code returns the cookies that skip MFA on the next login."""
        session = _FakeSession(
            aura={
                "handleChoiceofMFA": _login_response({"retMessage": "Success"}),
                "verifySignInCode": _login_response(
                    {
                        "returnResponse": "Success",
                        "wrapperObj": {
                            "retencrUsrname": "new-browsercookie",
                            "encryptedKey": "new-validation-cookie",
                            "expiryDateTime": "2027-03-01 12:00:00",
                        },
                    }
                ),
            }
        )
        handler = PgeMfaHandler(
            session,  # type: ignore[arg-type]
            "password",
            {"retencrUsrname": "encrypted-username", "encryptedTFT": "encrypted-tft"},
        )
        await handler.async_select_mfa_option("Email")

        login_data = await handler.async_submit_mfa_code("123456")

        self.assertEqual(
            {
                "browsercookie": "new-browsercookie",
                "validationCookie": "new-validation-cookie",
                "expiryDateTime": "2027-03-01 12:00:00",
            },
            login_data,
        )
        submitted = session.aura_requests[1]["params"]["params"]["input"]
        self.assertEqual("123456", submitted["authCode"])
        self.assertEqual("password", submitted["password"])
        self.assertEqual("encrypted-tft", submitted["encToken"])
        self.assertEqual("encrypted-username", submitted["usernameVal"])
        # The option chosen earlier is echoed back with the code.
        self.assertEqual("Email", submitted["otpType"])

    async def test_submit_mfa_code_without_selecting_an_option(self) -> None:
        """Accounts that skip the selection step submit no otpType."""
        session = _FakeSession(
            aura={
                "verifySignInCode": _login_response(
                    {"returnResponse": "Success", "wrapperObj": {"retencrUsrname": "c", "encryptedKey": "k"}}
                )
            }
        )
        handler = PgeMfaHandler(session, "password", {})  # type: ignore[arg-type]

        login_data = await handler.async_submit_mfa_code("123456")

        self.assertIsNone(session.aura_requests[0]["params"]["params"]["input"]["otpType"])
        self.assertIsNone(login_data["expiryDateTime"])

    async def test_submit_invalid_mfa_code_raises_invalid_auth(self) -> None:
        """A wrong code is an authentication failure, so it is not retried."""
        session = _FakeSession(aura={"verifySignInCode": _login_response({"returnResponse": "Invalid Code"})})
        handler = PgeMfaHandler(session, "password", {})  # type: ignore[arg-type]

        with self.assertRaises(InvalidAuth) as context:
            await handler.async_submit_mfa_code("000000")
        self.assertIn("Invalid Code", str(context.exception))

    async def test_submit_mfa_code_without_wrapper_raises_invalid_auth(self) -> None:
        """A success without the cookies cannot be used for the next login."""
        session = _FakeSession(aura={"verifySignInCode": _login_response({"returnResponse": "Success"})})
        handler = PgeMfaHandler(session, "password", {})  # type: ignore[arg-type]

        with self.assertRaises(InvalidAuth):
            await handler.async_submit_mfa_code("123456")

    async def test_submit_mfa_code_network_error_raises_cannot_connect(self) -> None:
        """A network error while submitting the code is retryable."""
        session = _FakeSession(aura={"verifySignInCode": aiohttp.ClientConnectionError("boom")})
        handler = PgeMfaHandler(session, "password", {})  # type: ignore[arg-type]

        with self.assertRaises(CannotConnect):
            await handler.async_submit_mfa_code("123456")


@pytest.mark.network
class TestPGELive(unittest.IsolatedAsyncioTestCase):
    """Perform a live login against the PG&E website."""

    async def test_real_login(self) -> None:
        """Log in for real and check that an Opower token comes back.

        This hits the live website, so it is excluded from the default run (see
        the "network" marker in pyproject.toml) and must be requested with
        `-m network`. PG&E requires MFA on first login, so it needs the login
        data saved by `python -m opower --login_data_file <file>` as well as
        the credentials.
        """
        config = {**dotenv_values(REPO_ROOT / ".env.secret"), **dotenv_values(REPO_ROOT / ".env"), **os.environ}
        username = config.get("PGE_USERNAME") or config.get("OPOWER_USERNAME")
        password = config.get("PGE_PASSWORD") or config.get("OPOWER_PASSWORD")
        login_data_file = config.get("PGE_LOGIN_DATA_FILE") or config.get("OPOWER_LOGIN_DATA_FILE")
        if not username or not password or not login_data_file:
            self.skipTest("Add PGE_USERNAME, PGE_PASSWORD and PGE_LOGIN_DATA_FILE to .env.secret to run the live PG&E test.")
        login_data_path = Path(login_data_file)
        if not login_data_path.is_absolute():
            login_data_path = REPO_ROOT / login_data_path
        if not login_data_path.is_file():
            self.skipTest(f"{login_data_path} not found; run the demo once to complete MFA and save it.")

        session = aiohttp.ClientSession()
        self.addCleanup(session.close)

        token = await PGE().async_login(session, username, password, json.loads(login_data_path.read_text(encoding="utf-8")))

        assert token
        self.assertTrue(len(token) > 0)
