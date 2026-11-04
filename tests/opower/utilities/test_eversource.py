"""Tests for the Eversource login flow (home-assistant/core#172379)."""

import unittest
from typing import Any

from opower.exceptions import CannotConnect, InvalidAuth, MfaChallenge
from opower.utilities.eversource import Eversource, EversourceMfaHandler
from tests.mock_http import MockResponse, MockSession

LOGIN_PAGE = "https://www.eversource.com/security/account/Login"
MSLOGIN = "https://www.eversource.com/security/account/MSLogin"
OKTA_AUTHN = "https://eversource-external.okta.com/api/v1/authn"
OKTA_AUTHORIZE = "https://eversource-external.okta.com/oauth2/ausrjxam6icWYMIj41t7/v1/authorize"
OKTA_TOKEN = "https://eversource-external.okta.com/oauth2/ausrjxam6icWYMIj41t7/v1/token"  # noqa: S105
ACCOUNT_API = "https://www.eversource.com/cg/customer/api/account"
WIDGET_API = "https://www.eversource.com/cg/customer/api/accountbilling/getOpowerWidgetData/"


def _accounts(account_ids: list[str]) -> MockResponse:
    return MockResponse(payload={"Accounts": [{"BillingAccountIdentifier": aid} for aid in account_ids]})


def _account_page(page: int) -> str:
    return f"{ACCOUNT_API}?pageNumber={page}&pageSize=5"


def _login_responses(account_payloads: dict[str, Any]) -> dict[str, MockResponse]:
    """Build a full canned login flow ending in per-account widget payloads."""
    return {
        LOGIN_PAGE: MockResponse(text="<html>&quot;formToken&quot;:&quot;tok-abc&quot;</html>"),
        MSLOGIN: MockResponse(payload={"IsSuccess": True, "status": "SUCCESS", "OktaUsername": "user@example.com"}),
        OKTA_AUTHN: MockResponse(payload={"status": "SUCCESS", "sessionToken": "sessTok123"}),
        OKTA_AUTHORIZE: MockResponse(text="<html>data.code = 'testauthcode'</html>"),
        OKTA_TOKEN: MockResponse(payload={"access_token": "oktaAccessToken"}),
        ACCOUNT_API: _accounts(list(account_payloads)),
        **{WIDGET_API + aid: MockResponse(payload=payload) for aid, payload in account_payloads.items()},
    }


def _widget_urls(session: MockSession) -> list[str]:
    return [r["url"].removeprefix(WIDGET_API) for r in session.requests if r["url"].startswith(WIDGET_API)]


class TestEversource(unittest.IsolatedAsyncioTestCase):
    """Test the parts of the login flow that were fixed for #172379."""

    def test_name(self) -> None:
        """Test name."""
        self.assertEqual("Eversource", Eversource().name())

    def test_subdomain(self) -> None:
        """Test subdomain."""
        self.assertEqual("ever", Eversource().subdomain())

    def test_timezone(self) -> None:
        """Test timezone."""
        self.assertEqual("America/New_York", Eversource().timezone())

    def test_supports_realtime_usage(self) -> None:
        """Test realtime usage is supported."""
        self.assertTrue(Eversource().supports_realtime_usage())

    async def test_token_from_second_account_when_first_is_dormant(self) -> None:
        """A null body for account[0] must not crash; account[1] supplies the token.

        This is the home-assistant/core#172379 scenario: closed/dormant accounts
        serve HTTP 200 with a null body and no token, and the old code did
        accounts[0].get("jwtToken") on that null and crashed with AttributeError.
        """
        session = MockSession(
            _login_responses(
                {
                    "dormant-account": None,
                    "active-account": {"jwtToken": "the_opower_token"},
                }
            )
        )

        token = await Eversource().async_login(session, "user", "pw", {})  # type: ignore[arg-type]

        self.assertEqual(token, "the_opower_token")
        # Exactly two widget attempts, in listed-account order:
        self.assertEqual(_widget_urls(session), ["dormant-account", "active-account"])

    async def test_all_accounts_dormant_raises_invalid_auth(self) -> None:
        """Every account answering null is an auth shape problem, not a network one."""
        session = MockSession(_login_responses({"dormant-a": None, "dormant-b": None}))

        with self.assertRaises(InvalidAuth):
            await Eversource().async_login(session, "user", "pw", {})  # type: ignore[arg-type]

    async def test_empty_account_list_raises_invalid_auth(self) -> None:
        """No accounts at all is an auth-shaped failure."""
        session = MockSession(_login_responses({}))

        with self.assertRaises(InvalidAuth):
            await Eversource().async_login(session, "user", "pw", {})  # type: ignore[arg-type]

    async def test_http_error_on_widget_raises_cannot_connect(self) -> None:
        """A non-200 widget answer is a server failure, reported as CannotConnect."""
        responses = _login_responses({"some-account": None})
        responses[WIDGET_API + "some-account"] = MockResponse(status=500)
        session = MockSession(responses)

        with self.assertRaises(CannotConnect):
            await Eversource().async_login(session, "user", "pw", {})  # type: ignore[arg-type]

    async def test_dormant_and_invalid_widget_body_raises_cannot_connect(self) -> None:
        """One unreadable widget body means the failure may not be auth-shaped."""
        responses = _login_responses({"dormant": None, "broken": None})
        responses[WIDGET_API + "broken"] = MockResponse(text="<html>error</html>", content_type="text/html")
        session = MockSession(responses)

        with self.assertRaises(CannotConnect):
            await Eversource().async_login(session, "user", "pw", {})  # type: ignore[arg-type]

    async def test_invalid_json_from_account_api_raises_cannot_connect(self) -> None:
        """A malformed account list body is reported, not leaked as a JSONDecodeError."""
        responses = _login_responses({"some-account": {"jwtToken": "tok"}})
        responses[ACCOUNT_API] = MockResponse(raw_json="{not json")
        session = MockSession(responses)

        with self.assertRaises(CannotConnect):
            await Eversource().async_login(session, "user", "pw", {})  # type: ignore[arg-type]

    async def test_token_from_later_account_among_many(self) -> None:
        """Token found from the last of several accounts."""
        session = MockSession(
            _login_responses(
                {
                    "dormant-a": None,
                    "dormant-b": None,
                    "active": {"jwtToken": "late_token"},
                }
            )
        )

        token = await Eversource().async_login(session, "user", "pw", {})  # type: ignore[arg-type]
        self.assertEqual(token, "late_token")

    async def test_token_from_account_on_second_page(self) -> None:
        """Accounts on later pages of the account list are tried too."""
        page_1 = [f"dormant-{i}" for i in range(5)]
        responses = _login_responses({**dict.fromkeys(page_1), "active": {"jwtToken": "page_2_token"}})
        responses[_account_page(1)] = _accounts(page_1)
        responses[_account_page(2)] = _accounts(["active"])
        session = MockSession(responses)

        token = await Eversource().async_login(session, "user", "pw", {})  # type: ignore[arg-type]

        self.assertEqual(token, "page_2_token")
        self.assertEqual(_widget_urls(session), [*page_1, "active"])

    async def test_account_list_stops_when_pages_repeat(self) -> None:
        """An API that ignores pageNumber does not loop forever."""
        page = [f"dormant-{i}" for i in range(5)]
        session = MockSession(_login_responses(dict.fromkeys(page)))

        with self.assertRaises(InvalidAuth):
            await Eversource().async_login(session, "user", "pw", {})  # type: ignore[arg-type]

        account_requests = [r for r in session.requests if r["url"] == ACCOUNT_API]
        self.assertEqual(len(account_requests), 2)
        self.assertEqual(_widget_urls(session), page)

    async def test_account_list_is_capped_with_a_warning(self) -> None:
        """At most 50 accounts are tried, and hitting the cap is logged."""
        responses = _login_responses({})
        for page in range(1, 12):
            responses[_account_page(page)] = _accounts([f"dormant-{page}-{i}" for i in range(5)])
        responses.update({WIDGET_API + f"dormant-{page}-{i}": MockResponse() for page in range(1, 12) for i in range(5)})
        session = MockSession(responses)

        with self.assertLogs("opower.utilities.eversource", "WARNING") as logs, self.assertRaises(InvalidAuth):
            await Eversource().async_login(session, "user", "pw", {})  # type: ignore[arg-type]

        self.assertEqual(len(_widget_urls(session)), 50)
        self.assertIn("after 50", logs.output[0])


MFA_ISSUE = "https://www.eversource.com/security/api/OktaMFA/IssueMFAFactor"
MFA_VERIFY = "https://www.eversource.com/security/api/OktaMFA/VerifyMFAFactor"
FACTORS = [
    {"id": "sms1", "factorType": "sms", "status": "ACTIVE", "profile": {"phoneNumber": "+1 603-555-1234"}},
    {"id": "em1", "factorType": "email", "status": "ACTIVE", "value": "someone@example.com"},
    {"id": "old", "factorType": "sms", "status": "PENDING_ACTIVATION"},
]


def _mfa_required() -> MockResponse:
    return MockResponse(
        payload={
            "IsSuccess": True,
            "status": "MFA_REQUIRED",
            "OktaUsername": "user@example.com",
            "token": "enc-user-id",
            "factors": FACTORS,
        }
    )


class TestEversourceMfa(unittest.IsolatedAsyncioTestCase):
    """Test interactive MFA (text/email code) for Eversource."""

    async def _challenge(self, session: MockSession) -> EversourceMfaHandler:
        with self.assertRaises(MfaChallenge) as context:
            await Eversource().async_login(session, "user", "pw", {})  # type: ignore[arg-type]
        handler = context.exception.handler
        assert isinstance(handler, EversourceMfaHandler)
        return handler

    async def test_mfa_required_raises_challenge_with_active_options(self) -> None:
        """MFA_REQUIRED raises MfaChallenge listing only active factors, masked."""
        responses = _login_responses({"a": {"jwtToken": "t"}})
        responses[MSLOGIN] = _mfa_required()
        handler = await self._challenge(MockSession(responses))
        self.assertEqual(
            {"sms1": "Text message to ***-***-1234", "em1": "Email to s***@example.com"},
            await handler.async_get_mfa_options(),
        )

    async def test_mfa_required_without_user_id_raises_invalid_auth(self) -> None:
        """No encrypted user id means the MFA calls cannot be made."""
        responses = _login_responses({})
        responses[MSLOGIN] = MockResponse(payload={"IsSuccess": True, "status": "MFA_REQUIRED", "OktaUsername": "u"})
        with self.assertRaises(InvalidAuth):
            await Eversource().async_login(MockSession(responses), "user", "pw", {})  # type: ignore[arg-type]

    async def test_select_sends_code_and_submit_returns_remember_me(self) -> None:
        """Selecting issues the code; a correct code returns remember-me login data."""
        responses = _login_responses({})
        responses[MSLOGIN] = _mfa_required()
        responses[MFA_ISSUE] = MockResponse(payload={"factorResult": "CHALLENGE"})
        responses[MFA_VERIFY] = MockResponse(payload={"factorResult": "SUCCESS", "mfaRememberMeData": "remember-abc"})
        session = MockSession(responses)
        handler = await self._challenge(session)
        await handler.async_select_mfa_option("sms1")
        login_data = await handler.async_submit_mfa_code(" 123456 ")
        self.assertEqual({"mfa_remember_me_data": "remember-abc"}, login_data)
        issue = next(r for r in session.requests if r["url"] == MFA_ISSUE)
        verify = next(r for r in session.requests if r["url"] == MFA_VERIFY)
        self.assertEqual({"userId": "enc-user-id", "factorId": "sms1"}, issue["json"])
        self.assertEqual(
            {"userId": "enc-user-id", "factorId": "sms1", "passCode": "123456", "mfaRememberMe": True}, verify["json"]
        )

    async def test_wrong_code_raises_invalid_auth(self) -> None:
        """An invalid passcode raises InvalidAuth."""
        responses = _login_responses({})
        responses[MSLOGIN] = _mfa_required()
        responses[MFA_ISSUE] = MockResponse(payload={"factorResult": "CHALLENGE"})
        responses[MFA_VERIFY] = MockResponse(payload={"invalidPasscode": True})
        handler = await self._challenge(MockSession(responses))
        await handler.async_select_mfa_option("em1")
        with self.assertRaises(InvalidAuth):
            await handler.async_submit_mfa_code("000000")

    async def test_code_not_sent_raises_cannot_connect(self) -> None:
        """A non-CHALLENGE reply to the send request raises CannotConnect."""
        responses = _login_responses({})
        responses[MSLOGIN] = _mfa_required()
        responses[MFA_ISSUE] = MockResponse(payload={"factorResult": "FAILED"})
        handler = await self._challenge(MockSession(responses))
        with self.assertRaises(CannotConnect):
            await handler.async_select_mfa_option("sms1")

    async def test_valid_remember_me_skips_mfa(self) -> None:
        """Saved remember-me data is sent and a valid one completes login without MFA."""
        responses = _login_responses({"a": {"jwtToken": "opower-token"}})
        responses[MSLOGIN] = MockResponse(
            payload={
                "IsSuccess": True,
                "status": "MFA_REQUIRED",
                "OktaUsername": "user@example.com",
                "token": "enc-user-id",
                "ValidMfaRememberMeData": True,
            }
        )
        session = MockSession(responses)
        token = await Eversource().async_login(
            session,  # type: ignore[arg-type]
            "user",
            "pw",
            {"mfa_remember_me_data": "remember-abc"},
        )
        self.assertEqual("opower-token", token)
        mslogin = next(r for r in session.requests if r["url"] == MSLOGIN)
        self.assertEqual("remember-abc", mslogin["json"]["MfaRememberMeData"])
