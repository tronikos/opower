"""Tests for the Eversource login flow (home-assistant/core#172379)."""

import unittest
from typing import Any

from opower.exceptions import CannotConnect, InvalidAuth
from opower.utilities.eversource import Eversource
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
