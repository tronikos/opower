"""Tests for the Eversource login flow (home-assistant/core#172379)."""

import unittest
from typing import Any

from opower.exceptions import CannotConnect, InvalidAuth
from opower.utilities.eversource import Eversource
from tests.mock_http import _MockResponse, _MockSession

LOGIN_PAGE = "https://www.eversource.com/security/account/Login"
MSLOGIN = "https://www.eversource.com/security/account/MSLogin"
OKTA_AUTHN = "https://eversource-external.okta.com/api/v1/authn"
OKTA_AUTHORIZE = "https://eversource-external.okta.com/oauth2/ausrjxam6icWYMIj41t7/v1/authorize"
OKTA_TOKEN = "https://eversource-external.okta.com/oauth2/ausrjxam6icWYMIj41t7/v1/token"  # noqa: S105
ACCOUNT_API = "https://www.eversource.com/cg/customer/api/account"
ACCOUNT_PARAMS = "pageNumber=1&pageSize=5"


def _login_responses(account_payloads: dict[str, Any]) -> dict[str, _MockResponse]:
    """Build a full canned login flow ending in per-account widget payloads."""
    return {
        LOGIN_PAGE: _MockResponse(text="<html>&quot;formToken&quot;:&quot;tok-abc&quot;</html>"),
        MSLOGIN: _MockResponse(payload={"IsSuccess": True, "status": "SUCCESS", "OktaUsername": "user@example.com"}),
        OKTA_AUTHN: _MockResponse(payload={"status": "SUCCESS", "sessionToken": "sessTok123"}),
        OKTA_AUTHORIZE: _MockResponse(text="<html>data.code = 'testauthcode'</html>"),
        OKTA_TOKEN: _MockResponse(payload={"access_token": "oktaAccessToken"}),
        ACCOUNT_API: _MockResponse(payload={"Accounts": [{"BillingAccountIdentifier": aid} for aid in account_payloads]}),
        **{
            f"https://www.eversource.com/cg/customer/api/accountbilling/getOpowerWidgetData/{aid}": _MockResponse(
                payload=payload
            )
            for aid, payload in account_payloads.items()
        },
    }


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
        session = _MockSession(
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
        widget_urls = [r["url"] for r in session.requests if "/getOpowerWidgetData/" in r["url"]]
        self.assertEqual(
            widget_urls,
            [
                "https://www.eversource.com/cg/customer/api/accountbilling/getOpowerWidgetData/dormant-account",
                "https://www.eversource.com/cg/customer/api/accountbilling/getOpowerWidgetData/active-account",
            ],
        )

    async def test_all_accounts_dormant_raises_invalid_auth(self) -> None:
        """Every account answering null is an auth shape problem, not a network one."""
        session = _MockSession(_login_responses({"dormant-a": None, "dormant-b": None}))

        with self.assertRaises(InvalidAuth):
            await Eversource().async_login(session, "user", "pw", {})  # type: ignore[arg-type]

    async def test_empty_account_list_raises_invalid_auth(self) -> None:
        """No accounts at all is an auth-shaped failure (was CannotConnect before)."""
        session = _MockSession(_login_responses({}))

        with self.assertRaises(InvalidAuth):
            await Eversource().async_login(session, "user", "pw", {})  # type: ignore[arg-type]

    async def test_http_error_on_widget_raises_cannot_connect(self) -> None:
        """A non-200 widget answer is a server failure, reported as CannotConnect."""
        session = _MockSession(_login_responses({"some-account": {"jwtToken": "tok"}}))
        # Replace the canned 200 widget response with a 500
        widget_url = "https://www.eversource.com/cg/customer/api/accountbilling/getOpowerWidgetData/some-account"
        session._responses[widget_url].status = 500

        with self.assertRaises(CannotConnect):
            await Eversource().async_login(session, "user", "pw", {})  # type: ignore[arg-type]

    async def test_token_from_later_account_among_many(self) -> None:
        """Pagination-safe iteration: token found from the last of several."""
        session = _MockSession(
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
