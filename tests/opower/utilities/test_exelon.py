"""Tests for the Exelon subsidiaries (ComEd, Pepco, ...)."""

from typing import Any

import pytest
from aiohttp import ClientResponseError, RequestInfo
from multidict import CIMultiDict, CIMultiDictProxy
from yarl import URL

from opower import Opower
from opower.exceptions import CannotConnect, InvalidAuth
from opower.utilities.comed import ComEd
from opower.utilities.exelon import ExelonURLHandler
from opower.utilities.pepco import Pepco
from tests.mock_http import MockResponse, MockSession

BASE_URL = "comedb2c.b2clogin.com/comedb2c.onmicrosoft.com/B2C_1A_SignIn_Mobile"
TOKEN_URL = f"https://{BASE_URL}/oauth2/v2.0/token"
COMED_ACCOUNTS_URL = "https://eudapi.comed.com/mobile/custom/auth/accounts"
PEPCO_ACCOUNTS_URL = "https://eudapi.pepco.com/mobile/custom/auth/accounts"
COMED_CUSTOMERS_URL = (
    "https://cec.opower.com/ei/edge/apis/multi-account-v1/cws/cec/customers?offset=0&batchSize=100&addressFilter="
)
BEARER_TOKEN = "bearer-token"  # noqa: S105
REFRESH_TOKEN = "refresh-token"  # noqa: S105


def _account(number: str, *, status: str = "Active", default: bool = False, **extra: Any) -> dict[str, Any]:
    """Return an account as the Exelon mobile accounts endpoint lists it."""
    return {"accountNumber": number, "status": status, "isDefaultProfile": default, **extra}


def _md_residential() -> dict[str, Any]:
    """Return the fields that put a Pepco account on the primary subdomain."""
    return {
        "isResidential": True,
        "PremiseInfo": [{"mainAddress": {"townDetail": {"stateOrProvince": "MD"}}}],
    }


def _customer(uuid: str, utility_account_id: str) -> dict[str, Any]:
    """Return an Opower customer with one electric account, as multi-account-v1 lists it."""
    return {
        "uuid": uuid,
        "utilityAccounts": [
            {
                "uuid": f"{uuid}-elec",
                "preferredUtilityAccountId": utility_account_id,
                "meterType": "ELEC",
                "readResolution": "HOUR",
            }
        ],
    }


def _http_error(url: str, status: int) -> ClientResponseError:
    """Return the error aiohttp raises for a failed response when raise_for_status is set."""
    request_info = RequestInfo(URL(url), "GET", CIMultiDictProxy(CIMultiDict()), URL(url))
    return ClientResponseError(request_info, (), status=status, message="error")


class _ExelonSession(MockSession):
    """Serves the Exelon token endpoint by grant, and canned responses for the rest.

    A refresh of the login token returns BEARER_TOKEN. A request for an Opower
    token returns "opower-<account number>", or raises the error registered for
    that account number in token_errors. The Opower customers endpoint answers
    with the customer registered in customers_by_token for the bearer token sent.
    """

    def __init__(self, responses: dict[str, MockResponse | Exception]) -> None:
        """Serve the given responses, raising those that are exceptions."""
        super().__init__({})
        self._routes = responses
        self.token_errors: dict[str, Exception] = {}
        self.customers_by_token: dict[str, dict[str, Any]] = {}

    def _handle(self, method: str, url: str, **kwargs: Any) -> MockResponse:
        self.requests.append({"method": method, "url": url, **kwargs})
        if url == COMED_CUSTOMERS_URL:
            token = kwargs["headers"]["authorization"].removeprefix("Bearer ")
            return MockResponse(payload={"customers": [self.customers_by_token[token]]})
        if url == TOKEN_URL:
            data = kwargs["data"]
            if "nonce" not in data:
                return MockResponse(payload={"access_token": BEARER_TOKEN, "refresh_token": REFRESH_TOKEN})
            if error := self.token_errors.get(data["nonce"]):
                raise error
            return MockResponse(payload={"access_token": f"opower-{data['nonce']}"})
        response = self._routes[url]
        if isinstance(response, Exception):
            raise response
        return response

    def opower_token_requests(self) -> list[str]:
        """Return the account numbers for which an Opower token was requested, in order."""
        return [
            request["data"]["nonce"] for request in self.requests if request["url"] == TOKEN_URL and "nonce" in request["data"]
        ]


def _login_data(account: dict[str, Any]) -> dict[str, Any]:
    """Return the login data Home Assistant stores after the MFA flow."""
    return {"token": REFRESH_TOKEN, "account": account, "base_url": BASE_URL}


async def _tokens(utility: ComEd | Pepco, session: _ExelonSession) -> list[str]:
    """Collect the tokens from async_iter_account_tokens."""
    return [token async for token in utility.async_iter_account_tokens(session)]  # type: ignore[arg-type]


@pytest.mark.asyncio
async def test_iter_account_tokens_yields_a_token_per_active_account() -> None:
    """Each active account gets its own Opower token, inactive ones are left out."""
    accounts = [_account("111", default=True), _account("222"), _account("333", status="Inactive")]
    session = _ExelonSession({COMED_ACCOUNTS_URL: MockResponse(payload={"success": True, "data": accounts})})
    utility = ComEd()

    from_login = await utility.async_login(session, "user", "pass", _login_data(accounts[0]))  # type: ignore[arg-type]
    tokens = await _tokens(utility, session)

    assert from_login == "opower-111"
    assert tokens == ["opower-111", "opower-222"]
    assert session.opower_token_requests() == ["111", "111", "222"]
    accounts_requests = [request for request in session.requests if request["url"] == COMED_ACCOUNTS_URL]
    assert len(accounts_requests) == 1
    assert accounts_requests[0]["headers"]["Authorization"] == f"Bearer {BEARER_TOKEN}"


@pytest.mark.asyncio
async def test_iter_account_tokens_yields_nothing_for_a_single_account() -> None:
    """With one active account the login token already covers everything."""
    accounts = [_account("111"), _account("333", status="Inactive")]
    session = _ExelonSession({COMED_ACCOUNTS_URL: MockResponse(payload={"success": True, "data": accounts})})
    utility = ComEd()

    await utility.async_login(session, "user", "pass", _login_data(accounts[0]))  # type: ignore[arg-type]

    assert await _tokens(utility, session) == []
    assert session.opower_token_requests() == ["111"]


@pytest.mark.asyncio
async def test_iter_account_tokens_yields_nothing_before_login() -> None:
    """Without a login there is no handler to mint tokens with."""
    session = _ExelonSession({})

    assert await _tokens(ComEd(), session) == []
    assert session.requests == []


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("status", "message"),
    [
        # A 400 means the token was rejected: refresh_token returns {} and no token is issued.
        (400, "did not issue an Opower token for account 222"),
        # A 5xx raises CannotConnect from the token refresh itself.
        (503, "Failed to refresh the Exelon token"),
    ],
    ids=["rejected", "http_error"],
)
async def test_iter_account_tokens_fails_when_an_account_gets_no_token(status: int, message: str) -> None:
    """A failure on one account fails the login instead of hiding that account.

    Skipping it would make the caller drop the account, and Home Assistant
    deletes the entities of an account that disappears from the list.
    """
    accounts = [_account("111", default=True), _account("222"), _account("333")]
    session = _ExelonSession({COMED_ACCOUNTS_URL: MockResponse(payload={"success": True, "data": accounts})})
    utility = ComEd()
    await utility.async_login(session, "user", "pass", _login_data(accounts[0]))  # type: ignore[arg-type]
    session.token_errors["222"] = _http_error(TOKEN_URL, status)

    with pytest.raises(CannotConnect, match=message):
        await _tokens(utility, session)


@pytest.mark.asyncio
@pytest.mark.parametrize(
    ("accounts_response", "message"),
    [
        (_http_error(COMED_ACCOUNTS_URL, 500), "Cannot obtain account information"),
        (MockResponse(payload={"success": False}), "Could not list Exelon accounts"),
    ],
    ids=["http_error", "unsuccessful"],
)
async def test_iter_account_tokens_fails_when_listing_fails(accounts_response: MockResponse | Exception, message: str) -> None:
    """When the accounts cannot be listed, the login fails rather than silently serving one account."""
    session = _ExelonSession({COMED_ACCOUNTS_URL: accounts_response})
    utility = ComEd()
    await utility.async_login(session, "user", "pass", _login_data(_account("111")))  # type: ignore[arg-type]

    with pytest.raises(CannotConnect, match=message):
        await _tokens(utility, session)
    assert session.opower_token_requests() == ["111"]


@pytest.mark.asyncio
async def test_iter_account_tokens_skips_accounts_on_another_subdomain() -> None:
    """Pepco serves MD residential accounts from pep and the rest from pepd, one subdomain per login."""
    accounts = [
        _account("111", default=True, **_md_residential()),
        _account("222", isResidential=False),
        _account("333", **_md_residential()),
    ]
    session = _ExelonSession({PEPCO_ACCOUNTS_URL: MockResponse(payload={"success": True, "data": accounts})})
    utility = Pepco()

    await utility.async_login(session, "user", "pass", _login_data(accounts[0]))  # type: ignore[arg-type]

    assert utility.subdomain() == "pep"
    assert await _tokens(utility, session) == ["opower-111", "opower-333"]


@pytest.mark.asyncio
async def test_opower_lists_the_meters_of_every_active_account() -> None:
    """End to end: Opower.async_get_accounts returns the meters of both ComEd accounts.

    async_login still returns the token of the default account. Opower then
    calls async_iter_account_tokens and fetches the customers of each token,
    so the meters of the second account show up and keep using its own token.
    """
    accounts = [_account("111", default=True), _account("222")]
    session = _ExelonSession({COMED_ACCOUNTS_URL: MockResponse(payload={"success": True, "data": accounts})})
    session.customers_by_token = {
        "opower-111": _customer("customer-1", "111"),
        "opower-222": _customer("customer-2", "222"),
    }
    opower = Opower(
        session,  # type: ignore[arg-type]
        ComEd.name(),
        username="user",
        password="pass",  # noqa: S106
        login_data=_login_data(accounts[0]),
    )

    await opower.async_login()
    result = await opower.async_get_accounts()

    assert [(account.customer.uuid, account.utility_account_id) for account in result] == [
        ("customer-1", "111"),
        ("customer-2", "222"),
    ]
    assert opower._get_headers("customer-1")["authorization"] == "Bearer opower-111"
    assert opower._get_headers("customer-2")["authorization"] == "Bearer opower-222"


@pytest.mark.asyncio
async def test_opower_keeps_known_accounts_when_one_token_refresh_fails() -> None:
    """A transient error on one account fails the login and keeps the accounts of the previous one.

    Regression test for the review of the 0.22.4 bump in Home Assistant: a 503
    refreshing only one account's token used to make async_login succeed with a
    shorter account list, and Home Assistant deleted the entities of the account
    that went missing.
    """
    accounts = [_account("111", default=True), _account("222")]
    session = _ExelonSession({COMED_ACCOUNTS_URL: MockResponse(payload={"success": True, "data": accounts})})
    session.customers_by_token = {
        "opower-111": _customer("customer-1", "111"),
        "opower-222": _customer("customer-2", "222"),
    }
    opower = Opower(
        session,  # type: ignore[arg-type]
        ComEd.name(),
        username="user",
        password="pass",  # noqa: S106
        login_data=_login_data(accounts[0]),
    )
    await opower.async_login()
    assert [account.utility_account_id for account in await opower.async_get_accounts()] == ["111", "222"]

    session.token_errors["222"] = _http_error(TOKEN_URL, 503)
    with pytest.raises(CannotConnect):
        await opower.async_login()

    assert [account.utility_account_id for account in await opower.async_get_accounts()] == ["111", "222"]
    assert opower._get_headers("customer-2")["authorization"] == "Bearer opower-222"


def _handler(session: _ExelonSession) -> ExelonURLHandler:
    """Return a handler for ComEd."""
    client_id, mobile_id = ComEd.mobile_client()
    return ExelonURLHandler(
        session=session,  # type: ignore[arg-type]
        base_url=BASE_URL,
        login_domain=ComEd.login_domain(),
        eu_domain=ComEd.eu_domain(),
        refresh_token=REFRESH_TOKEN,
        client_id=client_id,
        mobile_id=mobile_id,
    )


@pytest.mark.asyncio
async def test_get_first_account_prefers_the_default_profile() -> None:
    """The login token is minted for the default profile when there is one."""
    accounts = [_account("111"), _account("222", default=True)]
    session = _ExelonSession({COMED_ACCOUNTS_URL: MockResponse(payload={"success": True, "data": accounts})})

    account = await _handler(session).get_first_account(BEARER_TOKEN)

    assert account["accountNumber"] == "222"


@pytest.mark.asyncio
async def test_get_first_account_falls_back_to_the_first_active_account() -> None:
    """Without a default profile, the first active account is used."""
    accounts = [_account("000", status="Inactive"), _account("111"), _account("222")]
    session = _ExelonSession({COMED_ACCOUNTS_URL: MockResponse(payload={"success": True, "data": accounts})})

    account = await _handler(session).get_first_account(BEARER_TOKEN)

    assert account["accountNumber"] == "111"


@pytest.mark.asyncio
async def test_get_first_account_requires_an_active_account() -> None:
    """A user with only inactive accounts cannot log in."""
    accounts = [_account("000", status="Inactive")]
    session = _ExelonSession({COMED_ACCOUNTS_URL: MockResponse(payload={"success": True, "data": accounts})})

    with pytest.raises(InvalidAuth, match="No active accounts found"):
        await _handler(session).get_first_account(BEARER_TOKEN)
