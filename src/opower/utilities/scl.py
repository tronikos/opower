"""Seattle City Light (SCL)."""

import json
import re
from typing import Any
from urllib.parse import urlsplit, urlunsplit

import aiohttp

from ..const import USER_AGENT
from ..exceptions import CannotConnect, InvalidAuth
from .base import UtilityBase
from .helpers import get_form_action_url_and_hidden_inputs

REQUEST_TIMEOUT = aiohttp.ClientTimeout(total=30)


def _get_session_storage_values(html: str) -> dict[str, str]:
    """Return the items set in session storage on login.seattle.gov."""
    items: dict[str, str] = {}
    for match in re.finditer(r"sessionStorage\.setItem\(\"(.*?)\",\s*['\"](.*)['\"]\)", html):
        items[match.group(1)] = match.group(2)
    return items


def _describe_action_url(action_url: str) -> str:
    if not action_url:
        return "no form"
    parts = urlsplit(action_url)
    return urlunsplit((parts.scheme, parts.hostname or "", parts.path, "", ""))


def _get_user_token_from_url(url: str) -> str:
    match = re.search(r"https://myutilities.seattle.gov/eportal/#/ssohome/(.*)", url)
    if not match:
        return ""
    return match.group(1)


class SCL(UtilityBase):
    """Seattle City Light (SCL)."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Seattle City Light (SCL)"

    def subdomain(self) -> str:
        """Return the opower.com subdomain for this utility."""
        return "scl"

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/Los_Angeles"

    async def _async_sso_login(
        self,
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        hidden_inputs: dict[str, str],
    ) -> tuple[str, dict[str, str]]:
        """Perform SSO login flow and return SAML response action URL and hidden inputs."""
        if set(hidden_inputs.keys()) != {"signature", "state", "loginCtx"}:
            raise CannotConnect("Unexpected SSO login form fields")

        # POST to https://login.seattle.gov/#/login?appName=EPORTAL_PROD with signature, state, loginCtx
        # need to parse signinAT, initialState from html sessionStorage.setItem
        async with session.post(
            "https://login.seattle.gov/#/login?appName=EPORTAL_PROD",
            data=hidden_inputs,
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
            timeout=REQUEST_TIMEOUT,
        ) as resp:
            login_result = await resp.text()
            session_items = _get_session_storage_values(login_result)
        if not {"initialState", "signinAT"}.issubset(set(session_items.keys())):
            raise CannotConnect("Missing session storage values from login page")
        try:
            initial_state = json.loads(session_items.get("initialState", "{}"))
        except ValueError as err:
            raise CannotConnect("Unexpected initialState on login page") from err

        # POST to https://login.seattle.gov/authenticate with credentials, initialState, signinAT
        # response has authnToken in JSON response if initialState and signinAT present.
        # Origin/Referer are needed to get past the bot defense, which otherwise returns
        # a challenge page. The JSON response is served as text/html, so skip the check.
        async with session.post(
            "https://login.seattle.gov/authenticate",
            json={
                "credentials": {"username": username, "password": password},
                "initialState": initial_state,
                "signinAT": session_items.get("signinAT"),
            },
            headers={
                "User-Agent": USER_AGENT,
                "Origin": "https://login.seattle.gov",
                "Referer": "https://login.seattle.gov/",
            },
            raise_for_status=False,
            timeout=REQUEST_TIMEOUT,
        ) as resp:
            if resp.status == 400:
                raise InvalidAuth("Username and password failed")
            if not 200 <= resp.status < 300:
                raise CannotConnect(f"Unexpected status {resp.status} from authenticate")
            try:
                authenticate_result = await resp.json(content_type=None)
            except ValueError as err:
                raise CannotConnect("Unexpected non-JSON response from authenticate") from err
        if not isinstance(authenticate_result, dict):
            raise CannotConnect("Unexpected response from authenticate")
        if "error_description" in authenticate_result:
            raise InvalidAuth(authenticate_result["error_description"])
        authnToken = authenticate_result.get("authnToken")
        if not authnToken:
            raise InvalidAuth("Authentication failed: no authnToken received")

        # POST to https://idcs-3359adb31e35415e8c1729c5c8098c6d.identity.oraclecloud.com/sso/v1/sdk/session with authnToken
        # response has OCIS_REQ in HTML form
        async with session.post(
            "https://idcs-3359adb31e35415e8c1729c5c8098c6d.identity.oraclecloud.com/sso/v1/sdk/session",
            data={"authnToken": authnToken},
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
            timeout=REQUEST_TIMEOUT,
        ) as resp:
            session_result = await resp.text()
        action_url, hidden_inputs = get_form_action_url_and_hidden_inputs(session_result)
        if action_url != "https://idcs-3359adb31e35415e8c1729c5c8098c6d.identity.oraclecloud.com/fed/v1/user/response/login":
            raise CannotConnect(f"Unexpected Oracle IDCS session URL: {_describe_action_url(action_url)}")
        if set(hidden_inputs.keys()) != {"OCIS_REQ"}:
            raise CannotConnect("Unexpected Oracle IDCS session form fields")

        # POST to https://idcs-3359adb31e35415e8c1729c5c8098c6d.identity.oraclecloud.com/fed/v1/user/response/login
        # with OCIS_REQ (form data)
        # response has SAMLResponse in HTML form
        async with session.post(
            action_url,
            data=hidden_inputs,
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
            timeout=REQUEST_TIMEOUT,
        ) as resp:
            idcs_login_result = await resp.text()
        return get_form_action_url_and_hidden_inputs(idcs_login_result)

    async def async_login(
        self,
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        login_data: dict[str, Any],
    ) -> str:
        """Login to the utility website."""
        # GET https://myutilities.seattle.gov/rest/auth/ssologin
        # response has next URL, signature, state, loginCtx in HTML form
        async with session.get(
            "https://myutilities.seattle.gov/rest/auth/ssologin",
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
            timeout=REQUEST_TIMEOUT,
        ) as resp:
            ssologin_result = await resp.text()
        action_url, hidden_inputs = get_form_action_url_and_hidden_inputs(ssologin_result)
        step = "initial ssologin GET"
        if action_url == "https://login.seattle.gov/#/login?appName=EPORTAL_PROD":
            step = "SSO login"
            # Not logged in to seattle.gov, go through SSO flow
            action_url, hidden_inputs = await self._async_sso_login(session, username, password, hidden_inputs)

        if action_url != "https://myutilities.seattle.gov/rest/auth/samlresp":
            raise CannotConnect(f"Unexpected SAML response URL after {step}: {_describe_action_url(action_url)}")
        if set(hidden_inputs.keys()) != {"RelayState", "SAMLResponse"}:
            raise CannotConnect(f"Unexpected SAML response form fields after {step}")

        # POST to https://myutilities.seattle.gov/rest/auth/samlresp w/ RelayState https://myutilities.seattle.gov/eportal
        # and SAMLResponse
        # response redirects to https://myutilities.seattle.gov/eportal/#/ssohome/[user_token]
        # access from location header on hresponse
        async with session.post(
            action_url,
            data=hidden_inputs,
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
            timeout=REQUEST_TIMEOUT,
        ) as resp:
            url = resp.real_url.human_repr()
            user_token = _get_user_token_from_url(url)
            if not user_token:
                raise CannotConnect("Failed to extract user token from redirect URL")

        # getSSOToken (/auth/token)
        async with session.post(
            "https://myutilities.seattle.gov/rest/auth/token",
            data={
                "grant_type": "authorization_code",
                "logintype": "sso",
                "usertoken": user_token,
            },
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
            timeout=REQUEST_TIMEOUT,
        ) as resp:
            auth_token_result = await resp.json()
        access_token = auth_token_result.get("access_token")
        if not access_token:
            raise CannotConnect("Failed to retrieve access token")
        customer_id = auth_token_result["user"]["customerId"]

        # List SCL accounts, required to fetch opower token
        async with session.post(
            "https://myutilities.seattle.gov/rest/account/list/some",
            json={
                "customerId": customer_id,
                "companyCode": "SCL",
                "page": "1",
                "account": [],
                "sortColumn": "DUED",
                "sortOrder": "DESC",
            },
            headers={
                "User-Agent": USER_AGENT,
                "Authorization": f"Bearer {access_token}",
            },
            raise_for_status=True,
            timeout=REQUEST_TIMEOUT,
        ) as resp:
            list_result = await resp.json()
        accounts = list_result["account"]

        if len(accounts) == 0:
            raise CannotConnect("No accounts found")

        # This request lists current accounts by descending due date. Defaults
        # to taking to the most recent account if there are multiple.
        account = accounts[0]
        account_context_keys = [
            "accountNumber",
            "personId",
            "companyCd",
            "serviceAddress",
        ]
        account_context = {x: account[x] for x in account_context_keys}

        # get opower token (/usage/token)
        async with session.post(
            "https://myutilities.seattle.gov/rest/usage/token",
            json={"customerId": customer_id, "accountContext": account_context},
            headers={
                "User-Agent": USER_AGENT,
                "Authorization": f"Bearer {access_token}",
            },
            raise_for_status=True,
            timeout=REQUEST_TIMEOUT,
        ) as resp:
            result = await resp.json()
        token = result.get("token")
        if not token:
            raise CannotConnect("Failed to retrieve Opower token")

        return str(token)
