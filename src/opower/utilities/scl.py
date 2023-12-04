"""Seattle City Light (SCL)."""

import json
import re
from typing import Optional

import aiohttp

from ..const import USER_AGENT
from ..exceptions import InvalidAuth
from .base import UtilityBase


def _get_form_action_url_and_hidden_inputs(html: str) -> tuple[str, dict[str, str]]:
    """Return the URL and hidden inputs from the single form in a page."""
    match = re.search(r'action="([^"]*)"', html, re.IGNORECASE)
    if not match:
        return "", {}
    action_url = match.group(1)
    inputs = {}
    for match in re.finditer(
        r'input\s*type="hidden"\s*name="([^"]*)"\s*value="([^"]*)"', html, re.IGNORECASE
    ):
        inputs[match.group(1)] = match.group(2)
    return action_url, inputs


def _get_session_storage_values(html: str) -> dict[str, str]:
    """Return the items set in session storage on login.seattle.gov."""
    items = {}
    for match in re.finditer(
        r"sessionStorage\.setItem\(\"(.*?)\",\s*['\"](.*)['\"]\)", html
    ):
        items[match.group(1)] = match.group(2)
    return items


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

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "scl"

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/Los_Angeles"

    @staticmethod
    async def async_login(
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        optional_mfa_secret: Optional[str],
    ) -> str:
        """Login to the utility website."""
        # GET https://myutilities.seattle.gov/rest/auth/ssologin
        # response has next URL, signature, state, loginCtx in HTML form
        async with session.get(
            "https://myutilities.seattle.gov/rest/auth/ssologin"
        ) as resp:
            ssologin_result = await resp.text()
        action_url, hidden_inputs = _get_form_action_url_and_hidden_inputs(
            ssologin_result
        )
        if action_url == "https://login.seattle.gov/#/login?appName=EPORTAL_PROD":
            # Not logged in to seattle.gov, go through SSO flow
            assert set(hidden_inputs.keys()) == {"signature", "state", "loginCtx"}

            # POST to https://login.seattle.gov/#/login?appName=EPORTAL_PROD with signature, state, loginCtx
            # need to parse signinAT, initialState from html sessionStorage.setItem
            async with session.post(
                action_url,
                data=hidden_inputs,
                headers={"User-Agent": USER_AGENT},
                raise_for_status=True,
            ) as resp:
                login_result = await resp.text()
                session_items = _get_session_storage_values(login_result)
            assert {"initialState", "signinAT"}.issubset(set(session_items.keys()))

            # POST to https://login.seattle.gov/authenticate with credentials, initialState, signinAT?
            # response has authnToken in JSON response if initialState and signinAT present
            async with session.post(
                "https://login.seattle.gov/authenticate",
                json={
                    "credentials": {"username": username, "password": password},
                    "initialState": json.loads(session_items.get("initialState", "{}")),
                    "signinAT": session_items.get("signinAT"),
                },
                headers={"User-Agent": USER_AGENT},
                raise_for_status=False,
            ) as resp:
                if resp.status == 400:
                    raise InvalidAuth("Username and password failed")
                authenticate_result = await resp.json()
            if "error_description" in authenticate_result:
                raise InvalidAuth(authenticate_result["error_description"])
            assert authenticate_result["authnToken"]
            authnToken = authenticate_result["authnToken"]

            # POST to https://idcs-3359adb31e35415e8c1729c5c8098c6d.identity.oraclecloud.com/sso/v1/sdk/session with authnToken
            # response has OCIS_REQ in HTML form
            async with session.post(
                "https://idcs-3359adb31e35415e8c1729c5c8098c6d.identity.oraclecloud.com/sso/v1/sdk/session",
                data={"authnToken": authnToken},
                headers={"User-Agent": USER_AGENT},
                raise_for_status=True,
            ) as resp:
                session_result = await resp.text()
            action_url, hidden_inputs = _get_form_action_url_and_hidden_inputs(
                session_result
            )
            assert (
                action_url
                == "https://idcs-3359adb31e35415e8c1729c5c8098c6d.identity.oraclecloud.com/fed/v1/user/response/login"
            )
            assert set(hidden_inputs.keys()) == {"OCIS_REQ"}

            # POST to https://idcs-3359adb31e35415e8c1729c5c8098c6d.identity.oraclecloud.com/fed/v1/user/response/login
            # with OCIS_REQ (form data)
            # response has SAMLResponse in HTML form
            async with session.post(
                action_url,
                data=hidden_inputs,
                headers={"User-Agent": USER_AGENT},
                raise_for_status=True,
            ) as resp:
                idcs_login_result = await resp.text()
            action_url, hidden_inputs = _get_form_action_url_and_hidden_inputs(
                idcs_login_result
            )

        assert action_url == "https://myutilities.seattle.gov/rest/auth/samlresp"
        assert set(hidden_inputs.keys()) == {"RelayState", "SAMLResponse"}

        # POST to https://myutilities.seattle.gov/rest/auth/samlresp w/ RelayState https://myutilities.seattle.gov/eportal
        # and SAMLResponse
        # response redirects to https://myutilities.seattle.gov/eportal/#/ssohome/[user_token]
        # access from location header on hresponse
        async with session.post(
            action_url,
            data=hidden_inputs,
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        ) as resp:
            url = resp.real_url.human_repr()
            user_token = _get_user_token_from_url(url)
            assert user_token

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
        ) as resp:
            auth_token_result = await resp.json()
        assert auth_token_result["access_token"]
        access_token = auth_token_result["access_token"]
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
        ) as resp:
            list_result = await resp.json()
        accounts = list_result["account"]

        if len(accounts) == 0:
            raise InvalidAuth("No accounts found")

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
        ) as resp:
            result = await resp.json()
        assert result["token"]

        return str(result["token"])
