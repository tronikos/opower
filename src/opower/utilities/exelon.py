"""Base class for Exelon subsidiaries."""

import json
import logging
import re
from typing import Any, Optional

import aiohttp

from ..const import USER_AGENT
from ..exceptions import InvalidAuth

_LOGGER = logging.getLogger(__file__)


class Exelon:
    """Base class for Exelon subsidiaries."""

    _subdomain: Optional[str] = None

    # Can find the opower.com subdomain using the GetConfiguration endpoint
    # e.g. https://secure.bge.com/api/Services/MyAccountService.svc/GetConfiguration
    # returns bgec.opower.com

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/New_York"

    @staticmethod
    def login_domain() -> str:
        """Return the domain that hosts the login page."""
        raise NotImplementedError

    @classmethod
    def subdomain(cls) -> str:
        """Return the opower.com subdomain for this utility."""
        assert Exelon._subdomain, "async_login not called"
        return Exelon._subdomain

    @staticmethod
    def primary_subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        raise NotImplementedError

    @staticmethod
    def secondary_subdomain() -> str:
        """Return the opower.com secondary subdomain for this utility."""
        raise NotImplementedError

    @classmethod
    async def async_account(
        cls,
        session: aiohttp.ClientSession,
        bearer_token: str,
    ) -> Any:
        """Return the accounts for the current session."""
        # this path comes from GetConfiguration, unsure if its different
        # per utility, if so, would need to add it to the subtypes:
        # "euApiRoutePrefix": "/mobile/custom",
        eu_api_route_prefix = "/mobile/custom"
        # "euApiUrl": "/.euapi",
        eu_api_url = "/.euapi"
        async with session.get(
            "https://"
            + cls.login_domain()
            + eu_api_url
            + eu_api_route_prefix
            + "/auth/accounts",
            headers={
                "User-Agent": USER_AGENT,
                "Authorization": "Bearer " + bearer_token,
            },
            raise_for_status=True,
        ) as resp:
            # this has the wrong mime type for some reason
            result = await resp.json(content_type="text/html")

        if result["success"] is not True:
            raise InvalidAuth("Unable to list accounts")

        # Only include active accounts (after moving, old accounts have status: "Inactive")
        # NOTE: this logic currently assumes 1 active address per account, if multiple accounts found
        #      we default to taking the first in the list. Future enhancement is to support
        #      multiple accounts (which could result in different subdomain for each)
        active_accounts = [
            account for account in result["data"] if account["status"] == "Active"
        ]

        if len(active_accounts) == 0:
            raise InvalidAuth("No active accounts found")

        return active_accounts[0]

    @classmethod
    async def async_login(
        cls,
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        optional_mfa_secret: Optional[str],
    ) -> str:
        """Login to the utility website and authorize opower."""
        async with session.get(
            "https://" + cls.login_domain() + "/Pages/Login.aspx?/login",
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        ) as resp:
            result = await resp.text(encoding="utf-8")

        account = None
        # if we don't go to /accounts/dashboard, we need to perform some authorization steps
        if resp.request_info.url.path.endswith("/authorize"):
            # transId = "StateProperties=..."
            # policy = "B2C_1A_SignIn"
            # tenant = "/euazurebge.onmicrosoft.com/B2C_1A_SignIn"
            # api = "CombinedSigninAndSignup"
            settings_match = re.search(r"var SETTINGS = ({.*});", result)
            assert settings_match
            settings = json.loads(settings_match.group(1))
            login_post_domain = resp.real_url.host
            assert login_post_domain

            async with session.post(
                "https://"
                + login_post_domain
                + settings["hosts"]["tenant"]
                + "/SelfAsserted",
                params={
                    "tx": settings["transId"],
                    "p": settings["hosts"]["policy"],
                },
                data={
                    "request_type": "RESPONSE",
                    "signInName": username,
                    "password": password,
                },
                headers={
                    "X-CSRF-TOKEN": settings["csrf"],
                    "User-Agent": USER_AGENT,
                },
                raise_for_status=True,
            ) as resp:
                result_json = json.loads(await resp.text(encoding="utf-8"))

            if result_json["status"] != "200":
                raise InvalidAuth(result_json["message"])

            async with session.get(
                "https://"
                + login_post_domain
                + settings["hosts"]["tenant"]
                + "/api/"
                + settings["api"]
                + "/confirmed",
                params={
                    "rememberMe": settings["config"]["enableRememberMe"],
                    "csrf_token": settings["csrf"],
                    "tx": settings["transId"],
                    "p": settings["hosts"]["policy"],
                    "diags": json.dumps(
                        {
                            "pageViewId": settings["pageViewId"],
                            "pageId": settings["api"],
                            "trace": [],
                        }
                    ),
                },
                headers={"User-Agent": USER_AGENT},
                raise_for_status=True,
            ) as resp:
                result = await resp.text(encoding="utf-8")

            if resp.request_info.url.path.endswith(
                "/accounts/login/select-account"
            ) or resp.request_info.url.path.endswith("Pages/ChangeAccount.aspx"):
                # we probably need to select an account as we didn't automatically go to the dashboard
                async with session.get(
                    "https://"
                    + cls.login_domain()
                    + "/api/Services/MyAccountService.svc/GetSession",
                    headers={"User-Agent": USER_AGENT},
                    raise_for_status=True,
                ) as resp:
                    result_json = await resp.json()

                # confirm no account number is set
                if result_json["accountNumber"] is None:
                    bearer_token = result_json["token"]
                    # if we don't yet have an account, look one up and set it
                    if account is None:
                        account = await cls.async_account(session, bearer_token)

                    # set the first active one
                    account_number = account["accountNumber"]

                    async with session.post(
                        "https://"
                        + cls.login_domain()
                        + "/api/Services/AccountList.svc/ViewAccount",
                        json={
                            "accountNumber": account_number,
                        },
                        headers={"User-Agent": USER_AGENT},
                        raise_for_status=True,
                    ) as resp:
                        result = await resp.text(encoding="utf-8")

        async with session.post(
            "https://"
            + cls.login_domain()
            + "/api/Services/OpowerService.svc/GetOpowerToken",
            json={},
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        ) as resp:
            result_json = await resp.json()

        # If pepco or delmarva, determine if we should use secondary subdomain
        if cls.login_domain() in ["secure.pepco.com", "secure.delmarva.com"]:
            # Get the account type & state
            if account is None:
                account = await cls.async_account(session, result_json["access_token"])

            isResidential = account["isResidential"]
            state = account["PremiseInfo"][0]["mainAddress"]["townDetail"][
                "stateOrProvince"
            ]
            _LOGGER.debug("found exelon account isResidential: %s", isResidential)
            _LOGGER.debug("found exelon account state: %s", state)

            # Determine subdomain to use by matching logic found in https://cls.login_domain()/dist/app.js
            Exelon._subdomain = cls.primary_subdomain()
            if not isResidential or state != "MD":
                Exelon._subdomain = cls.secondary_subdomain()

            _LOGGER.debug("detected exelon subdomain to be: %s", Exelon._subdomain)

        return str(result_json["access_token"])
