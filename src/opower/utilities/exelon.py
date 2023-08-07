"""Base class for Exelon subsidiaries."""

import json
import re
import logging

import aiohttp

from ..const import USER_AGENT
from ..exceptions import InvalidAuth

_LOGGER = logging.getLogger(__file__)


class Exelon:
    """Base class for Exelon subsidiaries."""

    _access_token = None
    _subdomain = None
    _session = None

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
        return Exelon._subdomain

    @classmethod
    async def async_login(
        cls, session: aiohttp.ClientSession, username: str, password: str
    ) -> str:
        cls._session = session
        """Login to the utility website and authorize opower."""
        async with session.get(
            "https://" + cls.login_domain() + "/Pages/Login.aspx?/login",
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        ) as resp:
            result = await resp.text()

        # If we are already logged in, we get redirected to /accounts/dashboard, so skip the login
        if not resp.request_info.url.path.endswith("dashboard"):
            # transId = "StateProperties=..."
            # policy = "B2C_1A_SignIn"
            # tenant = "/euazurebge.onmicrosoft.com/B2C_1A_SignIn"
            # api = "CombinedSigninAndSignup"
            settings = json.loads(re.search(r"var SETTINGS = ({.*});", result).group(1))
            login_post_domain = resp.real_url.host

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
                result = json.loads(await resp.text())

            if result["status"] != "200":
                raise InvalidAuth(result["message"])

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

        async with session.post(
            "https://"
            + cls.login_domain()
            + "/api/Services/OpowerService.svc/GetOpowerToken",
            json={},
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        ) as resp:
            result = await resp.json()
            cls._access_token = result["access_token"]


        # Get the potential url subdomains, they can vary based on account type/location
        async with cls._session.get(
            "https://" + cls.login_domain() + "/api/Services/MyAccountService.svc/GetConfiguration",
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        ) as resp:
            data = await resp.json()

            opCo = data["opCo"].lower()
            oPowerURLBase = data["oPowerURLBase"].split(".", 1)[0].replace("https://", "")
            oPowerURLBaseJurisdiction = data["oPowerURLBaseJurisdiction"].split(".", 1)[0].replace("https://", "")
            _LOGGER.debug("found exelon opCo: %s", opCo)
            _LOGGER.debug("found exelon oPowerURLBase: %s", oPowerURLBase)
            _LOGGER.debug("found exelon oPowerURLBaseJurisdiction: %s", oPowerURLBaseJurisdiction)

        # Get the account type & state
        async with cls._session.get(
            "https://" + cls.login_domain() + "/.euapi/mobile/custom/auth/accounts",
            headers={"User-Agent": USER_AGENT, "authorization": f"Bearer {cls._access_token}"},
            raise_for_status=True,
        ) as resp:
            # returned mimetype is nonstandard, so this avoids a ContentTypeError
            response = await resp.json(content_type=None)

            #Only include active accounts (after moving, old accounts have status: "Inactive")
            #NOTE: this logic currently assumes 1 active address per account, if multiple accounts found
            #      we default to taking the first in the list. Future enhancement is to support
            #      multiple accounts (which could result in different subdomain for each)
            active_accounts = [account for account in response['data'] if account['status'] == 'Active']
            isResidential = active_accounts[0]["isResidential"]
            state = active_accounts[0]['PremiseInfo'][0]['mainAddress']['townDetail']['stateOrProvince']
            _LOGGER.debug("found exelon account isResidential: %s", isResidential)
            _LOGGER.debug("found exelon account state: %s", state)

        # Determine subdomain to use by matching logic found in https://cls.login_domain()/dist/app.js
        Exelon._subdomain = oPowerURLBase
        if('dpl' != opCo and
        'pepco' != opCo or
        not isResidential or
        'MD' != state):
            Exelon._subdomain = oPowerURLBaseJurisdiction

        _LOGGER.debug("detected exelon subdomain to be: %s", Exelon._subdomain)

        return result["access_token"]
