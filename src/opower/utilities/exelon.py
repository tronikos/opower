"""Base class for Exelon subsidiaries."""

import json
import re

import aiohttp

from ..const import USER_AGENT
from ..exceptions import InvalidAuth


class Exelon:
    """Base class for Exelon subsidiaries."""

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
    async def async_login(
        cls, session: aiohttp.ClientSession, username: str, password: str
    ) -> str:
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
        return result["access_token"]
