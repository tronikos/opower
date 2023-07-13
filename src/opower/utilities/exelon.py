"""Base class for Exelon subsidiaries."""

import json
import re

import aiohttp

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
    ) -> None:
        """Login to the utility website and authorize opower."""
        async with session.get(
            "https://" + cls.login_domain() + "/Pages/Login.aspx?/login"
        ) as resp:
            result = await resp.text()
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
            },
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
        ) as resp:
            result = await resp.text()

        async with session.post(
            "https://"
            + cls.login_domain()
            + "/api/Services/OpowerService.svc/GetOpowerToken",
            json={},
        ) as resp:
            result = await resp.json()
        access_token = result["access_token"]

        session.headers.add("authorization", f"Bearer {access_token}")
