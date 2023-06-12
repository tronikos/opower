"""Baltimore Gas and Electric (BGE)."""

import json
import re

import aiohttp
from aiohttp.client_exceptions import ClientResponseError

from .base import UtilityBase


class BGE(UtilityBase):
    """Baltimore Gas and Electric (BGE)."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Baltimore Gas and Electric (BGE)"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "bgec"

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/New_York"

    @staticmethod
    async def async_login(
        session: aiohttp.ClientSession, username: str, password: str
    ) -> None:
        """Login to the utility website and authorize opower."""
        async with session.get(
            "https://secure.bge.com/Pages/Login.aspx?/login"
        ) as resp:
            result = await resp.text()
        # transId = "StateProperties=..."
        # policy = "B2C_1A_SignIn"
        # tenant = "/euazurebge.onmicrosoft.com/B2C_1A_SignIn"
        # api = "CombinedSigninAndSignup"
        settings = json.loads(re.search(r"var SETTINGS = ({.*});", result).group(1))

        async with session.post(
            "https://secure2.bge.com" + settings["hosts"]["tenant"] + "/SelfAsserted",
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
            raise ClientResponseError(
                resp.request_info,
                resp.history,
                status=403,
                message=result["message"],
            )

        async with session.get(
            "https://secure2.bge.com"
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
            "https://secure.bge.com/api/Services/OpowerService.svc/GetOpowerToken",
            json={},
        ) as resp:
            result = await resp.json()
        access_token = result["access_token"]

        session.headers.add("authorization", f"Bearer {access_token}")
