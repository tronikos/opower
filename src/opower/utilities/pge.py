"""Pacific Gas & Electric (PG&E)."""

from typing import Optional
import urllib.parse

import aiohttp

from ..const import USER_AGENT
from ..exceptions import InvalidAuth
from .base import UtilityBase
from .helpers import async_auth_saml


class PGE(UtilityBase):
    """Pacific Gas & Electric (PG&E)."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Pacific Gas and Electric Company (PG&E)"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "pge"

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
    ) -> None:
        """Login to the utility website."""
        # 1st way of login
        async with session.post(
            "https://www.pge.com/eimpapi/auth/login",
            json={
                "username": username,
                "password": password,
                "appName": "CustomerSSO",
            },
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        ) as resp:
            result = await resp.json()
            if "errorMsg" in result:
                raise InvalidAuth(result["errorMsg"])

        # 2nd way of login
        # async with session.get(
        #     "https://apigprd.cloud.pge.com/myaccount/v1/login",
        #     headers={
        #         "Authorization": "Basic "
        #         + base64.b64encode(f"{username}:{password}".encode()).decode(),
        #         "User-Agent": USER_AGENT,
        #     },
        #     raise_for_status=True,
        # ) as resp:
        #     await resp.json()

        # Skip the following 2 requests since emToolUrl is constant.
        # If it ever changes consider uncommenting.
        # These only work with the 2nd way of login.

        # async with session.get(
        #     "https://apigprd.cloud.pge.com/myaccount/v1/cocaccount/secure/account/retrieveMyEnergyAccounts",
        #     params=(("userId", username),),
        #     headers={"User-Agent": USER_AGENT},
        #     raise_for_status=True,
        # ) as resp:
        #     energy_accounts = await resp.json()

        # for energy_account in energy_accounts["accounts"]:
        #     accountNumber = energy_account["accountNumber"]
        #     addressAsString = energy_account["accountAddress"]["addressAsString"]
        #     print(accountNumber)
        #     print(addressAsString)
        #     break

        # async with session.get(
        #     f"https://apigprd.cloud.pge.com/myaccount/v1/cocaccount/secure/retrieveEnergyManagementInfo/{accountNumber}/myusage",
        #     headers={"User-Agent": USER_AGENT},
        #     raise_for_status=True,
        # ) as resp:
        #     result = await resp.json()

        # for energyManagementInfo in result["energyManagementInfoList"]:
        #     if energyManagementInfo["vendorType"] == "OPOWER":
        #         emToolUrl = energyManagementInfo["emToolUrl"]
        #         break

        url = (
            "https://itiamping.cloud.pge.com/idp/startSSO.ping?"
            "PartnerSpId=sso.opower.com&TargetResource="
        ) + urllib.parse.quote_plus(
            "https://pge.opower.com/ei/app/r/energy-usage-details"
        )

        await async_auth_saml(session, url)
