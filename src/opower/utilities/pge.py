"""Pacific Gas & Electric (PG&E)."""

import aiohttp
from aiohttp.client_exceptions import ClientResponseError

from .base import UtilityBase


class PGE(UtilityBase):
    """Pacific Gas & Electric (PG&E)."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Pacific Gas & Electric"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "pge"

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/Los_Angeles"

    @staticmethod
    async def login(
        session: aiohttp.ClientSession, username: str, password: str
    ) -> str:
        """Login to the utility website and return a URL where we can authorize opower.com."""
        # 1st way of login
        async with session.post(
            "https://www.pge.com/eimpapi/auth/login",
            json={
                "username": username,
                "password": password,
                "appName": "CustomerSSO",
            },
        ) as resp:
            result = await resp.json()
            if "errorMsg" in result:
                raise ClientResponseError(
                    resp.request_info,
                    resp.history,
                    status=403,
                    message=result["errorMsg"],
                )

        # 2nd way of login
        # async with session.get(
        #     "https://apigprd.cloud.pge.com/myaccount/v1/login",
        #     headers={
        #         "Authorization": "Basic "
        #         + base64.b64encode(f"{username}:{password}".encode()).decode(),
        #     },
        # ) as resp:
        #     await resp.json()

        # Skip the following 2 requests since emToolUrl is constant.
        # If it ever changes consider uncommenting.
        # These only work with the 2nd way of login.

        # async with session.get(
        #     "https://apigprd.cloud.pge.com/myaccount/v1/cocaccount/secure/account/retrieveMyEnergyAccounts",
        #     params=(("userId", username),),
        # ) as resp:
        #     energy_accounts = await resp.json()

        # for energy_account in energy_accounts["accounts"]:
        #     accountNumber = energy_account["accountNumber"]
        #     addressAsString = energy_account["accountAddress"]["addressAsString"]
        #     print(accountNumber)
        #     print(addressAsString)
        #     break

        # async with session.get(
        #     f"https://apigprd.cloud.pge.com/myaccount/v1/cocaccount/secure/retrieveEnergyManagementInfo/{accountNumber}/myusage"
        # ) as resp:
        #     result = await resp.json()

        # for energyManagementInfo in result["energyManagementInfoList"]:
        #     if energyManagementInfo["vendorType"] == "OPOWER":
        #         emToolUrl = energyManagementInfo["emToolUrl"]
        #         break
        # assert emToolUrl == (
        #     "https://itiamping.cloud.pge.com/idp/startSSO.ping?"
        #     "PartnerSpId=sso.opower.com&TargetResource="
        #     "https%3A%2F%2Fpge.opower.com%2Fei%2Fapp%2Fr%2Fenergy-usage-details"
        # )

        return (
            "https://itiamping.cloud.pge.com/idp/startSSO.ping?"
            "PartnerSpId=sso.opower.com&TargetResource="
            "https%3A%2F%2Fpge.opower.com%2Fei%2Fapp%2Fr%2Fenergy-usage-details"
        )
