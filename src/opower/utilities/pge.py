"""Pacific Gas & Electric (PG&E)."""

import re

import aiohttp

from ..exceptions import InvalidAuth
from .base import UtilityBase


def _get_form_action_url_and_hidden_inputs(html: str):
    """Return the URL and hidden inputs from the single form in a page."""
    match = re.search(r'action="([^"]*)"', html)
    if not match:
        return None, None
    action_url = match.group(1)
    inputs = {}
    for match in re.finditer(
        r'input\s*type="hidden"\s*name="([^"]*)"\s*value="([^"]*)"', html
    ):
        inputs[match.group(1)] = match.group(2)
    return action_url, inputs


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
        session: aiohttp.ClientSession, username: str, password: str
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

        url = (
            "https://itiamping.cloud.pge.com/idp/startSSO.ping?"
            "PartnerSpId=sso.opower.com&TargetResource="
            "https%3A%2F%2Fpge.opower.com%2Fei%2Fapp%2Fr%2Fenergy-usage-details"
        )

        # Fetch the URL on the utility website to get RelayState and SAMLResponse.
        async with session.get(url) as resp:
            result = await resp.text()
        action_url, hidden_inputs = _get_form_action_url_and_hidden_inputs(result)
        assert action_url == "https://sso2.opower.com/sp/ACS.saml2"
        assert set(hidden_inputs.keys()) == {"RelayState", "SAMLResponse"}

        # Pass them to https://sso2.opower.com/sp/ACS.saml2 to get opentoken.
        async with session.post(action_url, data=hidden_inputs) as resp:
            result = await resp.text()
        action_url, hidden_inputs = _get_form_action_url_and_hidden_inputs(result)
        assert set(hidden_inputs.keys()) == {"opentoken"}

        # Pass it back to the utility website.
        async with session.post(action_url, data=hidden_inputs) as resp:
            pass
