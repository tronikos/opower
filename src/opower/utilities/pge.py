"""Pacific Gas & Electric (PG&E)."""

from typing import Optional
from urllib.parse import urlencode, urljoin

import aiohttp

from ..const import USER_AGENT
from ..exceptions import InvalidAuth
from .base import UtilityBase
from .helpers import async_follow_forms, get_form_action_url_and_hidden_inputs


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

        url = ("https://itiamping.cloud.pge.com/idp/startSSO.ping?") + urlencode(
            {
                "PartnerSpId": "https://idcs-36179eb69d904488aa3a9e0b7306d3fe.identity.oraclecloud.com:443/fed",
                "TargetResource": "https://pge.opower.com/ei/app/r/energy-usage-details",
            }
        )
        async with session.get(
            url,
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        ) as resp:
            result = await resp.text()
        action_url, _ = get_form_action_url_and_hidden_inputs(result)

        async with session.get(
            urljoin(url, action_url),
            params={"pfidpadapterid": "ad..EIMPCustomerSSO"},
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        ) as resp:
            result = await resp.text()
        await async_follow_forms(session, url, result)
