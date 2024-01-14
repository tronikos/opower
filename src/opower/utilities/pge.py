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

        url = (
            "https://itiamping.cloud.pge.com/idp/startSSO.ping?"
            "PartnerSpId=sso.opower.com&TargetResource="
        ) + urllib.parse.quote_plus(
            "https://pge.opower.com/ei/app/r/energy-usage-details"
        )

        await async_auth_saml(session, url)
