"""Glendale Water and Power (GWP)."""

from typing import Optional

import aiohttp

from ..const import USER_AGENT
from .base import UtilityBase


class GlendaleWaterAndPower(UtilityBase):
    """Glendale Water and Power (GWP)."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Glendale Water and Power (GWP)"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "gwp"

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
            "https://gwp.opower.com/ei/edge/apis/user-account-control-v1/cws/v1/gwp/account/signin",
            json={
                "username": username,
                "password": password,
            },
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        ) as _:
            pass
