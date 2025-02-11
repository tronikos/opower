"""Burbank Water and Power (BWP)."""

from typing import Optional

import aiohttp

from ..const import USER_AGENT
from .base import UtilityBase


class BurbankWaterAndPower(UtilityBase):
    """Burbank Water and Power (BWP)."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Burbank Water and Power (BWP)"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "bwp"

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
            "https://bwp.opower.com/ei/edge/apis/user-account-control-v1/cws/v1/bwp/account/signin",
            json={
                "username": username,
                "password": password,
            },
            headers={"User-Agent": USER_AGENT},
            raise_for_status=False,
        ) as _:
            pass
