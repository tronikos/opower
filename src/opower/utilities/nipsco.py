"""NIPSCO (Northern Indiana Public Service Company)."""
from typing import Any

import aiohttp

from .base import UtilityBase
from ..exceptions import InvalidAuth


class Nipsco(UtilityBase):
    """NIPSCO utility implementation."""

    @staticmethod
    def name() -> str:
        """Return the name of the utility."""
        return "Northern Indiana Public Service Company (NIPSCO)"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "nipsco"

    def utilitycode(self) -> str:
        """Return the opower.com utility code."""
        return "nie"

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/Indiana/Indianapolis"

    @staticmethod
    async def async_login(
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        login_data: dict[str, Any],
    ) -> str:
        """Login to the NIPSCO opower portal."""
        async with session.post(
            "https://nipsco.opower.com/ei/edge/apis/user-account-control-v1/cws/v1/nie/account/signin",
            json={"username": username, "password": password},
            headers={"x-requested-with": "XMLHttpRequest"},
            raise_for_status=False,
        ) as resp:
            if resp.status in (401, 403):
                raise InvalidAuth("Invalid NIPSCO credentials")
            resp.raise_for_status()

        return ""