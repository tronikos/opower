"""Rhode Island Energy (RIEnergy)."""

from typing import Any

import aiohttp

# --- FIX: Import the USER_AGENT constant ---
from ..const import USER_AGENT
from ..exceptions import InvalidAuth
from .base import UtilityBase


class RhodeIslandEnergy(UtilityBase):
    """Rhode Island Energy (RIEnergy).

    This utility uses the Opower portal at `rienergy.opower.com`.
    Login is handled via the 'user-account-control-v1' API endpoint.
    """

    @staticmethod
    def name() -> str:
        """Return a distinct, human-readable name for this utility."""
        return "Rhode Island Energy (RIEnergy)"

    def subdomain(self) -> str:
        """Return the opower.com subdomain for this utility."""
        return "rienergy"

    def utilitycode(self) -> str:
        """Return the utilitycode identifier for the utility."""
        return "ngri"

    @staticmethod
    def timezone() -> str:
        """Return the timezone for this utility."""
        return "America/New_York"

    async def async_login(
        self,
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        login_data: dict[str, Any],
    ) -> None:
        """Authenticate against the RIEnergy Opower portal."""
        # 1. Define URLs
        base_url = f"https://{self.subdomain()}.opower.com"
        login_page_url = f"{base_url}/ei/x/sign-in-wall?source=intercepted"
        api_url = f"{base_url}/ei/edge/apis/user-account-control-v1/cws/v1/{self.utilitycode()}/account/signin"

        # 2. Execute Login
        async with session.post(
            api_url,
            json={"username": username, "password": password},
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        ) as _:
            pass
