"""Washington Gas (WGL)."""

from typing import Any

import aiohttp

from ..const import USER_AGENT
from ..exceptions import CannotConnect, InvalidAuth
from .base import UtilityBase


class WashingtonGas(UtilityBase):
    """Washington Gas (WGL).

    Uses the Opower-hosted portal at wgl.opower.com, whose sign-in sets a
    session cookie (same API as Burbank, Clark, Glendale and RI Energy).
    """

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Washington Gas"

    def subdomain(self) -> str:
        """Return the opower.com subdomain for this utility."""
        return "wgl"

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/New_York"

    async def async_login(
        self,
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        login_data: dict[str, Any],
    ) -> None:
        """Login to the utility website."""
        async with session.post(
            "https://wgl.opower.com/ei/edge/apis/user-account-control-v1/cws/v1/wgl/account/signin",
            json={"username": username, "password": password},
            headers={"User-Agent": USER_AGENT},
            allow_redirects=False,  # never forward the password elsewhere
        ) as resp:
            if resp.status in (400, 401, 403):
                raise InvalidAuth("Username/Password are invalid")
            resp.raise_for_status()
            if resp.status >= 300:
                raise CannotConnect(f"Unexpected sign-in status {resp.status}")
