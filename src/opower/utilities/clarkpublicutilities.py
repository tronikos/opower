"""Clark Public Utilities."""

from typing import Any

import aiohttp

from ..const import USER_AGENT
from .base import UtilityBase


class ClarkPublicUtilities(UtilityBase):
    """Clark Public Utilities.

    Serves Clark County, Washington. Uses the Opower portal hosted directly
    at ``clrk.opower.com`` (no separate corporate-site SSO hop precedes it -
    the sign-in wall lives on the opower.com domain itself, at
    ``clrk.opower.com/ei/x/sign-in-wall``). This follows the same
    user-account-control-v1 signin pattern used by other utilities whose
    portal is directly opower-hosted, e.g. Burbank Water and Power (bwp.py),
    Glendale Water and Power (glendalewaterandpower.py), and Rhode Island
    Energy (rienergy.py): a JSON POST of the credentials sets an auth cookie,
    and no bearer token is returned or needed for subsequent requests.
    """

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Clark Public Utilities"

    def subdomain(self) -> str:
        """Return the opower.com subdomain for this utility."""
        return "clrk"

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/Los_Angeles"

    async def async_login(
        self,
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        login_data: dict[str, Any],
    ) -> None:
        """Login to the utility website."""
        async with session.post(
            "https://clrk.opower.com/ei/edge/apis/user-account-control-v1/cws/v1/clrk/account/signin",
            json={
                "username": username,
                "password": password,
            },
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        ) as _:
            pass
