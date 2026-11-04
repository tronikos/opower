"""Lafayette Utilities System (LUS)."""

from typing import Any

import aiohttp

from ..const import USER_AGENT
from ..exceptions import CannotConnect, InvalidAuth
from .base import UtilityBase


class LUS(UtilityBase):
    """Lafayette Utilities System (LUS).

    LUS, the municipal utility of Lafayette, Louisiana, uses the Opower Digital
    Self-Service (DSS) portal at ``dss-lus.opower.com`` for electric, water and
    wastewater. Credentials are posted to the portal's login API, which answers
    with a ``sessionToken`` used as the bearer token for later API calls.
    """

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Lafayette Utilities System (LUS)"

    def subdomain(self) -> str:
        """Return the opower.com subdomain for this utility."""
        return "lus"

    @staticmethod
    def timezone() -> str:
        """Return the timezone.

        Should match the siteTimeZoneId of the API responses.
        """
        return "America/Chicago"

    @staticmethod
    def is_dss() -> bool:
        """Check if Utility using DSS version of the portal."""
        return True

    async def async_login(
        self,
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        login_data: dict[str, Any],
    ) -> str | None:
        """Login to the utility website and return the session token."""
        session.cookie_jar.clear(lambda cookie: cookie["domain"].endswith(".opower.com"))

        async with session.post(
            "https://dss-lus.opower.com/webcenter/edge/apis/identity-management-v1/cws/v1/lus/login",
            data={"username": username, "password": password, "rememberMe": "true"},
            headers={"User-Agent": USER_AGENT},
        ) as response:
            if response.status in (400, 401, 403):
                raise InvalidAuth("Username/Password are invalid")
            response.raise_for_status()
            try:
                result = await response.json()
            except (aiohttp.ContentTypeError, ValueError) as err:
                # A non-JSON reply, e.g. a maintenance page, isn't a credential
                # problem, so don't make Home Assistant ask for the password again.
                raise CannotConnect("Unexpected response from the LUS login") from err

        token = result.get("sessionToken") if isinstance(result, dict) else None
        if not token:
            raise InvalidAuth("Login response had no sessionToken")

        # Selects the DSS version of the portal for later requests
        session.cookie_jar.update_cookies({"dssPortalCW": "1"})
        return str(token)
