"""Southwest Gas (SWG)."""

from typing import Any

import aiohttp

from ..const import USER_AGENT
from ..exceptions import CannotConnect, InvalidAuth
from .base import UtilityBase


class SouthwestGas(UtilityBase):
    """Southwest Gas (SWG).

    This utility uses the Opower portal at `swg.opower.com`.
    Login is handled via the 'user-account-control-v1' API endpoint.
    """

    @staticmethod
    def name() -> str:
        """Return a distinct, human-readable name for this utility."""
        return "Southwest Gas"

    def subdomain(self) -> str:
        """Return the opower.com subdomain for this utility."""
        return "swg"

    @staticmethod
    def timezone() -> str:
        """Return the timezone for this utility."""
        return "America/Phoenix"

    @staticmethod
    def is_dss() -> bool:
        """Indicate that this utility uses the DSS version of the portal."""
        return False

    async def async_login(
        self,
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        login_data: dict[str, Any],
    ) -> str | None:
        """Authenticate against the SWG Opower portal."""
        # 1. Define URLs
        base_url = f"https://{self.subdomain()}.opower.com"
        login_page_url = f"{base_url}/ei/x/sign-in-wall?source=intercepted"
        api_url = f"{base_url}/ei/edge/apis/user-account-control-v1/cws/v1/{self.subdomain()}/account/signin"

        # 2. Define Headers
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/plain, */*",
            "Accept-Language": "en-US,en;q=0.9",
        }

        # 3. Warm up the session
        # We just call the context manager to get the cookies
        async with session.get(login_page_url, headers=headers):
            pass

        # 4. Prepare Login Headers
        login_headers = headers.copy()
        login_headers.update(
            {
                "Content-Type": "application/json",
                "Origin": base_url,
                "Referer": login_page_url,
                "X-Requested-With": "XMLHttpRequest",
            }
        )

        # 5. Execute Login
        payload = {"username": username, "password": password}

        async with session.post(
            api_url,
            json=payload,
            headers=login_headers,
            raise_for_status=False,
        ) as resp:
            # A 204 means the login succeeded and the session is carried by the
            # cookie that was just set. Return None rather than a placeholder
            # string: any truthy return is used by Opower as a bearer token and
            # would be sent as "Authorization: Bearer ..." on every API call.
            if resp.status == 204:
                return None

            # Only treat an explicit rejection as bad credentials. Throttling,
            # 5xx and other failures are not something a different password
            # would fix, so they must not trigger a reauth prompt.
            if resp.status in (401, 403):
                raise InvalidAuth(f"Login failed: {resp.status} - {await resp.text()}")
            resp.raise_for_status()
            if resp.status != 200:
                raise CannotConnect(f"Unexpected status from SWG login: {resp.status}")

            try:
                result = await resp.json()
            except (aiohttp.ContentTypeError, ValueError) as exc:
                raise InvalidAuth("Unexpected response from SWG login") from exc

        # 6. Extract Token (Only if response was 200 JSON)
        token = result.get("sessionToken") or result.get("accessToken")

        if not token:
            raise InvalidAuth(f"Login failed; token not found. Response keys: {list(result.keys())}")

        return str(token)
