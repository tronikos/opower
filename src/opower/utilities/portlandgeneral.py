"""Portland General Electric (PGE)."""

from typing import Optional

import aiohttp

from ..const import USER_AGENT
from ..exceptions import InvalidAuth
from .base import UtilityBase


class PortlandGeneral(UtilityBase):
    """Portland General Electric (PGE)."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Portland General Electric (PGE)"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "pgn"

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
    ) -> str:
        """Login to the utility website."""
        async with session.post(
            "https://identitytoolkit.googleapis.com/v1/accounts:signInWithPassword",
            headers={
                "authority": "identitytoolkit.googleapis.com",
                "User-Agent": USER_AGENT,
                "accept": "*/*",
                "content-type": "application/json",
                "origin": "https://portlandgeneral.com",
                "referer": "https://portlandgeneral.com/",
            },
            json={
                "email": username,
                "password": password,
                "returnSecureToken": True,
            },
            params={
                "key": "AIzaSyDGQGl4SfFoD_KJTo87PboxfNmq89pifqU",  # learned from https://github.com/piekstra/portlandgeneral-api
                # If this is incorrect, the resp is 400 and indistinguishable from incorrect username or password
            },
            raise_for_status=False,
        ) as resp:
            if resp.status == 400:
                raise InvalidAuth("Username and password failed")
            result = await resp.json()

        async with session.post(
            "https://api.portlandgeneral.com/pg-token-implicit/token",
            params={
                "client_id": "VrrKnd0tw2O4zIM6vqHLYn0PxM3ZW2hY",  # learned from https://github.com/piekstra/portlandgeneral-api
                "response_type": "token",
                "redirect_uri": "",  # Not sure why this is present with an empty value
            },
            headers={
                "content-length": "0",
                "User-Agent": USER_AGENT,
                "idp_access_token": result.get("idToken"),
            },
            raise_for_status=False,
        ) as resp:
            result = await resp.json()
            if resp.status == 500:
                raise InvalidAuth(
                    "Username and Password Succeeded, but api responded with "
                    + str(result["errorResponse"])
                    + ". Code 500 could mean the client_id const is incorrect."
                )
            if "errorResponse" in result:
                raise InvalidAuth(
                    "Username and Password Succeeded, but api responded with "
                    + str(result["errorResponse"])
                )
            return str(result.get("access_token"))
