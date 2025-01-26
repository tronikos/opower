"""Enmax."""

import logging
from typing import Optional

import aiohttp

from ..const import USER_AGENT
from ..exceptions import CannotConnect, InvalidAuth
from .base import UtilityBase

_LOGGER = logging.getLogger(__name__)


class Enmax(UtilityBase):
    """Enmax."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Enmax Energy"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "enmx"

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/Edmonton"

    @staticmethod
    async def async_login(
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        optional_mfa_secret: Optional[str],
    ) -> str:
        """Login to the utility website."""
        _LOGGER.debug("Starting enmax login")
        # Login to the utility website
        async with session.post(
            "https://myaccount.enmax.com/api/account/sign-in-auth",
            json={
                "username": username,
                "password": password,
            },
            headers={
                "User-Agent": USER_AGENT,
                "referer": "https://myaccount.enmax.com",
            },
            raise_for_status=False,
        ) as resp:
            result = await resp.json()
            if "error" in result:
                error_message = result["error"]["message"]
                # The following text will likely be displayed during maintenance periods
                if ("an error occurred retrieving or updating data") in error_message:
                    raise CannotConnect(error_message)
                else:
                    raise InvalidAuth(error_message)
            token = result["token"]

        async with session.post(
            "https://myaccount.enmax.com/api/account/access-token",
            json={
                "code": token,
            },
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        ) as resp:
            result = await resp.json()
            access_token = result["access_token"]

        async with session.get(
            f"https://myaccount.enmax.com/api/account/associated-accounts?token={access_token}",
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        ) as resp:
            result = await resp.json()
            # Only include active accounts, then take the first one in the list
            active_accounts = [
                account
                for account in result["associated_account"]["accounts"]
                if account["account"]["status"] == "active"
                or account["account"]["is_plan_active"]
            ]
            if len(active_accounts) == 0:
                raise InvalidAuth("No active accounts found")
            account_no = active_accounts[0]["account"]["account_no"]

        # Get authorization token for opower
        async with session.post(
            "https://myaccount.enmax.com/api/myenergyiq/auth",
            json={
                "account_no": account_no,
                "token": access_token,
            },
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        ) as resp:
            result = await resp.json()

        return str(result["access_token"])
