"""Consolidated Edison (ConEd)."""

from typing import Optional

import aiohttp
from pyotp import TOTP

from ..const import USER_AGENT
from ..exceptions import InvalidAuth
from .base import UtilityBase

LOGIN_BASE = "https://www.coned.com/sitecore/api/ssc/ConEdWeb-Foundation-Login-Areas-LoginAPI/User/0"
LOGIN_HEADERS = {
    "User-Agent": USER_AGENT,
    "Referer": "https://www.coned.com/",
}
RETURN_URL = "/en/accounts-billing/my-account/energy-use"


class ConEd(UtilityBase):
    """Consolidated Edison (ConEd)."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Consolidated Edison (ConEd)"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "cned"

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/New_York"

    @staticmethod
    def accepts_mfa() -> bool:
        """Check if Utility implementations supports MFA."""
        return True

    @staticmethod
    async def async_login(
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        optional_mfa_secret: Optional[str],
    ) -> str:
        """Login to the utility website."""
        # Double-logins are somewhat broken if cookies stay around.
        # Let's clear everything except device tokens (which allow skipping 2FA)
        session.cookie_jar.clear(
            lambda cookie: cookie["domain"] == "www.coned.com"
            and cookie.key != "CE_DEVICE_ID"
        )

        async with session.post(
            LOGIN_BASE + "/Login",
            json={
                "LoginEmail": username,
                "LoginPassword": password,
                "LoginRememberMe": False,
                "ReturnUrl": RETURN_URL,
                "OpenIdRelayState": "",
            },
            headers=LOGIN_HEADERS,
            raise_for_status=True,
        ) as resp:
            result = await resp.json()
            if not result["login"]:
                raise InvalidAuth("Username/Password are invalid")

            redirectUrl = None
            if "authRedirectUrl" in result:
                redirectUrl = result["authRedirectUrl"]
            else:
                if result["newDevice"]:
                    if not result["noMfa"]:
                        if not optional_mfa_secret:
                            raise InvalidAuth(
                                "TOTP secret is required for MFA accounts"
                            )

                        mfaCode = TOTP(optional_mfa_secret).now()

                        async with session.post(
                            LOGIN_BASE + "/VerifyFactor",
                            headers=LOGIN_HEADERS,
                            json={
                                "MFACode": mfaCode,
                                "ReturnUrl": RETURN_URL,
                                "OpenIdRelayState": "",
                            },
                            raise_for_status=True,
                        ) as resp:
                            mfaResult = await resp.json()
                            if not mfaResult["code"]:
                                raise InvalidAuth(
                                    "2FA code was invalid. Is the secret wrong?"
                                )
                            redirectUrl = mfaResult["authRedirectUrl"]
                else:
                    raise InvalidAuth("Login Failed")

            assert redirectUrl
            async with session.get(
                redirectUrl,
                headers={
                    "User-Agent": USER_AGENT,
                },
                allow_redirects=True,
                raise_for_status=True,
            ) as resp:
                pass

        async with session.get(
            "https://www.coned.com/sitecore/api/ssc/ConEd-Cms-Services-Controllers-Opower/OpowerService/0/GetOPowerToken",
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        ) as resp:
            return await resp.text()
