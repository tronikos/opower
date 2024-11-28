"""Consolidated Edison (ConEd)."""

from typing import Optional

import aiohttp
from pyotp import TOTP

from ..const import USER_AGENT
from ..exceptions import InvalidAuth
from .base import UtilityBase

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
    def hostname() -> str:
        """Return the hostname for login. Allows overriding it for oru.com."""
        return "coned.com"

    @staticmethod
    def supports_realtime_usage() -> bool:
        """Check if Utility supports realtime usage reads."""
        return True

    @classmethod
    async def async_login(
        cls,
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        optional_mfa_secret: Optional[str],
    ) -> str:
        """Login to the utility website."""
        hostname = cls.hostname()
        login_base = (
            "https://www."
            + hostname
            + "/sitecore/api/ssc/ConEdWeb-Foundation-Login-Areas-LoginAPI/User/0"
        )
        login_headers = {
            "User-Agent": USER_AGENT,
            "Referer": "https://www." + hostname + "/",
        }

        # Double-logins are somewhat broken if cookies stay around.
        # Let's clear everything except device tokens (which allow skipping 2FA)
        session.cookie_jar.clear(
            lambda cookie: cookie["domain"] == "www." + hostname
            and cookie.key != "CE_DEVICE_ID"
        )

        async with session.post(
            login_base + "/Login",
            json={
                "LoginEmail": username,
                "LoginPassword": password,
                "LoginRememberMe": False,
                "ReturnUrl": RETURN_URL,
                "OpenIdRelayState": "",
            },
            headers=login_headers,
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

                        mfaCode = TOTP(optional_mfa_secret.strip()).now()

                        async with session.post(
                            login_base + "/VerifyFactor",
                            headers=login_headers,
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
            "https://www."
            + hostname
            + "/sitecore/api/ssc/ConEd-Cms-Services-Controllers-Opower/OpowerService/0/GetOPowerToken",
            headers=login_headers,
            raise_for_status=True,
        ) as resp:
            return str(await resp.json())
