"""Consolidated Edison (ConEd)."""

from typing import Any

import aiohttp
from pyotp import TOTP
from yarl import URL

from ..const import USER_AGENT
from ..exceptions import CannotConnect, InvalidAuth
from .base import UtilityBase

RETURN_URL = "/en/accounts-billing/my-account/energy-use"
DEVICE_COOKIE = "CE_DEVICE_ID"


class ConEd(UtilityBase):
    """Consolidated Edison (ConEd)."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Consolidated Edison (ConEd)"

    def subdomain(self) -> str:
        """Return the opower.com subdomain for this utility."""
        return "cned"

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/New_York"

    @staticmethod
    def accepts_totp_secret() -> bool:
        """Check if Utility accepts TOTP secret."""
        return True

    @staticmethod
    def hostname() -> str:
        """Return the hostname for login. Allows overriding it for oru.com."""
        return "coned.com"

    def base_url(self) -> str:
        """Return the website base URL. Overridable so tests can point at a local server."""
        return "https://www." + self.hostname()

    @staticmethod
    def supports_realtime_usage() -> bool:
        """Check if Utility supports realtime usage reads."""
        return True

    async def async_login(
        self,
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        login_data: dict[str, Any],
    ) -> str:
        """Login to the utility website and return the Opower access token.

        The login runs on a private session whose cookie jar does not quote
        cookie values: aiohttp quotes values containing characters such as
        '=' by default, and coned.com then rejects the Okta authorization code
        (it answers the code exchange by expiring its session cookies). Only the
        device cookie (which lets a remembered device skip 2FA) is carried
        between the caller's session and the private one.
        """
        base = self.base_url()
        base_url = URL(base)
        # filter_cookies does domain matching, so a Domain=.coned.com cookie counts.
        device = session.cookie_jar.filter_cookies(base_url).get(DEVICE_COOKIE)
        jar = aiohttp.CookieJar(quote_cookie=False)
        if device is not None:
            jar.update_cookies({DEVICE_COOKIE: device.value}, base_url)
        # Reuse the caller's connector (TLS, proxy, connection limits) without owning it.
        connector = session.connector
        try:
            async with aiohttp.ClientSession(
                connector=connector,
                connector_owner=connector is None,
                cookie_jar=jar,
                headers={"User-Agent": USER_AGENT},
                trust_env=session.trust_env,
                timeout=session.timeout,
            ) as login_session:
                return await self._async_login(login_session, base, username, password)
        finally:
            # Keep the device cookie even if a later step failed, as the shared
            # session did before. Copy the whole Morsel so domain, expiry and
            # Secure are kept.
            for cookie in jar:
                if cookie.key == DEVICE_COOKIE:
                    session.cookie_jar.update_cookies([(cookie.key, cookie)], base_url)

    async def _async_login(
        self,
        session: aiohttp.ClientSession,
        base: str,
        username: str,
        password: str,
    ) -> str:
        login_base = base + "/sitecore/api/ssc/ConEdWeb-Foundation-Login-Areas-LoginAPI/User/0"
        login_headers = {"Referer": base + "/en/login"}
        # The login page sets the pre-login session cookies the Login API expects.
        async with session.get(base + "/en/login", raise_for_status=True):
            pass

        async with session.post(
            login_base + "/Login",
            json={
                "LoginEmail": username,
                "LoginPassword": password,
                "LoginRememberMe": False,
                "ReturnUrl": "",
                "FromURI": "",
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
        elif result["newDevice"]:
            # With noMfa and no authRedirectUrl there is nothing to follow, so the
            # redirect URL check below raises; that response has not been observed.
            if not result["noMfa"]:
                if not self._totp_secret:
                    raise InvalidAuth("TOTP secret is required for MFA accounts")

                async with session.post(
                    login_base + "/VerifyFactor",
                    headers=login_headers,
                    json={
                        "MFACode": TOTP(self._totp_secret).now(),
                        "ReturnUrl": "",
                        "FromURI": "",
                        "OpenIdRelayState": "",
                    },
                    raise_for_status=True,
                ) as resp:
                    mfaResult = await resp.json()
                if not mfaResult["code"]:
                    raise InvalidAuth("2FA code was invalid. Is the secret wrong?")
                redirectUrl = mfaResult["authRedirectUrl"]
        else:
            raise InvalidAuth("Login Failed")

        if not redirectUrl:
            raise CannotConnect("ConEd login did not return a redirect URL")
        # Okta authorize -> coned.com/?code=... (the site exchanges the code server-side).
        async with session.get(redirectUrl, allow_redirects=True, raise_for_status=True):
            pass

        # The Opower token is only minted after a second Okta round that the
        # energy-use page starts (state=opower|...); visiting it performs that round.
        async with session.get(base + RETURN_URL, allow_redirects=True, raise_for_status=True) as resp:
            if "/login" in resp.url.path:
                raise CannotConnect("ConEd session was not established after login")

        async with session.get(
            base + "/sitecore/api/ssc/ConEd-Cms-Services-Controllers-Opower/OpowerService/0/GetOPowerToken",
            headers={"Referer": base + RETURN_URL},
            raise_for_status=True,
        ) as resp:
            token = await resp.json()
        if not token:
            raise CannotConnect("ConEd did not return an Opower token")
        return str(token)
