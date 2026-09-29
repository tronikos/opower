"""Eversource Energy."""

import base64
import hashlib
import logging
import re
import secrets
from typing import Any

import aiohttp

from ..const import USER_AGENT
from ..exceptions import CannotConnect, InvalidAuth
from .base import UtilityBase

_LOGGER = logging.getLogger(__name__)

# Okta configuration for Eversource
OKTA_CLIENT_ID = "0oarjx5m8i3r1586a1t7"
OKTA_ISSUER = "https://eversource-external.okta.com/oauth2/ausrjxam6icWYMIj41t7"


def _generate_pkce() -> tuple[str, str]:
    """Generate PKCE code_verifier and code_challenge."""
    # Generate a random code_verifier (43-128 characters)
    code_verifier = secrets.token_urlsafe(32)

    # Create code_challenge using S256 method
    code_challenge = base64.urlsafe_b64encode(hashlib.sha256(code_verifier.encode()).digest()).decode().rstrip("=")

    return code_verifier, code_challenge


class Eversource(UtilityBase):
    """Eversource Energy.

    Eversource serves customers in Connecticut, Massachusetts, and New Hampshire.
    https://www.eversource.com/

    Authentication flow:
    1. MSLogin to establish session and get OktaUsername
    2. Okta /api/v1/authn to get sessionToken
    3. PKCE OAuth flow to get Okta access_token
    4. Call getOpowerWidgetData API to get fresh Opower JWT token
    """

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Eversource"

    def subdomain(self) -> str:
        """Return the opower.com subdomain for this utility."""
        return "ever"

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/New_York"

    async def async_login(  # noqa: C901, PLR0912, PLR0915
        self,
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        login_data: dict[str, Any],
    ) -> str | None:
        """Login to the utility website and authorize opower.com for access.

        Returns the Opower access token obtained via the PKCE OAuth flow.
        """
        _LOGGER.debug("Starting Eversource login")

        # Step 1: Load the login page to get the formToken
        login_page_url = "https://www.eversource.com/security/account/Login"
        _LOGGER.debug("Fetching login page: %s", login_page_url)

        try:
            async with session.get(
                login_page_url,
                headers={"User-Agent": USER_AGENT},
                allow_redirects=True,
            ) as resp:
                if not resp.ok:
                    raise CannotConnect(f"Failed to load login page: {resp.status}")
                login_html = await resp.text()
                _LOGGER.debug("Login page loaded, length: %d", len(login_html))
        except aiohttp.ClientError as err:
            raise CannotConnect(f"Failed to connect to Eversource: {err}") from err

        # Extract the formToken from embedded JSON config in HTML
        verification_token = None
        token_match = re.search(r"&quot;formToken&quot;:&quot;([^&]+)&quot;", login_html)
        if token_match:
            verification_token = token_match.group(1)
            _LOGGER.debug("Found formToken")

        # Step 2: POST to MSLogin endpoint to establish session
        ms_login_url = "https://www.eversource.com/security/account/MSLogin"
        _LOGGER.debug("Posting credentials to MSLogin")

        json_data = {
            "WebId": username,
            "Password": password,
            "RememberID": False,
            "ReturnUrl": "/cg/customer/accountoverview",
            "MfaRememberMeData": "",
        }

        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/plain, */*",
            "Content-Type": "application/json",
            "Origin": "https://www.eversource.com",
            "Referer": login_page_url,
        }

        if verification_token:
            headers["__RequestVerificationToken"] = verification_token

        okta_username = None
        try:
            async with session.post(
                ms_login_url,
                json=json_data,
                headers=headers,
                allow_redirects=False,
            ) as resp:
                _LOGGER.debug("MSLogin response status: %s", resp.status)

                if resp.status == 200:
                    try:
                        json_response = await resp.json()
                        _LOGGER.debug("MSLogin status: %s", json_response.get("status"))

                        if json_response.get("IsSuccess"):
                            status = json_response.get("status")
                            okta_username = json_response.get("OktaUsername")

                            if status in ("SUCCESS", "MFA_ENROLL"):
                                _LOGGER.debug("Login successful, OktaUsername: %s", okta_username)
                            elif status == "MFA_REQUIRED":
                                raise InvalidAuth("MFA required - not yet supported")
                            elif status == "MFA_CHALLENGE":
                                raise InvalidAuth("MFA challenge required - not yet supported")
                        else:
                            errors = json_response.get("Errors", {})
                            if errors:
                                error_msg = next(iter(errors.values()), "Login failed")
                                error_msg = re.sub(r"<[^>]+>", "", error_msg)
                            else:
                                error_msg = "Login failed"
                            raise InvalidAuth(error_msg)

                    except (ValueError, aiohttp.ContentTypeError) as err:
                        raise CannotConnect("Unexpected response from login") from err
                else:
                    raise InvalidAuth(f"Login failed with status {resp.status}")

        except aiohttp.ClientError as err:
            raise CannotConnect(f"Login request failed: {err}") from err

        if not okta_username:
            raise InvalidAuth("Could not get OktaUsername from login response")

        # Step 3: Authenticate with Okta to get sessionToken
        _LOGGER.debug("Authenticating with Okta")
        okta_authn_url = "https://eversource-external.okta.com/api/v1/authn"

        try:
            async with session.post(
                okta_authn_url,
                json={"username": okta_username, "password": password},
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/json",
                    "Origin": "https://www.eversource.com",
                    "Referer": "https://www.eversource.com/",
                },
            ) as resp:
                if resp.status != 200:
                    raise InvalidAuth("Okta authentication failed")

                authn_response = await resp.json()
                okta_status = authn_response.get("status")
                session_token = authn_response.get("sessionToken")

                _LOGGER.debug("Okta authn status: %s", okta_status)

                if okta_status != "SUCCESS" or not session_token:
                    raise InvalidAuth(f"Okta authentication failed: {okta_status}")

        except aiohttp.ClientError as err:
            raise CannotConnect(f"Okta authentication failed: {err}") from err

        # Step 4: PKCE OAuth flow to get Okta access_token
        _LOGGER.debug("Starting PKCE OAuth flow")
        code_verifier, code_challenge = _generate_pkce()
        state = secrets.token_urlsafe(32)
        nonce = secrets.token_urlsafe(32)

        authorize_url = f"{OKTA_ISSUER}/v1/authorize"
        authorize_params = {
            "client_id": OKTA_CLIENT_ID,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
            "nonce": nonce,
            "prompt": "none",
            "redirect_uri": "https://www.eversource.com/security/account/Login",
            "response_mode": "okta_post_message",
            "response_type": "code",
            "sessionToken": session_token,
            "state": state,
            "scope": "openid email",
        }

        try:
            async with session.get(
                authorize_url,
                params=authorize_params,
                headers={
                    "Accept": "text/html",
                    "Referer": "https://www.eversource.com/",
                },
                allow_redirects=True,
            ) as resp:
                if resp.status != 200:
                    raise CannotConnect(f"OAuth authorize failed: {resp.status}")

                auth_html = await resp.text()

                # Extract the authorization code from the HTML response
                # Pattern: data.code = '\x2Dxxxx' or data.code = 'xxxx'
                code_match = re.search(r"data\.code\s*=\s*'([^']+)'", auth_html)
                if not code_match:
                    _LOGGER.error("No authorization code found in response")
                    raise InvalidAuth("OAuth authorization failed")

                # Decode any escaped characters
                auth_code = code_match.group(1).encode().decode("unicode_escape")
                _LOGGER.debug("Got authorization code")

        except aiohttp.ClientError as err:
            raise CannotConnect(f"OAuth authorize failed: {err}") from err

        # Step 5: Exchange authorization code for Okta access token
        _LOGGER.debug("Exchanging code for Okta access token")
        token_url = f"{OKTA_ISSUER}/v1/token"

        token_data = {
            "client_id": OKTA_CLIENT_ID,
            "redirect_uri": "https://www.eversource.com/security/account/Login",
            "grant_type": "authorization_code",
            "code_verifier": code_verifier,
            "code": auth_code,
        }

        try:
            async with session.post(
                token_url,
                data=token_data,
                headers={
                    "Accept": "application/json",
                    "Content-Type": "application/x-www-form-urlencoded",
                    "Origin": "https://www.eversource.com",
                    "Referer": "https://www.eversource.com/",
                },
            ) as resp:
                if resp.status != 200:
                    resp_text = await resp.text()
                    _LOGGER.error("Token exchange failed: %s", resp_text[:200])
                    raise InvalidAuth("OAuth token exchange failed")

                token_response = await resp.json()
                okta_access_token = token_response.get("access_token")

                if not okta_access_token:
                    raise InvalidAuth("No access token in response")

                _LOGGER.debug("Got Okta access token")

        except aiohttp.ClientError as err:
            raise CannotConnect(f"Token exchange failed: {err}") from err

        # Step 6: Get account ID from Eversource API
        _LOGGER.debug("Getting account information")
        account_url = "https://www.eversource.com/cg/customer/api/account"

        try:
            async with session.get(
                account_url,
                params={"pageNumber": 1, "pageSize": 5},
                headers={
                    "Authorization": f"Bearer {okta_access_token}",
                    "Accept": "application/json",
                    "User-Agent": USER_AGENT,
                },
            ) as resp:
                if resp.status != 200:
                    raise CannotConnect("Failed to get account information")

                account_response = await resp.json()
                accounts = account_response.get("Accounts", [])

                if not accounts:
                    raise InvalidAuth("No accounts found")

                account_id = accounts[0].get("BillingAccountIdentifier")
                _LOGGER.debug("Got account ID: %s", account_id)

        except aiohttp.ClientError as err:
            raise CannotConnect(f"Account lookup failed: {err}") from err

        # Step 7: Get Opower token from widget data API
        _LOGGER.debug("Getting Opower token from widget data API")
        widget_url = f"https://www.eversource.com/cg/customer/api/accountbilling/getOpowerWidgetData/{account_id}"

        try:
            async with session.get(
                widget_url,
                headers={
                    "Authorization": f"Bearer {okta_access_token}",
                    "Accept": "application/json",
                    "User-Agent": USER_AGENT,
                },
            ) as resp:
                if resp.status != 200:
                    raise CannotConnect("Failed to get Opower widget data")

                widget_response = await resp.json()
                opower_token: str | None = widget_response.get("jwtToken")

                if not opower_token:
                    raise InvalidAuth("No Opower token in widget response")

                _LOGGER.debug(
                    "Got Opower token: %s...%s (%d chars)",
                    opower_token[:10],
                    opower_token[-10:],
                    len(opower_token),
                )

                return opower_token

        except aiohttp.ClientError as err:
            raise CannotConnect(f"Widget data request failed: {err}") from err
