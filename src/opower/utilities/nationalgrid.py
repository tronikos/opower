"""Base class for National Grid subsidiaries.

This module handles the authentication and API interactions for National Grid.
It uses OAuth 2.0 with PKCE for secure authentication.
"""

import logging
from typing import Optional

import aiohttp

from .oidchelper import async_auth_oidc

_LOGGER = logging.getLogger(__name__)


class NationalGrid:
    """Base class for National Grid subsidiaries."""

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/New_York"

    BASE_URL = "https://login.nationalgrid.com"
    TENANT_ID = "0e1366c5-731c-42b3-90d3-508039d9e70f"
    POLICY = "B2C_1A_UWP_NationalGrid_convert_merge_signin"
    CLIENT_ID = "36488660-e86a-4a0d-8316-3df49af8d06d"
    REDIRECT_URI = "https://myaccount.nationalgrid.com/auth-landing"
    APPLICATION_URI = f"{BASE_URL}/"
    SCOPE_AUTH = "openid profile offline_access"
    SCOPE_ACCESS = f"{CLIENT_ID} openid profile offline_access"
    SELF_ASSERTED_ENDPOINT = "SelfAsserted"
    POLICY_CONFIRM_ENDPOINT = "api/CombinedSigninAndSignup/confirmed"

    @staticmethod
    async def async_login(
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        optional_mfa_secret: Optional[str],
    ) -> Optional[str]:
        """Perform the login process and return an access token."""
        _LOGGER.debug("Starting login process for National Grid")
        return await async_auth_oidc(
            username,
            password,
            NationalGrid.BASE_URL,
            NationalGrid.TENANT_ID,
            NationalGrid.POLICY,
            NationalGrid.CLIENT_ID,
            NationalGrid.REDIRECT_URI,
            NationalGrid.SCOPE_AUTH,
            NationalGrid.SCOPE_ACCESS,
            NationalGrid.SELF_ASSERTED_ENDPOINT,
            NationalGrid.POLICY_CONFIRM_ENDPOINT,
        )
