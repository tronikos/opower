"""Mercury NZ Limited utility implementation.

This module handles the authentication and API interactions for Mercury NZ.
It uses OAuth 2.0 with PKCE for secure authentication.
"""

import logging
from typing import Optional

import aiohttp

from .base import UtilityBase
from .oidchelper import async_auth_oidc

_LOGGER = logging.getLogger(__name__)


class Mercury(UtilityBase):
    """Mercury NZ Limited utility implementation.

    This class handles the authentication and API interactions for Mercury NZ.
    It uses OAuth 2.0 with PKCE for secure authentication.
    """

    BASE_URL = "https://login.mercury.co.nz"
    TENANT_ID = "fc07dca7-cd6a-4578-952b-de7a7afaebdc"
    POLICY = "b2c_1a_signup_signin"
    CLIENT_ID = "4c8c2c47-24cd-485d-aad9-12f3d95b3ceb"
    REDIRECT_URI = "https://myaccount.mercury.co.nz"
    APPLICATION_URI = f"{BASE_URL}/aded9884-533e-4081-a4ce-87b0d4e80a45/"
    SCOPE_AUTH = "openid profile offline_access"
    SCOPE_ACCESS = f"{APPLICATION_URI}customer:write {APPLICATION_URI}customer:read openid profile offline_access"
    SELF_ASSERTED_ENDPOINT = "SelfAsserted"
    POLICY_CONFIRM_ENDPOINT = "api/CombinedSigninAndSignup/confirmed"

    @staticmethod
    def name() -> str:
        """Return the name of the utility."""
        return "Mercury NZ Limited"

    @staticmethod
    def subdomain() -> str:
        """Return the subdomain for the utility."""
        return "mercury"

    @staticmethod
    def utilitycode() -> str:
        """Return the utilitycode identifier for the utility."""
        return "meen"

    @staticmethod
    def timezone() -> str:
        """Return the timezone for the utility."""
        return "Pacific/Auckland"

    @staticmethod
    def is_dss() -> bool:
        """Check if the utility uses DSS version of the portal."""
        return False

    @staticmethod
    async def async_login(
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        optional_mfa_secret: Optional[str],
    ) -> Optional[str]:
        """Perform the login process and return an access token."""
        _LOGGER.debug("Starting login process for Mercury NZ Limited")
        return await async_auth_oidc(
            username,
            password,
            Mercury.BASE_URL,
            Mercury.TENANT_ID,
            Mercury.POLICY,
            Mercury.CLIENT_ID,
            Mercury.REDIRECT_URI,
            Mercury.SCOPE_AUTH,
            Mercury.SCOPE_ACCESS,
            Mercury.SELF_ASSERTED_ENDPOINT,
            Mercury.POLICY_CONFIRM_ENDPOINT,
        )
