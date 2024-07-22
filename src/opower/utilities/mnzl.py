"""Mercury New Zealand Limited utility implementation.

This module handles the authentication and API interactions for Mercury NZ.
It uses OAuth 2.0 with PKCE for secure authentication.
"""

import base64
import hashlib
import json
import logging
import secrets
import ssl
from typing import Any, Optional, TypedDict
from urllib.parse import parse_qs, urlparse

import aiohttp

from ..exceptions import InvalidAuth
from .base import UtilityBase

_LOGGER = logging.getLogger(__name__)


class ConfigDict(TypedDict):
    """Dictionary to store configuration details for OAuth."""

    authorization_endpoint: str
    issuer: str
    token_endpoint: str


class TokenDict(TypedDict):
    """Dictionary to store OAuth tokens."""

    access_token: str


class MNZL(UtilityBase):
    """Mercury New Zealand Limited utility implementation.

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
        return "Mercury New Zealand Limited"

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
    def generate_code_verifier() -> str:
        """Generate a code verifier for PKCE."""
        return secrets.token_urlsafe(32)

    @staticmethod
    def generate_code_challenge(code_verifier: str) -> str:
        """Generate a code challenge for PKCE."""
        code_challenge_digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
        return (
            base64.urlsafe_b64encode(code_challenge_digest).decode("utf-8").rstrip("=")
        )

    @staticmethod
    async def async_login(
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        optional_mfa_secret: Optional[str],
    ) -> Optional[str]:
        """Perform the login process and return an access token."""
        ssl_context = ssl.create_default_context()
        connector = aiohttp.TCPConnector(ssl=ssl_context)
        secure_session = aiohttp.ClientSession(connector=connector)

        try:
            code_verifier = MNZL.generate_code_verifier()
            code_challenge = MNZL.generate_code_challenge(code_verifier)

            config = await MNZL._get_config(secure_session)
            auth_code = await MNZL._get_auth(
                secure_session, config, code_challenge, username, password
            )
            if auth_code is None:
                raise InvalidAuth("Failed to obtain authorization code")
            tokens = await MNZL._get_access(
                secure_session, config, auth_code, code_verifier
            )

            if tokens and "access_token" in tokens:
                return tokens["access_token"]
            else:
                raise InvalidAuth("Failed to obtain access token")

        finally:
            await secure_session.close()

    @staticmethod
    async def _get_config(session: aiohttp.ClientSession) -> ConfigDict:
        """Get the configuration from the server."""
        config_url = f"{MNZL.BASE_URL}/{MNZL.TENANT_ID}/{MNZL.POLICY}/v2.0/.well-known/openid-configuration"
        config_text, _, status = await MNZL._fetch(session, config_url)
        if status != 200 or not config_text:
            raise InvalidAuth("Failed to get configuration")
        config: ConfigDict = json.loads(config_text)
        return config

    @staticmethod
    async def _get_auth(
        session: aiohttp.ClientSession,
        config: ConfigDict,
        code_challenge: str,
        username: str,
        password: str,
    ) -> Optional[str]:
        """Get the authorization code."""
        auth_params = {
            "client_id": MNZL.CLIENT_ID,
            "response_type": "code",
            "redirect_uri": MNZL.REDIRECT_URI,
            "scope": MNZL.SCOPE_AUTH,
            "code_challenge": code_challenge,
            "code_challenge_method": "S256",
        }
        auth_content, final_url, status = await MNZL._fetch(
            session, config["authorization_endpoint"], params=auth_params
        )
        if status != 200 or not auth_content:
            raise InvalidAuth("Failed to get authorization")

        settings = MNZL._extract_settings(auth_content)
        if not settings:
            if final_url and final_url.startswith(MNZL.REDIRECT_URI):
                query = urlparse(final_url).query
                parsed_query = parse_qs(query)
                return parsed_query.get("code", [None])[0]
            return None

        await MNZL._post_credentials(
            session, config["issuer"], settings, username, password
        )
        return await MNZL._confirm_signin(session, config["issuer"], settings)

    @staticmethod
    async def _get_access(
        session: aiohttp.ClientSession,
        config: ConfigDict,
        auth_code: str,
        code_verifier: str,
    ) -> Optional[TokenDict]:
        """Get the access token."""
        token_data = {
            "client_id": MNZL.CLIENT_ID,
            "grant_type": "authorization_code",
            "code": auth_code,
            "redirect_uri": MNZL.REDIRECT_URI,
            "code_verifier": code_verifier,
            "scope": MNZL.SCOPE_ACCESS,
        }
        token_content, _, status = await MNZL._fetch(
            session, config["token_endpoint"], method="POST", data=token_data
        )
        if status != 200 or not token_content:
            raise InvalidAuth("Failed to get access token")
        tokens: TokenDict = json.loads(token_content)
        return tokens

    @staticmethod
    async def _fetch(
        session: aiohttp.ClientSession, url: str, **kwargs: Any
    ) -> tuple[Optional[str], Optional[str], int]:
        """Fetch data from a URL."""
        method = kwargs.pop("method", "GET")
        timeout = aiohttp.ClientTimeout(total=30)
        try:
            async with session.request(
                method, url, timeout=timeout, **kwargs
            ) as response:
                content = await response.text()
                return content, str(response.url), response.status
        except aiohttp.ClientError as e:
            _LOGGER.error(f"Network error occurred: {str(e)}")
            return None, None, 0

    @staticmethod
    def _extract_settings(auth_content: str) -> Optional[dict[str, Any]]:
        """Extract settings from the authorization content."""
        settings_start = auth_content.find("var SETTINGS = ")
        if settings_start == -1:
            return None
        settings_end = auth_content.find(";", settings_start)
        if settings_end == -1:
            return None
        settings_json = auth_content[settings_start + 15 : settings_end].strip()
        try:
            settings: dict[str, Any] = json.loads(settings_json)
            return settings
        except json.JSONDecodeError:
            return None

    @staticmethod
    async def _post_credentials(
        session: aiohttp.ClientSession,
        issuer: str,
        settings: dict[str, Any],
        username: str,
        password: str,
    ) -> None:
        """Post credentials to the server."""
        base_url = issuer.rsplit("/", 2)[0]
        _, _, status = await MNZL._fetch(
            session,
            f"{base_url}/{MNZL.POLICY}/{MNZL.SELF_ASSERTED_ENDPOINT}",
            method="POST",
            data={
                "tx": settings["transId"],
                "p": MNZL.POLICY,
                "request_type": "RESPONSE",
                "signInName": username,
                "password": password,
            },
            headers={"X-CSRF-TOKEN": settings["csrf"]},
        )
        if status != 200:
            raise InvalidAuth("Failed to post credentials")

    @staticmethod
    async def _confirm_signin(
        session: aiohttp.ClientSession, issuer: str, settings: dict[str, Any]
    ) -> Optional[str]:
        """Confirm the sign-in process."""
        base_url = issuer.rsplit("/", 2)[0]
        _, final_url, status = await MNZL._fetch(
            session,
            f"{base_url}/{MNZL.POLICY}/{MNZL.POLICY_CONFIRM_ENDPOINT}",
            params={
                "rememberMe": "false",
                "csrf_token": settings["csrf"],
                "tx": settings["transId"],
                "p": MNZL.POLICY,
            },
            allow_redirects=True,
        )
        if status != 200:
            raise InvalidAuth("Failed to confirm signin")
        if final_url:
            query = urlparse(final_url).query
            parsed_query = parse_qs(query)
            return parsed_query.get("code", [None])[0]
        return None
