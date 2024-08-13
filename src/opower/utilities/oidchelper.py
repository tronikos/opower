"""OIDC Login Helper and its constituent functions."""

import base64
import hashlib
import json
import logging
import secrets
import ssl
from typing import Any, Optional, TypedDict
from urllib.parse import parse_qs, urlparse

import aiohttp

from ..exceptions import CannotConnect, InvalidAuth

_LOGGER = logging.getLogger(__name__)


async def async_auth_oidc(
    username: str,
    password: str,
    base_url: str,
    tenant_id: str,
    policy: str,
    client_id: str,
    redirect_uri: str,
    scope_auth: str,
    scope_access: str,
    self_asserted_endpoint: str,
    policy_confirm_endpoint: str,
) -> Optional[str]:
    """Perform the login process and return an access token."""
    ssl_context = ssl.create_default_context()
    connector = aiohttp.TCPConnector(ssl=ssl_context)
    secure_session = aiohttp.ClientSession(connector=connector)
    try:
        code_verifier = _generate_code_verifier()
        code_challenge = _generate_code_challenge(code_verifier)
        _LOGGER.debug("Generated PKCE code verifier and challenge")
        config = await _get_config(secure_session, base_url, tenant_id, policy)
        _LOGGER.debug("Retrieved OAuth configuration")
        auth_code = await _get_auth(
            secure_session,
            config,
            code_challenge,
            username,
            password,
            client_id,
            redirect_uri,
            scope_auth,
            policy,
            self_asserted_endpoint,
            policy_confirm_endpoint,
        )
        if auth_code is None:
            _LOGGER.error("Failed to obtain authorization code")
            raise CannotConnect("Failed to obtain authorization code")
        _LOGGER.debug("Obtained authorization code")

        tokens = await _get_access(
            secure_session,
            config,
            auth_code,
            code_verifier,
            client_id,
            redirect_uri,
            scope_access,
        )

        if tokens and "access_token" in tokens:
            _LOGGER.debug("Successfully obtained access token")
            return tokens["access_token"]
        else:
            _LOGGER.error("Failed to obtain access token")
            raise CannotConnect("Failed to obtain access token")

    except aiohttp.ClientError as err:
        _LOGGER.error("Connection error during login: %s", str(err))
        raise CannotConnect(f"Connection error: {err}")
    finally:
        await secure_session.close()


class ConfigDict(TypedDict):
    """Dictionary to store configuration details for OAuth."""

    authorization_endpoint: str
    issuer: str
    token_endpoint: str


class TokenDict(TypedDict):
    """Dictionary to store OAuth tokens."""

    access_token: str


def _generate_code_verifier() -> str:
    """Generate a code verifier for PKCE."""
    return secrets.token_urlsafe(32)


def _generate_code_challenge(code_verifier: str) -> str:
    """Generate a code challenge for PKCE."""
    code_challenge_digest = hashlib.sha256(code_verifier.encode("utf-8")).digest()
    return base64.urlsafe_b64encode(code_challenge_digest).decode("utf-8").rstrip("=")


async def _get_config(
    session: aiohttp.ClientSession, base_url: str, tenant_id: str, policy: str
) -> ConfigDict:
    """Get the configuration from the server."""
    config_url = (
        f"{base_url}/{tenant_id}/{policy}/v2.0/.well-known/openid-configuration"
    )
    _LOGGER.debug("Fetching OAuth configuration from: %s", config_url)
    config_text, _, status = await _fetch(session, config_url)
    if status != 200 or not config_text:
        _LOGGER.error("Failed to get configuration. Status: %s", status)
        raise CannotConnect("Failed to get configuration")
    config: ConfigDict = json.loads(config_text)
    return config


async def _get_auth(
    session: aiohttp.ClientSession,
    config: ConfigDict,
    code_challenge: str,
    username: str,
    password: str,
    client_id: str,
    redirect_uri: str,
    scope_auth: str,
    policy: str,
    self_asserted_endpoint: str,
    policy_confirm_endpoint: str,
) -> Optional[str]:
    """Get the authorization code."""
    auth_params = {
        "client_id": client_id,
        "response_type": "code",
        "redirect_uri": redirect_uri,
        "scope": scope_auth,
        "code_challenge": code_challenge,
        "code_challenge_method": "S256",
    }
    _LOGGER.debug("Requesting authorization code")
    auth_content, final_url, status = await _fetch(
        session, config["authorization_endpoint"], params=auth_params
    )
    if status != 200 or not auth_content:
        _LOGGER.error("Failed to get authorization. Status: %s", status)
        raise CannotConnect("Failed to get authorization")

    settings = _extract_settings(auth_content)
    if not settings:
        _LOGGER.debug("No settings extracted, checking for direct authorization code")
        if final_url and final_url.startswith(redirect_uri):
            query = urlparse(final_url).query
            parsed_query = parse_qs(query)
            return parsed_query.get("code", [None])[0]
        return None

    _LOGGER.debug("Posting credentials")
    await _post_credentials(
        session,
        config["issuer"],
        settings,
        username,
        password,
        policy,
        self_asserted_endpoint,
    )
    _LOGGER.debug("Confirming sign-in")
    return await _confirm_signin(
        session, config["issuer"], settings, policy, policy_confirm_endpoint
    )


async def _get_access(
    session: aiohttp.ClientSession,
    config: ConfigDict,
    auth_code: str,
    code_verifier: str,
    client_id: str,
    redirect_uri: str,
    scope_access: str,
) -> Optional[TokenDict]:
    """Get the access token."""
    token_data = {
        "client_id": client_id,
        "grant_type": "authorization_code",
        "code": auth_code,
        "redirect_uri": redirect_uri,
        "code_verifier": code_verifier,
        "scope": scope_access,
    }
    _LOGGER.debug("Requesting access token")
    token_content, _, status = await _fetch(
        session, config["token_endpoint"], method="POST", data=token_data
    )
    if status != 200 or not token_content:
        _LOGGER.error("Failed to get access token. Status: %s", status)
        raise CannotConnect("Failed to get access token")
    tokens: TokenDict = json.loads(token_content)
    return tokens


async def _fetch(
    session: aiohttp.ClientSession, url: str, **kwargs: Any
) -> tuple[Optional[str], Optional[str], int]:
    """Fetch data from a URL."""
    method = kwargs.pop("method", "GET")
    timeout = aiohttp.ClientTimeout(total=30)
    try:
        _LOGGER.debug("Fetching URL: %s, Method: %s", url, method)
        async with session.request(method, url, timeout=timeout, **kwargs) as response:
            content = await response.text()
            _LOGGER.debug("Fetch completed. Status: %s", response.status)
            return content, str(response.url), response.status
    except aiohttp.ClientError as e:
        _LOGGER.error("Network error occurred: %s", str(e))
        return None, None, 0


def _extract_settings(auth_content: str) -> Optional[dict[str, Any]]:
    """Extract settings from the authorization content."""
    _LOGGER.debug("Extracting settings from authorization content")
    settings_start = auth_content.find("var SETTINGS = ")
    if settings_start == -1:
        _LOGGER.debug("Settings not found in authorization content")
        return None
    settings_end = auth_content.find(";", settings_start)
    if settings_end == -1:
        _LOGGER.debug("End of settings not found in authorization content")
        return None
    settings_json = auth_content[settings_start + 15 : settings_end].strip()
    try:
        settings: dict[str, Any] = json.loads(settings_json)
        _LOGGER.debug("Settings successfully extracted")
        return settings
    except json.JSONDecodeError:
        _LOGGER.error("Failed to parse settings JSON")
        return None


async def _post_credentials(
    session: aiohttp.ClientSession,
    issuer: str,
    settings: dict[str, Any],
    username: str,
    password: str,
    policy: str,
    self_asserted_endpoint: str,
) -> None:
    """Post credentials to the server."""
    base_url = issuer.rsplit("/", 2)[0]
    _LOGGER.debug("Posting credentials to %s", base_url)
    _, _, status = await _fetch(
        session,
        f"{base_url}/{policy}/{self_asserted_endpoint}",
        method="POST",
        data={
            "tx": settings["transId"],
            "p": policy,
            "request_type": "RESPONSE",
            "signInName": username,
            "password": password,
        },
        headers={"X-CSRF-TOKEN": settings["csrf"]},
    )
    if status != 200:
        _LOGGER.error("Failed to post credentials. Status: %s", status)
        raise InvalidAuth("Invalid username or password")
    _LOGGER.debug("Credentials posted successfully")


async def _confirm_signin(
    session: aiohttp.ClientSession,
    issuer: str,
    settings: dict[str, Any],
    policy: str,
    policy_confirm_endpoint: str,
) -> Optional[str]:
    """Confirm the sign-in process."""
    base_url = issuer.rsplit("/", 2)[0]
    _LOGGER.debug("Confirming sign-in at %s", base_url)
    _, final_url, status = await _fetch(
        session,
        f"{base_url}/{policy}/{policy_confirm_endpoint}",
        params={
            "rememberMe": "false",
            "csrf_token": settings["csrf"],
            "tx": settings["transId"],
            "p": policy,
        },
        allow_redirects=True,
    )
    if status != 200:
        _LOGGER.error("Failed to confirm signin. Status: %s", status)
        raise CannotConnect("Failed to confirm signin")
    if final_url:
        query = urlparse(final_url).query
        parsed_query = parse_qs(query)
        auth_code = parsed_query.get("code", [None])[0]
        if auth_code:
            _LOGGER.debug("Sign-in confirmed, authorization code obtained")
        else:
            _LOGGER.warning("Sign-in confirmed, but no authorization code found")
        return auth_code
    _LOGGER.warning("Sign-in confirmation did not result in a final URL")
    return None
