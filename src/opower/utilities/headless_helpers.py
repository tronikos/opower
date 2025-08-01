"""Helper functions for utilities that use the headless login service."""

import logging
from typing import Any

import aiohttp

from ..exceptions import CannotConnect, InvalidAuth, MfaChallenge
from .base import MfaHandlerBase

_LOGGER = logging.getLogger(__name__)


async def async_headless_login(
    session: aiohttp.ClientSession,
    login_service_url: str,
    utility_name: str,
    username: str,
    password: str,
    mfa_handler_class: type["HeadlessMfaHandler"],
) -> str:
    """Login via the headless login service."""
    payload = {"utility": utility_name, "username": username, "password": password}
    api_url = f"{login_service_url}/api/v1/login"

    try:
        async with session.post(api_url, json=payload) as resp:
            data = await resp.json()
            if resp.status == 200:
                status = data.get("status")
                if status == "success":
                    _LOGGER.debug("Login service reported success.")
                    return str(data["access_token"])
                if status == "mfa_required":
                    _LOGGER.debug("Login service requires MFA.")
                    raise MfaChallenge(
                        f"{utility_name.upper()} MFA validation required",
                        mfa_handler_class(
                            session,
                            login_service_url,
                            data["session_id"],
                            data["mfa_options"],
                        ),
                    )
                raise CannotConnect(f"Unknown success status from login service: {status}")
            # Handle 4xx, 5xx errors
            error_detail = data.get("detail") or data.get("error", "Unknown Error")
            if resp.status == 401:
                raise InvalidAuth(f"Login failed: {error_detail}")
            raise CannotConnect(f"Login failed with status {resp.status}: {error_detail}")
    except aiohttp.ClientError as err:
        raise CannotConnect(f"Could not connect to the login service: {err}") from err


class HeadlessMfaHandler(MfaHandlerBase):
    """Handles interactive MFA by calling a headless login service's JSON API."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        login_service_url: str,
        session_id: str,
        mfa_options: dict[str, Any],
    ):
        """Initialize the MFA handler."""
        self._session = session
        self._login_service_url = login_service_url
        self._session_id = session_id
        self._mfa_options = mfa_options

    async def async_get_mfa_options(self) -> dict[str, str]:
        """Return a dictionary of MFA options available to the user."""
        return self._mfa_options

    async def async_select_mfa_option(self, option_id: str) -> None:
        """Select an MFA option by calling the login service."""
        _LOGGER.debug("Selecting MFA option %s via login service.", option_id)
        payload = {"session_id": self._session_id, "method": option_id}
        api_url = f"{self._login_service_url}/api/v1/mfa/select"
        try:
            async with self._session.post(api_url, json=payload) as resp:
                if resp.status != 200:
                    data = await resp.json()
                    raise CannotConnect(f"Failed to select MFA option: {data.get('detail', 'Unknown error')}")
        except aiohttp.ClientError as err:
            raise CannotConnect(f"Could not connect to the login service for MFA select: {err}") from err

    async def async_submit_mfa_code(self, code: str) -> str | None:
        """Submit the user-provided code by calling the login service."""
        _LOGGER.debug("Submitting MFA code via login service.")
        payload = {"session_id": self._session_id, "code": code}
        api_url = f"{self._login_service_url}/api/v1/mfa/submit"
        try:
            async with self._session.post(api_url, json=payload) as resp:
                data = await resp.json()
                if resp.status == 200 and data.get("status") == "success":
                    _LOGGER.debug("MFA submission successful.")
                    return str(data["access_token"])
                # e.g. 400 for incorrect code
                raise InvalidAuth(f"MFA submission failed: {data.get('error', 'Unknown error')}")
        except aiohttp.ClientError as err:
            raise CannotConnect(f"Could not connect to the login service for MFA submit: {err}") from err
