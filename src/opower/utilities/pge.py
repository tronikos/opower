"""Pacific Gas & Electric (PG&E)."""

import logging
from typing import Any

import aiohttp

from .base import UtilityBase
from .headless_helpers import HeadlessMfaHandler, async_headless_login

_LOGGER = logging.getLogger(__name__)


class PgeMfaHandler(HeadlessMfaHandler):
    """Handles interactive MFA for PG&E by calling the login service's JSON API."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        login_service_url: str,
        session_id: str,
        mfa_options: dict[str, Any],
    ):
        """Initialize the MFA handler."""
        super().__init__(session, login_service_url, session_id, mfa_options)


class PGE(UtilityBase):
    """Pacific Gas & Electric (PG&E)."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Pacific Gas and Electric Company (PG&E)"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "pge"

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/Los_Angeles"

    @staticmethod
    def requires_headless_login_service() -> bool:
        """Check if the utility requires a headless browser login service."""
        return True

    @classmethod
    async def async_login(
        cls,
        session: aiohttp.ClientSession,
        username: str,
        password: str,
    ) -> str:
        """Login by calling the Opower Utility Headless Login service's JSON API."""
        if not cls._headless_login_service_url:
            raise ValueError("Headless login service URL is not set.")
        _LOGGER.debug(
            "Starting PG&E login via Opower Utility Headless Login service at %s",
            cls._headless_login_service_url,
        )
        return await async_headless_login(
            session,
            cls._headless_login_service_url,
            "pge",
            username,
            password,
            PgeMfaHandler,
        )
