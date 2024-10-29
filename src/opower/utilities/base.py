"""Base class that each utility needs to extend."""

from typing import Any, Optional

import aiohttp


class UtilityBase:
    """Base class that each utility needs to extend."""

    subclasses: list[type["UtilityBase"]] = []

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Keep track of all subclass implementations."""
        super().__init_subclass__(**kwargs)
        cls.subclasses.append(cls)

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        raise NotImplementedError

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        raise NotImplementedError

    @staticmethod
    def timezone() -> str:
        """Return the timezone.

        Should match the siteTimeZoneId of the API responses.
        """
        raise NotImplementedError

    @staticmethod
    def accepts_mfa() -> bool:
        """Check if Utility implementations supports MFA."""
        return False

    @staticmethod
    def is_dss() -> bool:
        """Check if Utility using DSS version of the portal."""
        return False

    @classmethod
    def utilitycode(cls) -> str:
        """Return the utilitycode identifier for the utility."""
        return cls.subdomain()

    @staticmethod
    def supports_realtime_usage() -> bool:
        """Check if Utility supports realtime usage reads."""
        return False

    @staticmethod
    async def async_login(
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        optional_mfa_secret: Optional[str],
    ) -> Optional[str]:
        """Login to the utility website.

        Return the Opower access token or None if this function authorizes with Opower in other ways.

        :raises InvalidAuth: if login information is incorrect
        """
        raise NotImplementedError
