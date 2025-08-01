"""Base class that each utility needs to extend."""

import abc
from typing import Any, ClassVar

import aiohttp


class UtilityBase:
    """Base class that each utility needs to extend."""

    subclasses: ClassVar[list[type["UtilityBase"]]] = []
    _headless_login_service_url: str | None = None
    _totp_secret: str | None = None

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
    def accepts_totp_secret() -> bool:
        """Check if Utility accepts TOTP secret."""
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
    def requires_headless_login_service() -> bool:
        """Check if the utility requires a headless browser login service."""
        return False

    @classmethod
    def set_headless_login_service_url(cls, url: str) -> None:
        """Set the URL for the headless login service."""
        cls._headless_login_service_url = url

    @classmethod
    def set_totp_secret(cls, totp_secret: str) -> None:
        """Set the TOTP secret."""
        cls._totp_secret = totp_secret

    @staticmethod
    async def async_login(
        session: aiohttp.ClientSession,
        username: str,
        password: str,
    ) -> str | None:
        """Login to the utility website.

        Return the Opower access token or None if this function authorizes with Opower in other ways.

        :raises InvalidAuth: if login information is incorrect
        :raises MfaChallenge: if interactive MFA is required
        """
        raise NotImplementedError


class MfaHandlerBase(abc.ABC):
    """Abstract base class for handling interactive MFA."""

    @abc.abstractmethod
    async def async_get_mfa_options(self) -> dict[str, str]:
        """Return a dictionary of MFA options available to the user.

        The key is a stable identifier for the option, and the value is a
        user-friendly description (e.g., {"sms_1": "Text message to ******1234"}).
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def async_select_mfa_option(self, option_id: str) -> None:
        """Select an MFA option and trigger the code delivery.

        :raises CannotConnect: if the selection fails for reasons other than bad credentials.
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def async_submit_mfa_code(self, code: str) -> str | None:
        """Submit the user-provided code and complete the login process.

        On success, return the Opower access token (if applicable).
        On failure, raise InvalidAuth.

        :raises InvalidAuth: if the code is incorrect.
        """
        raise NotImplementedError
