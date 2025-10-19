"""Base class that each utility needs to extend."""

import abc
from typing import Any, ClassVar

import aiohttp


class UtilityBase(abc.ABC):
    """Base class that each utility needs to extend."""

    subclasses: ClassVar[list[type["UtilityBase"]]] = []

    def __init_subclass__(cls, **kwargs: Any) -> None:
        """Keep track of all subclass implementations."""
        super().__init_subclass__(**kwargs)
        cls.subclasses.append(cls)

    def __init__(self) -> None:
        """Initialize."""
        self._totp_secret: str | None = None

    @staticmethod
    @abc.abstractmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        raise NotImplementedError

    @abc.abstractmethod
    def subdomain(self) -> str:
        """Return the opower.com subdomain for this utility."""
        raise NotImplementedError

    @staticmethod
    @abc.abstractmethod
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

    def utilitycode(self) -> str:
        """Return the utilitycode identifier for the utility."""
        return self.subdomain()

    @staticmethod
    def supports_realtime_usage() -> bool:
        """Check if Utility supports realtime usage reads."""
        return False

    def set_totp_secret(self, totp_secret: str) -> None:
        """Set the TOTP secret."""
        self._totp_secret = totp_secret

    @abc.abstractmethod
    async def async_login(
        self,
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        login_data: dict[str, Any],
    ) -> str | None:
        """Login to the utility website.

        Return the Opower access token or None if this function authorizes with Opower in other ways.

        :raises InvalidAuth: if login information is incorrect
        :raises MfaChallenge: if interactive MFA is required
        :raises CannotConnect: if there is a retryable connection exception
        :raises aiohttp.ClientError: if there is a network error
        """
        raise NotImplementedError


class MfaHandlerBase(abc.ABC):
    """Abstract base class for handling interactive MFA."""

    @abc.abstractmethod
    async def async_get_mfa_options(self) -> dict[str, str]:
        """Return a dictionary of MFA options available to the user.

        The key is a stable identifier for the option, and the value is a
        user-friendly description (e.g., {"sms_1": "Text message to ******1234"}).

        The returned dictionary can be empty if no MFA options are available, i.e. the utility
        immediately asks for the code after login.
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def async_select_mfa_option(self, option_id: str) -> None:
        """Select an MFA option and trigger the code delivery.

        :raises CannotConnect: if the selection fails for reasons other than bad credentials.
        """
        raise NotImplementedError

    @abc.abstractmethod
    async def async_submit_mfa_code(self, code: str) -> dict[str, Any]:
        """Submit the user-provided code.

        On success, return login data that can be passed to async_login in order to skip MFA.
        On failure, raise InvalidAuth.

        :raises InvalidAuth: if the code is incorrect.
        """
        raise NotImplementedError
