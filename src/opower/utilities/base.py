"""Base class that each utility needs to extend."""


import aiohttp


class UtilityBase:
    """Base class that each utility needs to extend."""

    subclasses: list[type["UtilityBase"]] = []

    def __init_subclass__(cls, **kwargs) -> None:
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
    async def login(
        session: aiohttp.ClientSession, username: str, password: str
    ) -> str:
        """Login to the utility website and return a URL where we can authorize opower.com.

        Any failure to login should raise ClientResponseError with status 401 or 403.
        """
        raise NotImplementedError
