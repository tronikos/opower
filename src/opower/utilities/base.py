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
    async def async_login(
        session: aiohttp.ClientSession, username: str, password: str
    ) -> None:
        """Login to the utility website and authorize opower.

        :raises InvalidAuth: if login information is incorrect
        """
        raise NotImplementedError
