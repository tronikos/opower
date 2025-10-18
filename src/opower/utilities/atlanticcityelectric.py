"""Atlantic City Electric."""

from .base import UtilityBase
from .exelon import Exelon


class AtlanticCityElectric(Exelon, UtilityBase):
    """Atlantic City Electric."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Atlantic City Electric"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "ace"

    @staticmethod
    def login_domain() -> str:
        """Return the domain that hosts the login page."""
        return "secure.atlanticcityelectric.com"

    @staticmethod
    def eu_domain() -> str:
        """Return the azure authentication domain for this utility."""
        return "eudapi.atlanticcityelectric.com"

    @staticmethod
    def mobile_client() -> tuple[str, str]:
        """Return the client id and mobile id pair used by this utility."""
        return "64930d53-e888-45f9-9b02-aeed39ba48ca", "msauth.com.ifactorconsulting.acelectric"
