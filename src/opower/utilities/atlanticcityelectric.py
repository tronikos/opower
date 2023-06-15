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
