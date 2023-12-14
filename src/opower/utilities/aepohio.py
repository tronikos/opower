"""American Electric Power Ohio."""

from .aep import AEP
from .base import UtilityBase


class AEPOHio(AEP, UtilityBase):
    """American Electric Power Ohio."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "American Electric Power Ohio"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "aepo"

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/New_York"

    @staticmethod
    def hostname() -> str:
        """Return the hostname for login."""
        return "aepohio.com"
