"""National Grid Long Island NY."""

from .base import UtilityBase
from .nationalgrid import NationalGrid


class NationalGridLI(NationalGrid, UtilityBase):
    """National Grid Long Island NY."""

    @staticmethod
    def name() -> str:
        """Return the name of the utility."""
        return "National Grid (Long Island)"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "ngli"
