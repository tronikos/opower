"""National Grid NY Upstate."""

from .base import UtilityBase
from .nationalgrid import NationalGrid


class NationalGridUpstate(NationalGrid, UtilityBase):
    """National Grid NY Upstate."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "National Grid (NY Upstate)"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "ngny"
