"""National Grid NY Metro."""

from .base import UtilityBase
from .nationalgrid import NationalGrid


class NationalGridNYMetro(NationalGrid, UtilityBase):
    """National Grid NY Metro."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "National Grid (NY Metro)"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "ngny-gas"

    @classmethod
    def utilitycode(cls) -> str:
        """Return the utilitycode identifier for the utility."""
        return "ngbk"
