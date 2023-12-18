"""AEP Texas."""

from .aepbase import AEPBase
from .base import UtilityBase


class AEPTexas(AEPBase, UtilityBase):
    """AEP Texas."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "AEP Texas"

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/Chicago"

    @staticmethod
    def hostname() -> str:
        """Return the hostname for login."""
        return "aeptexas.com"
