"""Indiana Michigan Power."""

from .aepbase import AEPBase
from .base import UtilityBase


class IndianaMichiganPower(AEPBase, UtilityBase):
    """Indiana Michigan Power."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Indiana Michigan Power"

    @staticmethod
    def hostname() -> str:
        """Return the hostname for login."""
        return "indianamichiganpower.com"
