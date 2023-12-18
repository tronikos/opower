"""Kentucky Power."""

from .aepbase import AEPBase
from .base import UtilityBase


class KentuckyPower(AEPBase, UtilityBase):
    """Kentucky Power."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Kentucky Power"

    @staticmethod
    def hostname() -> str:
        """Return the hostname for login."""
        return "kentuckypower.com"
