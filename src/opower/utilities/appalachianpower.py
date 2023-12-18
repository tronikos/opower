"""Appalachian Power."""

from .aepbase import AEPBase
from .base import UtilityBase


class AppalachianPower(AEPBase, UtilityBase):
    """Appalachian Power."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Appalachian Power"

    @staticmethod
    def hostname() -> str:
        """Return the hostname for login."""
        return "appalachianpower.com"
