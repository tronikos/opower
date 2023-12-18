"""Southwestern Electric Power Company (SWEPCO)."""

from .aepbase import AEPBase
from .base import UtilityBase


class SWEPCO(AEPBase, UtilityBase):
    """Southwestern Electric Power Company (SWEPCO)."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Southwestern Electric Power Company (SWEPCO)"

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/Chicago"

    @staticmethod
    def hostname() -> str:
        """Return the hostname for login."""
        return "swepco.com"
