"""Public Service Company of Oklahoma (PSO)."""

from .aepbase import AEPBase
from .base import UtilityBase


class PSOklahoma(AEPBase, UtilityBase):
    """Public Service Company of Oklahoma (PSO)."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Public Service Company of Oklahoma (PSO)"

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/Chicago"

    @staticmethod
    def hostname() -> str:
        """Return the hostname for login."""
        return "psoklahoma.com"
