"""Potomac Electric Power Company (Pepco)."""

from .base import UtilityBase
from .exelon import Exelon


class Pepco(Exelon, UtilityBase):
    """Potomac Electric Power Company (Pepco)."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Potomac Electric Power Company (Pepco)"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "pep"

    @staticmethod
    def login_domain() -> str:
        """Return the domain that hosts the login page."""
        return "secure.pepco.com"
