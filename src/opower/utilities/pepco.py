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
    def primary_subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "pep"

    @staticmethod
    def secondary_subdomain() -> str:
        """Return the opower.com secondary subdomain for this utility."""
        return "pepd"

    @staticmethod
    def login_domain() -> str:
        """Return the domain that hosts the login page."""
        return "secure.pepco.com"
