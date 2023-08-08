"""Delmarva Power."""

from .base import UtilityBase
from .exelon import Exelon


class Delmarva(Exelon, UtilityBase):
    """Delmarva Power."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Delmarva Power"

    @staticmethod
    def primary_subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "dpl"

    @staticmethod
    def secondary_subdomain() -> str:
        """Return the opower.com secondary subdomain for this utility."""
        return "dpld"

    @staticmethod
    def login_domain() -> str:
        """Return the domain that hosts the login page."""
        return "secure.delmarva.com"
