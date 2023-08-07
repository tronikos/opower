"""PECO Energy Company (PECO)."""

from .base import UtilityBase
from .exelon import Exelon


class PECO(Exelon, UtilityBase):
    """PECO Energy Company (PECO)."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "PECO Energy Company (PECO)"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "peco"

    @staticmethod
    def login_domain() -> str:
        """Return the domain that hosts the login page."""
        return "secure.peco.com"
