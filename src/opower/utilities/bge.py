"""Baltimore Gas and Electric (BGE)."""

from .base import UtilityBase
from .exelon import Exelon


class BGE(Exelon, UtilityBase):
    """Baltimore Gas and Electric (BGE)."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Baltimore Gas and Electric (BGE)"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "bgec"

    @staticmethod
    def login_domain() -> str:
        """Return the domain that hosts the login page."""
        return "secure.bge.com"
