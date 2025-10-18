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

    @staticmethod
    def eu_domain() -> str:
        """Return the azure authentication domain for this utility."""
        return "eudapi.bge.com"

    @staticmethod
    def mobile_client() -> tuple[str, str]:
        """Return the client id and mobile id pair used by this utility."""
        return "202e1b60-9ba3-4e49-ab43-a1ebd438aa97", "msauth.com.exelon.mobile.bge"
