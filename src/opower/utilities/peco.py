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

    @staticmethod
    def eu_domain() -> str:
        """Return the azure authentication domain for this utility."""
        return "eudapi.peco.com"

    @staticmethod
    def mobile_client() -> tuple[str, str]:
        """Return the client id and mobile id pair used by this utility."""
        return "e555f5eb-b9ec-48b8-9452-fa0ed2ddeeda", "msauth.com.exelon.mobile.peco"
