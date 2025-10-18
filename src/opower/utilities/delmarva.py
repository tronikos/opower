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

    @staticmethod
    def eu_domain() -> str:
        """Return the azure authentication domain for this utility."""
        return "eudapi.delmarva.com"

    @staticmethod
    def mobile_client() -> tuple[str, str]:
        """Return the client id and mobile id pair used by this utility."""
        return "571ee0e4-c2cc-4d39-b784-6395571cb077", "msauth.com.ifactorconsulting.delmarva"
