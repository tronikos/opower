"""Commonwealth Edison (ComEd)."""

from .base import UtilityBase
from .exelon import Exelon


class ComEd(Exelon, UtilityBase):
    """Commonwealth Edison (ComEd)."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Commonwealth Edison (ComEd)"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "cec"

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/Chicago"

    @staticmethod
    def login_domain() -> str:
        """Return the domain that hosts the login page."""
        return "secure.comed.com"

    @staticmethod
    def eu_domain() -> str:
        """Return the azure authentication domain for this utility."""
        return "eudapi.comed.com"

    @staticmethod
    def mobile_client() -> tuple[str, str]:
        """Return the client id and mobile id pair used by this utility."""
        return "b587ed2d-28a5-462c-8c1f-835f9d73f7c3", "msauth.com.comed.mobile"
