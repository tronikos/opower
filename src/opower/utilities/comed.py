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
