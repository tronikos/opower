"""Orange & Rockland Utilities (ORU)."""

from .coned import ConEd


class Oru(ConEd):
    """Orange & Rockland Utilities (ORU)."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Orange & Rockland Utilities (ORU)"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "oru"

    @staticmethod
    def hostname() -> str:
        """Return the hostname for login."""
        return "oru.com"
