"""Orange & Rockland Utilities (ORU)."""

from typing import Optional

import aiohttp
from pyotp import TOTP

from ..const import USER_AGENT
from ..exceptions import InvalidAuth
from .base import UtilityBase
from .coned import ConEd

HOSTNAME = "oru.com"

class Oru(ConEd, UtilityBase):
    """Orange & Rockland Utilities (ORU)."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Orange & Rockland Utilities (ORU)"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "oru"
