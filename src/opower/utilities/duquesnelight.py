"""Duquesne Light Company (DQE)."""

from html.parser import HTMLParser
import re
from typing import Optional

import aiohttp

from ..const import USER_AGENT
from ..exceptions import InvalidAuth
from .base import UtilityBase


class DQEUsageParser(HTMLParser):
    """HTML parser to extract OPower bearer token from DQE Usage page."""

    _regexp = re.compile(r'"OPowerToken": "(?P<token>.+)"')

    def __init__(self) -> None:
        """Initialize."""
        super().__init__()
        self.opower_access_token: Optional[str] = None
        self._in_inline_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        """Recognizes inline scripts."""
        if (
            tag == "script"
            and next(filter(lambda attr: attr[0] == "src", attrs), None) is None
        ):
            self._in_inline_script = True

    def handle_data(self, data: str) -> None:
        """Try to extract the access token from the inline script."""
        if self._in_inline_script:
            result = self._regexp.search(data)
            if result and result.group("token"):
                self.opower_access_token = result.group("token")

    def handle_endtag(self, tag: str) -> None:
        """Recognizes the end of inline scripts."""
        if tag == "script":
            self._in_inline_script = False


class DuquesneLight(UtilityBase):
    """Duquesne Light Company (DQE)."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Duquesne Light Company (DQE)"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "duq"

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/New_York"

    @staticmethod
    async def async_login(
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        optional_mfa_secret: Optional[str],
    ) -> str:
        """Login to the utility website."""
        # Double-logins are somewhat broken if cookies stay around.
        session.cookie_jar.clear(
            lambda cookie: cookie["domain"] == "www.duquesnelight.com"
        )
        # DQE uses Incapsula and merely passing the User-Agent is not enough.
        headers = {
            "User-Agent": USER_AGENT,
            "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
            "Accept-Language": "en-US,en;q=0.5",
            "Accept-Encoding": "gzip, deflate",
            "Connection": "keep-alive",
            "Upgrade-Insecure-Requests": "1",
            "Sec-Fetch-Dest": "document",
            "Sec-Fetch-Mode": "navigate",
            "Sec-Fetch-Site": "none",
            "Sec-Fetch-User": "?1",
            "Cache-Control": "max-age=0",
        }

        async with session.post(
            "https://www.duquesnelight.com/login/login",
            data={
                "Phone": "",
                "Email": "",
                "IsLoginOff": "false",
                "RedFlagPassword": "",
                "RememberUsername": "false",
                "Username": username,
                "Password": password,
                "RedirectUrl": "/my-account/account-summary",
                "SuppressPleaseLoginMessage": "true",
                "LoginTurnedOffMessage": "",
                "RedirectPath": "",
                "PersonId": "",
            },
            headers=headers,
            raise_for_status=True,
        ) as resp:
            # Check for failed login - DQE returns status 200 with a json body that can be parsed.
            if "invalid" in await resp.text():
                raise InvalidAuth("Login failed")

        usage_parser = DQEUsageParser()

        async with session.get(
            "https://www.duquesnelight.com/energy-money-savings/my-electric-use",
            headers=headers,
            raise_for_status=True,
        ) as resp:
            usage_parser.feed(await resp.text())

            assert (
                usage_parser.opower_access_token
            ), "Failed to parse OPower bearer token"

        return usage_parser.opower_access_token
