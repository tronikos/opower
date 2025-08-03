"""Duquesne Light Company (DQE)."""

import re
from html.parser import HTMLParser
from typing import Any

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
        self.opower_access_token: str | None = None
        self._in_inline_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Recognizes inline scripts."""
        if tag == "script" and next(filter(lambda attr: attr[0] == "src", attrs), None) is None:
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
        login_data: dict[str, Any],
    ) -> str:
        """Login to the utility website."""
        # Double-logins are somewhat broken if cookies stay around.
        # Some use auth.duquesnelight.com and others use duquesnelight.com (session token)
        session.cookie_jar.clear(lambda cookie: "duquesnelight.com" in cookie["domain"])
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
            "https://auth.duquesnelight.com/oauth/authorize/login",
            data={
                "grant_type": "password",
                "remember_username": True,
                "username": username,
                "password": password,
            },
            headers=headers,
            raise_for_status=False,
        ) as resp:
            if resp.status == 400:
                raise InvalidAuth(await resp.text())
            if resp.status != 200:
                resp.raise_for_status()

        usage_parser = DQEUsageParser()

        async with session.get(
            "https://www.duquesnelight.com/energy-money-savings/my-electric-use",
            headers=headers,
            raise_for_status=True,
        ) as resp:
            usage_parser.feed(await resp.text())

            if not usage_parser.opower_access_token:
                raise InvalidAuth("No OPower access token found in response")

        return usage_parser.opower_access_token
