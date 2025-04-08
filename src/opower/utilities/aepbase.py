"""Base Abstract class for American Electric Power."""

from abc import ABC
from html.parser import HTMLParser
import re
from typing import Optional

import aiohttp

from ..const import USER_AGENT
from ..exceptions import InvalidAuth


class AEPLoginParser(HTMLParser):
    """HTML parser to extract login input fields."""

    def __init__(self, username: str, password: str) -> None:
        """Initialize."""
        super().__init__()
        self.inputs: dict[str, str] = {}
        self.username = username
        self.password = password
        self.password_field_found = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        """Try to extract the login input fields."""
        if tag == "input":
            name = ""
            value = ""
            for a in attrs:
                if a[0] == "name" and a[1] is not None:
                    name = a[1]
                if a[0] == "value" and a[1] is not None:
                    value = a[1]
            if "UserID" in name:
                value = self.username
            if "Password" in name:
                value = self.password
                self.password_field_found = True
            self.inputs[name] = value


class AEPBase(ABC):
    """Base Abstract class for American Electric Power."""

    _subdomain: Optional[str] = None

    @classmethod
    def subdomain(cls) -> str:
        """Return the opower.com subdomain for this utility."""
        assert cls._subdomain, "async_login not called"
        return cls._subdomain

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/New_York"

    @staticmethod
    def hostname() -> str:
        """Return the hostname for login."""
        raise NotImplementedError

    @classmethod
    async def async_login(
        cls,
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        optional_mfa_secret: Optional[str],
    ) -> str:
        """Login in AEP using user/pass and return the Opower access token."""
        # Clear cookies before logging in again, in case old ones are still around
        session.cookie_jar.clear(lambda c: c["domain"].endswith("opower.com"))

        login_parser = AEPLoginParser(username, password)

        # Get the login page and parse the ASP.Net Form Field that have generated names
        usage_url = f"https://www.{cls.hostname()}/account/usage/"
        async with session.get(
            usage_url,
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        ) as resp:
            text = await resp.text()
            login_parser.feed(text)

        # Post the login page with the user credentials
        async with session.post(
            usage_url,
            headers={
                "User-Agent": USER_AGENT,
                "Content-Type": "application/x-www-form-urlencoded",
                "Referer": usage_url,
            },
            raise_for_status=True,
            data=login_parser.inputs,
        ) as resp:
            html = await resp.text()

        match = re.search(
            r'<[^>]*?class="error"[^>]*?>.*?<p>(.*?)</p>', html, re.DOTALL
        )
        if match:
            raise InvalidAuth(match.group(1).strip())

        match = re.search(r"https://([^.]*).opower.com", html)
        assert match
        cls._subdomain = match.group(1)

        async with session.get(
            f"https://www.{cls.hostname()}/account/oauth/ValidToken",
            headers={
                "User-Agent": USER_AGENT,
                "Accept": "application/json, text/javascript, */*; q=0.01",
                "X-Requested-With": "XMLHttpRequest",
                "Referer": usage_url,
            },
            raise_for_status=True,
        ) as token_resp:
            token_data = await token_resp.json()
            return str(token_data[0]["data"]["AccessToken"])
