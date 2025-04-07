"""Base Abstract class for American Electric Power."""

from abc import ABC
from html.parser import HTMLParser
import re
from typing import Optional
import urllib.parse

import aiohttp

from ..const import USER_AGENT
from ..exceptions import InvalidAuth
from .helpers import async_auth_saml


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


class AEPTokenParser(HTMLParser):
    """HTML parser to extract token url and cookie."""

    _regexp = re.compile(r"var cookieKey = '(?P<cookieKey>\w+)'")

    def __init__(self) -> None:
        """Initialize."""
        super().__init__()
        self._in_inline_script = False
        self.cookieKey: Optional[str] = None
        self.token_url: Optional[str] = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        """Try to extract the token url."""
        if tag == "iframe":
            # Look for <iframe src=\"//www.aepohio.com/widgets/sso/opower?token=...&domain=www.aepohio.com\"
            for a in attrs:
                if a[0] == "src" and a[1] is not None and "opower" in a[1]:
                    self.token_url = a[1]

        # Recognizes inline scripts.
        if (
            tag == "script"
            and next(filter(lambda attr: attr[0] == "src", attrs), None) is None
        ):
            self._in_inline_script = True

    def handle_data(self, data: str) -> None:
        """Try to extract the cookie from the inline script."""
        if self._in_inline_script:
            result = self._regexp.search(data)
            if result and result.group("cookieKey"):
                self.cookieKey = result.group("cookieKey")

    def handle_endtag(self, tag: str) -> None:
        """Recognizes the end of inline scripts."""
        if tag == "script":
            self._in_inline_script = False


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
    ) -> str: # MODIFIED: Return type
        """Login in AEP using user/pass and fetch the AccessToken via AJAX endpoint.""" # MODIFIED: Docstring
        # Clear cookies before logging in again, in case old ones are still around
        session.cookie_jar.clear(lambda c: c["domain"].endswith("opower.com"))

        login_parser = AEPLoginParser(username, password)

        # Get the login page and parse the ASP.Net Form Field that have generated names
        async with session.get(
            f"https://www.{cls.hostname()}/account/usage/",
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True, # Keep True for initial GET
        ) as resp:
            text = await resp.text()
            login_parser.feed(text)

        # Post the login page with the user credentials
        post_url = f"https://www.{cls.hostname()}/account/usage/"
        async with session.post(
            post_url,
            headers={"User-Agent": USER_AGENT, "Content-Type": "application/x-www-form-urlencoded", "Referer": post_url},
            raise_for_status=False, # MODIFIED: Must be False to allow reading html below
            data=login_parser.inputs,
        ) as resp:
            html = await resp.text()
            # ADDED: Necessary check to replace raise_for_status=True functionality
            if resp.status != 200:
                raise InvalidAuth(f"Login POST failed with status {resp.status}")

        # REMOVED: token_parser logic and check

        # Keep original subdomain extraction and assertion
        match = re.search(r"https://([^.]*).opower.com", html)
        assert match # Reverted to original assert
        cls._subdomain = match.group(1)

        # REMOVED: SAML URL construction and await async_auth_saml

        # --- ADDED: New Token Fetch Logic (Minimal Version) ---
        token_url = f"https://www.{cls.hostname()}/account/oauth/ValidToken"
        token_headers = {
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/javascript, */*; q=0.01",
            "X-Requested-With": "XMLHttpRequest",
            "Referer": post_url
        }
        async with session.get(token_url, headers=token_headers, raise_for_status=True) as token_resp:
            token_data = await token_resp.json()
            # Minimal parsing/error handling - relies on structure being correct
            try:
                access_token = token_data[0]['data']['AccessToken']
                return access_token # ADDED: Return token
            except (KeyError, IndexError, TypeError) as e:
                # Raise InvalidAuth on parsing failure, as original logic would have failed too
                raise InvalidAuth("Failed to parse access token from JSON response.") from e
