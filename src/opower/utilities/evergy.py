"""Evergy."""

from html.parser import HTMLParser

import aiohttp

from ..exceptions import InvalidAuth
from .base import UtilityBase


class EvergyLoginParser(HTMLParser):
    """HTML parser to extract login verification token from Evergy Login page."""

    def __init__(self) -> None:
        """Initialize."""
        super().__init__()
        self.verification_token = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Try to extract the verification token from the login input."""
        if tag == "input" and ("name", "evrgaf") in attrs:
            _, token = next(filter(lambda attr: attr[0] == "value", attrs))
            self.verification_token = token


class Evergy(UtilityBase):
    """Evergy."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Evergy"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "kcpk"

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/Chicago"

    @staticmethod
    async def async_login(
        session: aiohttp.ClientSession, username: str, password: str
    ) -> None:
        """Login to the utility website and authorize opower."""
        # Evergy does not like the default user agent and will block the page. We need to make it more believable
        session.headers[
            "User-Agent"
        ] = "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/114.0.0.0"

        login_parser = EvergyLoginParser()

        async with session.get("https://www.evergy.com/log-in") as resp:
            login_parser.feed(await resp.text())

            assert (
                login_parser.verification_token
            ), "Failed to parse login verification token"

        login_payload = {
            "username": username,
            "password": password,
            "evrgaf": login_parser.verification_token,
        }

        async with session.post(
            "https://www.evergy.com/log-in",
            data=login_payload,
            allow_redirects=False,
            raise_for_status=False,
        ) as resp:
            # The response status will be 500 if verification token did not work
            if resp.status == 500:
                raise InvalidAuth("Login verification token failed")

            # Counterintuitively, if we get a 200 back, that means the login failed
            if resp.status == 200:
                raise InvalidAuth("Username and password failed")

        opower_access_token = None

        async with session.get(
            "https://www.evergy.com/api/sso/jwt", raise_for_status=False
        ) as resp:
            opower_access_token = resp.headers["jwt"]

            assert opower_access_token, "Failed to parse OPower bearer token"

        session.headers.add("authorization", f"{opower_access_token}")
