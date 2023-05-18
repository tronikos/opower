"""Puget Sound Energy (PSE)."""

from html.parser import HTMLParser
import re

import aiohttp
from aiohttp.client_exceptions import ClientResponseError

from .base import UtilityBase


class PSELoginParser(HTMLParser):
    """HTML parser to extract login verification token from PSE Login page."""

    def __init__(self, *, convert_charrefs: bool = True) -> None:
        """Initialize."""
        super().__init__(convert_charrefs=convert_charrefs)
        self.verification_token = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Try to extract the verification token from the login input."""
        if tag == "input" and ("name", "__RequestVerificationToken") in attrs:
            _, token = next(filter(lambda attr: attr[0] == "value", attrs))
            self.verification_token = token


class PSEUsageParser(HTMLParser):
    """HTML parser to extract OPower bearer token from PSE Usage page."""

    _regexp = re.compile(r'var accessToken\s+=\s+["\'](?P<token>.+)["\']')

    def __init__(self, *, convert_charrefs: bool = True) -> None:
        """Initialize."""
        super().__init__(convert_charrefs=convert_charrefs)
        self.opower_access_token = None
        self._in_inline_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
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


class PSE(UtilityBase):
    """Puget Sound Energy (PSE)."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Puget Sound Energy (PSE)"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "pse"

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/Los_Angeles"

    @staticmethod
    async def login(
        session: aiohttp.ClientSession, username: str, password: str
    ) -> None:
        """Login to PSE and update the client session with OPower authorization headers."""
        login_parser = PSELoginParser()

        async with session.get("https://www.pse.com/en/login") as resp:
            login_parser.feed(await resp.text())

            if login_parser.verification_token is None:
                raise ClientResponseError(
                    resp.request_info,
                    resp.history,
                    status=403,
                    message="Failed to parse __RequestVerificationToken",
                )

        await session.post(
            "https://www.pse.com/api/pseauthentication/AsyncSignIn",
            data={
                "__RequestVerificationToken": login_parser.verification_token,
                "GenericMessage": "Incorrect username or password",
                "LockedMessage": "Account is locked",
                "ReturnUrl": "",
                "OtherPageUrl": "False",
                "Username": username,
                "Password": password,
                "RememberMe": "true",
            },
        )

        async with session.get(
            "https://www.pse.com/api/AccountSelector/GetContractAccountJson"
        ) as resp:
            if len(await resp.text()) == 0:
                raise ClientResponseError(
                    resp.request_info,
                    resp.history,
                    status=403,
                    message="Login failed",
                )

        usage_parser = PSEUsageParser()

        async with session.get(
            "https://www.pse.com/en/account-and-billing/my-usage/view-my-usage"
        ) as resp:
            usage_parser.feed(await resp.text())

            if usage_parser.opower_access_token is None:
                raise ClientResponseError(
                    resp.request_info,
                    resp.history,
                    status=403,
                    message="Failed to parse OPower bearer token",
                )

        session.headers.add(
            "authorization", f"Bearer {usage_parser.opower_access_token}"
        )

        return None
