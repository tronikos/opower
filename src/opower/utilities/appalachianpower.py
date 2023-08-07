"""Appalachian Power (APCO)"""

from html.parser import HTMLParser
import logging

import aiohttp

from ..const import USER_AGENT
from ..exceptions import InvalidAuth
from .base import UtilityBase

_LOGGER = logging.getLogger(__file__)

class APCOLoginParser(HTMLParser):
    """HTML parser to extract login verification token from APCO Login page."""

    def __init__(self) -> None:
        """Initialize."""
        super().__init__()
        self.verification_token = None
        self.settings = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Try to extract the verification token from the login input."""
        if tag == "input" and ("type", "hidden") in attrs:
            breakpoint()
            temp = dict(attrs)
            self.settings[temp["name"]] = temp["value"]


class APCO(UtilityBase):
    """Appalachian Power (APCO)"""

    _subdomain = None

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "APCO"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        assert APCO._subdomain, "async_login not called"
        return APCO._subdomain

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/New_York"

    @staticmethod
    async def async_login(
        session: aiohttp.ClientSession, username: str, password: str
    ) -> str:
        """Login to the utility website and authorize opower."""
        login_parser = APCOLoginParser()

        async with session.get(
            "https://www.appalachianpower.com/account/login/",
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        ) as resp:
            login_parser.feed(await resp.text())

            assert (
                login_parser.settings["__EVENTVALIDATION"]
            ), "Failed to parse login verification token"

        login_payload = {
            "username": username,
            "password": password,
            "evrgaf": login_parser.settings["__EVENTVALIDATION"],
        }

        async with session.post(
            "https://www.appalachianpower.com/account/login/",
            data=login_payload,
            headers={"User-Agent": USER_AGENT},
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
            "https://www.evergy.com/api/sso/jwt",
            headers={"User-Agent": USER_AGENT},
            raise_for_status=False,
        ) as resp:
            opower_access_token = resp.headers["jwt"].removeprefix("Bearer ")

            assert opower_access_token, "Failed to parse OPower bearer token"

        async with session.get(
            "https://www.evergy.com/sc-api/account/getaccountpremiseselector",
            params={"isWidgetPage": "false", "hasNoSelector": "false"},
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        ) as resp:
            # returned mimetype is nonstandard, so this avoids a ContentTypeError
            data = await resp.json(content_type=None)
            # shape is: [{"accountNumber": 123456789, "oPowerDomain": "kcpl.opower.com", ...}]
            domain: str = data[0]["oPowerDomain"]
            APCO._subdomain = domain.split(".", 1)[0]
            _LOGGER.debug("detected Evergy subdomain: %s", APCO._subdomain)
            if APCO._subdomain not in {"kcpk", "kcpl"}:
                _LOGGER.warn(
                    "unexpected Evergy subdomain %s, continuing",
                    APCO._subdomain,
                )

        return opower_access_token
