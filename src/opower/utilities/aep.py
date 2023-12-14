"""Base Abstract class for American Electric Power."""
from abc import ABC
from html.parser import HTMLParser
import logging
import re
from typing import Optional
import urllib.parse

import aiohttp

from ..const import USER_AGENT


def _get_form_action_url_and_hidden_inputs(html: str) -> tuple[str, dict[str, str]]:
    """Return the URL and hidden inputs from the single form in a page."""
    match = re.search(r'action="([^"]*)"', html)
    if not match:
        return "", {}
    action_url = match.group(1)
    inputs = {}
    for match in re.finditer(
        r'input\s*type="hidden"\s*name="([^"]*)"\s*value="([^"]*)"', html
    ):
        inputs[match.group(1)] = match.group(2)
    return action_url, inputs


class AEPLoginParser(HTMLParser):
    """HTML parser to extract login verification token from PSE Login page."""

    def __init__(self, username: str, password: str) -> None:
        """Initialize."""
        super().__init__()
        self.inputs: dict[str, str] = {}
        self.username = username
        self.password = password

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        """Try to extract the verification token from the login input."""
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
            self.inputs[name] = value


class AEPTokenParser(HTMLParser):
    """HTML parser to extract token and cookies."""

    _regexp = re.compile(r"var cookieKey = '(?P<cookieKey>\w+)'")

    def __init__(self) -> None:
        """Initialize."""
        super().__init__()
        self._in_inline_script = False
        self.cookieKey: Optional[str] = None
        self.token_url: Optional[str] = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        """Try to extract the verification token from the login input."""
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
        """Try to extract the access token from the inline script."""
        if self._in_inline_script:
            result = self._regexp.search(data)
            if result and result.group("cookieKey"):
                self.cookieKey = result.group("cookieKey")

    def handle_endtag(self, tag: str) -> None:
        """Recognizes the end of inline scripts."""
        if tag == "script":
            self._in_inline_script = False


class AEP(ABC):
    """Base class for American Electric Power Companies."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return ""

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return ""

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return ""

    @staticmethod
    def hostname() -> str:
        """Return the hostname for login."""
        return ""

    @classmethod
    async def async_login(
        cls,
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        optional_mfa_secret: Optional[str],
    ) -> None:
        """Login in AEP using user/pass and then do the SAML call to opower."""
        login_parser = AEPLoginParser(username, password)
        token_parser = AEPTokenParser()

        # Get the login page and parse the ASP.Net Form Field that have generated names
        async with session.get(
            f"https://www.{cls.hostname()}/account/usage/",
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        ) as resp:
            login_parser.feed(await resp.text())

        # Post the login page with the user credentials and get the cookieKey
        async with session.post(
            f"https://www.{cls.hostname()}/account/usage/",
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
            data=login_parser.inputs,
        ) as resp:
            token_parser.feed(await resp.text())

        async with session.get(
            f"https://{cls.subdomain()}.opower.com/ei/x/embedded-api/core.js?auth-mode=saml&ou-entity-id={token_parser.cookieKey}",
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        ) as resp:
            logging.debug("Added AEP Cookies")

        assert token_parser.token_url is not None
        client_url_callback = urllib.parse.quote_plus(
            "https:" + token_parser.token_url + "&ou-session-initiated=true", safe=""
        )
        client_url = urllib.parse.quote_plus(
            f"/x/embedded-api/redirect?client-url={client_url_callback}", safe=""
        )
        failure_url_callback = urllib.parse.quote_plus(
            "https:"
            + token_parser.token_url
            + "&ou-session-initiated=true&ou-auth-error=auth-failed",
            safe="",
        )
        failure_url = urllib.parse.quote_plus(
            f"/x/embedded-api/redirect?client-url={failure_url_callback}", safe=""
        )
        target = (
            f"https://{cls.subdomain()}.opower.com/ei/app/api/authenticate"
            + urllib.parse.quote_plus(
                f"?redirectUrl={client_url}&failureUrl={failure_url}"
            )
        )

        url = (
            "https://sso.opower.com/sp/startSSO.ping?"
            f"PartnerIdpId=AEPCustomer&TargetResource={target}"
        )

        # This section below was mostly copied from the pge.py file
        # Fetch the URL on the utility website to get RelayState and SAMLResponse.
        async with session.get(url) as resp:
            result = await resp.text()
        action_url, hidden_inputs = _get_form_action_url_and_hidden_inputs(result)
        assert action_url == "https://sso.opower.com/sp/ACS.saml2"
        assert set(hidden_inputs.keys()) == {"RelayState", "SAMLResponse"}

        # Pass them to https://sso2.opower.com/sp/ACS.saml2 to get opentoken.
        async with session.post(
            action_url,
            data=hidden_inputs,
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        ) as resp:
            result = await resp.text()
        action_url, hidden_inputs = _get_form_action_url_and_hidden_inputs(result)
        assert set(hidden_inputs.keys()) == {"opentoken"}

        # Pass it back to the utility website.
        async with session.post(
            action_url,
            data=hidden_inputs,
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        ) as resp:
            pass
