"""Evergy."""

import json
import logging
from html.parser import HTMLParser
from typing import Any

import aiohttp

from ..const import USER_AGENT
from ..exceptions import InvalidAuth
from .base import UtilityBase

_LOGGER = logging.getLogger(__file__)


class EvergyDavinciWidgetParser(HTMLParser):
    """HTML parser to extract Davinci api and flow data for PingOne Authentication."""

    def __init__(self) -> None:
        """Initialize."""
        super().__init__()
        self.data: dict[str, str] = {}

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Recognizes data-davinci attrs from davinci-widget-wrapper class."""
        if tag == "div" and ("class", "davinci-widget-wrapper") in attrs:
            _, token = next(filter(lambda attr: attr[0] == "data-davinci-company-id", attrs))
            self.data["company_id"] = str(token)
            _, token = next(filter(lambda attr: attr[0] == "data-davinci-sk-api-key", attrs))
            self.data["sk_api_key"] = str(token)
            _, token = next(filter(lambda attr: attr[0] == "data-davinci-api-root", attrs))
            self.data["api_root"] = str(token)
            _, token = next(filter(lambda attr: attr[0] == "data-davinci-policy-id", attrs))
            self.data["policy_id"] = str(token)
            _, token = next(filter(lambda attr: attr[0] == "data-davinci-post-processing-api", attrs))
            self.data["post_processing_api"] = str(token)
            _, token = next(filter(lambda attr: attr[0] == "data-davinci-datasource-item-id", attrs))
            self.data["datasource_item_id"] = str(token)


class EvergyLoginHandler:
    """Handle davinci widget authentication for Evergy Login page."""

    def __init__(self, session: aiohttp.ClientSession) -> None:
        """Initialize."""
        self.session = session
        self.auth_data: dict[str, str]
        self.access_token: str
        self.connectionId: str
        self.interactionId: str
        self.flowId: str
        self.ID: str

    async def get_auth_data(self) -> None:
        """Parse davinci widget for api data."""
        parse_auth_data = EvergyDavinciWidgetParser()

        login_page_url = "https://www.evergy.com/log-in"

        _LOGGER.debug("Fetching Evergy login page: %s", login_page_url)

        async with self.session.get(
            login_page_url,
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        ) as resp:
            parse_auth_data.feed(await resp.text())
            self.auth_data = parse_auth_data.data

            assert self.auth_data, "Failed to get davinci widget data"

    async def get_sdktoken(self) -> None:
        """First get the access_token."""
        login_sdktoken_url = (
            self.auth_data["api_root"].replace("auth", "orchestrate-api")
            + "/v1/company/"
            + self.auth_data["company_id"]
            + "/sdktoken"
        )

        _LOGGER.debug("Fetching Evergy login page: %s", login_sdktoken_url)

        async with self.session.get(
            login_sdktoken_url,
            headers={"User-Agent": USER_AGENT, "x-sk-api-key": self.auth_data["sk_api_key"]},
            raise_for_status=True,
        ) as resp:
            data = await resp.json()
            self.access_token = data["access_token"]

    async def start_flow(self) -> None:
        """Start the davinci widget flow."""
        login_start_url = (
            self.auth_data["api_root"]
            + "/"
            + self.auth_data["company_id"]
            + "/davinci/policy/"
            + self.auth_data["policy_id"]
            + "/start"
        )

        _LOGGER.debug("Fetching start page for davinci flow: %s", login_start_url)

        async with self.session.get(
            login_start_url,
            headers={
                "User-Agent": USER_AGENT,
                "Authorization": "Bearer " + self.access_token,
            },
            raise_for_status=True,
        ) as resp:
            data = await resp.json()
            self.ID = data["id"]
            self.connectionId = data["connectionId"]
            self.interactionId = data["interactionId"]
            self.flowId = data["flowId"]

    async def get_login_form(self) -> None:
        """Retrieve submit form."""
        login_template_url = (
            self.auth_data["api_root"]
            + "/"
            + self.auth_data["company_id"]
            + "/davinci/connections/"
            + self.connectionId
            + "/capabilities/customHTMLTemplate"
        )

        _LOGGER.debug("Fetching login template page: %s", login_template_url)
        async with self.session.post(
            login_template_url,
            headers={
                "User-Agent": USER_AGENT,
                "Content-Type": "application/json",
                "interactionId": self.interactionId,
                "Origin": "https://www.evergy.com",
            },
            data=json.dumps(
                {
                    "id": self.ID,
                    "eventName": "continue",
                }
            ),
            raise_for_status=True,
        ) as resp:
            data = await resp.json()
            self.ID = data["id"]

    async def submit_login_form(self, username: str, password: str) -> None:
        """Login to the utility website."""
        login_template_url = (
            self.auth_data["api_root"]
            + "/"
            + self.auth_data["company_id"]
            + "/davinci/connections/"
            + self.connectionId
            + "/capabilities/customHTMLTemplate"
        )

        _LOGGER.debug("Submit login data to template page: %s", login_template_url)

        async with self.session.post(
            login_template_url,
            headers={
                "User-Agent": USER_AGENT,
                "Content-Type": "application/json",
                "Origin": "https://www.evergy.com",
            },
            data=json.dumps(
                {
                    "id": self.ID,
                    "nextEvent": {
                        "constructType": "skEvent",
                        "eventName": "continue",
                        "params": [],
                        "eventType": "post",
                        "postProcess": {},
                    },
                    "parameters": {
                        "buttonType": "form-submit",
                        "buttonValue": "submit",
                        "username": username,
                        "password": password,
                    },
                    "eventName": "continue",
                }
            ),
            allow_redirects=False,
            raise_for_status=True,
        ) as resp:
            data = await resp.json()
            """If the submitted login form returns a different flowId, then the username doesn't exist."""
            if data["flowId"] != self.flowId:
                raise InvalidAuth("No such username. Login failed.")
            """If the submitted login form returns the same ID, then the password isn't correct."""
            if data["id"] == self.ID:
                raise InvalidAuth("Wrong password. Login failed.")
            self.ID = data["id"]

    async def get_new_connection_id(self) -> None:
        """Retrieve new connection id."""
        login_template_url = (
            self.auth_data["api_root"]
            + "/"
            + self.auth_data["company_id"]
            + "/davinci/connections/"
            + self.connectionId
            + "/capabilities/customHTMLTemplate"
        )

        _LOGGER.debug("Fetching login template page: %s", login_template_url)

        async with self.session.post(
            login_template_url,
            headers={
                "User-Agent": USER_AGENT,
                "Content-Type": "application/json",
                "Origin": "https://www.evergy.com",
            },
            data=json.dumps({"id": self.ID, "eventName": "continue"}),
            raise_for_status=True,
        ) as resp:
            data = await resp.json()
            self.ID = data["id"]
            self.connectionId = data["connectionId"]

    async def get_new_connection_cookie(self) -> None:
        """Set complete to generate cookie."""
        login_set_cookie_url = (
            self.auth_data["api_root"]
            + "/"
            + self.auth_data["company_id"]
            + "/davinci/connections/"
            + self.connectionId
            + "/capabilities/setCookieWithoutUser"
        )

        _LOGGER.debug("Start setCookieWithoutUser processing with new connectionId: %s", login_set_cookie_url)

        async with self.session.post(
            login_set_cookie_url,
            headers={
                "User-Agent": USER_AGENT,
                "Content-Type": "application/json",
            },
            data=json.dumps(
                {
                    "eventName": "complete",
                    "parameters": {},
                    "id": self.ID,
                }
            ),
            raise_for_status=True,
        ) as resp:
            data = await resp.json()
            self.ID = data["id"]

    async def get_new_access_token(self) -> None:
        """Set cookie and generate new access_token."""
        login_set_cookie_url = (
            self.auth_data["api_root"]
            + "/"
            + self.auth_data["company_id"]
            + "/davinci/connections/"
            + self.connectionId
            + "/capabilities/setCookieWithoutUser"
        )

        _LOGGER.debug("Fetch new access_token with new connectionId: %s", login_set_cookie_url)

        async with self.session.post(
            login_set_cookie_url,
            headers={
                "User-Agent": USER_AGENT,
                "Content-Type": "application/json",
            },
            data=json.dumps(
                {
                    "eventName": "complete",
                    "parameters": {},
                    "id": self.ID,
                }
            ),
            raise_for_status=True,
        ) as resp:
            data = await resp.json()
            self.ID = data["id"]
            self.access_token = data["access_token"]

    async def postprocessing_api(self) -> None:
        """Postprocess url to get access by cookie."""
        login_postprocess_url = "https://www.evergy.com" + self.auth_data["post_processing_api"]

        _LOGGER.debug("Set cookie with new token for login access: %s", login_postprocess_url)

        async with self.session.post(
            login_postprocess_url,
            headers={
                "User-Agent": USER_AGENT,
                "Content-Type": "application/json",
            },
            data=json.dumps({"Token": self.access_token, "DataSourceItemId": self.auth_data["datasource_item_id"]}),
            raise_for_status=True,
        ) as resp:
            await resp.json(content_type=None)

    async def login(self, username: str, password: str) -> None:
        """First parse davinci widget for api data."""
        await EvergyLoginHandler.get_auth_data(self)
        """Get the access_token."""
        await EvergyLoginHandler.get_sdktoken(self)
        """Start the flow."""
        await EvergyLoginHandler.start_flow(self)
        """Retrieve submit form."""
        await EvergyLoginHandler.get_login_form(self)
        """Submit login form."""
        await EvergyLoginHandler.submit_login_form(self, username, password)
        """Retrieve new connection id."""
        await EvergyLoginHandler.get_new_connection_id(self)
        """Set complete to generate cookie."""
        await EvergyLoginHandler.get_new_connection_cookie(self)
        """Set cookie and generate new access_token."""
        await EvergyLoginHandler.get_new_access_token(self)
        """Postprocess url at Evergy to get access by cookie."""
        await EvergyLoginHandler.postprocessing_api(self)


class Evergy(UtilityBase):
    """Evergy."""

    _subdomain: str | None = None

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Evergy"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        assert Evergy._subdomain, "async_login not called"
        return Evergy._subdomain

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/Chicago"

    @staticmethod
    async def async_login(
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        login_data: dict[str, Any],
    ) -> str:
        """Evergy log-in flow with davinci widget."""
        login_evergy = EvergyLoginHandler(session)
        await login_evergy.login(username, password)

        opower_access_token: str | None = None

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
            Evergy._subdomain = domain.split(".", 1)[0]
            _LOGGER.debug("detected Evergy subdomain: %s", Evergy._subdomain)
            if Evergy._subdomain not in {"kcpk", "kcpl"}:
                _LOGGER.warning(
                    "unexpected Evergy subdomain %s, continuing",
                    Evergy._subdomain,
                )

        return opower_access_token
