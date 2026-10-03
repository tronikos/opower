"""Evergy."""

import json
import logging
from html.parser import HTMLParser
from typing import Any

import aiohttp

from ..const import USER_AGENT
from ..exceptions import CannotConnect, InvalidAuth
from .base import UtilityBase

_LOGGER = logging.getLogger(__name__)


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
        self.id: str

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

            if not self.auth_data:
                raise CannotConnect("Failed to get davinci widget data from the Evergy login page")

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
            self.id = data["id"]
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
                    "id": self.id,
                    "eventName": "continue",
                }
            ),
            raise_for_status=True,
        ) as resp:
            data = await resp.json()
            self.id = data["id"]

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
                    "id": self.id,
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
            # A different flowId in the reply means the username doesn't exist.
            if data["flowId"] != self.flowId:
                raise InvalidAuth("No such username. Login failed.")
            # The same id coming back means the password isn't correct.
            if data["id"] == self.id:
                raise InvalidAuth("Wrong password. Login failed.")
            self.id = data["id"]

    async def get_new_connection_id(self) -> bool:
        """Retrieve new connection id. Return True if the response already has the access_token."""
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
            data=json.dumps({"id": self.id, "eventName": "continue"}),
            raise_for_status=True,
        ) as resp:
            data = await resp.json()
            self.id = data["id"]
            self.connectionId = data["connectionId"]
            if token := data.get("access_token"):
                _LOGGER.debug("Got access_token from: customHTMLTemplate, skipping setCookieWithoutUser")
                self.access_token = token
                return True
            return False

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
                    "id": self.id,
                }
            ),
            raise_for_status=True,
        ) as resp:
            data = await resp.json()
            self.id = data["id"]

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
                    "id": self.id,
                }
            ),
            raise_for_status=True,
        ) as resp:
            data = await resp.json()
            self.id = data["id"]
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
        """Run the full davinci widget login flow."""
        # Parse the davinci widget for api data.
        await self.get_auth_data()
        # Get the access_token.
        await self.get_sdktoken()
        # Start the flow.
        await self.start_flow()
        # Retrieve the submit form.
        await self.get_login_form()
        # Submit the login form.
        await self.submit_login_form(username, password)
        # Since Sept 2026 the token may come back directly; older flows need two more steps.
        if not await self.get_new_connection_id():
            # Set complete to generate the cookie.
            await self.get_new_connection_cookie()
            # Set the cookie and generate a new access_token.
            await self.get_new_access_token()
        # Postprocess the url at Evergy to get access by cookie.
        await self.postprocessing_api()


class Evergy(UtilityBase):
    """Evergy."""

    def __init__(self) -> None:
        """Initialize."""
        super().__init__()
        self._subdomain: str | None = None

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Evergy"

    def subdomain(self) -> str:
        """Return the opower.com subdomain for this utility."""
        if not self._subdomain:
            raise CannotConnect("async_login was not called before subdomain")
        return self._subdomain

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/Chicago"

    async def async_login(
        self,
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
            # The header is absent when the session was not established, so do
            # not index into it blindly.
            jwt_header = resp.headers.get("jwt", "")
            opower_access_token = jwt_header.removeprefix("Bearer ")
            if not opower_access_token:
                raise CannotConnect(f"Failed to parse the Opower bearer token from Evergy (status {resp.status})")

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
            self._subdomain = domain.split(".", 1)[0]
            _LOGGER.debug("detected Evergy subdomain: %s", self._subdomain)
            if self._subdomain not in {"kcpk", "kcpl"}:
                _LOGGER.warning(
                    "unexpected Evergy subdomain %s, continuing",
                    self._subdomain,
                )

        return opower_access_token
