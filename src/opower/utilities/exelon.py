"""Base class for Exelon subsidiaries."""

import json
import logging
import re
from http.cookies import Morsel
from typing import Any

import aiohttp
from yarl import URL

from ..const import USER_AGENT
from ..exceptions import CannotConnect, InvalidAuth, MfaChallenge
from .base import MfaHandlerBase

_LOGGER = logging.getLogger(__file__)


def _load_javascript(text: str, var: str) -> dict[str, Any] | None:
    """Return json from a javascript variable in the html text."""
    var_match = re.search(r"var " + var + r" = ({.*});", text)
    if var_match:
        return dict(json.loads(var_match.group(1)))
    return None


class ExelonURLHandler:
    """Centralizes and handles all web communication with Exelon."""

    def __init__(self, session: aiohttp.ClientSession, settings: dict[str, Any], base_url: str, login_domain: str):
        """Initialize the handler."""
        self._session = session
        self._login_domain = login_domain
        self.update_base_url(base_url)
        self.update_settings(settings)

    def update_settings(self, settings: dict[str, Any]) -> None:
        """Update settings whenever it is returned as it maintains a history."""
        self._settings = settings

    def update_base_url(self, base_url: str) -> None:
        """Subsidiaries will have a new base URL."""
        self._base_url = base_url

    def get_api(self) -> str:
        """Return the current page (api) for next command evaluation."""
        return str(self._settings.get("api", ""))

    async def get(self, url: str) -> tuple[str, str, str | None]:
        """Return the result of a get command containing CSRF tokens."""
        params = {}
        if self._settings:  #  Handle initial login which will not have a settings
            params = {
                "csrf_token": self._settings["csrf"],
                "tx": self._settings["transId"],
                "p": self._settings["hosts"]["policy"],
                "diags": json.dumps(
                    {
                        "pageViewId": self._settings["pageViewId"],
                        "pageId": self.get_api(),
                        "trace": [],
                    }
                ),
            }

        async with self._session.get(
            f"https://{self._base_url}/{url}",
            params=params,
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        ) as resp:
            result = await resp.text(encoding="utf-8")
            return result, resp.request_info.url.path, resp.real_url.host

    async def post(self, url: str, data: dict[str, Any], error_msg: str = "") -> dict[str, Any]:
        """Return the result of a post command containing CSRF tokens in the header."""
        try:
            async with self._session.post(
                f"https://{self._base_url}/{url}",
                params={
                    "tx": self._settings["transId"],
                    "p": self._settings["hosts"]["policy"],
                },
                data=data,
                headers={
                    "X-CSRF-TOKEN": self._settings["csrf"],
                    "User-Agent": USER_AGENT,
                },
                raise_for_status=True,
            ) as resp:
                result_json = dict(json.loads(await resp.text(encoding="utf-8")))
        except aiohttp.ClientError as err:
            raise CannotConnect(f"Failed to post during {error_msg} with error: {err}") from err
        else:
            if result_json["status"] != "200":
                raise InvalidAuth(f"Failed to authenticate during {error_msg} with error: {result_json['message']}")
        return result_json

    async def get_token(self) -> tuple[str, dict[str, Any], dict[str, str]]:
        """Return the the first account and the associated bearer token."""
        # we probably need to select an account as we didn't automatically go to the dashboard
        # so we store these details, always looking up the account

        account: dict[str, Any] = {}

        async with self._session.get(
            f"https://{self._login_domain}/api/Services/MyAccountService.svc/GetSession",
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        ) as resp:
            result_json = await resp.json()

        if not result_json.get("token"):
            _LOGGER.error("No token provided, authentication flow likely failed")
            return "", {}, {}

        # If all necessary fields are present then we can use the Session data structure,
        # otherwise we need to retrieve the accounts explicitly.
        try:
            state = result_json["PremiseInfo"][0]["mainAddress"]["townDetail"]["stateOrProvince"]
        except (KeyError, IndexError):
            state = None
        if result_json.get("accountNumber") and result_json.get("isResidential") and state:
            account = result_json
        else:
            bearer_token = result_json["token"]

            # this path comes from GetConfiguration, unsure if its different
            # per utility, if so, would need to add it to the subtypes:
            # "euApiRoutePrefix": "/mobile/custom",
            eu_api_route_prefix = "mobile/custom"
            # "euApiUrl": "/.euapi",
            eu_api_url = ".euapi"
            async with self._session.get(
                f"https://{self._login_domain}/{eu_api_url}/{eu_api_route_prefix}/auth/accounts",
                headers={
                    "User-Agent": USER_AGENT,
                    "Authorization": "Bearer " + bearer_token,
                },
                raise_for_status=True,
            ) as resp:
                # this has the wrong mime type for some reason
                result = await resp.json(content_type="text/html")

            if result.get("success") is not True:
                raise InvalidAuth("Unable to list accounts")

            # Only include active accounts (after moving, old accounts have status: "Inactive")
            # NOTE: this logic currently assumes 1 active address per account, if multiple accounts found
            #      we default to taking the first in the list. Future enhancement is to support
            #      multiple accounts (which could result in different subdomain for each)
            active_accounts = [account for account in result.get("data", []) if account.get("status") == "Active"]

            if len(active_accounts) == 0:
                raise InvalidAuth("No active accounts found")

            # set the first active one
            account = active_accounts[0]
            account_number = account["accountNumber"]

            async with self._session.post(
                f"https://{self._login_domain}/api/Services/AccountList.svc/ViewAccount",
                json={
                    "accountNumber": account_number,
                },
                headers={"User-Agent": USER_AGENT},
                raise_for_status=True,
            ) as resp:
                result = await resp.text(encoding="utf-8")

        async with self._session.post(
            f"https://{self._login_domain}/api/Services/OpowerService.svc/GetOpowerToken",
            json={},
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        ) as resp:
            result_json = await resp.json()

        relevant_cookies = {}
        if cookies := self._session.cookie_jar.filter_cookies(URL("https://" + self._login_domain)):
            asp_session = cookies.get("ASP.NET_SessionId", Morsel())
            asp_c1 = cookies.get(".AspNet.cookieC1", Morsel())
            asp_c2 = cookies.get(".AspNet.cookieC2", Morsel())
            if asp_session and asp_c1 and asp_c2:
                relevant_cookies = {
                    "ASP.NET_SessionId": asp_session.value,
                    ".AspNet.cookie": "chunks:2",
                    ".AspNet.cookieC1": asp_c1.value,
                    ".AspNet.cookieC2": asp_c2.value,
                }

        return str(result_json["access_token"]), account, relevant_cookies


class ExelonMfaHandler(MfaHandlerBase):
    """Handles interactive MFA for Exelon."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        password: str,
        data: dict[str, Any],
    ):
        """Initialize the MFA handler."""
        self._session = session
        self._password = password  #  Not used in Exelon
        self._exelon_handler: ExelonURLHandler = data.get("handler", ExelonURLHandler(self._session, {}, "", ""))
        self._sa_fields = data.get("sa_fields", {})
        self._mfa_options: dict[str, str] = {}
        self._option_id = "Unknown"

    async def async_get_mfa_options(self) -> dict[str, str]:
        """Return a dictionary of MFA options available to the user."""
        # What is currently known are 2 forms of MFA:
        # Forced and opted, where opted has a phone based MFA that no one
        # knows how to remove.
        # This results in two forms of logic handled, if this logic breaks
        # check this section and review sa_fields as this is what is known:

        mfa_options: dict[str, str] = {}
        phone_mfa_off = False
        bypass_selection = False
        if fields := self._sa_fields.get("AttributeFields", []):
            for field in fields:
                # Logic for forced MFA where there is only email
                if field.get("ID") == "extension_isMFAEnabled":
                    if field.get("PRE") == "False":
                        _LOGGER.debug("Phone based MFA is off")
                        phone_mfa_off = True
                    else:
                        _LOGGER.error("MFA condition is not mapped")
                if field.get("ID") == "emailVerificationControl":
                    for display in field.get("DISPLAY_FIELDS", []):
                        if display.get("ID") == "displayEmailAddress":
                            mfa_options["Email"] = display.get("PRE")
                            bypass_selection = True

                # Logic for MFA that was opted in with phone
                if field.get("ID") == "displayEmailAddress":
                    mfa_options["Email"] = field.get("PRE")
                if field.get("ID") == "displayPhoneNumber":
                    mfa_options["Text"] = field.get("PRE")
        self._mfa_options = mfa_options

        # The user will have a choice since normal MFA flow offers
        # this, however we need to designate between forced and opted
        if phone_mfa_off and bypass_selection:
            self._option_id = "Bypass"
        return mfa_options

    async def async_select_mfa_option(self, option_id: str) -> None:
        """Select an MFA option and trigger the code delivery."""
        _LOGGER.debug("Selecting MFA option %s", option_id)

        if self._option_id != "Bypass":
            self._option_id = option_id
            # NOTE MFA supports Text, Email, and Call
            # Call requires polling, which is outside
            # the scope of supporting this type of flow
            _ = await self._exelon_handler.post(
                "SelfAsserted",
                {
                    "displayEmailAddress": self._mfa_options["Email"],
                    "displayPhoneNumber": self._mfa_options["Text"],
                    "mfaEnabledRadio": self._option_id,
                    "request_type": "RESPONSE",
                },
                "MFA setup",
            )

            result, *_ = await self._exelon_handler.get(f"api/{self._exelon_handler.get_api()}/confirmed")
            settings = _load_javascript(result, "SETTINGS")
            if settings is None:
                raise InvalidAuth(f"Failed to confirm MFA option: {self._option_id}")
            self._exelon_handler.update_settings(settings)

        if self._option_id == "Text":
            uv_phone = _load_javascript(result, "UV_PHONE")
            if uv_phone is None:
                raise InvalidAuth("Failed to select phone MFA")
            phone_id = uv_phone.get("PhoneNumbers", [{"Id": "0"}])[0].get("Id", "0")
            verify_url = f"{self._exelon_handler.get_api()}/verify"
            verify_data = {"request_type": "VERIFICATION_REQUEST", "auth_type": "onewaysms", "id": phone_id}
        else:
            verify_url = "SelfAsserted/DisplayControlAction/vbeta/emailVerificationControl/SendCode"
            verify_data = {"displayEmailAddress": self._mfa_options["Email"]}

        _ = await self._exelon_handler.post(verify_url, verify_data, "MFA verify")

        _LOGGER.debug("Successfully selected MFA option")

    async def async_submit_mfa_code(self, code: str) -> dict[str, Any]:
        """Submit the user-provided code."""
        _LOGGER.debug("Submitting MFA code")
        if self._option_id == "Text":
            submit_url = f"{self._exelon_handler.get_api()}/verify"
            submit_data = {"request_type": "VALIDATION_REQUEST", "verification_code": code}
        else:
            submit_url = "SelfAsserted/DisplayControlAction/vbeta/emailVerificationControl/VerifyCode"
            submit_data = {"displayEmailAddress": self._mfa_options["Email"], "verificationCode": code}

        _ = await self._exelon_handler.post(submit_url, submit_data, "MFA code")

        # Email and phone have different flows and nothing may come back but we still have to send it
        if self._option_id == "Email" or self._option_id == "Bypass":
            _ = await self._exelon_handler.post(
                "SelfAsserted",
                {
                    "displayEmailAddress": self._mfa_options["Email"],
                    "verificationCode": code,
                    "extension_isMFAEnabled": "True",
                    "request_type": "RESPONSE",
                },
            )

        _ = await self._exelon_handler.get(f"api/{self._exelon_handler.get_api()}/confirmed")
        token, account, cookies = await self._exelon_handler.get_token()

        if token and account:
            _LOGGER.debug("MFA code accepted, received login data")
            return {"token": token, "account": account, "cookies": cookies}

        raise InvalidAuth("Authentication flow failed")


class Exelon:
    """Base class for Exelon subsidiaries."""

    _subdomain: str | None = None

    # Can find the opower.com subdomain using the GetConfiguration endpoint
    # e.g. https://secure.bge.com/api/Services/MyAccountService.svc/GetConfiguration
    # returns bgec.opower.com

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/New_York"

    @staticmethod
    def login_domain() -> str:
        """Return the domain that hosts the login page."""
        raise NotImplementedError

    @classmethod
    def subdomain(cls) -> str:
        """Return the opower.com subdomain for this utility."""
        assert Exelon._subdomain, "async_login not called"
        return Exelon._subdomain

    @staticmethod
    def primary_subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        raise NotImplementedError

    @staticmethod
    def secondary_subdomain() -> str:
        """Return the opower.com secondary subdomain for this utility."""
        raise NotImplementedError

    @classmethod
    async def async_login(
        cls,
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        login_data: dict[str, Any],
    ) -> str:
        """Login to the utility website and authorize opower."""
        account = login_data.get("account", {})
        token: str = str(login_data.get("token", ""))
        cookies = login_data.get("cookies", {})
        # Initial URL is the login_domain, but it will change if we are redirected
        exelon_handler = ExelonURLHandler(session, {}, cls.login_domain(), cls.login_domain())

        if cookies:
            session.cookie_jar.update_cookies(cookies, URL("https://" + cls.login_domain()))

        result, path, login_post_domain = await exelon_handler.get("Pages/Login.aspx?/login")
        if not token or not account:
            # if we don't go to /accounts/dashboard, we need to perform some authorization steps
            if path.endswith("/authorize"):
                # transId = "StateProperties=..."
                # policy = "B2C_1A_SignIn"
                # tenant = "/euazurebge.onmicrosoft.com/B2C_1A_SignIn"
                # api = "CombinedSigninAndSignup"
                assert login_post_domain, "no real host found"
                settings = _load_javascript(result, "SETTINGS")
                assert settings is not None, "settings not found"
                base_url = login_post_domain + settings["hosts"]["tenant"]
                exelon_handler.update_base_url(base_url)
                exelon_handler.update_settings(settings)

                _ = await exelon_handler.post(
                    "SelfAsserted",
                    {
                        "request_type": "RESPONSE",
                        "signInName": username,
                        "password": password,
                    },
                    "Initial authorization",
                )

                result, path, _ = await exelon_handler.get(f"api/{exelon_handler.get_api()}/confirmed")

                sa_fields = _load_javascript(result, "SA_FIELDS")
                settings = _load_javascript(result, "SETTINGS")
                if settings is None:
                    raise InvalidAuth("Failed to initiate authorization")
                if sa_fields is not None:
                    _LOGGER.debug("MFA challenge received")
                    exelon_handler.update_settings(settings)
                    challenge = {
                        "sa_fields": sa_fields,
                        "handler": exelon_handler,
                    }
                    raise MfaChallenge("Exelon MFA required", ExelonMfaHandler(session, password, challenge))

            else:
                raise InvalidAuth("Site is down or has changed behavior")

        token, account, _ = await exelon_handler.get_token()
        if not token:
            raise InvalidAuth("Reauthentication is needed")

        # If pepco or delmarva, determine if we should use secondary subdomain
        if cls.login_domain() in ["secure.pepco.com", "secure.delmarva.com"]:
            # Get the account type & state

            isResidential = account["isResidential"]
            state = account["PremiseInfo"][0]["mainAddress"]["townDetail"]["stateOrProvince"]
            _LOGGER.debug("found exelon account isResidential: %s", isResidential)
            _LOGGER.debug("found exelon account state: %s", state)

            # Determine subdomain to use by matching logic found in https://cls.login_domain()/dist/app.js
            Exelon._subdomain = cls.primary_subdomain()
            if not isResidential or state != "MD":
                Exelon._subdomain = cls.secondary_subdomain()

            _LOGGER.debug("detected exelon subdomain to be: %s", Exelon._subdomain)

        return token
