"""Base class for Exelon subsidiaries."""

import base64
import hashlib
import json
import logging
import re
import secrets
import urllib
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

    def __init__(
        self,
        session: aiohttp.ClientSession,
        base_url: str,
        login_domain: str,
        eu_domain: str,
        refresh_token: str,
        client_id: str,
        mobile_id: str,
    ):
        """Initialize the handler."""
        self._session = session
        self._base_url = login_domain  # The login domain ultimately changes when you hit it
        self._eu_domain = eu_domain
        self._refresh_token = refresh_token
        self._code_verifier = secrets.token_urlsafe(32)
        code_challenge_digest = hashlib.sha256(self._code_verifier.encode("utf-8")).digest()
        self._code_challenge = base64.urlsafe_b64encode(code_challenge_digest).decode("utf-8").rstrip("=")
        self._client_id = client_id
        self._mobile_id = mobile_id

        self._settings: dict[str, Any] = {}
        self.update_base_url(base_url)

    def get_base_url(self) -> str:
        """Return the endpoint for our api calls."""
        return self._base_url

    def update_base_url(self, base_url: str) -> None:
        """Subsidiaries will have a new base URL."""
        self._base_url = base_url

    async def load_mobile(self, authorize_path: str) -> None:
        """Workaround to make this app appear as a mobile."""
        params: str = urllib.parse.urlencode(
            {
                "p": "B2C_1A_SignIn_Mobile",
                "client_id": self._client_id,
                "nonce": "defaultNonce",
                "redirect_uri": self._mobile_id + "://auth",
                "scope": "openid offline_access",
                "response_type": "code",
                "code_challenge": self._code_challenge,
                "code_challenge_method": "S256",
                "prompt": "login",
            },
            quote_via=urllib.parse.quote,
        )
        async with self._session.get(
            URL(
                f"https://{authorize_path}?" + params,
                encoded=True,
            ),
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        ) as resp:
            result = await resp.text(encoding="utf-8")
        settings = _load_javascript(result, "SETTINGS")
        if settings is None:
            raise InvalidAuth("Failed to perform first level authorization")
        # The mobile app seems to switch to SelfAsserted on its own
        settings["api"] = "SelfAsserted"
        self._settings = settings

    async def getapi(self, url: str, redirects: bool = True) -> tuple[str, str, str | None]:
        """Return the result of a get command containing CSRF tokens.

        This function handles 3 types of API get requests:
        1. The initial login, when nothing is known
        2. The catch redirect_uri (redirects = False), which happens during an authorize
        3. The standard API, when settings are known (which contain API)

        As such it will return the result and for redirects the path and the host
        """
        params = {}
        final_url = url
        if self._settings:  # Case 2 or 3 else case 1
            final_url = f"api/{self._settings.get('api', '')}/{url}"
            params = {
                "csrf_token": self._settings.get("csrf", ""),
                "tx": self._settings.get("transId", ""),
                "p": self._settings.get("hosts", {"policy": ""}).get("policy", ""),
                "diags": json.dumps(
                    {
                        "pageViewId": self._settings.get("pageViewId", ""),
                        "pageId": self._settings.get("api", ""),
                        "trace": [],
                    }
                ),
            }

        try:
            async with self._session.get(
                f"https://{self._base_url}/{final_url}",
                params=params,
                headers={"User-Agent": USER_AGENT},
                raise_for_status=True,
                allow_redirects=redirects,  # Case 2
            ) as resp:
                result = await resp.text(encoding="utf-8")
                if not redirects:  # Workaround for the redirect uri mobile intervention
                    return result, resp.headers["Location"], resp.real_url.host
                settings = _load_javascript(result, "SETTINGS")
                if settings is None:
                    raise InvalidAuth("No settings returned")
                self._settings = settings
                return result, resp.request_info.url.path, resp.real_url.host
        except aiohttp.ClientError as err:
            raise CannotConnect(f"Failed to make an API call with error: {err}") from err

    async def postapi(self, path: str, data: dict[str, Any], error_msg: str = "") -> dict[str, Any]:
        """Return the result of a post command containing CSRF tokens in the header."""
        final_url = self._settings.get("api", "")
        if path:
            final_url += f"/{path}"
        try:
            async with self._session.post(
                f"https://{self._base_url}/{final_url}",
                params={
                    "tx": self._settings.get("transId", ""),
                    "p": self._settings.get("hosts", {"policy": ""}).get("policy", ""),
                },
                data=data,
                headers={
                    "X-CSRF-TOKEN": self._settings.get("csrf", ""),
                    "X-Requested-With": "XMLHttpRequest",
                    "User-Agent": USER_AGENT,
                },
                raise_for_status=True,
            ) as resp:
                result_json = dict(json.loads(await resp.text(encoding="utf-8")))
        except aiohttp.ClientError as err:
            raise CannotConnect(f"Failed to post during {error_msg} with error: {err}") from err
        if result_json.get("status", "") != "200":
            raise InvalidAuth(f"Failed to authenticate during {error_msg} with error: {result_json.get('message', '')}")
        return result_json

    async def refresh_refresh(self) -> str:
        """Refresh the refresh token."""
        result_json = await self.refresh_token(
            data={
                "grant_type": "refresh_token",
                "response_type": "token",
                "scope": "openid offline_access " + self._client_id,
                "client_id": self._client_id,
                "refresh_token": self._refresh_token,
            }
        )
        self._refresh_token = result_json.get("refresh_token", "")
        return str(result_json.get("access_token", ""))

    async def refresh_opower(self, account_number: str) -> str:
        """Refresh opower token using the refresh token."""
        if m := re.search(r"\/(.*)\.onmicrosoft\.com/", self._base_url):
            scope = m.group(1)
        else:  # Fallback
            scope = self._eu_domain.replace("eudapi.", "euazure")
        result_json = await self.refresh_token(
            data={
                "grant_type": "refresh_token",
                "response_type": "token",
                "scope": f"https://{scope}.onmicrosoft.com/opower/opower_connect",
                "client_id": self._client_id,
                "refresh_token": self._refresh_token,
                "nonce": account_number,
            }
        )
        return str(result_json.get("access_token", ""))

    async def refresh_token(self, data: dict[str, str]) -> Any:
        """Generate a token from the data and return the field."""
        try:
            async with self._session.post(
                f"https://{self._base_url}/oauth2/v2.0/token",
                headers={"User-Agent": USER_AGENT},
                data=data,
                raise_for_status=True,
            ) as resp:
                result_json = await resp.json()
        except aiohttp.ClientError as err:
            _LOGGER.warning("Failed to obtain refresh token thus likely unauthorized due to error: %s", err)
            return {}

        return result_json

    async def get_first_account(self, bearer_token: str) -> dict[str, Any]:
        """Get the first active account information."""
        try:
            async with self._session.get(
                f"https://{self._eu_domain}/mobile/custom/auth/accounts",
                headers={
                    "User-Agent": USER_AGENT,
                    "Authorization": "Bearer " + bearer_token,
                },
                raise_for_status=True,
            ) as resp:
                result_json = await resp.json()

            if result_json.get("success", False) is not True:
                raise InvalidAuth("Unable to list accounts")

            # Only include active accounts (after moving, old accounts have status: "Inactive")
            # NOTE: this logic currently assumes 1 active address per account, if multiple accounts found
            #      we default to taking the first in the list. Future enhancement is to support
            #      multiple accounts (which could result in different subdomain for each)
            active_accounts: list[dict[str, Any]] = [
                account for account in result_json.get("data", {}) if account.get("status", "") == "Active"
            ]

            if len(active_accounts) == 0:
                raise InvalidAuth("No active accounts found")
            if len(active_accounts) > 1:
                _LOGGER.info("Found multiple active accounts, using %s", active_accounts[0].get("accountNumber", ""))
            return active_accounts[0]
        except aiohttp.ClientError as err:
            raise CannotConnect(f"Cannot obtain account information, unauthorized with error: {err}") from err

    async def get_token(self, account: dict[str, Any] | None, code: str) -> tuple[str, str, dict[str, Any]]:
        """Return the the first account and the associated tokens for our authorization."""
        bearer_token = ""
        if code:
            stripped_code = code.replace(self._mobile_id + "://auth/?code=", "")
            async with self._session.post(
                f"https://{self._base_url}/oauth2/v2.0/token",
                data={
                    "grant_type": "authorization_code",
                    "scope": "openid offline_access " + self._client_id,
                    "client_id": self._client_id,
                    "code": stripped_code,
                    "code_verifier": self._code_verifier,
                    "redirect_uri": self._mobile_id,
                },
            ) as resp:
                result_json = await resp.json()
            bearer_token = result_json.get("access_token", "")
            self._refresh_token = result_json.get("refresh_token", "")
        else:
            bearer_token = await self.refresh_refresh()

        if not account:
            account = await self.get_first_account(bearer_token)

        opower_token = await self.refresh_opower(account.get("accountNumber", ""))

        return opower_token, self._refresh_token, account


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
        self._exelon_handler: ExelonURLHandler = data.get("handler", ExelonURLHandler(self._session, "", "", "", "", "", ""))
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
            _ = await self._exelon_handler.postapi(
                "",
                {
                    "displayEmailAddress": self._mfa_options["Email"],
                    "displayPhoneNumber": self._mfa_options["Text"],
                    "mfaEnabledRadio": self._option_id,
                    "request_type": "RESPONSE",
                },
                "MFA setup",
            )

            _ = await self._exelon_handler.getapi("confirmed")

        if self._option_id == "Text":
            verify_url = "DisplayControlAction/vbeta/textVerificationControl/SendCode"
            verify_data = {"displayPhoneNumber": self._mfa_options["Text"]}
        else:
            verify_url = "DisplayControlAction/vbeta/emailVerificationControl/SendCode"
            verify_data = {"displayEmailAddress": self._mfa_options["Email"]}

        _ = await self._exelon_handler.postapi(verify_url, verify_data, "MFA verify")

        _LOGGER.debug("Successfully selected MFA option")

    async def async_submit_mfa_code(self, code: str) -> dict[str, Any]:
        """Submit the user-provided code."""
        _LOGGER.debug("Submitting MFA code")
        if self._option_id == "Text":
            submit_url = "DisplayControlAction/vbeta/textVerificationControl/VerifyCode"
            submit_data = {
                "displayPhoneNumber": self._mfa_options["Text"],
                "verificationCode": code,
            }
        else:
            submit_url = "DisplayControlAction/vbeta/emailVerificationControl/VerifyCode"
            submit_data = {
                "displayEmailAddress": self._mfa_options["Email"],
                "verificationCode": code,
            }

        _ = await self._exelon_handler.postapi(submit_url, submit_data, "MFA code")

        submit_data["request_type"] = "RESPONSE"
        _ = await self._exelon_handler.postapi("", submit_data)

        # Here we catch the redirect_uri which will contain our initial authorization code
        _, path, _ = await self._exelon_handler.getapi("confirmed", redirects=False)

        _, refresh_token, account = await self._exelon_handler.get_token(account=None, code=path)

        if account and refresh_token:
            _LOGGER.debug("MFA code accepted, received all necessary login data")
            return {
                "token": refresh_token,
                "account": account,
                "base_url": self._exelon_handler.get_base_url(),
            }

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

    @staticmethod
    def eu_domain() -> str:
        """Return the azure authentication domain for this utility."""
        raise NotImplementedError

    @staticmethod
    def mobile_client() -> tuple[str, str]:
        """Return the client id and mobile id pair used by this utility."""
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
        account: dict[str, Any] | None = login_data.get("account")
        token: str = str(login_data.get("token", ""))
        base_url: str = str(login_data.get("base_url", cls.login_domain()))
        # Initial URL is the login_domain, but it will change if we are redirected

        client_id, mobile_id = cls.mobile_client()
        exelon_handler = ExelonURLHandler(
            session=session,
            base_url=base_url,
            eu_domain=cls.eu_domain(),
            login_domain=cls.login_domain(),
            refresh_token=token,
            client_id=client_id,
            mobile_id=mobile_id,
        )

        opower_token = ""
        if account:  # We will always refresh the tokens
            opower_token, _, account = await exelon_handler.get_token(account, "")

        if not account or not opower_token:
            # Either an unexpected auth connection or first time so we setup our mobile
            # redirect stack to restart the MFA authentication flow cleanly
            exelon_handler.update_base_url(cls.login_domain())
            result, path, login_post_domain = await exelon_handler.getapi("Pages/Login.aspx?/login")

            # Make sure we were redirected to an authorize endpoint which changes our base URL
            if path.endswith("/authorize"):
                assert login_post_domain, "no real host found"
                settings = _load_javascript(result, "SETTINGS")
                assert settings is not None, "settings not found"

                # Here we employ a hack. Mobile apps know where their tenants are, so they do not need
                # to visit the login page. They can be updated whereas the login domain is unlikely to be updated
                # so we use the web base login page to get the mobile endpoints
                # Then we swap out the policy to the mobile endpoint and start the authorization
                base_url = login_post_domain + settings["hosts"]["tenant"]
                exelon_handler.update_base_url(base_url.replace(settings["hosts"]["policy"], "B2C_1A_SignIn_Mobile"))
                await exelon_handler.load_mobile(login_post_domain + path)

                _ = await exelon_handler.postapi(
                    "",
                    {
                        "request_type": "RESPONSE",
                        "signInName": username,
                        "password": password,
                    },
                    "Initial authorization",
                )

                result, path, _ = await exelon_handler.getapi("confirmed")

                sa_fields = _load_javascript(result, "SA_FIELDS")
                if sa_fields is not None:
                    _LOGGER.debug("MFA challenge received")
                    challenge = {
                        "sa_fields": sa_fields,
                        "handler": exelon_handler,
                    }
                    raise MfaChallenge(
                        "Reauthentication required" if token else "Exelon MFA required",
                        ExelonMfaHandler(session, password, challenge),
                    )
                raise InvalidAuth("This integration only supports MFA authentication")

            raise InvalidAuth("Site is down or has changed behavior")

        # If pepco or delmarva, determine if we should use secondary subdomain
        if cls.login_domain() in ["secure.pepco.com", "secure.delmarva.com"]:
            # Get the account type & state

            is_residential = account.get("isResidential", False)
            try:
                state = account["PremiseInfo"][0]["mainAddress"]["townDetail"]["stateOrProvince"]
            except (KeyError, IndexError):
                state = None
            _LOGGER.debug("found exelon account isResidential: %s", is_residential)
            _LOGGER.debug("found exelon account state: %s", state)

            # Determine subdomain to use by matching logic found in https://cls.login_domain()/dist/app.js
            Exelon._subdomain = cls.primary_subdomain()
            if not (is_residential and state == "MD"):
                Exelon._subdomain = cls.secondary_subdomain()

            _LOGGER.debug("detected exelon subdomain to be: %s", Exelon._subdomain)

        return opower_token
