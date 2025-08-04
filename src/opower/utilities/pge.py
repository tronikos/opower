"""Pacific Gas & Electric (PG&E)."""

import json
import logging
import re
from typing import Any
from urllib.parse import urlencode

import aiohttp

from ..const import USER_AGENT
from ..exceptions import CannotConnect, InvalidAuth, MfaChallenge
from .base import MfaHandlerBase, UtilityBase

_LOGGER = logging.getLogger(__name__)


async def _aura_apex_action_execute(session: aiohttp.ClientSession, body: dict[str, Any]) -> Any:
    payload = body.copy()
    for key, value in payload.items():
        if isinstance(value, dict):
            payload[key] = json.dumps(value, separators=(",", ":"))
    resp = await session.post(
        "https://myaccount.pge.com/myaccount/s/sfsites/aura?aura.ApexAction.execute=1",
        headers={
            "User-Agent": USER_AGENT,
            "content-type": "application/x-www-form-urlencoded; charset=UTF-8",
        },
        data=urlencode(payload),
        raise_for_status=True,
    )
    return await resp.json()


class PgeMfaHandler(MfaHandlerBase):
    """Handles interactive MFA for PG&E."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        password: str,
        data: dict[str, Any],
    ):
        """Initialize the MFA handler."""
        self._session = session
        self._password = password
        self._data = data

    async def async_get_mfa_options(self) -> dict[str, str]:
        """Return a dictionary of MFA options available to the user."""
        mfa_options: dict[str, str] = {}
        if email := self._data.get("EmailVal"):
            mfa_options["Email"] = email
        if phone := self._data.get("PhoneVal"):
            mfa_options["Phone"] = phone
        return mfa_options

    async def async_select_mfa_option(self, option_id: str) -> None:
        """Select an MFA option and trigger the code delivery."""
        _LOGGER.debug("Selecting MFA option %s", option_id)
        self._option_id = option_id
        body: dict[str, Any] = {
            "message": {
                "actions": [
                    {
                        "descriptor": "aura://ApexActionController/ACTION$execute",
                        "params": {
                            "classname": "MyAcct_Apex_CustomMFAController",
                            "method": "handleChoiceofMFA",
                            "params": {
                                "username": self._data.get("retencrUsrname"),
                                "selectedChoice": option_id,
                                # "uuid": "",
                                "isforgotpassword": False,
                            },
                        },
                    }
                ]
            },
            "aura.context": {"app": "siteforce:loginApp2"},
            "aura.pageURI": "/myaccount/s/login/",
            "aura.token": "null",
        }
        try:
            res = await _aura_apex_action_execute(self._session, body)
        except aiohttp.ClientError as err:
            raise CannotConnect(f"MFA option selection failed: {err}") from err
        else:
            returnValue = res["actions"][0]["returnValue"]["returnValue"]
            if returnValue.get("retMessage", "").lower() != "success":
                raise CannotConnect(f"Failed to select MFA option: {returnValue.get('retMessage', 'Unknown error')}")
            _LOGGER.debug("Successfully selected MFA option")

    async def async_submit_mfa_code(self, code: str) -> dict[str, Any]:
        """Submit the user-provided code."""
        _LOGGER.debug("Submitting MFA code")
        body: dict[str, Any] = {
            "message": {
                "actions": [
                    {
                        "descriptor": "aura://ApexActionController/ACTION$execute",
                        "params": {
                            "classname": "MyAcct_Apex_CustomMFAController",
                            "method": "verifySignInCode",
                            "params": {
                                "input": {
                                    "authCode": code,
                                    # "uuid": "",
                                    "password": self._password,
                                    "encToken": self._data.get("encryptedTFT"),
                                    "usernameVal": self._data.get("retencrUsrname"),
                                    "isForgotPasswordFlow": False,
                                    "otpType": self._option_id,
                                }
                            },
                        },
                    }
                ]
            },
            "aura.context": {"app": "siteforce:loginApp2"},
            "aura.pageURI": "/myaccount/s/login/",
            "aura.token": "null",
        }
        try:
            res = await _aura_apex_action_execute(self._session, body)
        except aiohttp.ClientError as err:
            raise CannotConnect(f"MFA code submission failed: {err}") from err
        else:
            returnValue = res["actions"][0]["returnValue"]["returnValue"]
            if returnValue.get("returnResponse", "").lower() != "success":
                raise InvalidAuth(f"Invalid MFA code: {returnValue.get('returnResponse', 'Unknown error')}")

            if not (wrapperObj := returnValue.get("wrapperObj")):
                raise InvalidAuth("MFA submission response missing 'wrapperObj'")

            _LOGGER.debug("MFA code accepted, received login data")
            return {
                "browsercookie": wrapperObj.get("retencrUsrname"),
                "validationCookie": wrapperObj.get("encryptedKey"),
                "expiryDateTime": wrapperObj.get("expiryDateTime"),
            }


class PGE(UtilityBase):
    """Pacific Gas & Electric (PG&E)."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Pacific Gas and Electric Company (PG&E)"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "pge"

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/Los_Angeles"

    @staticmethod
    async def async_login(
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        login_data: dict[str, Any],
    ) -> str:
        """Login to the utility website."""
        _LOGGER.debug("Logging in to PG&E")
        body: dict[str, Any] = {
            "message": {
                "actions": [
                    {
                        "descriptor": "aura://ApexActionController/ACTION$execute",
                        "params": {
                            "classname": "MyAcct_customLoginLWCController",
                            "method": "login",
                            "params": {
                                "username": username,
                                "password": password,
                                "browsercookie": login_data.get("browsercookie", "null"),
                                "validationCookie": login_data.get("validationCookie", "null"),
                            },
                        },
                    }
                ]
            },
            "aura.context": {"app": "siteforce:loginApp2"},
            "aura.pageURI": "/myaccount/s/login/",
            "aura.token": "null",
        }
        res = await _aura_apex_action_execute(session, body)
        actions = res.get("actions", [])
        if not actions:
            raise InvalidAuth("No actions returned from login response")
        action = actions[0]
        if not action.get("state") == "SUCCESS":
            raise InvalidAuth(f"Login failed: {action.get('error', 'Unknown error')}")
        returnValue = action.get("returnValue", {}).get("returnValue")
        retMessage = returnValue.get("retMessage", "")
        _LOGGER.debug("Login action returned message: %s", retMessage)
        if retMessage == "verifymfa :":
            _LOGGER.debug("MFA challenge received")
            raise MfaChallenge("PG&E MFA required", PgeMfaHandler(session, password, returnValue))
        if not retMessage.startswith("http"):
            raise InvalidAuth(f"Login failed: {retMessage}")

        _LOGGER.debug("Following redirect")
        resp = await session.get(
            retMessage,
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        )

        _LOGGER.debug("Accessing main account page to set cookies")
        resp = await session.get(
            "https://myaccount.pge.com/myaccount/s/",
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        )

        aura_token = None
        for cookie in session.cookie_jar:
            if cookie.key.startswith("__Host-ERIC_PROD"):
                aura_token = cookie.value
                _LOGGER.debug("Found Aura token in cookies")
                break
        if not aura_token:
            raise InvalidAuth("Could not find Aura token in cookies after login")

        for classname, method in (
            ("MyAcct_OneTrustIntegrationController", "generateToken"),
            ("MyAcct_AccountCacheHandler", "copyToSessionCacheForUser"),
        ):
            _LOGGER.debug("Executing action: %s.%s", classname, method)
            body = {
                "message": {
                    "actions": [
                        {
                            "descriptor": "aura://ApexActionController/ACTION$execute",
                            "params": {"classname": classname, "method": method},
                        }
                    ]
                },
                "aura.context": {"app": "siteforce:communityApp"},
                "aura.pageURI": "/myaccount/s/",
                "aura.token": aura_token,
            }
            await _aura_apex_action_execute(session, body)

        _LOGGER.debug("Fetching OpowerDataBrowser to extract token")
        resp = await session.get(
            "https://myaccount.pge.com/myaccount/apex/MyAcct_VF_BillInsights_OpowerDataBrowser",
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        )
        res_text = await resp.text()

        if not (m := re.search(r"let tokenFromApex = '([^']*)'", res_text)):
            _LOGGER.error("Could not find Opower token in page content.")
            raise InvalidAuth("Failed to retrieve Opower token after login.")

        token = m.group(1)
        if not token:
            _LOGGER.error("Opower token is empty.")
            # Raise a retryable exception because this might be a temporary issue
            raise CannotConnect("Opower token is empty")

        _LOGGER.debug("Successfully retrieved Opower token")
        return token
