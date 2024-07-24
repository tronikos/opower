"""Enmax."""

import logging
from typing import Optional
import xml.etree.ElementTree as ET

import aiohttp

from ..const import USER_AGENT
from ..exceptions import CannotConnect, InvalidAuth
from .base import UtilityBase

_LOGGER = logging.getLogger(__name__)


class Enmax(UtilityBase):
    """Enmax."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Enmax Energy"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "enmx"

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/Edmonton"

    @staticmethod
    async def async_login(
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        optional_mfa_secret: Optional[str],
    ) -> str:
        """Login to the utility website."""
        _LOGGER.debug("Starting enmax login")
        # Get request digest (required for authentication to Enmax)
        async with session.post(
            "https://www.enmax.com/ForYourHomeSite/_vti_bin/sites.asmx",
            headers={
                "User-Agent": USER_AGENT,
                "Content-Type": "text/xml",
            },
            data=(
                b'<?xml version="1.0" encoding="utf-8"?>'
                b'<soap:Envelope xmlns:xsi="http://www.w3.org/2001/XMLSchema-instance" '
                b'xmlns:xsd="http://www.w3.org/2001/XMLSchema" xmlns:soap="http://schemas.xmlsoap.org/soap/envelope/">  '
                b'<soap:Body>     <GetUpdatedFormDigest xmlns="http://schemas.microsoft.com/sharepoint/soap/" />  '
                b"</soap:Body></soap:Envelope>"
            ),
            raise_for_status=True,
        ) as resp:
            xml_response = await resp.text()

        try:
            xml = ET.fromstring(xml_response)
        except ET.ParseError as e:
            raise CannotConnect(f"XML error. Failed to parse request digest: {e.text}")

        for i in xml.iter():
            if (
                i.tag
                == "{http://schemas.microsoft.com/sharepoint/soap/}GetUpdatedFormDigestResult"
            ):
                requestdigest = i.text
                break
        if not requestdigest:
            raise CannotConnect("Request digest was not found.")

        # Login to the utility website
        async with session.post(
            "https://www.enmax.com/ForYourHomeSite/_vti_bin/Enmax.Internet.Auth/AuthService.svc/AuthenticateUser",
            json={
                "email": username,
                "password": password,
                "autoUnlockIntervalMinutes": 15,
                "queryString": "",
            },
            headers={
                "User-Agent": USER_AGENT,
                "X-RequestDigest": requestdigest,
                "referer": "https://www.enmax.com/sign-in",
            },
            raise_for_status=True,
        ) as resp:
            result = await resp.json()
            error_message = result.get("ErrorMessage")
            if error_message:
                # The following text will likely be displayed during maintenance periods
                if ("an error occurred retrieving or updating data") in error_message:
                    raise CannotConnect(error_message)
                else:
                    raise InvalidAuth(error_message)

        # Get authorization token for opower
        async with session.post(
            "https://www.enmax.com/YourAccountSite/_vti_bin/Enmax.Internet.Opower/MyEnergyIQService.svc/IssueAccessToken",
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        ) as resp:
            token = await resp.text()

        return str(token.replace('"', ""))
