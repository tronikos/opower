"""Enmax."""
from typing import Optional
import xml.etree.ElementTree as ET

import aiohttp

from ..const import USER_AGENT
from ..exceptions import InvalidAuth
from .base import UtilityBase


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

        xml = ET.fromstring(xml_response)
        for i in xml.iter():
            if (
                i.tag
                == "{http://schemas.microsoft.com/sharepoint/soap/}GetUpdatedFormDigestResult"
            ):
                requestdigest = i.text
                break
        if not requestdigest:
            raise InvalidAuth("Request digest was not found.")

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
            if result["ErrorMessage"]:
                raise InvalidAuth(result["ErrorMessage"])

        # Get authorization token for opower
        async with session.post(
            "https://www.enmax.com/YourAccountSite/_vti_bin/Enmax.Internet.Opower/MyEnergyIQService.svc/IssueAccessToken",
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        ) as resp:
            token = await resp.text()

        return token.replace('"', "")
