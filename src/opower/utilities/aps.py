"""Arizona Public Service (APS)."""

import logging
import re
from typing import Optional

import aiohttp

from ..const import USER_AGENT
from ..exceptions import CannotConnect, InvalidAuth
from .base import UtilityBase
from .helpers import async_auth_saml, js_encrypt

_LOGGER = logging.getLogger(__name__)


class Aps(UtilityBase):
    """Arizona Public Service (APS)."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Arizona Public Service (APS)"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "aps"

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/Phoenix"

    @staticmethod
    async def async_login(
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        optional_mfa_secret: Optional[str],
    ) -> None:
        """Login to the utility website."""
        _LOGGER.debug("Starting login process for Arizona Public Service (APS)")
        session.cookie_jar.clear(lambda cookie: cookie["domain"] == "www.aps.com")

        # Get public RSA key APS uses to encrypt the password
        async with session.get(
            "https://www.aps.com/Assets/Js/aps-apscom.js",
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        ) as resp:
            html = await resp.text()
        rsa_key_text = extract_rsa_key(html)

        # Encrypt the password
        encrypted_password = js_encrypt(rsa_key_text, password)

        data = {
            "username": username,
            "password": encrypted_password,
        }

        # Send the POST request
        async with session.post(
            "https://www.aps.com/api/sitecore/SitecoreReactApi/UserAuthentication",
            json=data,
            raise_for_status=True,
        ) as resp:
            login_result = await resp.json(content_type="text/html")
            if login_result["isLoginSuccess"] is False:
                raise InvalidAuth("Username and password failed")

        # Get All User Details to get APS Account ID and Service Address ID
        async with session.get(
            "https://www.aps.com/api/sitecore/sitecorereactapi/GetAllUserDetails",
            raise_for_status=True,
        ) as resp:
            user_details = await resp.json(content_type="application /json")
            account_id = user_details["Details"]["AccountDetails"][
                "getAccountDetailsResponse"
            ]["getAccountDetailsRes"]["getPersonDetails"]["accountID"]

            service_address_id = user_details["Details"]["AccountDetails"][
                "getAccountDetailsResponse"
            ]["getAccountDetailsRes"]["getSASPListByAccountID"]["premiseDetailsList"][
                0
            ][
                "sASPDetails"
            ][
                0
            ][
                "sAID"
            ]

        account_service_id = f"{account_id}_{service_address_id}"

        # Start SAML authentication with APS and Opower
        url = f"https://www.aps.com/en/Residential/Save-Money-and-Energy/Opower?CA_SA={account_service_id}"
        await async_auth_saml(session, url)


def extract_rsa_key(js_content: str) -> str:
    """Extract the RSA public key from the APS JS file, using the identifier 'APSCOMWebPasswordpublicKey'."""
    pattern = r'APSCOMWebPasswordpublicKey:"(-----BEGIN PUBLIC KEY-----.*?-----END PUBLIC KEY-----)"'

    # Find the RSA key associated with the regex pattern above
    match = re.search(pattern, js_content, re.DOTALL)

    if match:
        # Get and format the RSA key
        rsa_key = match.group(1)
        formatted_key = re.sub(
            r"(-----BEGIN PUBLIC KEY-----)(.*)(-----END PUBLIC KEY-----)",
            r"\1\n\2\n\3",
            rsa_key,
            flags=re.DOTALL,
        )
        return formatted_key
    else:
        raise CannotConnect("The RSA public key was not found.")
