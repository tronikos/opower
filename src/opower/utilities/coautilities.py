"""City of Austin Utilities."""

from typing import Optional
from urllib.parse import parse_qs, urlparse

import aiohttp
from yarl import URL

from ..const import USER_AGENT
from ..exceptions import InvalidAuth
from .base import UtilityBase
from .helpers import get_form_action_url_and_hidden_inputs


class COAUtilities(UtilityBase):
    """City of Austin Utilities."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "City of Austin Utilities"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "coa"

    @staticmethod
    def timezone() -> str:
        """Return the timezone.

        Should match the siteTimeZoneId of the API responses.
        """
        return "America/Chicago"

    @staticmethod
    def is_dss() -> bool:
        """Check if Utility using DSS version of the portal."""
        return True

    @staticmethod
    async def async_login(
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        optional_mfa_secret: Optional[str],
    ) -> Optional[str]:
        """Login to the utility website."""
        # Get cookies
        await session.get(
            "https://coautilities.com/wps/wcm/connect/occ/coa/home",
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        )

        # Auth using username and password on coautilities
        url = (
            "https://coautilities.com/pkmslogin.form?/isam/sps/OPowerIDP_DSS/saml20/logininitial?"
            "RequestBinding=HTTPPost&"
            "NameIdFormat=email&"
            "PartnerId=opower-coa-dss-webUser&"
            "Target=https://dss-coa.opower.com"
        )

        async with session.post(
            url,
            headers={"User-Agent": USER_AGENT},
            data={
                "username": username,
                "password": password,
                "login-form-type": "pwd",
            },
            raise_for_status=True,
        ) as response:
            await response.text()
            if "PD-S-SESSION-ID-PCOAUT" not in session.cookie_jar.filter_cookies(
                URL("https://coautilities.com")
            ):
                raise InvalidAuth("Username/Password are invalid")

        # Getting SAML Request from opower
        url = (
            "https://sso.opower.com/sp/startSSO.ping?"
            "PartnerIdpId=https://coautilities.com/isam/sps/OPowerIDP_DSS/saml20&"
            "TargetResource=https%3A%2F%2Fdss-coa.opower.com%2Fwebcenter%2Fedge%2Fapis%2Fidentity-management-v1%2Fcws"
            "%2Fv1%2Fauth%2Fcoa%2Fsaml%2Flogin%2Fcallback%3FsuccessUrl%3Dhttps%253A%252F%252Fdss-coa.opower.com%252Fdss"
            "%252Flogin-success%253Ftoken%253D%2525s%2526nextPathname%253DL2Rzcy8%253D%26failureUrl%3Dhttps%253A%252F"
            "%252Fdss-coa.opower.com%252Fdss%252Flogin-error%253Freason%253D%2525s"
        )

        async with session.post(url, raise_for_status=True) as response:
            html = await response.text()
            action_url, hidden_inputs = get_form_action_url_and_hidden_inputs(html)
            assert set(hidden_inputs.keys()) == {"RelayState", "SAMLRequest"}

        # Getting SAML Response from coautilities
        headers = {
            "Referer": "https://sso.opower.com/",
            "User-Agent": USER_AGENT,
        }
        async with session.post(
            action_url,
            headers=headers,
            data=hidden_inputs,
            raise_for_status=True,
        ) as response:
            html = await response.text()
            action_url, hidden_inputs = get_form_action_url_and_hidden_inputs(html)
            assert set(hidden_inputs.keys()) == {"RelayState", "SAMLResponse"}

        # Getting Open Token from opower
        async with session.post(
            action_url,
            headers={"User-Agent": USER_AGENT},
            data=hidden_inputs,
            raise_for_status=True,
        ) as response:
            html = await response.text()
            action_url, hidden_inputs = get_form_action_url_and_hidden_inputs(html)
            assert set(hidden_inputs.keys()) == {"opentoken"}

        session.cookie_jar.update_cookies({"dssPortalCW": "1"})

        # Getting success token
        async with session.post(
            action_url,
            headers={"User-Agent": USER_AGENT},
            data=hidden_inputs,
            allow_redirects=False,
            raise_for_status=True,
        ) as response:
            await response.text()
            parsed_url = urlparse(response.headers["Location"])
            parsed_query = parse_qs(parsed_url.query)
            assert "token" in parsed_query
            token = parsed_query["token"][0]

        # Finally exchange this token to Auth token
        async with session.post(
            "https://dss-coa.opower.com"
            "/webcenter/edge/apis/identity-management-v1/cws/v1/auth/coa/saml/ott/confirm",
            headers={"User-Agent": USER_AGENT},
            data={"token": token},
            raise_for_status=True,
        ) as response:
            content = await response.json()
            return str(content["sessionToken"])
