"""City of Austin Utilities."""

from typing import Any
from urllib.parse import parse_qs, quote, urlparse

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
        login_data: dict[str, Any],
    ) -> str | None:
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
            if "PD-S-SESSION-ID-PCOAUT" not in session.cookie_jar.filter_cookies(URL("https://coautilities.com")):
                raise InvalidAuth("Username/Password are invalid")

        # Getting SSO URL from opower
        url = "https://dss-coa.opower.com/webcenter/edge/apis/identity-management-v1/cws/v1/auth/coa/user-details"
        TargetResource = (
            "https%3A%2F%2Fdss-coa.opower.com%2Fwebcenter%2Fedge%2Fapis%2F"
            "identity-management-v1%2Fcws%2Fv1%2Fauth%2Fcoa%2Fsso%2Flogin%2Fcallback"
        )

        async with session.get(
            url,
            headers={
                "User-Agent": USER_AGENT,
                "Opower-Auth-Mode": "sso",
            },
        ) as response:
            content = await response.json()
            location = content["error"]["location"]
            action_url = location.replace("${TargetResource}", TargetResource)

        # Getting SAML Request from opower
        auth_response = await session.get(
            action_url,
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        )
        action_url = str(auth_response.url)

        # Fix encoding since can't set requote_redirect_url to False
        index = action_url.index("?")
        url_slice1 = action_url[: index + 1]
        url_slice2 = quote(action_url[index + 1 :], safe="%&=")
        action_url = url_slice1 + url_slice2

        # Getting SAML Response from coautilities
        headers = {
            "Referer": "https://dss-coa.opower.com/",
            "User-Agent": USER_AGENT,
        }
        async with session.get(
            URL(action_url, encoded=True),
            headers=headers,
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
            assert set(hidden_inputs.keys()) == {"OCIS_REQ_SP"}

        session.cookie_jar.update_cookies({"dssPortalCW": "1"})

        # Getting success token
        async with session.post(
            action_url,
            headers={"User-Agent": USER_AGENT},
            data=hidden_inputs,
            raise_for_status=True,
        ) as response:
            await response.text()
            parsed_url = urlparse(str(response.url))
            parsed_query = parse_qs(parsed_url.query)
            assert "token" in parsed_query
            token = parsed_query["token"][0]

        # Finally exchange this token to Auth token
        async with session.post(
            "https://dss-coa.opower.com/webcenter/edge/apis/identity-management-v1/cws/v1/auth/coa/sso/ott/confirm",
            headers={"User-Agent": USER_AGENT},
            data={"token": token},
            raise_for_status=True,
        ) as response:
            content = await response.json()
            return str(content["sessionToken"])
