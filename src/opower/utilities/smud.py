"""Sacramento Municipal Utility District (SMUD)."""

#
# SMUD is a community owned, local monopoly power company in Sacramento, California.
#
# https://smud.org
# https://en.wikipedia.org/wiki/Sacramento_Municipal_Utility_District
# https://www.reddit.com/r/homeassistant/comments/10wnoox/smud_energy_smart_meter_integration/
#
# The web UI for power usage is at:
# https://myaccount.smud.org/manage/opowerresidential/energyusage
#
# OKTA is an enterprise identity/SSO provider
# https://www.okta.com/
#
# To filter FireFox network inspector when logging in:
# `-regexp:woff|beacon|appdynamics|fonts|css|hotjar|usabilla|chat|ico|analytics|promo|nextprofilequestion|trackEvent
# -mime-type:image`
#
# Test with:
# `python src/demo.py --utility smud --username mysmudloginemail@example.com --password "mypassword" -v`

from html.parser import HTMLParser
import logging
from typing import Optional
from urllib.parse import parse_qs

from aiohttp import ClientResponse, ClientSession
from aiohttp.client_exceptions import ClientResponseError
from yarl import URL

import opower

from ..const import USER_AGENT
from .base import UtilityBase

_LOGGER = logging.getLogger(__file__)


class SMUDLoginParser(HTMLParser):
    """HTML parser to extract login verification token from SMUD Login page."""

    def __init__(self) -> None:
        """Initialize."""
        super().__init__()
        self.verification_token: Optional[str] = None
        self.ocis_req_sp: Optional[str] = None
        self.relay_state: Optional[str] = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        """Try to extract the verification token from the login input."""
        if tag == "input" and ("name", "__RequestVerificationToken") in attrs:
            _, token = next(filter(lambda attr: attr[0] == "value", attrs))
            if token is None:
                return
            _LOGGER.debug(
                "SMUD self verify token: %s...%s (%d characters)",
                token[0:5],
                token[-5:],
                len(token),
            )
            self.verification_token = token
        """Try to extract the OCIS_REQ_SP input value from the identity.oraclecloud.com sso HTML"""
        if tag == "input" and ("name", "OCIS_REQ_SP") in attrs:
            _, token = next(filter(lambda attr: attr[0] == "value", attrs))
            if token is None:
                return
            _LOGGER.debug(
                "OCIS_REQ_SP self verify token: %s...%s (%d characters)",
                token[0:5],
                token[-5:],
                len(token),
            )
            self.ocis_req_sp = token
        """Try to extract the RelayState input value from the smud.okta.com HTML"""
        if tag == "input" and ("name", "RelayState") in attrs:
            _, token = next(filter(lambda attr: attr[0] == "value", attrs))
            if token is None:
                return
            _LOGGER.debug(
                "RelayState value: %s...%s (%d characters)",
                token[0:5],
                token[-5:],
                len(token),
            )
            self.relay_state = token


class SMUDOktaResponseSamlResponseValueParser(HTMLParser):
    """HTML parser to extract SAMLResponse token from OKTA response for Opower SSO."""

    # <input name="SAMLResponse" type="hidden" value="..."/>
    def handle_starttag(self, tag: str, attrs: list[tuple[str, Optional[str]]]) -> None:
        """Try to extract the SAMLResponse value."""
        if tag == "input":
            for name, value in attrs:
                if name == "name" and value == "SAMLResponse":
                    self.saml_response = attrs[2][1]


class SMUD(UtilityBase):
    """Sacramento Municipal Utility District (SMUD)."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Sacramento Municipal Utility District (SMUD)"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "smud"

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/Los_Angeles"

    @staticmethod
    async def async_login(
        session: ClientSession,
        username: str,
        password: str,
        optional_mfa_secret: Optional[str],  # Not used by SMUD.
    ) -> None:
        """Login to the utility website and authorize opower."""
        # If we already have a cookie, return early if it is valid.
        if (
            len(session.cookie_jar.filter_cookies(URL("https://smud.opower.com/ei")))
            > 0
        ):
            try:
                async with session.get(
                    "https://smud.opower.com/ei/edge/apis/multi-account-v1/cws/smud/customers",
                    headers={"User-Agent": USER_AGENT},
                    raise_for_status=True,
                ):
                    return
            except ClientResponseError:
                _LOGGER.debug("Failed to login to SMUD with existing cookies")
                session.cookie_jar.clear()
                pass

        smud_login_page_url = "https://myaccount.smud.org/"

        _LOGGER.debug("Fetching SMUD login page: %s", smud_login_page_url)

        myaccount_response = await session.get(
            smud_login_page_url,
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        )

        await SMUD.log_response(myaccount_response, session)

        # Parse the verification token which will be used during login.
        # NB: Although the response cookies contain a `__RequestVerificationToken`, it does not match
        # the one contained in the HTML and results in a 500 server error from SMUD during login.
        login_parser = SMUDLoginParser()
        login_parser.feed(await myaccount_response.text())
        requestVerificationToken = login_parser.verification_token

        _LOGGER.debug("Performing SMUD login to: %s", smud_login_page_url)

        # Do the SMUD login which will set cookies in the session.
        login_response = await session.post(
            smud_login_page_url,
            data={
                "Lang": "en",
                "UserID": username,
                "Password": password,
                "__RequestVerificationToken": requestVerificationToken,
            },
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        )

        await SMUD.log_response(login_response, session)

        login_response_body = await login_response.text()
        if "could not be authenticated" in login_response_body:
            raise opower.InvalidAuth

        smud_energyusage_page_url = (
            "https://myaccount.smud.org/manage/opowerresidential/energyusage"
        )

        _LOGGER.debug("Opening SMUD energy usage page: %s", smud_energyusage_page_url)

        # Visit the Energy Usage page
        energyusage_response = await session.get(
            smud_energyusage_page_url,
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        )

        await SMUD.log_response(energyusage_response, session)

        okta_login_2_url = SMUD.get_okta_url_from_response_redirect(
            energyusage_response
        )

        _LOGGER.debug("Fetching second OKTA login page: %s", okta_login_2_url)

        smud_okta_response = await session.get(
            okta_login_2_url,
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        )

        await SMUD.log_response(smud_okta_response, session)

        parser = SMUDOktaResponseSamlResponseValueParser()
        parser.feed(await smud_okta_response.text())
        saml_response = parser.saml_response
        assert saml_response

        _LOGGER.debug(
            "Parsed SAMLResponse: %s...%s (%d characters)",
            saml_response[0:5],
            saml_response[-5:],
            len(saml_response),
        )

        # This step is done in the web browser but doesn't seem to matter here.
        smud_ssotransition_url = "https://myaccount.smud.org/signin/ssotransition"

        _LOGGER.debug("Fetching SMUD ssotransition page: %s", smud_ssotransition_url)
        smud_ssotransition_response = await session.get(
            smud_ssotransition_url,
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        )

        await SMUD.log_response(smud_ssotransition_response, session)

        # This is the action of the #appForm form in the smud_okta_response HTML.
        opower_sso_url = "https://idcs-8d184356671642c58ea38b42e6420ed2.identity.oraclecloud.com/fed/v1/sp/sso"

        _LOGGER.debug("POSTing opower sso page with SAMLResponse: %s", opower_sso_url)

        opower_sso_response = await session.post(
            opower_sso_url,
            data={
                "SAMLResponse": saml_response,
                "RelayState": "https://smud.opower.com/ei/app/myEnergyUse",
            },
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
            allow_redirects=True,
        )
        await SMUD.log_response(opower_sso_response, session)

        login_parser.feed(await opower_sso_response.text())
        ocis_req_sp = login_parser.ocis_req_sp

        identity_oraclecloud_login_url = "https://idcs-8d184356671642c58ea38b42e6420ed2.identity.oraclecloud.com/sso/v1/user/login"

        _LOGGER.debug(
            "POSTing opower sso login page with OCIS_REQ_SP: %s",
            identity_oraclecloud_login_url,
        )

        identity_oraclecloud_login_response = await session.post(
            identity_oraclecloud_login_url,
            data={
                "OCIS_REQ_SP": ocis_req_sp,
            },
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
            allow_redirects=True,
            max_redirects=10,
        )

        await SMUD.log_response(identity_oraclecloud_login_response, session)

        okta_saml_request_url = identity_oraclecloud_login_response.real_url
        _LOGGER.debug(
            "RESPONSE from opower sso login page with OCIS_REQ_SP, RelayState: %s",
            okta_saml_request_url,
        )

        return

    @classmethod
    def get_okta_url_from_response_redirect(
        cls, energyusage_response: ClientResponse
    ) -> str:
        """Get the OKTA URL to open next from the last redirect of the previous response."""
        # https://smud.okta.com/login/sessionCookieRedirect
        #   ?token=20111...6QJMn
        #   &redirectUrl=https://smud.okta.com/app/sacramentomunicipalutilitydistrict_opower_1/exk2i...cF0x7/sso/saml
        #       ?RelayState=https://smud.opower.com/ei/app/myEnergyUse
        energyUsageResponseRedirectedFinalUrl = energyusage_response.history[-1].url

        query_parts = parse_qs(energyUsageResponseRedirectedFinalUrl.query_string)

        return query_parts["redirectUrl"][0]

    # Store cookies so we can log what is new after each request.
    cookies: dict[str, list[str]] = {}

    @staticmethod
    async def log_response(response: ClientResponse, session: ClientSession) -> None:
        """Log any redirects and new cookies. Log full HTML when -vv is set."""
        host = response.host  # Is this the request URL or the final redirected url?

        redirects = [r.url for r in response.history]
        if len(redirects) > 1:
            _LOGGER.debug("Performed %d redirects", len(redirects) - 1)
            for redirect in redirects[1:]:
                _LOGGER.debug("-> %s", redirect.__str__())

        if len(session.cookie_jar.filter_cookies(response.url)) > 0:
            response_cookie_names = list(
                session.cookie_jar.filter_cookies(response.url).keys()
            )
            last_cookie_names = SMUD.cookies.get(host, [])
            response_new_cookie_names = set(response_cookie_names) - set(
                last_cookie_names
            )

            if len(response_new_cookie_names) > 0:
                _LOGGER.debug(
                    "Set new cookies: `%s`", "`, `".join(response_new_cookie_names)
                )

                SMUD.cookies[host] = last_cookie_names + response_cookie_names

        response_html = await response.text()
        _LOGGER.log(logging.DEBUG - 1, "Response %s:", response.url)
        _LOGGER.log(logging.DEBUG - 1, response_html)
