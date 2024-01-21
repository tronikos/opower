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
#    -mime-type:image`
#
# Test with:
# `python src/demo.py --utility smud --username mysmudloginemail@example.com --password "mypassword" -v`

from html.parser import HTMLParser
import logging
from typing import Optional
from urllib.parse import parse_qs

from aiohttp import ClientResponse, ClientSession

import opower

from ..const import USER_AGENT
from .base import UtilityBase

_LOGGER = logging.getLogger(__file__)


class SMUDLoginParser(HTMLParser):
    """HTML parser to extract login verification token from SMUD Login page."""

    def __init__(self) -> None:
        """Initialize."""
        super().__init__()
        self.verification_token = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Try to extract the verification token from the login input."""
        if tag == "input" and ("name", "__RequestVerificationToken") in attrs:
            _, token = next(filter(lambda attr: attr[0] == "value", attrs))
            _LOGGER.debug("SMUD self verify token: %s", token)
            self.verification_token = token


class SMUDOktaResponseSamlResponseValueParser(HTMLParser):
    """HTML parser to extract SAMLResponse token from OKTA response for Opower SSO."""

    # <input name="SAMLResponse" type="hidden" value="..."/>
    def handle_starttag(self, tag, attrs):
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
        if (
            session.cookie_jar.filter_cookies("https://smud.opower.com/ei").__len__()
            > 0
        ):
            return

        smud_login_page_url = "https://myaccount.smud.org/"

        _LOGGER.debug("Fetching SMUD login page: %s", smud_login_page_url)

        myaccount_response = await session.get(
            smud_login_page_url,
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        )

        SMUD.log_response(myaccount_response, session)

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

        SMUD.log_response(login_response, session)

        # TODO: assert logged in here... test with bad username and password.

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

        SMUD.log_response(energyusage_response, session)

        okta_login_2_url = SMUD.get_okta_url_from_response_redirect(
            energyusage_response
        )

        _LOGGER.debug("Fetching second OKTA login page: %s", okta_login_2_url)

        smud_okta_response = await session.get(
            okta_login_2_url,
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        )

        SMUD.log_response(smud_okta_response, session)

        parser = SMUDOktaResponseSamlResponseValueParser()
        parser.feed(await smud_okta_response.text())
        saml_response = parser.saml_response
        assert saml_response

        _LOGGER.debug(
            "Parsed SAMLResponse: %s...%s (%d characters)",
            saml_response[0:5],
            saml_response[-5:],
            saml_response.__len__(),
        )

        # This step is done in the web browser but doesn't seem to matter here.
        #
        # smud_ssotransition_url = "https://myaccount.smud.org/signin/ssotransition"
        #
        # _LOGGER.debug("Fetching SMUD ssotransition page: %s", smud_ssotransition_url)
        # smud_ssotransition_response = await session.get(
        #     smud_ssotransition_url,
        #     headers={"User-Agent": USER_AGENT},
        #     raise_for_status=True,
        # )
        #
        # SMUD.print_redirects_cookies_response(smud_ssotransition_response, session)

        opower_sso_url = "https://sso.opower.com/sp/ACS.saml2"

        _LOGGER.debug("POSTing opower sso page with SAMLResponse: %s", opower_sso_url)

        opower_sso_response = await session.post(
            opower_sso_url,
            data={
                "SAMLResponse": saml_response,
                "RelayState": "https://smud.opower.com/ei/app/myEnergyUse",
            },
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        )

        SMUD.log_response(opower_sso_response, session)

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
    cookies = {}

    @staticmethod
    def log_response(response: ClientResponse, session):
        """Log any redirects and new cookies. Log full HTML when DEBUG_LOG_RESPONSE is set."""
        host = response.host  # Is this the request URL or the final redirected url?

        redirects = [r.url for r in response.history]
        if redirects.__len__() > 0:
            _LOGGER.debug("Performed %d redirects", redirects.__len__())
            for redirect in redirects:
                _LOGGER.debug("-> %s", redirect.__str__())

        if session.cookie_jar.filter_cookies(response.url).__len__() > 0:
            response_cookie_names = list(
                session.cookie_jar.filter_cookies(response.url).keys()
            )
            last_cookie_names = SMUD.cookies.get(host, [])
            response_new_cookie_names = set(response_cookie_names) - set(
                last_cookie_names
            )

            if response_new_cookie_names.__len__() > 0:
                _LOGGER.debug(
                    "Set new cookies: `%s`", "`, `".join(response_new_cookie_names)
                )

                SMUD.cookies[host] = last_cookie_names + response_cookie_names

        if hasattr("opower", "DEBUG_LOG_RESPONSE") and opower.DEBUG_LOG_RESPONSE:
            response_html = response.text()
            _LOGGER.debug("Response %s:", response.url)
            _LOGGER.debug(response_html)
