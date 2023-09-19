"""Sacramento Municipal Utility District (SMUD)."""

from html.parser import HTMLParser
import re
from typing import Optional

import aiohttp

from ..const import USER_AGENT
from ..exceptions import InvalidAuth
from .base import UtilityBase


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
            print("self verify token:", token)
            self.verification_token = token


class SMUDUsageParser(HTMLParser):
    """HTML parser to extract OPower bearer token from SMUD Usage page."""
    """<input name="SAMLResponse" type="hidden" value="PD94bW"""

    #_regexp = re.compile(r'var accessToken\s+=\s+["\'](?P<token>.+)["\']')
    #_regexp = re.compile(r'"SAMLResponse" type="hidden" value=["\'](?P<token>.+)["\']')
    _regexp = re.compile(r'https:\/\/smud\.okta\.com\/login\/sessionCookieRedirect\?token=(?P<token>.+)&redirect.*')

    def __init__(self) -> None:
        """Initialize."""
        super().__init__()
        self.opower_access_token = None
        self._in_inline_script = False

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Recognizes inline scripts."""
        if (
            tag == "script"
            and next(filter(lambda attr: attr[0] == "src", attrs), None) is None
        ):
            self._in_inline_script = True

    def handle_data(self, data: str) -> None:
        """Try to extract the access token from the inline script."""
        if self._in_inline_script:
            result = self._regexp.search(data)
            if result and result.group("token"):
                self.opower_access_token = result.group("token")

    def handle_endtag(self, tag: str) -> None:
        """Recognizes the end of inline scripts."""
        if tag == "script":
            self._in_inline_script = False


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
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        optional_mfa_secret: Optional[str],
    ) -> str:
        """Login to the utility website and authorize opower."""
        login_parser = SMUDLoginParser()

        async with session.get(
            "https://myaccount.smud.org",
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        ) as resp:
            login_parser.feed(await resp.text())

            assert (
                login_parser.verification_token
            ), "Failed to parse __RequestVerificationToken"

        await session.post(
            "https://myaccount.smud.org",
            data={
                "__RequestVerificationToken": login_parser.verification_token,
                #"GenericMessage": "Incorrect username or password",
                "GenericMessage": "Sorry, you could not be authenticated with the information provided. Please try again.",
                "LockedMessage": "Account is locked",
                "ReturnUrl": "",
                #"OtherPageUrl": "False",
                "UserID": username,
                "Password": password,
                #"RememberMe": "true",
            },
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        )

        usage_parser = SMUDUsageParser()
        #session: aiohttp.ClientSession,
        async with session.get(
            #"https://www.pse.com/api/AccountSelector/GetContractAccountJson",
            "https://myaccount.smud.org/manage/opowerresidential/energyusage",
            allow_redirects=True,
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
#        ) as resp:
            #if len(await resp.text()) == 0:
            #    raise InvalidAuth("Login failed")
            #rhistory = resp.history
####            print(type(resp.history))
 ###           print('history: ', resp.history[1])
 ###           print()
            #usage_parser.feed(rhistory)
            #print('text: ', resp.text)
            #print('url: ', resp.url)
            #print('status: ', resp.status)

          ) as resp:
            #print('resp: ', resp)
            #print('TYPE RESP:', type(resp))
            #print('TYPE RESP.HIST:', type(resp.history))

            rhistory = resp.history
            rhistory = str(rhistory[1])
            #print('TYPE RHISTORY', type(rhistory))
            print('history: ', rhistory)
            regexp = re.compile(r'https:\/\/smud\.okta\.com\/login\/sessionCookieRedirect\?token=(?P<token>.+)&redirect.*')
            result = regexp.search(rhistory)
            print('-----------------' )
            if result and result.group("token"):
                #self.opower_access_token = result.group("token")
                print(result.group("token"))
                print()
            exit()
            usage_parser.feed(rhistory)

            assert (
                usage_parser.opower_access_token
            ), "Failed to parse OPower bearer token"

        print("Access Token:", usage_parser.opower_access_token)
        return usage_parser.opower_access_token

       # async with session.get(
        #    "https://smud.okta.com/app/sacramentomunicipalutilitydistrict_opower_1/exk2iie3ttVlW7icF0x7/sso/saml?RelayState=https://smud.opower.com/ei/app/myEnergyUse",
            #"https://myaccount.smud.org/manage/opowerresidential/energyusage",

         #   headers={"User-Agent": USER_AGENT},
        #    raise_for_status=True,
       # ) as resp:
            #usage_parser.feed(await resp.text())

           # assert (
          #      usage_parser.opower_access_token
         #   ), "Failed to parse OPower bearer token"

        #return usage_parser.opower_access_token
