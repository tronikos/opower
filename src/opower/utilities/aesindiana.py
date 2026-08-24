"""AES Indiana (formerly Indianapolis Power & Light).

AES Indiana's OPower portal (aesi.opower.com) delegates authentication to
Oracle Identity Cloud Service (IDCS) which federates to
myaccount.aesindiana.com via SAML. The login flow is:

1. GET aesi.opower.com/ei/ which redirects through OPower -> Oracle IDCS ->
   myaccount.aesindiana.com, ending on an ASP.NET login form.
2. POST the ASP.NET form (ViewState/EventValidation + credentials).
3. Follow redirects back through the SAML endpoint which returns an
   auto-submitting form containing the SAMLResponse.
4. POST the SAMLResponse to Oracle IDCS, follow the resulting redirects
   back to OPower which sets session cookies.

All redirects must be followed manually with the raw Location header because
aiohttp re-encodes redirect URLs by default (requote_redirect_url=True) and
yarl's normalization breaks the byte-exact signed SAMLRequest query string,
causing "The authn request signature failed to verify" errors.
"""

import logging
import re
from html import unescape
from typing import Any
from urllib.parse import urljoin

import aiohttp
from yarl import URL

from ..const import USER_AGENT
from ..exceptions import InvalidAuth
from .base import UtilityBase

_LOGGER = logging.getLogger(__name__)

# Safety bound for the SSO flow. A full login takes ~20 requests.
_MAX_STEPS = 40

# Marker of the ASP.NET login form on myaccount.aesindiana.com.
_LOGIN_FORM_MARKER = "iplLogin$UserName"
_USERNAME_FIELD = "ctl00$phMainColumn$ctl00$iplLogin$UserName"
_PASSWORD_FIELD = "ctl00$phMainColumn$ctl00$iplLogin$Password"  # noqa: S105
_LOGIN_BUTTON_FIELD = "ctl00$phMainColumn$ctl00$iplLogin$LoginButton"

_TAG_RE = re.compile(r"<(?:input|form)\b[^>]*>", re.IGNORECASE)
_ATTR_RE = re.compile(r'([\w-]+)\s*=\s*"([^"]*)"')


def _get_form_action_and_hidden_inputs(html: str) -> tuple[str, dict[str, str]]:
    """Return the action URL and hidden inputs of the first form in the page.

    Unlike helpers.get_form_action_url_and_hidden_inputs, this tolerates extra
    attributes between name and value (ASP.NET renders id attributes) and
    unescapes HTML entities: AES Indiana emits the form action with &amp;
    separators and browsers submit decoded attribute values.
    """
    action_url = ""
    inputs: dict[str, str] = {}
    for match in _TAG_RE.finditer(html):
        tag = match.group(0)
        attrs = {m.group(1).lower(): unescape(m.group(2)) for m in _ATTR_RE.finditer(tag)}
        if tag[1:5].lower() == "form":
            if not action_url:
                action_url = attrs.get("action", "")
        elif attrs.get("type") == "hidden" and "name" in attrs:
            inputs[attrs["name"]] = attrs.get("value", "")
    return action_url, inputs


class AESIndiana(UtilityBase):
    """AES Indiana utility implementation."""

    @staticmethod
    def name() -> str:
        """Return the name of the utility."""
        return "AES Indiana"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        return "aesi"

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/Indiana/Indianapolis"

    @staticmethod
    async def async_login(
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        login_data: dict[str, Any],
    ) -> str:
        """Login to the AES Indiana OPower portal.

        Drives the SAML SSO flow described in the module docstring and returns
        an empty token since subsequent API calls are authorized by the
        session cookies OPower sets (like NIPSCO).
        """
        # Pending request: method, URL, optional form data.
        pending: tuple[str, str, dict[str, str] | None] = ("GET", "https://aesi.opower.com/ei/", None)
        submitted_login = False

        for step in range(_MAX_STEPS):
            method, url, data = pending
            # Authentication URLs contain short-lived SAML/OAuth credentials in
            # their query strings. Keep those values out of diagnostic logs.
            _LOGGER.debug("AES Indiana login step %d: %s %s", step, method, url.split("?", 1)[0][:120])
            async with session.request(
                method,
                # encoded=True keeps yarl from normalizing (and thus breaking)
                # the signed SAMLRequest query string.
                URL(url, encoded=True),
                data=data,
                allow_redirects=False,
                headers={"User-Agent": USER_AGENT},
                raise_for_status=True,
            ) as resp:
                status = resp.status
                location = resp.headers.get("Location")
                body = await resp.text()

            if status in (301, 302, 303, 307, 308) and location:
                # urljoin is a pure string operation that, unlike yarl,
                # preserves the redirect URL bytes exactly.
                redirect_url = urljoin(url, location)
                # 307 and 308 preserve the request method and body. The other
                # redirect statuses in this browser-oriented flow become GETs.
                pending = (method, redirect_url, data) if status in (307, 308) else ("GET", redirect_url, None)
                continue

            if _LOGIN_FORM_MARKER in body:
                if submitted_login:
                    # The login form is rendered again on failed logins.
                    raise InvalidAuth("Invalid AES Indiana credentials")
                action_url, inputs = _get_form_action_and_hidden_inputs(body)
                inputs[_USERNAME_FIELD] = username
                inputs[_PASSWORD_FIELD] = password
                inputs[_LOGIN_BUTTON_FIELD] = "Sign In"
                pending = ("POST", urljoin(url, action_url), inputs)
                submitted_login = True
                continue

            if "SAMLResponse" in body or "OCIS_REQ" in body:
                # Auto-submitting form that carries the SAML assertion back to
                # Oracle IDCS.
                action_url, inputs = _get_form_action_and_hidden_inputs(body)
                if not action_url:
                    raise InvalidAuth("AES Indiana login: SAML form has no action URL")
                pending = ("POST", urljoin(url, action_url), inputs)
                continue

            if url.split("?", 1)[0].rstrip("/") == "https://aesi.opower.com/ei/x/dashboard":
                # Landed on the OPower dashboard; session cookies are set.
                _LOGGER.debug("AES Indiana login successful")
                return ""

            raise InvalidAuth(f"AES Indiana login: unexpected page at {url[:120]}")

        raise InvalidAuth("AES Indiana login did not complete")
