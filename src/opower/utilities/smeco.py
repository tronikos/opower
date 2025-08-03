"""Southern Maryland Electric Cooperative (SMECO)."""

from typing import Any

import aiohttp

from ..const import USER_AGENT
from ..exceptions import InvalidAuth
from .base import UtilityBase


class SMECO(UtilityBase):
    """Southern Maryland Electric Cooperative (SMECO).

    This utility uses the Opower Digital Self-Service (DSS) portal hosted at
    ``dss-smcc.opower.com``.  The login flow is simpler than some other DSS
    providers: credentials are submitted directly to an API endpoint on the
    Opower domain, and the response includes a ``sessionToken`` that can be
    used as the bearer token for subsequent API calls.
    """

    @staticmethod
    def name() -> str:
        """Return a distinct, human-readable name for this utility."""
        return "Southern Maryland Electric Cooperative (SMECO)"

    @staticmethod
    def subdomain() -> str:
        """Return the opower.com subdomain for this utility."""
        # The SMECO DSS portal lives at dss-smcc.opower.com, so the subdomain is
        # ``smcc``.  Opower API calls will be made against ``smcc.opower.com``.
        return "smcc"

    @staticmethod
    def timezone() -> str:
        """Return the timezone for this utility."""
        # SMECO serves Southern Maryland, which is in the Eastern time zone.
        return "America/New_York"

    @staticmethod
    def is_dss() -> bool:
        """Indicate that this utility uses the DSS version of the portal."""
        return True

    @staticmethod
    async def async_login(
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        login_data: dict[str, Any],
    ) -> str | None:
        """Authenticate against the SMECO DSS portal and return a session token.

        The SMECO login endpoint expects form-encoded data containing the
        ``username``, ``password``, and a ``rememberMe`` flag.  A successful
        response includes a JSON object with a ``sessionToken`` field.  This
        method returns that token as a string; if authentication fails, an
        ``InvalidAuth`` exception will be raised.

        :param session: An existing aiohttp.ClientSession to reuse.
        :param username: The SMECO account username (email address).
        :param password: The SMECO account password.
        :param optional_mfa_secret: Not used by SMECO; MFA is not supported.
        :returns: The Opower session token on success.
        :raises InvalidAuth: If login is unsuccessful or the response format
            differs from what is expected.
        """
        # Clear any lingering opower.com cookies to avoid double-login issues.
        session.cookie_jar.clear(lambda cookie: cookie["domain"].endswith(".opower.com"))

        # Construct the login payload.  ``rememberMe`` must be a string (not
        # boolean) because the API expects form-encoded values.
        payload = {
            "username": username,
            "password": password,
            "rememberMe": "true",
        }

        # SMECO's DSS login endpoint.  This path comes from browser network
        # inspection; the base domain must include the ``dss-smcc`` prefix to
        # direct requests to the DSS portal rather than the legacy EI portal.
        login_url = "https://dss-smcc.opower.com/webcenter/edge/apis/identity-management-v1/cws/v1/smcc/login"

        # Submit credentials.  Use form data instead of JSON.  Expect a JSON
        # response containing ``sessionToken``.  If the server returns a non
        # 2xx status code, aiohttp will raise; we let that propagate.
        async with session.post(
            login_url,
            data=payload,
            headers={"User-Agent": USER_AGENT},
            raise_for_status=True,
        ) as resp:
            try:
                result = await resp.json()
            except Exception as exc:
                # If the response is not JSON, authentication likely failed.
                raise InvalidAuth("Unexpected response from SMECO login") from exc

        # Ensure we have a sessionToken in the response; otherwise the
        # credentials are invalid or the API has changed.
        token = result.get("sessionToken")
        if not token:
            raise InvalidAuth("Login failed; sessionToken not found in response")

        # Set a DSS portal cookie to select the correct site version.  The
        # ``dssPortalCW`` cookie informs the Opower backend that a DSS
        # session is being used.
        session.cookie_jar.update_cookies({"dssPortalCW": "1"})

        return str(token)
