"""Portland General Electric (PGE)."""

from typing import Any

import aiohttp

from ..const import USER_AGENT
from ..exceptions import CannotConnect, InvalidAuth
from .base import UtilityBase

# PGE migrated their identity provider from Firebase to AWS Cognito around
# June 2026, which broke the previous identitytoolkit.googleapis.com-based
# login. These values were learned from portlandgeneral.com's own web app.
_COGNITO_REGION = "us-west-2"
_COGNITO_CLIENT_ID = "4q9nbgmi0gcks5t7d6fkhubfnm"
_APIGEE_CLIENT_ID = "rHuS10KrfsLwFAr2sZ7MHh7oHELGx6YK"

# Cognito error types that genuinely mean "these credentials are wrong",
# as opposed to throttling/5xx/other transient errors, which should
# surface as CannotConnect instead of telling the user their password
# is bad during an outage.
_COGNITO_AUTH_ERROR_TYPES = frozenset(
    {
        "NotAuthorizedException",
        "UserNotFoundException",
        "PasswordResetRequiredException",
        "UserNotConfirmedException",
    }
)


class PortlandGeneral(UtilityBase):
    """Portland General Electric (PGE)."""

    @staticmethod
    def name() -> str:
        """Distinct recognizable name of the utility."""
        return "Portland General Electric (PGE)"

    def subdomain(self) -> str:
        """Return the opower.com subdomain for this utility."""
        return "pgn"

    @staticmethod
    def timezone() -> str:
        """Return the timezone."""
        return "America/Los_Angeles"

    async def async_login(
        self,
        session: aiohttp.ClientSession,
        username: str,
        password: str,
        login_data: dict[str, Any],
    ) -> str:
        """Login to the utility website."""
        async with session.post(
            f"https://cognito-idp.{_COGNITO_REGION}.amazonaws.com/",
            headers={
                "User-Agent": USER_AGENT,
                "Content-Type": "application/x-amz-json-1.1",
                "X-Amz-Target": "AWSCognitoIdentityProviderService.InitiateAuth",
                "Origin": "https://portlandgeneral.com",
                "Referer": "https://portlandgeneral.com/",
            },
            json={
                "AuthFlow": "USER_PASSWORD_AUTH",
                "ClientId": _COGNITO_CLIENT_ID,
                "AuthParameters": {
                    "USERNAME": username,
                    "PASSWORD": password,
                },
            },
            # raise_for_status is left False here because a 400 from Cognito
            # needs its body inspected (it's how wrong credentials, as
            # opposed to throttling, are distinguished) before deciding
            # whether to raise at all.
            raise_for_status=False,
        ) as resp:
            # Cognito responds with Content-Type: application/x-amz-json-1.1,
            # not application/json, so the content-type check must be skipped.
            try:
                result = await resp.json(content_type=None)
            except (aiohttp.ContentTypeError, ValueError):
                result = {}
            if not isinstance(result, dict):
                result = {}
            if resp.status == 400 and result.get("__type") in _COGNITO_AUTH_ERROR_TYPES:
                raise InvalidAuth("Username and password failed: " + str(result.get("message") or result["__type"]))
            if resp.status in (401, 403):
                # Cognito's InitiateAuth doesn't normally use 401/403 - a
                # WAF block or other gateway-level failure could, though,
                # and Opower.async_login() unconditionally maps any
                # ClientResponseError with status 401/403 to InvalidAuth
                # regardless of body. Raise CannotConnect directly here so
                # an unrecognized 401/403 isn't misreported as bad
                # credentials.
                raise CannotConnect(f"Cognito returned {resp.status} without a recognized error body: {result}")
            # Anything else non-200 (throttling, 5xx, an unparsable body, or
            # an unrecognized error type) is treated as a connectivity
            # problem rather than bad credentials: it surfaces here as
            # aiohttp.ClientResponseError, which Opower.async_login() maps
            # to CannotConnect.
            resp.raise_for_status()
            id_token = (result.get("AuthenticationResult") or {}).get("IdToken")
            if not id_token:
                # Cognito can respond with HTTP 200 and a challenge (e.g.
                # NEW_PASSWORD_REQUIRED, SMS_MFA) instead of tokens when the
                # account needs an additional step this flow doesn't
                # support, or rarely with an unparsable/unexpected body.
                raise InvalidAuth(
                    "Username and password succeeded, but Cognito did not return a usable token: "
                    + str(result.get("ChallengeName") or result)
                )

        async with session.post(
            "https://apix.portlandgeneral.com/pg-token-implicit-aws/token",
            params={
                "client_id": _APIGEE_CLIENT_ID,  # learned from portlandgeneral.com's own web app
                "response_type": "token",
                "redirect_uri": "",  # Not sure why this is present with an empty value
            },
            headers={
                "content-length": "0",
                "User-Agent": USER_AGENT,
                "idp_access_token": id_token,
            },
            raise_for_status=False,
        ) as resp:
            try:
                result = await resp.json(content_type=None)
            except (aiohttp.ContentTypeError, ValueError):
                result = {}
            if not isinstance(result, dict):
                result = {}
            if resp.status in (400, 401, 403) and "errorResponse" in result:
                raise InvalidAuth(
                    "Username and password succeeded with the identity provider, but PGE's own API rejected "
                    "the token exchange with "
                    + str(result["errorResponse"])
                    + f". This usually means _APIGEE_CLIENT_ID ({_APIGEE_CLIENT_ID}) is stale and needs updating."
                )
            if resp.status in (401, 403):
                # A 401/403 without the errorResponse body above isn't
                # necessarily proof the client_id/credentials are wrong -
                # could be a WAF block or an unrelated gateway failure. As
                # above, Opower.async_login() maps any ClientResponseError
                # with status 401/403 to InvalidAuth regardless of body, so
                # raise CannotConnect directly instead of going through
                # resp.raise_for_status() here.
                raise CannotConnect(f"PGE token exchange returned {resp.status} without a recognized error body: {result}")
            # Anything else non-200 (5xx, an unparsable body) is a
            # connectivity problem, not something a different password
            # would fix - let it surface as CannotConnect via
            # ClientResponseError instead.
            resp.raise_for_status()
            access_token = result.get("access_token")
            if not access_token:
                raise InvalidAuth(
                    "Username and password succeeded, but the token exchange response was unexpected: " + str(result)
                )
            return str(access_token)
