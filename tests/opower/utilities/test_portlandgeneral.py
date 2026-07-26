"""Tests for Portland General Electric (PGE)."""

import os
import unittest
from typing import Any

import aiohttp
from aiohttp import RequestInfo
from dotenv import load_dotenv
from multidict import CIMultiDict, CIMultiDictProxy
from yarl import URL

from opower.exceptions import CannotConnect, InvalidAuth
from opower.utilities.portlandgeneral import PortlandGeneral

ENV_SECRET_PATH = os.path.join(os.path.dirname(__file__), "../../../.env.secret")


class TestPortlandGeneral(unittest.IsolatedAsyncioTestCase):
    """Test public methods inherited from UtilityBase."""

    def test_name(self) -> None:
        """Test name."""
        self.assertEqual("Portland General Electric (PGE)", PortlandGeneral.name())

    def test_subdomain(self) -> None:
        """Test subdomain."""
        self.assertEqual("pgn", PortlandGeneral().subdomain())

    def test_timezone(self) -> None:
        """Test timezone."""
        self.assertEqual("America/Los_Angeles", PortlandGeneral.timezone())

    async def test_real_login(self) -> None:
        """Perform a live test against PGE's Cognito and Apigee gateway."""
        load_dotenv(dotenv_path=ENV_SECRET_PATH)

        username = os.getenv("PORTLANDGENERAL_USERNAME")
        password = os.getenv("PORTLANDGENERAL_PASSWORD")

        if username is None or password is None:
            self.skipTest(
                "Add `PORTLANDGENERAL_USERNAME=` and `PORTLANDGENERAL_PASSWORD=` "
                "to `.env.secret` to run live PortlandGeneral test."
            )

        pge = PortlandGeneral()
        session = aiohttp.ClientSession()
        self.addAsyncCleanup(session.close)

        access_token = await pge.async_login(session, username, password, {})

        self.assertIsNotNone(access_token)
        self.assertTrue(len(access_token) > 0)


class _MockResponse:
    """Minimal stand-in for aiohttp.ClientResponse."""

    def __init__(self, *, status: int = 200, payload: Any = None, raise_on_json: Exception | None = None) -> None:
        self.status = status
        self._payload = payload
        self._raise_on_json = raise_on_json

    async def json(self, *, content_type: str | None = "application/json") -> Any:
        if self._raise_on_json is not None:
            raise self._raise_on_json
        return self._payload

    def raise_for_status(self) -> None:
        if self.status >= 400:
            raise aiohttp.ClientResponseError(
                RequestInfo(URL("http://example.com"), "POST", CIMultiDictProxy(CIMultiDict()), URL("http://example.com")),
                (),
                status=self.status,
                message="mock error",
            )

    async def __aenter__(self) -> "_MockResponse":
        return self

    async def __aexit__(self, *args: object) -> None:
        return None


class _MockSession:
    """Records requests and returns canned responses keyed by URL."""

    def __init__(self, responses: dict[str, _MockResponse]) -> None:
        self._responses = responses
        self.requests: list[dict[str, Any]] = []

    def post(self, url: str, **kwargs: Any) -> _MockResponse:
        self.requests.append({"url": url, **kwargs})
        return self._responses[url]


COGNITO_URL = "https://cognito-idp.us-west-2.amazonaws.com/"
TOKEN_URL = "https://apix.portlandgeneral.com/pg-token-implicit-aws/token"  # noqa: S105


class TestPortlandGeneralLoginFlow(unittest.IsolatedAsyncioTestCase):
    """Test the Cognito-based login flow with mocked HTTP responses."""

    async def test_login_success(self) -> None:
        """A successful Cognito auth followed by a successful token exchange returns the access token."""
        responses = {
            COGNITO_URL: _MockResponse(
                status=200,
                payload={
                    "AuthenticationResult": {
                        "AccessToken": "cognito_access_token",
                        "IdToken": "cognito_id_token",
                        "RefreshToken": "cognito_refresh_token",
                        "TokenType": "Bearer",
                        "ExpiresIn": 3600,
                    }
                },
            ),
            TOKEN_URL: _MockResponse(status=200, payload={"access_token": "pge_access_token", "client_id": "test"}),
        }
        session = _MockSession(responses)

        token = await PortlandGeneral().async_login(session, "user", "pass", {})  # type: ignore[arg-type]

        self.assertEqual(token, "pge_access_token")

        cognito_request = next(r for r in session.requests if r["url"] == COGNITO_URL)
        self.assertEqual(cognito_request["json"]["AuthParameters"]["USERNAME"], "user")
        self.assertEqual(cognito_request["json"]["AuthParameters"]["PASSWORD"], "pass")
        self.assertEqual(cognito_request["headers"]["X-Amz-Target"], "AWSCognitoIdentityProviderService.InitiateAuth")

        token_request = next(r for r in session.requests if r["url"] == TOKEN_URL)
        self.assertEqual(token_request["headers"]["idp_access_token"], "cognito_id_token")

    async def test_login_wrong_credentials_raises_invalid_auth(self) -> None:
        """A Cognito NotAuthorizedException (wrong username/password) raises InvalidAuth."""
        responses = {
            COGNITO_URL: _MockResponse(
                status=400,
                payload={"__type": "NotAuthorizedException", "message": "Incorrect username or password."},
            ),
        }
        session = _MockSession(responses)

        with self.assertRaises(InvalidAuth):
            await PortlandGeneral().async_login(session, "user", "wrong", {})  # type: ignore[arg-type]

    async def test_login_cognito_5xx_raises_client_response_error(self) -> None:
        """A Cognito 5xx (outage) raises ClientResponseError, not InvalidAuth, so it maps to CannotConnect."""
        responses = {
            COGNITO_URL: _MockResponse(status=500, payload={"__type": "InternalErrorException", "message": "oops"}),
        }
        session = _MockSession(responses)

        with self.assertRaises(aiohttp.ClientResponseError):
            await PortlandGeneral().async_login(session, "user", "pass", {})  # type: ignore[arg-type]

    async def test_login_cognito_throttling_raises_client_response_error(self) -> None:
        """Cognito throttling (400 but not a credentials error type) raises ClientResponseError, not InvalidAuth."""
        responses = {
            COGNITO_URL: _MockResponse(status=400, payload={"__type": "TooManyRequestsException", "message": "Rate exceeded"}),
        }
        session = _MockSession(responses)

        with self.assertRaises(aiohttp.ClientResponseError):
            await PortlandGeneral().async_login(session, "user", "pass", {})  # type: ignore[arg-type]

    async def test_login_cognito_401_without_error_type_raises_cannot_connect(self) -> None:
        """A 401 from Cognito with no recognized error body raises CannotConnect, not InvalidAuth.

        Opower.async_login() maps any ClientResponseError with status 401/403 to InvalidAuth
        regardless of body, so an unrecognized 401 (e.g. a WAF block) must not be allowed to
        reach resp.raise_for_status() here or it would get misreported as bad credentials.
        """
        responses = {
            COGNITO_URL: _MockResponse(status=401, payload={"message": "Forbidden by WAF"}),
        }
        session = _MockSession(responses)

        with self.assertRaises(CannotConnect):
            await PortlandGeneral().async_login(session, "user", "pass", {})  # type: ignore[arg-type]

    async def test_login_challenge_raises_invalid_auth(self) -> None:
        """A Cognito challenge (e.g. NEW_PASSWORD_REQUIRED) instead of tokens raises InvalidAuth, not KeyError."""
        responses = {
            COGNITO_URL: _MockResponse(
                status=200,
                payload={"ChallengeName": "NEW_PASSWORD_REQUIRED", "ChallengeParameters": {}, "Session": "abc"},
            ),
        }
        session = _MockSession(responses)

        with self.assertRaises(InvalidAuth):
            await PortlandGeneral().async_login(session, "user", "pass", {})  # type: ignore[arg-type]

    async def test_login_null_id_token_raises_invalid_auth(self) -> None:
        """AuthenticationResult present but with a null/missing IdToken raises InvalidAuth, not TypeError."""
        responses = {
            COGNITO_URL: _MockResponse(
                status=200,
                payload={"AuthenticationResult": {"IdToken": None, "AccessToken": "at"}},
            ),
        }
        session = _MockSession(responses)

        with self.assertRaises(InvalidAuth):
            await PortlandGeneral().async_login(session, "user", "pass", {})  # type: ignore[arg-type]

    async def test_token_exchange_failure_raises_invalid_auth(self) -> None:
        """If Cognito succeeds but PGE's own gateway rejects the token exchange, InvalidAuth is raised."""
        responses = {
            COGNITO_URL: _MockResponse(
                status=200,
                payload={"AuthenticationResult": {"IdToken": "cognito_id_token"}},
            ),
            TOKEN_URL: _MockResponse(
                status=401,
                payload={"errorResponse": {"code": "401", "message": "api key is invalid"}},
            ),
        }
        session = _MockSession(responses)

        with self.assertRaises(InvalidAuth):
            await PortlandGeneral().async_login(session, "user", "pass", {})  # type: ignore[arg-type]

    async def test_token_exchange_403_without_error_response_raises_cannot_connect(self) -> None:
        """A 403 from the token exchange with no recognized errorResponse body raises CannotConnect.

        Same reasoning as the Cognito 401 case: a bare 403 (e.g. a WAF block at PGE's gateway)
        must not fall through to resp.raise_for_status(), since Opower.async_login() would map
        that unconditionally to InvalidAuth regardless of body content.
        """
        responses = {
            COGNITO_URL: _MockResponse(
                status=200,
                payload={"AuthenticationResult": {"IdToken": "cognito_id_token"}},
            ),
            TOKEN_URL: _MockResponse(status=403, payload={"message": "Forbidden by WAF"}),
        }
        session = _MockSession(responses)

        with self.assertRaises(CannotConnect):
            await PortlandGeneral().async_login(session, "user", "pass", {})  # type: ignore[arg-type]

    async def test_token_exchange_non_json_response_raises_client_response_error(self) -> None:
        """A non-JSON (e.g. HTML gateway error page) token-exchange response raises ClientResponseError.

        Not a raw JSON decode error, and not InvalidAuth - a 502 with an unparsable body is a
        connectivity problem, not proof the credentials are wrong.
        """
        responses = {
            COGNITO_URL: _MockResponse(
                status=200,
                payload={"AuthenticationResult": {"IdToken": "cognito_id_token"}},
            ),
            TOKEN_URL: _MockResponse(status=502, raise_on_json=ValueError("Expecting value: line 1 column 1")),
        }
        session = _MockSession(responses)

        with self.assertRaises(aiohttp.ClientResponseError):
            await PortlandGeneral().async_login(session, "user", "pass", {})  # type: ignore[arg-type]

    async def test_token_exchange_missing_access_token_raises_invalid_auth(self) -> None:
        """A 200 response missing access_token raises InvalidAuth instead of returning the string "None"."""
        responses = {
            COGNITO_URL: _MockResponse(
                status=200,
                payload={"AuthenticationResult": {"IdToken": "cognito_id_token"}},
            ),
            TOKEN_URL: _MockResponse(status=200, payload={"client_id": "test"}),
        }
        session = _MockSession(responses)

        with self.assertRaises(InvalidAuth):
            await PortlandGeneral().async_login(session, "user", "pass", {})  # type: ignore[arg-type]

    async def test_token_exchange_null_access_token_raises_invalid_auth(self) -> None:
        """A 200 response with access_token explicitly null raises InvalidAuth, not the literal string "None"."""
        responses = {
            COGNITO_URL: _MockResponse(
                status=200,
                payload={"AuthenticationResult": {"IdToken": "cognito_id_token"}},
            ),
            TOKEN_URL: _MockResponse(status=200, payload={"access_token": None, "client_id": "test"}),
        }
        session = _MockSession(responses)

        with self.assertRaises(InvalidAuth):
            await PortlandGeneral().async_login(session, "user", "pass", {})  # type: ignore[arg-type]

    async def test_token_exchange_500_raises_client_response_error(self) -> None:
        """A 500 from the token exchange (server-side outage) raises ClientResponseError, not InvalidAuth."""
        responses = {
            COGNITO_URL: _MockResponse(
                status=200,
                payload={"AuthenticationResult": {"IdToken": "cognito_id_token"}},
            ),
            TOKEN_URL: _MockResponse(
                status=500,
                payload={"errorResponse": {"code": "500", "message": "server error"}},
            ),
        }
        session = _MockSession(responses)

        with self.assertRaises(aiohttp.ClientResponseError):
            await PortlandGeneral().async_login(session, "user", "pass", {})  # type: ignore[arg-type]
