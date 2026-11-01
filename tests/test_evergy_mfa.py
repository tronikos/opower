"""Tests for Evergy email MFA support."""

from unittest.mock import AsyncMock, MagicMock, patch

import pytest

from opower.exceptions import InvalidAuth, MfaChallenge
from opower.utilities.evergy import Evergy, EvergyLoginHandler, EvergyMfaHandler


class FakeResponse:
    """Minimal async HTTP response."""

    def __init__(self, data):
        self.data = data

    async def __aenter__(self):
        return self

    async def __aexit__(self, *_args):
        return False

    async def json(self):
        return self.data


@pytest.mark.asyncio
async def test_email_mfa_challenge():
    """Email MFA is raised only when the DaVinci response identifies the challenge."""
    session = MagicMock()
    session.post.return_value = FakeResponse(
        {
            "id": "mfa-id",
            "connectionId": "mfa-connection",
            "interactionId": "mfa-interaction",
            "capabilityName": "customHTMLTemplate",
            "startUiSubFlow": True,
        }
    )
    handler = EvergyLoginHandler(session)
    handler.auth_data = {"api_root": "https://auth.example", "company_id": "company"}
    handler.id = "previous-id"
    handler.connectionId = "previous-connection"
    handler.interactionId = "previous-interaction"

    with pytest.raises(MfaChallenge) as exc:
        await handler.get_new_connection_id()

    assert isinstance(exc.value.handler, EvergyMfaHandler)
    assert handler.id == "mfa-id"
    assert handler.connectionId == "mfa-connection"
    assert handler.interactionId == "mfa-interaction"
    assert await exc.value.handler.async_get_mfa_options() == {}


@pytest.mark.asyncio
async def test_mfa_code_submission():
    """The code is sent using the observed DaVinci form payload."""
    session = MagicMock()
    session.post.return_value = FakeResponse(
        {"id": "success-id", "capabilityName": "returnSuccessResponseWidget", "access_token": "secret"}
    )
    handler = EvergyLoginHandler(session)
    handler.auth_data = {"api_root": "https://auth.example", "company_id": "company"}
    handler.id = "mfa-id"
    handler.connectionId = "mfa-connection"
    handler.interactionId = "mfa-interaction"

    await handler.submit_mfa_code("123456")

    payload = session.post.call_args.kwargs["json"]
    assert payload["parameters"] == {
        "buttonType": "form-submit", "buttonValue": "NEXT", "passcode": "123456"
    }
    assert payload["interactionId"] == "mfa-interaction"
    assert handler.access_token == "secret"


@pytest.mark.asyncio
async def test_mfa_invalid_code():
    """A non-successful response rejects the code."""
    session = MagicMock()
    session.post.return_value = FakeResponse({"id": "mfa-id", "capabilityName": "customHTMLTemplate"})
    handler = EvergyLoginHandler(session)
    handler.auth_data = {"api_root": "https://auth.example", "company_id": "company"}
    handler.id = "mfa-id"
    handler.connectionId = "mfa-connection"
    handler.interactionId = "mfa-interaction"

    with pytest.raises(InvalidAuth):
        await handler.submit_mfa_code("000000")


@pytest.mark.asyncio
async def test_mfa_completion():
    """MFA completion returns token and subdomain for a subsequent login."""
    handler = MagicMock(spec=EvergyLoginHandler)
    handler.session = MagicMock()
    handler.submit_mfa_code = AsyncMock()
    handler.postprocessing_api = AsyncMock()
    with patch(
        "opower.utilities.evergy._get_opower_credentials", new_callable=AsyncMock,
        return_value=("jwt", "kcpl"),
    ):
        result = await EvergyMfaHandler(handler).async_submit_mfa_code("123456")
    assert result == {"evergy_opower_token": "jwt", "evergy_subdomain": "kcpl"}
    handler.submit_mfa_code.assert_awaited_once_with("123456")
    handler.postprocessing_api.assert_awaited_once()


@pytest.mark.asyncio
async def test_login_with_saved_mfa_data():
    """A previously completed MFA flow does not trigger another challenge."""
    utility = Evergy()
    token = await utility.async_login(
        MagicMock(), "user", "password",
        {"evergy_opower_token": "jwt", "evergy_subdomain": "kcpl"},
    )
    assert token == "jwt"
    assert utility.subdomain() == "kcpl"

@pytest.mark.asyncio
async def test_login_without_mfa():
    """Existing direct-token logins still complete without MFA."""
    session = MagicMock()
    session.post.return_value = FakeResponse(
        {"id": "done", "connectionId": "next", "access_token": "secret"}
    )
    handler = EvergyLoginHandler(session)
    handler.auth_data = {"api_root": "https://auth.example", "company_id": "company"}
    handler.id = "previous"
    handler.connectionId = "previous"
    assert await handler.get_new_connection_id() is True
    assert handler.access_token == "secret"
