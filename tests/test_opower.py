"""Tests for Opower."""

import aiohttp
import pytest

from opower import Opower, create_cookie_jar, get_supported_utilities
from opower.exceptions import InvalidAuth
from opower.utilities import UtilityBase


def test_dummy() -> None:
    """Test dummy."""
    assert True


@pytest.mark.parametrize("utility", get_supported_utilities())
@pytest.mark.asyncio
async def test_invalid_auth(utility: type["UtilityBase"]) -> None:
    """Test invalid username/password raises InvalidAuth."""
    async with aiohttp.ClientSession(cookie_jar=create_cookie_jar()) as session:
        opower = Opower(
            session,
            utility.name(),
            username="test",
            password="test",
            optional_mfa_secret=None,
        )
        with pytest.raises(InvalidAuth):
            await opower.async_login()
