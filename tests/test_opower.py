"""Tests for Opower."""

from typing import TYPE_CHECKING

import aiohttp
import pytest

from opower import Opower, create_cookie_jar, get_supported_utilities
from opower.exceptions import InvalidAuth

if TYPE_CHECKING:
    from opower.utilities import UtilityBase


@pytest.mark.parametrize("utility", get_supported_utilities())
@pytest.mark.asyncio
async def test_invalid_auth(utility: type["UtilityBase"]) -> None:
    """Test invalid username/password raises InvalidAuth."""
    async with aiohttp.ClientSession(cookie_jar=create_cookie_jar()) as session:
        opower = Opower(
            session,
            utility.name(),
            username="test",
            password="test",  # noqa: S106
            optional_totp_secret=None,
        )
        with pytest.raises(InvalidAuth):
            await opower.async_login()
