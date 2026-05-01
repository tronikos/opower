"""Tests for Opower."""

from typing import TYPE_CHECKING
from unittest.mock import Mock

import aiohttp
import pytest

from opower import (
    Account,
    AggregateType,
    MeterType,
    Opower,
    ReadResolution,
    create_cookie_jar,
    get_supported_utilities,
)
from opower.exceptions import ApiException, InvalidAuth

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


@pytest.mark.asyncio
async def test_cost_reads_falls_back_to_usage_on_api_error(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Cost endpoint errors fall back to usage-only reads for non-bill aggregations."""
    async with aiohttp.ClientSession(cookie_jar=create_cookie_jar()) as session:
        opower = Opower(
            session,
            "Pacific Gas and Electric Company (PG&E)",
            username="test",
            password="test",  # noqa: S106
        )

        account = Account(
            customer=Mock(),
            uuid="test-uuid",
            utility_account_id="test-id",
            id="test-id",
            meter_type=MeterType.ELEC,
            read_resolution=ReadResolution.HOUR,
        )

        call_log: list[bool] = []  # tracks usage_only values

        async def fake_get_dated_data(
            acc: object,
            agg: AggregateType,
            start: object,
            end: object,
            usage_only: bool = False,
        ) -> list[dict[str, object]]:
            call_log.append(usage_only)
            if not usage_only:
                raise ApiException(message="HTTP Error: 500", url="http://example.com")
            return [
                {
                    "startTime": "2026-01-01T00:00:00-05:00",
                    "endTime": "2026-01-02T00:00:00-05:00",
                    "consumption": {"value": 10.0},
                }
            ]

        monkeypatch.setattr(opower, "_async_get_dated_data", fake_get_dated_data)

        result = await opower.async_get_cost_reads(account, AggregateType.DAY, None, None)
        # Should have tried cost first, then fallen back to usage-only
        assert call_log == [False, True]
        assert len(result) == 1
        assert result[0].consumption == 10.0
        assert result[0].provided_cost == 0.0


@pytest.mark.asyncio
async def test_cost_reads_bill_does_not_fall_back(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bill-level cost endpoint errors should not fall back; they should raise."""
    async with aiohttp.ClientSession(cookie_jar=create_cookie_jar()) as session:
        opower = Opower(
            session,
            "Pacific Gas and Electric Company (PG&E)",
            username="test",
            password="test",  # noqa: S106
        )

        account = Account(
            customer=Mock(),
            uuid="test-uuid",
            utility_account_id="test-id",
            id="test-id",
            meter_type=MeterType.ELEC,
            read_resolution=ReadResolution.HOUR,
        )

        async def fake_get_dated_data(*args: object, **kwargs: object) -> list[object]:
            raise ApiException(message="HTTP Error: 500", url="http://example.com")

        monkeypatch.setattr(opower, "_async_get_dated_data", fake_get_dated_data)

        with pytest.raises(ApiException):
            await opower.async_get_cost_reads(account, AggregateType.BILL, None, None)


# test
