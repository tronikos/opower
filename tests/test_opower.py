"""Tests for Opower."""

from typing import TYPE_CHECKING

import aiohttp
import pytest

from opower import Opower, create_cookie_jar, get_supported_utilities
from opower.exceptions import InvalidAuth
from opower.opower import Account, Customer, MeterType, ReadResolution

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
async def test_graphql_bill_reads_parse_and_filter_electric(monkeypatch: pytest.MonkeyPatch) -> None:
    """Parse GraphQL bill reads and keep matching electric segments."""
    async with aiohttp.ClientSession(cookie_jar=create_cookie_jar()) as session:
        opower = Opower(session, "coned", username="test", password="test", optional_totp_secret=None)  # noqa: S106
        account = Account(
            customer=Customer(uuid="customer-1"),
            uuid="account-1",
            utility_account_id="utility-1",
            id="utility-1",
            meter_type=MeterType.ELEC,
            read_resolution=ReadResolution.QUARTER_HOUR,
        )

        captured_variables: dict[str, object] = {}

        async def fake_post_graphql(
            query: str, headers: dict[str, str], variables: dict[str, object] | None = None
        ) -> dict[str, object]:
            captured_variables.update(variables or {})
            return {
                "data": {
                    "billingAccountByAuthContext": {
                        "bills": [
                            {
                                "timeInterval": "2026-01-23T05:00:00+00:00/2026-02-24T05:00:00+00:00",
                                "segments": [
                                    {
                                        "usageInterval": "2026-01-23T05:00:00+00:00/2026-02-24T05:00:00+00:00",
                                        "serviceAgreement": {"serviceType": "ELECTRICITY"},
                                        "serviceQuantities": [
                                            {
                                                "serviceQuantityIdentifier": "other",
                                                "serviceQuantity": {"value": 123.4},
                                            }
                                        ],
                                        "usageCharges": {"value": 12.34},
                                        "currentAmount": {"value": 56.78},
                                    }
                                ],
                            }
                        ]
                    }
                }
            }

        monkeypatch.setattr(opower, "_async_post_graphql", fake_post_graphql)
        monkeypatch.setattr(opower, "_get_headers", lambda customer_uuid=None: {})

        reads = await opower._async_get_bill_cost_reads(account)

        assert "forceLegacyData" not in captured_variables
        assert len(reads) == 1
        assert reads[0].consumption == 123.4
        assert reads[0].usage_charges == 12.34
        assert reads[0].current_amount == 56.78


@pytest.mark.asyncio
async def test_graphql_bill_reads_accept_natural_gas(monkeypatch: pytest.MonkeyPatch) -> None:
    """Accept NATURAL_GAS service types for gas accounts."""
    async with aiohttp.ClientSession(cookie_jar=create_cookie_jar()) as session:
        opower = Opower(session, "coned", username="test", password="test", optional_totp_secret=None)  # noqa: S106
        account = Account(
            customer=Customer(uuid="customer-1"),
            uuid="account-1",
            utility_account_id="utility-1",
            id="utility-1",
            meter_type=MeterType.GAS,
            read_resolution=ReadResolution.QUARTER_HOUR,
        )

        async def fake_post_graphql(
            query: str, headers: dict[str, str], variables: dict[str, object] | None = None
        ) -> dict[str, object]:
            return {
                "data": {
                    "billingAccountByAuthContext": {
                        "bills": [
                            {
                                "timeInterval": "2026-01-23T05:00:00+00:00/2026-02-24T05:00:00+00:00",
                                "segments": [
                                    {
                                        "serviceAgreement": {"serviceType": "NATURAL_GAS"},
                                        "serviceQuantities": [
                                            {
                                                "serviceQuantityIdentifier": "consumption",
                                                "serviceQuantity": {"value": 21.0},
                                            }
                                        ],
                                        "usageCharges": {"value": 8.0},
                                        "currentAmount": {"value": 11.0},
                                    },
                                    {
                                        "serviceAgreement": {"serviceType": "ELECTRICITY"},
                                        "serviceQuantities": [
                                            {
                                                "serviceQuantityIdentifier": "consumption",
                                                "serviceQuantity": {"value": 999.0},
                                            }
                                        ],
                                        "usageCharges": {"value": 99.0},
                                        "currentAmount": {"value": 199.0},
                                    },
                                ],
                            }
                        ]
                    }
                }
            }

        monkeypatch.setattr(opower, "_async_post_graphql", fake_post_graphql)
        monkeypatch.setattr(opower, "_get_headers", lambda customer_uuid=None: {})

        reads = await opower._async_get_bill_cost_reads(account)

        assert len(reads) == 1
        assert reads[0].consumption == 21.0
        assert reads[0].usage_charges == 8.0
        assert reads[0].current_amount == 11.0
