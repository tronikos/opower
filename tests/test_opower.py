"""Tests for Opower."""

from datetime import UTC, datetime
from typing import TYPE_CHECKING

import aiohttp
import pytest

from opower import Opower, create_cookie_jar, get_supported_utilities
from opower.exceptions import ApiException, InvalidAuth
from opower.opower import Account, AggregateType, CostRead, Customer, MeterType, ReadResolution, UsageRead

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


@pytest.mark.asyncio
async def test_graphql_interval_reads_discovery_and_fetch(monkeypatch: pytest.MonkeyPatch) -> None:
    """Discover service point and fetch interval reads via GraphQL."""
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

        call_count = 0

        async def fake_post_graphql(
            query: str, headers: dict[str, str], variables: dict[str, object] | None = None
        ) -> dict[str, object]:
            nonlocal call_count
            call_count += 1
            if "registerId" not in (variables or {}):
                # Discovery query
                return {
                    "data": {
                        "billingAccountByAuthContext": {
                            "serviceAgreementsConnection": {
                                "edges": [
                                    {
                                        "node": {
                                            "uuid": "sa-1",
                                            "serviceType": "ELECTRICITY",
                                            "servicePointsConnection": {
                                                "edges": [
                                                    {
                                                        "node": {
                                                            "uuid": "sp-1",
                                                            "intervalReads": [{"registerId": "reg-1"}],
                                                        }
                                                    }
                                                ]
                                            },
                                        }
                                    }
                                ]
                            }
                        }
                    }
                }
            # Reads query
            t = "2026-02-24T0"  # prefix
            reads_data = [
                {"timeInterval": f"{t}5:00:00Z/{t}5:15:00Z", "measuredAmount": {"value": 0.1}},
                {"timeInterval": f"{t}5:15:00Z/{t}5:30:00Z", "measuredAmount": {"value": 0.2}},
                {"timeInterval": f"{t}5:30:00Z/{t}5:45:00Z", "measuredAmount": {"value": 0.3}},
                {"timeInterval": f"{t}5:45:00Z/{t}6:00:00Z", "measuredAmount": {"value": 0.4}},
                {"timeInterval": f"{t}6:00:00Z/{t}6:15:00Z", "measuredAmount": None},
            ]
            return {
                "data": {
                    "billingAccountByAuthContext": {
                        "serviceAgreementsConnection": {
                            "edges": [
                                {
                                    "node": {
                                        "servicePointsConnection": {
                                            "edges": [
                                                {
                                                    "node": {
                                                        "intervalReads": [{"reads": reads_data}],
                                                    }
                                                }
                                            ]
                                        },
                                    }
                                }
                            ]
                        }
                    }
                }
            }

        monkeypatch.setattr(opower, "_async_post_graphql", fake_post_graphql)
        monkeypatch.setattr(opower, "_get_headers", lambda customer_uuid=None: {})

        reads = await opower._async_get_graphql_interval_reads(account)

        # Discovery (1) + reads (1) = 2 GraphQL calls
        assert call_count == 2
        # 5th read has measuredAmount=None, should be skipped
        assert len(reads) == 4
        assert reads[0].consumption == 0.1
        assert reads[3].consumption == 0.4

        # Second call should use cache (no extra discovery call)
        await opower._async_get_graphql_interval_reads(account)
        assert call_count == 3  # Only 1 more call (reads), no discovery


@pytest.mark.asyncio
async def test_aggregate_interval_reads_to_hour() -> None:
    """Aggregate quarter-hour reads to hourly."""
    reads = [
        UsageRead(
            start_time=datetime(2026, 2, 24, 5, 0),
            end_time=datetime(2026, 2, 24, 5, 15),
            consumption=0.1,
        ),
        UsageRead(
            start_time=datetime(2026, 2, 24, 5, 15),
            end_time=datetime(2026, 2, 24, 5, 30),
            consumption=0.2,
        ),
        UsageRead(
            start_time=datetime(2026, 2, 24, 5, 30),
            end_time=datetime(2026, 2, 24, 5, 45),
            consumption=0.3,
        ),
        UsageRead(
            start_time=datetime(2026, 2, 24, 5, 45),
            end_time=datetime(2026, 2, 24, 6, 0),
            consumption=0.4,
        ),
        UsageRead(
            start_time=datetime(2026, 2, 24, 6, 0),
            end_time=datetime(2026, 2, 24, 6, 15),
            consumption=0.5,
        ),
    ]

    hourly = Opower._aggregate_interval_reads(reads, AggregateType.HOUR)
    assert len(hourly) == 2
    assert hourly[0].start_time == datetime(2026, 2, 24, 5, 0)
    assert hourly[0].end_time == datetime(2026, 2, 24, 6, 0)
    assert hourly[0].consumption == 1.0
    assert hourly[1].start_time == datetime(2026, 2, 24, 6, 0)
    assert hourly[1].consumption == 0.5

    daily = Opower._aggregate_interval_reads(reads, AggregateType.DAY)
    assert len(daily) == 1
    assert daily[0].consumption == 1.5

    # QUARTER_HOUR returns reads unchanged
    raw = Opower._aggregate_interval_reads(reads, AggregateType.QUARTER_HOUR)
    assert len(raw) == 5


@pytest.mark.asyncio
async def test_aggregate_interval_reads_uses_utility_timezone_for_day(monkeypatch: pytest.MonkeyPatch) -> None:
    """Day aggregation buckets timezone-aware reads in utility local time."""
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

        async def fake_graphql_interval_reads(
            account_param: Account,
            start_date: datetime | None = None,
            end_date: datetime | None = None,
        ) -> list[UsageRead]:
            assert account_param == account
            return [
                UsageRead(
                    start_time=datetime(2026, 2, 24, 23, 30, tzinfo=UTC),
                    end_time=datetime(2026, 2, 24, 23, 45, tzinfo=UTC),
                    consumption=0.5,
                ),
                UsageRead(
                    start_time=datetime(2026, 2, 25, 1, 0, tzinfo=UTC),
                    end_time=datetime(2026, 2, 25, 1, 15, tzinfo=UTC),
                    consumption=1.0,
                ),
            ]

        monkeypatch.setattr(opower, "_async_get_graphql_interval_reads", fake_graphql_interval_reads)
        reads = await opower.async_get_usage_reads(account, AggregateType.DAY)

        assert len(reads) == 1
        assert reads[0].consumption == 1.5
        assert reads[0].start_time.isoformat() == "2026-02-24T00:00:00-05:00"


@pytest.mark.asyncio
async def test_interval_reads_24h_batching(monkeypatch: pytest.MonkeyPatch) -> None:
    """Interval reads are batched into 24-hour chunks when dates are provided."""
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

        requested_intervals: list[str] = []

        async def fake_post_graphql(
            query: str, headers: dict[str, str], variables: dict[str, object] | None = None
        ) -> dict[str, object]:
            vars_ = variables or {}
            if "registerId" not in vars_:
                return {
                    "data": {
                        "billingAccountByAuthContext": {
                            "serviceAgreementsConnection": {
                                "edges": [
                                    {
                                        "node": {
                                            "uuid": "sa-1",
                                            "serviceType": "ELECTRICITY",
                                            "servicePointsConnection": {
                                                "edges": [
                                                    {
                                                        "node": {
                                                            "uuid": "sp-1",
                                                            "intervalReads": [{"registerId": "reg-1"}],
                                                        }
                                                    }
                                                ]
                                            },
                                        }
                                    }
                                ]
                            }
                        }
                    }
                }
            # Track requested time intervals
            if "timeInterval" in vars_:
                requested_intervals.append(str(vars_["timeInterval"]))
            return {"data": {"billingAccountByAuthContext": {"serviceAgreementsConnection": {"edges": []}}}}

        monkeypatch.setattr(opower, "_async_post_graphql", fake_post_graphql)
        monkeypatch.setattr(opower, "_get_headers", lambda customer_uuid=None: {})

        # Request 3 days → should produce 3 batches of 24 hours
        start = datetime(2026, 2, 24, 0, 0)
        end = datetime(2026, 2, 27, 0, 0)
        await opower._async_get_graphql_interval_reads(account, start, end)

        assert len(requested_intervals) == 3
        # Each interval should be 24 hours
        for interval in requested_intervals:
            assert "Z/" in interval  # UTC format


@pytest.mark.asyncio
async def test_discovery_failure_raises(monkeypatch: pytest.MonkeyPatch) -> None:
    """Discovery raises ApiException when no service point is found."""
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

        async def fake_post_graphql(
            query: str, headers: dict[str, str], variables: dict[str, object] | None = None
        ) -> dict[str, object]:
            return {"data": {"billingAccountByAuthContext": {"serviceAgreementsConnection": {"edges": []}}}}

        monkeypatch.setattr(opower, "_async_post_graphql", fake_post_graphql)
        monkeypatch.setattr(opower, "_get_headers", lambda customer_uuid=None: {})

        with pytest.raises(ApiException, match="No service point"):
            await opower._async_discover_service_point(account)


@pytest.mark.asyncio
async def test_async_get_cost_reads_non_bill(monkeypatch: pytest.MonkeyPatch) -> None:
    """async_get_cost_reads for non-BILL types returns CostRead with provided_cost=0."""
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

        async def fake_post_graphql(
            query: str, headers: dict[str, str], variables: dict[str, object] | None = None
        ) -> dict[str, object]:
            if "registerId" not in (variables or {}):
                return {
                    "data": {
                        "billingAccountByAuthContext": {
                            "serviceAgreementsConnection": {
                                "edges": [
                                    {
                                        "node": {
                                            "uuid": "sa-1",
                                            "serviceType": "ELECTRICITY",
                                            "servicePointsConnection": {
                                                "edges": [
                                                    {
                                                        "node": {
                                                            "uuid": "sp-1",
                                                            "intervalReads": [{"registerId": "reg-1"}],
                                                        }
                                                    }
                                                ]
                                            },
                                        }
                                    }
                                ]
                            }
                        }
                    }
                }
            t = "2026-02-24T0"
            return {
                "data": {
                    "billingAccountByAuthContext": {
                        "serviceAgreementsConnection": {
                            "edges": [
                                {
                                    "node": {
                                        "servicePointsConnection": {
                                            "edges": [
                                                {
                                                    "node": {
                                                        "intervalReads": [
                                                            {
                                                                "reads": [
                                                                    {
                                                                        "timeInterval": f"{t}5:00:00Z/{t}5:15:00Z",
                                                                        "measuredAmount": {"value": 0.1},
                                                                    },
                                                                    {
                                                                        "timeInterval": f"{t}5:15:00Z/{t}5:30:00Z",
                                                                        "measuredAmount": {"value": 0.2},
                                                                    },
                                                                    {
                                                                        "timeInterval": f"{t}5:30:00Z/{t}5:45:00Z",
                                                                        "measuredAmount": {"value": 0.3},
                                                                    },
                                                                    {
                                                                        "timeInterval": f"{t}5:45:00Z/{t}6:00:00Z",
                                                                        "measuredAmount": {"value": 0.4},
                                                                    },
                                                                ]
                                                            }
                                                        ],
                                                    }
                                                }
                                            ]
                                        },
                                    }
                                }
                            ]
                        }
                    }
                }
            }

        monkeypatch.setattr(opower, "_async_post_graphql", fake_post_graphql)
        monkeypatch.setattr(opower, "_get_headers", lambda customer_uuid=None: {})

        cost_reads = await opower.async_get_cost_reads(account, AggregateType.HOUR)
        assert len(cost_reads) == 1  # 4 quarter-hour reads → 1 hour
        assert isinstance(cost_reads[0], CostRead)
        assert cost_reads[0].consumption == 1.0
        assert cost_reads[0].provided_cost == 0
