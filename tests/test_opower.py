"""Tests for Opower."""

from datetime import datetime
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


def _account(
    meter_type: MeterType = MeterType.ELEC,
    uuid: str = "account-1",
    utility_account_id: str = "test-id",
) -> Account:
    """Return a test account."""
    return Account(
        customer=Mock(uuid="customer-1"),
        uuid=uuid,
        utility_account_id=utility_account_id,
        id=utility_account_id,
        meter_type=meter_type,
        read_resolution=ReadResolution.HOUR,
    )


def _customer_accounts(*accounts: tuple[str, MeterType]) -> list[dict[str, object]]:
    """Return a cached customers response for test accounts."""
    return [
        {
            "uuid": "customer-1",
            "utilityAccounts": [
                {
                    "uuid": uuid,
                    "preferredUtilityAccountId": uuid,
                    "meterType": meter_type.value,
                    "readResolution": ReadResolution.HOUR.value,
                }
                for uuid, meter_type in accounts
            ],
        }
    ]


def _billing_accounts(*accounts: tuple[str, MeterType] | tuple[str, MeterType, str]) -> dict[str, object]:
    """Return a GraphQL billingAccountsConnection response for test accounts."""
    return {
        "data": {
            "billingAccountsConnection": {
                "edges": [
                    {
                        "node": {
                            "urn": f"urn:opower:v1:account:test:uuid:{account[0]}",
                            "uuid": account[0],
                            "accountNumber": account[2] if len(account) > 2 else "",
                            "utilityId": account[2] if len(account) > 2 else "",
                            "serviceAgreementsConnection": {
                                "edges": [{"node": {"serviceType": account[1].value}}],
                            },
                        },
                    }
                    for account in accounts
                ],
            }
        }
    }


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
async def test_graphql_bill_reads_parse_electric(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Parse GraphQL bill reads and keep electric account segments."""
    async with aiohttp.ClientSession(cookie_jar=create_cookie_jar()) as session:
        opower = Opower(
            session,
            "coned",
            username="test",
            password="test",  # noqa: S106
        )
        account = _account()
        opower.customers = _customer_accounts(("account-1", MeterType.ELEC))
        captured_variables: dict[str, object] = {}

        async def fake_post_graphql(
            query: str,
            headers: dict[str, str],
            variables: dict[str, object] | None = None,
        ) -> dict[str, object]:
            if "billingAccountsConnection" in query:
                return _billing_accounts(("billing-account-1", MeterType.ELEC))
            captured_variables.update(variables or {})
            return {
                "data": {
                    "billingAccountByAuthContext": {
                        "bills": [
                            {
                                "timeInterval": "2023-01-01T05:00:00+00:00/2023-02-01T05:00:00+00:00",
                                "segments": [
                                    {
                                        "usageInterval": None,
                                        "serviceAgreement": {
                                            "uuid": "account-1",
                                            "serviceType": "ELECTRICITY",
                                        },
                                        "serviceQuantities": [
                                            {
                                                "serviceQuantityIdentifier": "consumption",
                                                "serviceQuantity": {"value": 123.4},
                                            }
                                        ],
                                        "usageCharges": {"value": 12.34},
                                        "currentAmount": {"value": 56.78},
                                    },
                                    {
                                        "serviceAgreement": {
                                            "uuid": "account-1",
                                            "serviceType": "NATURAL_GAS",
                                        },
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

        reads = await opower._async_get_bill_cost_reads(
            account,
            start_date=datetime(2020, 1, 1),
            end_date=datetime(2023, 1, 1),
        )

        assert captured_variables["last"] == 38
        assert captured_variables["selectedAccount"] == "urn:opower:v1:account:test:uuid:billing-account-1"
        assert len(reads) == 1
        assert reads[0].consumption == 123.4
        assert reads[0].provided_cost == 56.78
        assert reads[0].usage_charges == 12.34
        assert reads[0].current_amount == 56.78


@pytest.mark.asyncio
async def test_graphql_bill_reads_accept_natural_gas(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Accept NATURAL_GAS segments for gas accounts."""
    async with aiohttp.ClientSession(cookie_jar=create_cookie_jar()) as session:
        opower = Opower(
            session,
            "coned",
            username="test",
            password="test",  # noqa: S106
        )
        account = _account(MeterType.GAS)
        opower.customers = _customer_accounts(("account-1", MeterType.GAS))

        async def fake_post_graphql(
            query: str,
            headers: dict[str, str],
            variables: dict[str, object] | None = None,
        ) -> dict[str, object]:
            if "billingAccountsConnection" in query:
                return _billing_accounts(("billing-account-1", MeterType.GAS))
            return {
                "data": {
                    "billingAccountByAuthContext": {
                        "bills": [
                            {
                                "timeInterval": "2023-01-01T05:00:00+00:00/2023-02-01T05:00:00+00:00",
                                "segments": [
                                    {
                                        "serviceAgreement": {
                                            "uuid": "account-1",
                                            "serviceType": "NATURAL_GAS",
                                        },
                                        "serviceQuantities": [
                                            {
                                                "serviceQuantityIdentifier": "consumption",
                                                "serviceQuantity": {"value": 21.0},
                                            }
                                        ],
                                        "usageCharges": {"value": 8.0},
                                    },
                                    {
                                        "serviceAgreement": {
                                            "uuid": "account-1",
                                            "serviceType": "ELECTRICITY",
                                        },
                                        "serviceQuantities": [
                                            {
                                                "serviceQuantityIdentifier": "consumption",
                                                "serviceQuantity": {"value": 999.0},
                                            }
                                        ],
                                        "usageCharges": {"value": 99.0},
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
        assert reads[0].provided_cost == 8.0
        assert reads[0].usage_charges == 8.0
        assert reads[0].current_amount is None


@pytest.mark.asyncio
async def test_graphql_bill_reads_match_billing_account_identifier(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Use selectedAccount when GraphQL billing account identifiers match the requested account."""
    async with aiohttp.ClientSession(cookie_jar=create_cookie_jar()) as session:
        opower = Opower(
            session,
            "coned",
            username="test",
            password="test",  # noqa: S106
        )

        account = _account(uuid="account-2", utility_account_id="account-2")
        opower.customers = _customer_accounts(
            ("account-1", MeterType.ELEC),
            ("account-2", MeterType.ELEC),
        )
        captured_variables: dict[str, object] = {}

        async def fake_post_graphql(
            query: str,
            headers: dict[str, str],
            variables: dict[str, object] | None = None,
        ) -> dict[str, object]:
            if "billingAccountsConnection" in query:
                return _billing_accounts(
                    ("billing-account-1", MeterType.ELEC, "account-1"),
                    ("billing-account-2", MeterType.ELEC, "account-2"),
                )
            captured_variables.update(variables or {})
            return {"data": {"billingAccountByAuthContext": {"bills": []}}}

        monkeypatch.setattr(opower, "_async_post_graphql", fake_post_graphql)
        monkeypatch.setattr(opower, "_get_headers", lambda customer_uuid=None: {})

        await opower._async_get_bill_cost_reads(account)

        assert captured_variables["selectedAccount"] == "urn:opower:v1:account:test:uuid:billing-account-2"


@pytest.mark.asyncio
async def test_cost_reads_bill_falls_back_to_rest_when_graphql_segments_are_ambiguous(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """GraphQL bill costs fall back to REST when same-meter accounts cannot be distinguished."""
    async with aiohttp.ClientSession(cookie_jar=create_cookie_jar()) as session:
        opower = Opower(
            session,
            "coned",
            username="test",
            password="test",  # noqa: S106
        )

        account = _account()
        opower.customers = _customer_accounts(
            ("account-1", MeterType.ELEC),
            ("account-2", MeterType.ELEC),
        )
        call_log: list[bool] = []
        graphql_queries: list[str] = []

        async def fake_post_graphql(
            query: str,
            headers: dict[str, str],
            variables: dict[str, object] | None = None,
        ) -> dict[str, object]:
            graphql_queries.append(query)
            if "billingAccountsConnection" in query:
                return _billing_accounts(
                    ("billing-account-1", MeterType.ELEC),
                    ("billing-account-2", MeterType.ELEC),
                )
            pytest.fail("Ambiguous same-meter accounts should not query GraphQL bill segments")

        async def fake_get_dated_data(
            acc: object,
            agg: AggregateType,
            start: object,
            end: object,
            usage_only: bool = False,
        ) -> list[dict[str, object]]:
            call_log.append(usage_only)
            return [
                {
                    "startTime": "2026-01-01T00:00:00-05:00",
                    "endTime": "2026-02-01T00:00:00-05:00",
                    "value": 123.0,
                    "providedCost": 45.67,
                }
            ]

        monkeypatch.setattr(opower, "_async_post_graphql", fake_post_graphql)
        monkeypatch.setattr(opower, "_async_get_dated_data", fake_get_dated_data)

        result = await opower.async_get_cost_reads(account, AggregateType.BILL, None, None)

        assert call_log == [False]
        assert len(graphql_queries) == 1
        assert len(result) == 1
        assert result[0].consumption == 123.0
        assert result[0].provided_cost == 45.67


@pytest.mark.asyncio
async def test_cost_reads_bill_falls_back_to_rest_when_graphql_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Bill-level cost reads fall back to REST if GraphQL is unavailable."""
    async with aiohttp.ClientSession(cookie_jar=create_cookie_jar()) as session:
        opower = Opower(
            session,
            "Pacific Gas and Electric Company (PG&E)",
            username="test",
            password="test",  # noqa: S106
        )

        account = _account()
        call_log: list[bool] = []

        async def fake_get_bill_cost_reads(*args: object, **kwargs: object) -> list[object]:
            raise ApiException(message="GraphQL Error", url="graphql")

        async def fake_get_dated_data(
            acc: object,
            agg: AggregateType,
            start: object,
            end: object,
            usage_only: bool = False,
        ) -> list[dict[str, object]]:
            call_log.append(usage_only)
            return [
                {
                    "startTime": "2026-01-01T00:00:00-05:00",
                    "endTime": "2026-02-01T00:00:00-05:00",
                    "value": 123.0,
                    "providedCost": 45.67,
                }
            ]

        monkeypatch.setattr(opower, "_async_get_bill_cost_reads", fake_get_bill_cost_reads)
        monkeypatch.setattr(opower, "_async_get_dated_data", fake_get_dated_data)

        result = await opower.async_get_cost_reads(account, AggregateType.BILL, None, None)

        assert call_log == [False]
        assert len(result) == 1
        assert result[0].consumption == 123.0
        assert result[0].provided_cost == 45.67


@pytest.mark.asyncio
async def test_cost_reads_bill_usage_only_uses_rest(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """usage_only=True preserves the REST usage endpoint for bill reads."""
    async with aiohttp.ClientSession(cookie_jar=create_cookie_jar()) as session:
        opower = Opower(
            session,
            "Pacific Gas and Electric Company (PG&E)",
            username="test",
            password="test",  # noqa: S106
        )

        account = _account()
        call_log: list[bool] = []

        async def fake_get_bill_cost_reads(*args: object, **kwargs: object) -> list[object]:
            pytest.fail("GraphQL bill reads should not be used for usage_only=True")

        async def fake_get_dated_data(
            acc: object,
            agg: AggregateType,
            start: object,
            end: object,
            usage_only: bool = False,
        ) -> list[dict[str, object]]:
            call_log.append(usage_only)
            return [
                {
                    "startTime": "2026-01-01T00:00:00-05:00",
                    "endTime": "2026-02-01T00:00:00-05:00",
                    "consumption": {"value": 10.0},
                }
            ]

        monkeypatch.setattr(opower, "_async_get_bill_cost_reads", fake_get_bill_cost_reads)
        monkeypatch.setattr(opower, "_async_get_dated_data", fake_get_dated_data)

        result = await opower.async_get_cost_reads(account, AggregateType.BILL, None, None, usage_only=True)

        assert call_log == [True]
        assert len(result) == 1
        assert result[0].consumption == 10.0
        assert result[0].provided_cost == 0.0
