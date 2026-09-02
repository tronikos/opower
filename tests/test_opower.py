"""Tests for Opower."""

import asyncio
import json
from datetime import date, datetime
from typing import TYPE_CHECKING, Any
from unittest.mock import Mock
from zoneinfo import ZoneInfo

import aiohttp
import pytest

from opower import (
    Account,
    AggregateType,
    CannotConnect,
    MeterType,
    Opower,
    ReadResolution,
    UnitOfMeasure,
    create_cookie_jar,
    get_supported_utilities,
    get_supported_utility_names,
    select_utility,
)
from opower.exceptions import ApiException, InvalidAuth
from opower.opower import Customer
from opower.utilities.pge import PGE

if TYPE_CHECKING:
    from opower.utilities import UtilityBase


@pytest.mark.network
@pytest.mark.parametrize("utility", get_supported_utilities())
@pytest.mark.asyncio
async def test_invalid_auth(utility: type["UtilityBase"]) -> None:
    """Test invalid username/password raises InvalidAuth.

    This performs a real failed login against every supported utility's live
    website, so it is excluded from the default run (see the "network" marker
    in pyproject.toml) and must be requested explicitly with `-m network`.
    """
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


@pytest.mark.asyncio
async def test_cost_reads_parse_read_components(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Parse readComponents (TOU/tier breakdown) when present, default to empty otherwise."""
    async with aiohttp.ClientSession(cookie_jar=create_cookie_jar()) as session:
        opower = Opower(
            session,
            "Sacramento Municipal Utility District (SMUD)",
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

        async def fake_get_dated_data(*args: object, **kwargs: object) -> list[dict[str, object]]:
            return [
                # Real (redacted) SMUD read on a time-of-use rate.
                {
                    "startTime": "2026-06-17T00:00:00.000-07:00",
                    "endTime": "2026-06-18T00:00:00.000-07:00",
                    "value": 33.732,
                    "readType": "ACTUAL",
                    "providedCost": 6.9044064,
                    "readComponents": [
                        {
                            "tierType": "ORDINAL",
                            "tierNumber": None,
                            "season": "SUMMER",
                            "dayPart": "ON_PEAK+RT02/TOD",
                            "cost": 0.8195652,
                            "value": 2.1768,
                        },
                        {
                            "tierType": "ORDINAL",
                            "tierNumber": None,
                            "season": "SUMMER",
                            "dayPart": "OFF_PEAK+RT02/TOD",
                            "cost": 1.749516,
                            "value": 11.2872,
                        },
                        {
                            "tierType": "ORDINAL",
                            "tierNumber": None,
                            "season": "SUMMER",
                            "dayPart": "PART_PEAK+RT02/TOD",
                            "cost": 4.3353252,
                            "value": 20.268,
                        },
                    ],
                },
                # Read without components (not all utilities return them).
                {
                    "startTime": "2026-06-18T00:00:00.000-07:00",
                    "endTime": "2026-06-19T00:00:00.000-07:00",
                    "value": 31.104,
                    "readType": "ACTUAL",
                    "providedCost": 6.4527,
                },
            ]

        monkeypatch.setattr(opower, "_async_get_dated_data", fake_get_dated_data)

        result = await opower.async_get_cost_reads(account, AggregateType.DAY, None, None)
        assert len(result) == 2

        components = result[0].read_components
        assert len(components) == 3
        assert components[0].tier_type == "ORDINAL"
        assert components[0].tier_number is None
        assert components[0].season == "SUMMER"
        assert components[0].day_part == "ON_PEAK+RT02/TOD"
        assert components[0].cost == 0.8195652
        assert components[0].consumption == 2.1768
        # Components sum to the read's totals.
        assert sum(c.consumption for c in components) == pytest.approx(result[0].consumption)
        assert sum(c.cost for c in components) == pytest.approx(result[0].provided_cost)

        assert result[1].read_components == []


@pytest.mark.asyncio
async def test_five_minute_read_resolution(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Parse five-minute accounts and allow existing fine-grained aggregations."""
    async with aiohttp.ClientSession(cookie_jar=create_cookie_jar()) as session:
        opower = Opower(
            session,
            "Consolidated Edison (ConEd)",
            username="test",
            password="test",  # noqa: S106
        )

        async def fake_get_customers() -> list[dict[str, object]]:
            return [
                {
                    "uuid": "customer-uuid",
                    "utilityAccounts": [
                        {
                            "uuid": "account-uuid",
                            "preferredUtilityAccountId": "account-id",
                            "meterType": "ELEC",
                            "readResolution": "FIVE_MINUTE",
                        }
                    ],
                }
            ]

        calls: list[AggregateType] = []

        async def fake_async_fetch(
            account: Account,
            aggregate_type: AggregateType,
            start_date: datetime | None = None,
            end_date: datetime | None = None,
            usage_only: bool = False,
        ) -> tuple[list[dict[str, object]], bool]:
            calls.append(aggregate_type)
            return [{"start": start_date, "end": end_date, "usage_only": usage_only}], False

        monkeypatch.setattr(opower, "_async_get_customers", fake_get_customers)
        monkeypatch.setattr(opower, "_async_fetch", fake_async_fetch)

        accounts = await opower.async_get_accounts()

        assert len(accounts) == 1
        assert accounts[0].read_resolution is ReadResolution.FIVE_MINUTE
        await opower._async_get_dated_data(
            accounts[0],
            AggregateType.QUARTER_HOUR,
            datetime(2026, 1, 1),
            datetime(2026, 1, 1),
        )
        assert calls == [AggregateType.QUARTER_HOUR]


@pytest.mark.asyncio
async def test_dss_bill_trends_fallback_is_not_refetched_per_window(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The bill-trends fallback must not be re-fetched once per date batch.

    DSS utilities whose DataBrowser-v1 is inaccessible fall back to
    bill-trends, which returns the full bill history regardless of the
    requested window. Batching the request across a multi-year range would
    otherwise return every bill once per window.
    """
    async with aiohttp.ClientSession(cookie_jar=create_cookie_jar()) as session:
        opower = Opower(
            session,
            "City of Austin Utilities",
            username="test",
            password="test",  # noqa: S106
        )
        opower._user_accounts = [{"accountId": "123", "premises": ["p"]}]

        requested_urls: list[str] = []

        async def fake_get_request(url: str, params: dict[str, str], headers: dict[str, str]) -> Any:
            requested_urls.append(url)
            if "DataBrowser-v1" in url:
                raise ApiException("HTTP Error: 403", url=url, status=403)
            return {
                "bills": [
                    {"billDate": "2024-03-15", "cost": 120.0},
                    {"billDate": "2024-02-15", "cost": 110.0},
                    {"billDate": "2024-01-15", "cost": 100.0},
                ]
            }

        monkeypatch.setattr(opower, "_async_get_request", fake_get_request)

        account = Account(
            customer=Mock(uuid="customer-uuid"),
            uuid="sa1",
            utility_account_id="123",
            id="123",
            meter_type=MeterType.ELEC,
            read_resolution=ReadResolution.DAY,
        )

        # A three-year range spans several 363-day batches.
        result = await opower.async_get_cost_reads(account, AggregateType.DAY, datetime(2023, 1, 1), datetime(2025, 12, 31))

        # Two periods derived from three bills, each returned exactly once.
        assert [(read.provided_cost, read.start_time.date().isoformat()) for read in result] == [
            (110.0, "2024-01-16"),
            (120.0, "2024-02-16"),
        ]
        assert sum("billHistory" in url for url in requested_urls) == 1


@pytest.mark.asyncio
async def test_concurrent_fetches_do_not_share_dss_fallback_state(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Whether a fetch fell back to bill-trends must not leak between callers.

    _async_fetch reports the fallback through its return value. Tracking it on
    the client instead would let a usage-only fetch observe a concurrent cost
    fetch's fallback and stop batching after a single window.
    """
    async with aiohttp.ClientSession(cookie_jar=create_cookie_jar()) as session:
        opower = Opower(
            session,
            "City of Austin Utilities",
            username="test",
            password="test",  # noqa: S106
        )
        opower._user_accounts = [{"accountId": "123", "premises": ["p"]}]

        usage_windows: list[str] = []
        cost_fell_back = asyncio.Event()

        async def fake_get_request(url: str, params: dict[str, str], headers: dict[str, str]) -> Any:
            if "cost/utilityAccount" in url:
                # DataBrowser-v1 is inaccessible for this DSS utility.
                raise ApiException("HTTP Error: 403", url=url, status=403)
            if "billHistory" in url:
                cost_fell_back.set()
                return {"bills": [{"billDate": "2024-02-15", "cost": 110.0}, {"billDate": "2024-01-15", "cost": 100.0}]}
            usage_windows.append(params["startDate"])
            # Hold the first usage window open until the cost call has fallen
            # back, so the two are guaranteed to interleave.
            if len(usage_windows) == 1:
                await cost_fell_back.wait()
            return {
                "reads": [
                    {"startTime": "2024-01-01T00:00:00", "endTime": "2024-01-02T00:00:00", "consumption": {"value": 1.0}}
                ]
            }

        monkeypatch.setattr(opower, "_async_get_request", fake_get_request)

        account = Account(
            customer=Mock(uuid="customer-uuid"),
            uuid="sa1",
            utility_account_id="123",
            id="123",
            meter_type=MeterType.ELEC,
            read_resolution=ReadResolution.DAY,
        )
        start, end = datetime(2023, 1, 1), datetime(2025, 12, 31)

        await asyncio.gather(
            opower.async_get_usage_reads(account, AggregateType.DAY, start, end),
            opower.async_get_cost_reads(account, AggregateType.DAY, start, end),
        )

        # The usage call must keep batching across its own windows regardless of
        # what the concurrent cost call did.
        assert len(usage_windows) > 1


@pytest.mark.asyncio
async def test_meters_are_cached_per_account(monkeypatch: pytest.MonkeyPatch) -> None:
    """Meters are fetched per account, so the cache must be keyed by account.

    A customer typically has both an electricity and a gas account; a single
    shared cache would serve the first account's meters for every other one.
    """
    async with aiohttp.ClientSession(cookie_jar=create_cookie_jar()) as session:
        opower = Opower(
            session,
            "Consolidated Edison (ConEd)",
            username="test",
            password="test",  # noqa: S106
        )

        async def fake_get_request(url: str, params: dict[str, str], headers: dict[str, str]) -> Any:
            account_uuid = url.split("/accounts/")[1].split("/", maxsplit=1)[0]
            return {"meters_ids": [f"meter-for-{account_uuid}"]}

        monkeypatch.setattr(opower, "_async_get_request", fake_get_request)

        def account(uuid: str) -> Account:
            return Account(
                customer=Mock(uuid="customer-uuid"),
                uuid=uuid,
                utility_account_id=uuid,
                id=uuid,
                meter_type=MeterType.ELEC,
                read_resolution=ReadResolution.QUARTER_HOUR,
            )

        assert await opower._async_get_meters(account("elec")) == ["meter-for-elec"]
        assert await opower._async_get_meters(account("gas")) == ["meter-for-gas"]
        # Still cached: a repeat lookup must not re-request.
        monkeypatch.setattr(opower, "_async_get_request", None)
        assert await opower._async_get_meters(account("elec")) == ["meter-for-elec"]


@pytest.mark.asyncio
async def test_naive_read_times_localized_to_utility_timezone(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Reads without a UTC offset are localized to the utility's timezone.

    Some utilities (e.g. City of Austin) return timestamps with no offset.
    Statistics consumers (such as Home Assistant's recorder) require
    timezone-aware datetimes, so naive values must be localized rather than
    passed through unchanged.
    """
    async with aiohttp.ClientSession(cookie_jar=create_cookie_jar()) as session:
        opower = Opower(
            session,
            "City of Austin Utilities",
            username="test",
            password="test",  # noqa: S106
        )

        account = Account(
            customer=Mock(),
            uuid="test-uuid",
            utility_account_id="test-id",
            id="test-id",
            meter_type=MeterType.ELEC,
            read_resolution=ReadResolution.DAY,
        )

        async def fake_get_dated_data(
            *args: object,
            **kwargs: object,
        ) -> list[dict[str, object]]:
            return [
                {
                    "startTime": "2026-06-01T00:00:00",
                    "endTime": "2026-06-02T00:00:00",
                    "consumption": {"value": 10.0},
                    "providedCost": 1.23,
                }
            ]

        monkeypatch.setattr(opower, "_async_get_dated_data", fake_get_dated_data)

        result = await opower.async_get_cost_reads(account, AggregateType.DAY, None, None)

        tz = ZoneInfo("America/Chicago")
        assert len(result) == 1
        assert result[0].start_time == datetime(2026, 6, 1, tzinfo=tz)
        assert result[0].end_time == datetime(2026, 6, 2, tzinfo=tz)
        assert result[0].start_time.tzinfo is not None
        assert result[0].end_time.tzinfo is not None


# --- Fake session --------------------------------------------------------
#
# The tests below drive the client through its real request layer so that URL
# construction, headers, batching and the fallbacks between endpoints are
# covered too. The payloads mirror the shape of real PG&E responses; the
# identifiers and values in them are made up.


class _FakeResponse:
    """Minimal stand-in for aiohttp.ClientResponse."""

    def __init__(self, payload: Any, status: int = 200) -> None:
        """Initialize with the payload to serve and the HTTP status."""
        self.status = status
        self._payload = payload

    @property
    def ok(self) -> bool:
        """Mimic aiohttp: any status below 400 is a success."""
        return self.status < 400

    async def json(self) -> Any:
        """Return the canned payload."""
        return self._payload

    async def text(self) -> str:
        """Return the canned payload serialized, as aiohttp would."""
        return json.dumps(self._payload)

    async def __aenter__(self) -> "_FakeResponse":
        return self

    async def __aexit__(self, *args: object) -> None:
        return None


class _FakeSession:
    """Serves canned responses keyed by URL substring and records requests.

    A route value is either a payload, a `_FakeResponse` (to serve an error
    status) or a callable taking the query parameters and returning either.
    """

    def __init__(self, routes: dict[str, Any]) -> None:
        """Initialize with the routes to serve."""
        self._routes = routes
        self.requests: list[dict[str, Any]] = []

    def _handle(self, method: str, url: str, **kwargs: Any) -> _FakeResponse:
        self.requests.append({"method": method, "url": url, **kwargs})
        for substring, route in self._routes.items():
            if substring in url:
                result = route(kwargs.get("params") or {}) if callable(route) else route
                return result if isinstance(result, _FakeResponse) else _FakeResponse(result)
        raise AssertionError(f"Unexpected request to {url}")

    def get(self, url: str, **kwargs: Any) -> _FakeResponse:
        """Serve a GET request."""
        return self._handle("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> _FakeResponse:
        """Serve a POST request."""
        return self._handle("POST", url, **kwargs)


_CUSTOMER_UUID = "11111111-1111-11e5-bf2b-000000000001"
_ELEC_ACCOUNT_UUID = "22222222-2222-11e5-bf2b-000000000002"
_GAS_ACCOUNT_UUID = "33333333-3333-11e5-bf2b-000000000003"

# Shape of a real pge.opower.com multi-account-v1 response.
_CUSTOMERS_RESPONSE = {
    "customers": [
        {
            "id": 10000001,
            "uuid": _CUSTOMER_UUID,
            "legacyOpowerId": "3f-1-000000",
            "accountNumber": "1000000001",
            "accountName": "TEST RES 1000000001",
            "address": {
                "uuid": "44444444-4444-11e3-9228-000000000004",
                "streetNumber": "1",
                "streetName": "MAIN ST",
                "subpremise": None,
                "postalCode": "94000",
                "city": "TESTVILLE",
                "country": "US",
                "state": "CA",
            },
            "type": "RESIDENTIAL",
            "utilityAccounts": [
                {
                    "id": 20000001,
                    "uuid": _ELEC_ACCOUNT_UUID,
                    "utilityAccountId": "1000000002",
                    "utilityAccountId2": "1000000003",
                    "servicePointId": 3000001,
                    "meterType": "ELEC",
                    "preferredUtilityAccountId": "1000000003",
                    "readResolution": "QUARTER_HOUR",
                }
            ],
        }
    ],
    "offset": 0,
    "batchSize": 100,
    "total": 1,
}


_ACCESS_TOKEN = "test-token"  # noqa: S105


def _pge(session: _FakeSession) -> Opower:
    """Return a PG&E client wired to a fake session and already "logged in"."""
    opower = Opower(
        session,  # type: ignore[arg-type]
        "Pacific Gas and Electric Company (PG&E)",
        username="test",
        password="test",  # noqa: S106
    )
    opower._access_token = _ACCESS_TOKEN
    return opower


def _coned(session: _FakeSession) -> Opower:
    """Return a ConEd client wired to a fake session and already logged in."""
    opower = Opower(
        session,  # type: ignore[arg-type]
        "Consolidated Edison (ConEd)",
        "test",
        "test",
    )
    opower._access_token = _ACCESS_TOKEN
    return opower


@pytest.mark.asyncio
async def test_get_accounts_parses_customers_response() -> None:
    """Parse accounts out of a multi-account-v1 response."""
    session = _FakeSession({"multi-account-v1": _CUSTOMERS_RESPONSE})
    accounts = await _pge(session).async_get_accounts()

    assert len(accounts) == 1
    account = accounts[0]
    assert account.customer.uuid == _CUSTOMER_UUID
    assert account.uuid == _ELEC_ACCOUNT_UUID
    # preferredUtilityAccountId, not utilityAccountId, and unique so it is the id.
    assert account.utility_account_id == "1000000003"
    assert account.id == "1000000003"
    assert account.meter_type is MeterType.ELEC
    assert account.read_resolution is ReadResolution.QUARTER_HOUR

    request = session.requests[0]
    assert request["url"].startswith("https://pge.opower.com/ei/edge/apis/multi-account-v1/cws/pge/customers")
    assert request["headers"]["authorization"] == f"Bearer {_ACCESS_TOKEN}"
    # The customer is not known yet, so no customer claim is sent for this request.
    assert "Opower-Selected-Entities" not in request["headers"]


@pytest.mark.asyncio
async def test_get_accounts_falls_back_to_uuid_for_duplicate_utility_account_id() -> None:
    """Accounts sharing a preferredUtilityAccountId are identified by uuid.

    Electricity and gas on one bill can share the utility account id, which
    would otherwise give both accounts the same id.
    See https://github.com/home-assistant/core/issues/108260.
    """
    customers = {
        "customers": [
            {
                "uuid": _CUSTOMER_UUID,
                "utilityAccounts": [
                    {
                        "uuid": _ELEC_ACCOUNT_UUID,
                        "preferredUtilityAccountId": "1000000003",
                        "meterType": "ELEC",
                        "readResolution": "QUARTER_HOUR",
                    },
                    {
                        "uuid": _GAS_ACCOUNT_UUID,
                        "preferredUtilityAccountId": "1000000003",
                        "meterType": "GAS",
                        "readResolution": "DAY",
                    },
                ],
            }
        ]
    }
    accounts = await _pge(_FakeSession({"multi-account-v1": customers})).async_get_accounts()

    assert [account.id for account in accounts] == [_ELEC_ACCOUNT_UUID, _GAS_ACCOUNT_UUID]
    assert [account.utility_account_id for account in accounts] == ["1000000003", "1000000003"]
    assert [account.meter_type for account in accounts] == [MeterType.ELEC, MeterType.GAS]


@pytest.mark.asyncio
async def test_get_accounts_raises_when_no_customers() -> None:
    """An empty customers list is not a usable login."""
    opower = _pge(_FakeSession({"multi-account-v1": {"customers": []}}))
    with pytest.raises(CannotConnect):
        await opower.async_get_accounts()


@pytest.mark.asyncio
async def test_get_forecast_parses_graphql_response() -> None:
    """Parse the bill forecast, mapping the "TH" unit to THERM."""
    customers = {
        "customers": [
            {
                "uuid": _CUSTOMER_UUID,
                "utilityAccounts": [
                    {
                        "uuid": _ELEC_ACCOUNT_UUID,
                        "preferredUtilityAccountId": "1000000003",
                        "meterType": "ELEC",
                        "readResolution": "QUARTER_HOUR",
                    },
                    {
                        "uuid": _GAS_ACCOUNT_UUID,
                        "preferredUtilityAccountId": "1000000004",
                        "meterType": "GAS",
                        "readResolution": "DAY",
                    },
                ],
            }
        ]
    }
    graphql = {
        "data": {
            "billingAccountsConnection": {
                "edges": [
                    {
                        "node": {
                            "billForecast": {
                                "timeInterval": "2026-07-30T00:00:00-07:00/2026-08-31T00:00:00-07:00",
                                "currentDateTime": "2026-08-15T00:00:00-07:00",
                                "segments": [
                                    {
                                        "serviceAgreement": {"uuid": _ELEC_ACCOUNT_UUID},
                                        "estimatedUsage": {"value": 500.0, "unit": "KWH"},
                                        "estimatedUsageCharges": {"value": 150.0},
                                        "soFarUsage": {"value": 240.0},
                                        "soFarUsageCharges": {"value": 72.0},
                                        "priorYearUsage": {"value": 480.0},
                                        "priorYearUsageCharges": {"value": 140.0},
                                    },
                                    {
                                        "serviceAgreement": {"uuid": _GAS_ACCOUNT_UUID},
                                        # Gas is reported in "TH", which is not a UnitOfMeasure value.
                                        "estimatedUsage": {"value": 12.0, "unit": "TH"},
                                        "estimatedUsageCharges": {"value": 30.0},
                                        "soFarUsage": {"value": 6.0},
                                        "soFarUsageCharges": {"value": 15.0},
                                        "priorYearUsage": {"value": 11.0},
                                        "priorYearUsageCharges": {"value": 28.0},
                                    },
                                ],
                            }
                        }
                    }
                ]
            }
        }
    }
    session = _FakeSession({"multi-account-v1": customers, "dsm-graphql-v1": graphql})
    forecasts = await _pge(session).async_get_forecast()

    assert len(forecasts) == 2
    elec, gas = forecasts
    assert elec.account.uuid == _ELEC_ACCOUNT_UUID
    assert elec.start_date == date(2026, 7, 30)
    assert elec.end_date == date(2026, 8, 31)
    assert elec.current_date == date(2026, 8, 15)
    assert elec.unit_of_measure is UnitOfMeasure.KWH
    assert (elec.usage_to_date, elec.cost_to_date) == (240.0, 72.0)
    assert (elec.forecasted_usage, elec.forecasted_cost) == (500.0, 150.0)
    assert (elec.typical_usage, elec.typical_cost) == (480.0, 140.0)
    assert gas.unit_of_measure is UnitOfMeasure.THERM
    assert gas.forecasted_usage == 12.0

    graphql_request = next(r for r in session.requests if "dsm-graphql-v1" in r["url"])
    assert graphql_request["method"] == "POST"
    assert "billForecast" in graphql_request["json"]["query"]


@pytest.mark.asyncio
async def test_get_forecast_without_estimates_defaults_by_meter_type() -> None:
    """A forecast with no estimate yet keeps the account's default unit.

    PG&E returns null estimates at the start of a billing period.
    """
    graphql = {
        "data": {
            "billingAccountsConnection": {
                "edges": [
                    {
                        "node": {
                            "billForecast": {
                                "timeInterval": "2026-08-31T00:00:00-07:00/2026-10-01T00:00:00-07:00",
                                "currentDateTime": "2026-09-02T00:00:00-07:00",
                                "segments": [
                                    {
                                        "serviceAgreement": {"uuid": _ELEC_ACCOUNT_UUID},
                                        "estimatedUsage": None,
                                        "estimatedUsageCharges": None,
                                        "soFarUsage": {"value": 0.0},
                                        "soFarUsageCharges": {"value": 0.0},
                                        "priorYearUsage": {"value": 241.0},
                                        "priorYearUsageCharges": {"value": 51.0},
                                    }
                                ],
                            }
                        }
                    }
                ]
            }
        }
    }
    session = _FakeSession({"multi-account-v1": _CUSTOMERS_RESPONSE, "dsm-graphql-v1": graphql})
    forecasts = await _pge(session).async_get_forecast()

    assert len(forecasts) == 1
    assert forecasts[0].unit_of_measure is UnitOfMeasure.KWH
    assert forecasts[0].forecasted_usage == 0
    assert forecasts[0].forecasted_cost == 0
    assert forecasts[0].typical_usage == 241.0


@pytest.mark.asyncio
async def test_get_forecast_skips_unusable_segments() -> None:
    """Skip forecasts for unknown accounts, and nodes without a usable interval."""
    graphql = {
        "data": {
            "billingAccountsConnection": {
                "edges": [
                    {"node": {"billForecast": None}},
                    {"node": {"billForecast": {"timeInterval": "", "segments": []}}},
                    {
                        "node": {
                            "billForecast": {
                                "timeInterval": "2026-07-30T00:00:00-07:00/2026-08-31T00:00:00-07:00",
                                "currentDateTime": "2026-08-15T00:00:00-07:00",
                                "segments": [
                                    # A service agreement that is not one of the user's accounts.
                                    {
                                        "serviceAgreement": {"uuid": _GAS_ACCOUNT_UUID},
                                        "estimatedUsage": {"value": 1.0, "unit": "KWH"},
                                    },
                                    {
                                        "serviceAgreement": {"uuid": _ELEC_ACCOUNT_UUID},
                                        # An unrecognized unit falls back to the meter type default.
                                        "estimatedUsage": {"value": 2.0, "unit": "BTU"},
                                    },
                                ],
                            }
                        }
                    },
                ]
            }
        }
    }
    session = _FakeSession({"multi-account-v1": _CUSTOMERS_RESPONSE, "dsm-graphql-v1": graphql})
    forecasts = await _pge(session).async_get_forecast()

    assert len(forecasts) == 1
    assert forecasts[0].account.uuid == _ELEC_ACCOUNT_UUID
    assert forecasts[0].unit_of_measure is UnitOfMeasure.KWH
    assert forecasts[0].forecasted_usage == 2.0
    # Absent values default to 0 rather than raising.
    assert forecasts[0].cost_to_date == 0


@pytest.mark.asyncio
async def test_get_forecast_ignores_graphql_errors() -> None:
    """A GraphQL error yields no forecasts instead of failing the update."""
    session = _FakeSession(
        {
            "multi-account-v1": _CUSTOMERS_RESPONSE,
            "dsm-graphql-v1": {"errors": [{"message": "Not authorized"}]},
        }
    )
    assert await _pge(session).async_get_forecast() == []


@pytest.mark.asyncio
async def test_cost_reads_parse_tiered_and_time_of_use_components() -> None:
    """Parse a daily cost response with per-tier, per-TOU-period components."""
    cost_response = {
        "servicePointId": "9000000001",
        "utilityAccountUuid": _ELEC_ACCOUNT_UUID,
        "unit": "KWH",
        "siteTimeZoneId": "America/Los_Angeles",
        "reads": [
            {
                "startTime": "2026-07-01T00:00:00.000-07:00",
                "endTime": "2026-07-02T00:00:00.000-07:00",
                "value": 29.4584,
                "readType": "ACTUAL",
                "providedCost": 9.632872208,
                "readComponents": [
                    {
                        "tierType": "ORDINAL",
                        "tierNumber": 1,
                        "season": "SUMMER",
                        "dayPart": "OFF_PEAK",
                        "cost": 6.724775951,
                        "value": 21.6701,
                    },
                    {
                        "tierType": "ORDINAL",
                        "tierNumber": 2,
                        "season": "SUMMER",
                        "dayPart": "ON_PEAK",
                        "cost": 2.908096257,
                        "value": 7.7883,
                    },
                ],
                "rebateAmount": 0,
                "milesDriven": 49,
                "isPeakPeriod": False,
            },
            # Trailing all-zero reads are days that have not been metered yet.
            {
                "startTime": "2026-07-02T00:00:00.000-07:00",
                "endTime": "2026-07-03T00:00:00.000-07:00",
                "value": 0,
                "readType": "ACTUAL",
                "providedCost": 0,
                "readComponents": None,
                "rebateAmount": None,
                "milesDriven": 0,
                "isPeakPeriod": None,
            },
        ],
        "seriesComponents": None,
        "ratePlans": None,
    }
    session = _FakeSession({"cost/utilityAccount": cost_response})
    account = Account(
        customer=Customer(uuid=_CUSTOMER_UUID),
        uuid=_ELEC_ACCOUNT_UUID,
        utility_account_id="1000000003",
        id="1000000003",
        meter_type=MeterType.ELEC,
        read_resolution=ReadResolution.QUARTER_HOUR,
    )

    result = await _pge(session).async_get_cost_reads(account, AggregateType.DAY, datetime(2026, 7, 1), datetime(2026, 7, 2))

    # The trailing zero read is dropped.
    assert len(result) == 1
    tz = ZoneInfo("America/Los_Angeles")
    assert result[0].start_time == datetime(2026, 7, 1, tzinfo=tz)
    assert result[0].consumption == 29.4584
    assert result[0].provided_cost == 9.632872208
    assert [(c.tier_number, c.day_part, c.cost, c.consumption) for c in result[0].read_components] == [
        (1, "OFF_PEAK", 6.724775951, 21.6701),
        (2, "ON_PEAK", 2.908096257, 7.7883),
    ]

    headers = session.requests[0]["headers"]
    assert headers["authorization"] == f"Bearer {_ACCESS_TOKEN}"
    assert json.loads(headers["Opower-Selected-Entities"]) == [f"urn:opower:customer:uuid:{_CUSTOMER_UUID}"]

    # The cost endpoint takes full timestamps, unlike the usage endpoint.
    params = session.requests[0]["params"]
    assert params == {
        "aggregateType": "day",
        "startDate": "2026-07-01T00:00:00-07:00",
        "endDate": "2026-07-03T00:00:00-07:00",
    }


@pytest.mark.asyncio
async def test_cost_reads_fall_back_to_usage_when_cost_response_is_empty() -> None:
    """An empty cost response falls back to the usage endpoint.

    PG&E returns no reads from the cost endpoint for recent days on some rate
    plans, while the usage endpoint still has the consumption.
    """
    usage_response = {
        "startDate": "2026-08-25",
        "endDate": "2026-08-27",
        "reads": [
            {
                "startTime": "2026-08-25T00:00:00.000-07:00",
                "endTime": "2026-08-26T00:00:00.000-07:00",
                "providedCost": None,
                "milesDriven": 25,
                "demand": None,
                "consumption": {"value": 15.0677, "type": "ACTUAL"},
                "exported": None,
                "grossConsumption": None,
                "grossGeneration": None,
                "imported": None,
                "reactivePower": None,
            },
            {
                "startTime": "2026-08-26T00:00:00.000-07:00",
                "endTime": "2026-08-27T00:00:00.000-07:00",
                "providedCost": None,
                "milesDriven": 19,
                "demand": None,
                "consumption": {"value": 11.4372, "type": "ACTUAL"},
                "exported": None,
                "grossConsumption": None,
                "grossGeneration": None,
                "imported": None,
                "reactivePower": None,
            },
        ],
    }
    cost_response = {
        "servicePointId": "9000000001",
        "utilityAccountUuid": _ELEC_ACCOUNT_UUID,
        "unit": "KWH",
        "siteTimeZoneId": "America/Los_Angeles",
        "reads": [],
        "seriesComponents": [],
        "ratePlans": [
            {
                "code": "HETOUC/NEM2/CCA",
                "name": None,
                "meterType": "ELEC",
                "startDate": "2023-06-12T00:00:00.000-07:00",
                "endDate": None,
                "series": {},
            }
        ],
    }
    session = _FakeSession({"cost/utilityAccount": cost_response, "/reads": usage_response})
    account = Account(
        customer=Customer(uuid=_CUSTOMER_UUID),
        uuid=_ELEC_ACCOUNT_UUID,
        utility_account_id="1000000003",
        id="1000000003",
        meter_type=MeterType.ELEC,
        read_resolution=ReadResolution.QUARTER_HOUR,
    )

    result = await _pge(session).async_get_cost_reads(account, AggregateType.DAY, datetime(2026, 8, 25), datetime(2026, 8, 26))

    assert [read.consumption for read in result] == [15.0677, 11.4372]
    # No cost is available on this path.
    assert {read.provided_cost for read in result} == {0.0}

    assert [r["url"].rsplit("/ei/edge/apis/", maxsplit=1)[1] for r in session.requests] == [
        f"DataBrowser-v1/cws/cost/utilityAccount/{_ELEC_ACCOUNT_UUID}",
        f"DataBrowser-v1/cws/utilities/pge/utilityAccounts/{_ELEC_ACCOUNT_UUID}/reads",
    ]
    # The usage endpoint takes plain dates.
    assert session.requests[1]["params"] == {
        "aggregateType": "day",
        "startDate": "2026-08-25",
        "endDate": "2026-08-27",
    }


@pytest.mark.asyncio
async def test_usage_reads_parse_reads() -> None:
    """Usage reads read consumption from the nested consumption object."""
    usage_response = {
        "startDate": "2026-07-10",
        "endDate": "2026-07-11",
        "reads": [
            {
                "startTime": "2026-07-10T00:00:00.000-07:00",
                "endTime": "2026-07-10T01:00:00.000-07:00",
                "providedCost": None,
                "consumption": {"value": 0.58, "type": "ACTUAL"},
            },
            {
                "startTime": "2026-07-10T01:00:00.000-07:00",
                "endTime": "2026-07-10T02:00:00.000-07:00",
                "providedCost": None,
                "consumption": {"value": 0.4942, "type": "ACTUAL"},
            },
        ],
    }
    session = _FakeSession({"/reads": usage_response})
    account = Account(
        customer=Customer(uuid=_CUSTOMER_UUID),
        uuid=_ELEC_ACCOUNT_UUID,
        utility_account_id="1000000003",
        id="1000000003",
        meter_type=MeterType.ELEC,
        read_resolution=ReadResolution.QUARTER_HOUR,
    )

    result = await _pge(session).async_get_usage_reads(
        account, AggregateType.HOUR, datetime(2026, 7, 10), datetime(2026, 7, 10)
    )

    tz = ZoneInfo("America/Los_Angeles")
    assert [read.consumption for read in result] == [0.58, 0.4942]
    assert result[0].start_time == datetime(2026, 7, 10, tzinfo=tz)
    assert result[0].end_time == datetime(2026, 7, 10, 1, tzinfo=tz)


@pytest.mark.asyncio
async def test_hourly_requests_are_batched_and_ordered() -> None:
    """Hourly ranges are fetched in 26 day windows, newest first, and reassembled."""
    windows: list[tuple[str, str]] = []

    def cost(params: dict[str, str]) -> dict[str, Any]:
        windows.append((params["startDate"], params["endDate"]))
        start = params["startDate"][:10]
        return {
            "reads": [
                {
                    "startTime": f"{start}T00:00:00.000-07:00",
                    "endTime": f"{start}T01:00:00.000-07:00",
                    "value": 1.0,
                    "providedCost": 0.5,
                }
            ]
        }

    session = _FakeSession({"cost/utilityAccount": cost})
    account = Account(
        customer=Customer(uuid=_CUSTOMER_UUID),
        uuid=_ELEC_ACCOUNT_UUID,
        utility_account_id="1000000003",
        id="1000000003",
        meter_type=MeterType.ELEC,
        read_resolution=ReadResolution.QUARTER_HOUR,
    )

    result = await _pge(session).async_get_cost_reads(account, AggregateType.HOUR, datetime(2026, 6, 1), datetime(2026, 7, 31))

    # 61 days back from the end of 2026-07-31 in 26 day windows.
    assert [(start[:10], end[:10]) for start, end in windows] == [
        ("2026-07-06", "2026-08-01"),
        ("2026-06-09", "2026-07-05"),
        ("2026-06-01", "2026-06-08"),
    ]
    # Reads come back in chronological order even though windows are fetched in reverse.
    assert [read.start_time.date().isoformat() for read in result] == ["2026-06-01", "2026-06-09", "2026-07-06"]


@pytest.mark.asyncio
async def test_aggregate_type_must_be_supported_by_read_resolution() -> None:
    """Asking for a finer aggregation than the account supports is rejected."""
    session = _FakeSession({})
    account = Account(
        customer=Customer(uuid=_CUSTOMER_UUID),
        uuid=_GAS_ACCOUNT_UUID,
        utility_account_id="1000000004",
        id="1000000004",
        meter_type=MeterType.GAS,
        read_resolution=ReadResolution.DAY,
    )

    with pytest.raises(ValueError, match="not supported by account's read_resolution"):
        await _pge(session).async_get_usage_reads(account, AggregateType.HOUR, datetime(2026, 7, 1), datetime(2026, 7, 2))
    assert session.requests == []


@pytest.mark.asyncio
async def test_dated_data_requires_a_date_range_unless_bill() -> None:
    """Only bill aggregation may omit the date range."""
    session = _FakeSession({"cost/utilityAccount": {"reads": []}})
    account = Account(
        customer=Customer(uuid=_CUSTOMER_UUID),
        uuid=_ELEC_ACCOUNT_UUID,
        utility_account_id="1000000003",
        id="1000000003",
        meter_type=MeterType.ELEC,
        read_resolution=ReadResolution.QUARTER_HOUR,
    )
    opower = _pge(session)

    with pytest.raises(ValueError, match="start_date is required"):
        await opower.async_get_usage_reads(account, AggregateType.DAY, None, None)
    with pytest.raises(ValueError, match="end_date is required"):
        await opower.async_get_usage_reads(account, AggregateType.DAY, datetime(2026, 7, 1), None)


@pytest.mark.asyncio
async def test_bill_reads_ignore_server_errors() -> None:
    """A 500 from the bill endpoint means no bills yet, not a failure.

    It happens when the requested range predates the account's activation.
    """
    session = _FakeSession({"cost/utilityAccount": _FakeResponse({"error": "server error"}, status=500)})
    account = Account(
        customer=Customer(uuid=_CUSTOMER_UUID),
        uuid=_ELEC_ACCOUNT_UUID,
        utility_account_id="1000000003",
        id="1000000003",
        meter_type=MeterType.ELEC,
        read_resolution=ReadResolution.QUARTER_HOUR,
    )

    assert await _pge(session).async_get_cost_reads(account, AggregateType.BILL) == []


@pytest.mark.asyncio
async def test_realtime_usage_reads_use_the_first_meter() -> None:
    """Realtime reads come from the first meter of the account."""
    meters_response = {"MAID": "1000000002", "meters_ids": ["KWH:DELIVERED", "KWH:RECEIVED", "KWH:NET_USAGE"]}
    usage_response = {
        "reads": [
            {"startTime": "2026-09-01T10:00:00.000-07:00", "endTime": "2026-09-01T10:15:00.000-07:00", "value": 0.25},
            {"startTime": "2026-09-01T10:15:00.000-07:00", "endTime": "2026-09-01T10:30:00.000-07:00", "value": 0.31},
        ]
    }
    session = _FakeSession({"/meters/": usage_response, "/meters": meters_response})
    account = Account(
        customer=Customer(uuid=_CUSTOMER_UUID),
        uuid=_ELEC_ACCOUNT_UUID,
        utility_account_id="1000000003",
        id="1000000003",
        meter_type=MeterType.ELEC,
        read_resolution=ReadResolution.QUARTER_HOUR,
    )

    result = await _pge(session).async_get_realtime_usage_reads(account)

    tz = ZoneInfo("America/Los_Angeles")
    assert [read.consumption for read in result] == [0.25, 0.31]
    assert result[0].start_time == datetime(2026, 9, 1, 10, 0, tzinfo=tz)
    assert session.requests[1]["url"].endswith(
        f"cws-real-time-ami-v1/cws/pge/accounts/{_ELEC_ACCOUNT_UUID}/meters/KWH:DELIVERED/usage"
    )


@pytest.mark.asyncio
async def test_realtime_usage_reads_surface_api_errors() -> None:
    """A meter without realtime data raises with the status and response body."""
    meters_response = {"MAID": "1000000002", "meters_ids": ["KWH:DELIVERED"]}
    error_body = {"error": {"details": "No data returned from API. (00000000-0000-0000-0000-000000000000)"}}
    session = _FakeSession({"/meters/": _FakeResponse(error_body, status=404), "/meters": meters_response})
    account = Account(
        customer=Customer(uuid=_CUSTOMER_UUID),
        uuid=_ELEC_ACCOUNT_UUID,
        utility_account_id="1000000003",
        id="1000000003",
        meter_type=MeterType.ELEC,
        read_resolution=ReadResolution.QUARTER_HOUR,
    )

    with pytest.raises(ApiException) as exc_info:
        await _pge(session).async_get_realtime_usage_reads(account)

    assert exc_info.value.status == 404
    assert "No data returned from API" in (exc_info.value.response_text or "")


@pytest.mark.asyncio
async def test_realtime_usage_reads_require_a_meter() -> None:
    """An account with no meters cannot serve realtime reads."""
    session = _FakeSession({"/meters": {"MAID": "1000000002", "meters_ids": []}})
    account = Account(
        customer=Customer(uuid=_CUSTOMER_UUID),
        uuid=_ELEC_ACCOUNT_UUID,
        utility_account_id="1000000003",
        id="1000000003",
        meter_type=MeterType.ELEC,
        read_resolution=ReadResolution.QUARTER_HOUR,
    )

    with pytest.raises(CannotConnect):
        await _pge(session).async_get_realtime_usage_reads(account)


def _realtime_account() -> Account:
    """Return a synthetic ConEd electric account."""
    return Account(
        customer=Customer(uuid=_CUSTOMER_UUID),
        uuid=_ELEC_ACCOUNT_UUID,
        utility_account_id="1000000003",
        id="1000000003",
        meter_type=MeterType.ELEC,
        read_resolution=ReadResolution.QUARTER_HOUR,
    )


def _realtime_topology(*billing_accounts: dict[str, Any]) -> dict[str, Any]:
    """Build a GraphQL billing account topology response."""
    return {
        "data": {"billingAccountsConnection": {"edges": [{"node": billing_account} for billing_account in billing_accounts]}}
    }


def _realtime_billing_account(
    billing_uuid: str,
    service_agreement_uuid: str,
    *,
    account_number: str = "1000000003",
    service_agreement_utility_id: str | None = None,
) -> dict[str, Any]:
    """Build one GraphQL billing account with an electric service point."""
    return {
        "urn": f"urn:opower:v1:account:cned:uuid:{billing_uuid}",
        "uuid": billing_uuid,
        "accountNumber": account_number,
        "utilityId": account_number,
        "serviceAgreementsConnection": {
            "edges": [
                {
                    "node": {
                        "uuid": service_agreement_uuid,
                        "utilityId": service_agreement_utility_id,
                        "serviceType": "ELECTRICITY",
                        "servicePointsConnection": {
                            "edges": [
                                {
                                    "node": {
                                        "uuid": f"sp-{service_agreement_uuid}",
                                        "serviceType": "ELECTRICITY",
                                    }
                                }
                            ]
                        },
                    }
                }
            ]
        },
    }


def _realtime_registers(*register_ids: str) -> dict[str, Any]:
    """Build a GraphQL WRTAMI register response."""
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
                                                "intervalReads": [{"registerId": register_id} for register_id in register_ids]
                                            }
                                        }
                                    ]
                                }
                            }
                        }
                    ]
                }
            }
        }
    }


def _realtime_usage(*reads: dict[str, Any]) -> dict[str, Any]:
    """Build a GraphQL WRTAMI usage response."""
    return {
        "data": {
            "billingAccountByAuthContext": {
                "serviceAgreementsConnection": {
                    "edges": [
                        {
                            "node": {
                                "servicePointsConnection": {"edges": [{"node": {"intervalReads": [{"reads": list(reads)}]}}]}
                            }
                        }
                    ]
                }
            }
        }
    }


@pytest.mark.asyncio
async def test_realtime_usage_reads_use_graphql_net_usage_and_cache_discovery(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """ConEd uses unverified NET_USAGE reads and caches stable register metadata."""
    opower = _coned(_FakeSession({}))
    account = _realtime_account()
    calls: list[tuple[str, dict[str, Any] | None]] = []

    async def fake_post_graphql(
        query: str,
        headers: dict[str, str],
        variables: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        del headers
        calls.append((query, variables))
        if "WRTAMI_GetTopology" in query:
            return _realtime_topology(
                _realtime_billing_account(
                    "other-billing-account",
                    "other-service-agreement",
                    account_number="9999999999",
                ),
                _realtime_billing_account(
                    "selected-billing-account",
                    "selected-service-agreement",
                    account_number="9999999998",
                    service_agreement_utility_id=account.utility_account_id,
                ),
            )
        if "WRTAMI_GetRegisters" in query:
            return _realtime_registers("net-register")
        return _realtime_usage(
            {
                "timeInterval": "2026-09-01T10:15:00-04:00/2026-09-01T10:30:00-04:00",
                "measuredAmount": {"value": -0.12},
            },
            {
                "timeInterval": "2026-09-01T10:00:00-04:00/2026-09-01T10:15:00-04:00",
                "measuredAmount": {"value": 0.25},
            },
            {
                "timeInterval": "2026-09-01T10:30:00-04:00/2026-09-01T10:45:00-04:00",
                "measuredAmount": None,
            },
        )

    monkeypatch.setattr(opower, "_async_post_graphql", fake_post_graphql)

    first = await opower.async_get_realtime_usage_reads(account)
    second = await opower.async_get_realtime_usage_reads(account)

    assert [read.consumption for read in first] == [0.25, -0.12]
    assert second == first
    assert first[0].start_time == datetime(2026, 9, 1, 10, 0, tzinfo=ZoneInfo("America/New_York"))
    assert sum("WRTAMI_GetTopology" in query for query, _ in calls) == 1
    assert sum("WRTAMI_GetRegisters" in query for query, _ in calls) == 1
    assert sum("WRTAMI_GetRegisterUsage" in query for query, _ in calls) == 2
    realtime_queries = [query for query, _ in calls if "WRTAMI_GetRegisters" in query or "WRTAMI_GetRegisterUsage" in query]
    assert all("serviceQuantityIdentifier: [NET_USAGE]" in query for query in realtime_queries)
    assert all("onlyUnverifiedStreams: true" in query for query in realtime_queries)
    usage_variables = next(variables for query, variables in calls if "WRTAMI_GetRegisterUsage" in query)
    assert usage_variables == {
        "selectedAccount": ("urn:opower:v1:account:cned:uuid:selected-billing-account"),
        "registerId": "net-register",
        "saUuid": "selected-service-agreement",
        "spUuid": "sp-selected-service-agreement",
    }


@pytest.mark.asyncio
async def test_realtime_usage_reads_fall_back_when_graphql_mapping_is_ambiguous(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Multiple matching GraphQL account paths use the compatibility REST API."""
    meters_response = {"meters_ids": ["KWH:NET_USAGE"]}
    usage_response = {
        "reads": [
            {
                "startTime": "2026-09-01T10:00:00-04:00",
                "endTime": "2026-09-01T10:15:00-04:00",
                "value": 0.4,
            }
        ]
    }
    session = _FakeSession({"/meters/": usage_response, "/meters": meters_response})
    opower = _coned(session)
    account = _realtime_account()
    topology_calls = 0

    async def fake_post_graphql(
        query: str,
        headers: dict[str, str],
        variables: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        nonlocal topology_calls
        del query, headers, variables
        topology_calls += 1
        return _realtime_topology(
            _realtime_billing_account("billing-1", "service-agreement-1"),
            _realtime_billing_account("billing-2", "service-agreement-2"),
        )

    monkeypatch.setattr(opower, "_async_post_graphql", fake_post_graphql)

    first = await opower.async_get_realtime_usage_reads(account)
    second = await opower.async_get_realtime_usage_reads(account)

    assert [read.consumption for read in first] == [0.4]
    assert second == first
    assert topology_calls == 1
    assert [request["method"] for request in session.requests] == ["GET", "GET", "GET"]


@pytest.mark.asyncio
async def test_realtime_usage_reads_fall_back_when_graphql_fails(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A GraphQL API failure uses the existing realtime REST path."""
    session = _FakeSession(
        {
            "/meters/": {
                "reads": [
                    {
                        "startTime": "2026-09-01T10:00:00-04:00",
                        "endTime": "2026-09-01T10:15:00-04:00",
                        "value": 0.4,
                    }
                ]
            },
            "/meters": {"meters_ids": ["KWH:NET_USAGE"]},
        }
    )
    opower = _coned(session)

    async def fail_graphql(
        query: str,
        headers: dict[str, str],
        variables: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        del query, headers, variables
        raise ApiException("GraphQL failed", url="https://example.test/graphql")

    monkeypatch.setattr(opower, "_async_post_graphql", fail_graphql)

    result = await opower.async_get_realtime_usage_reads(_realtime_account())

    assert [read.consumption for read in result] == [0.4]


@pytest.mark.asyncio
async def test_realtime_usage_reads_surface_rest_error_after_graphql_failure(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """The compatibility REST error propagates when both realtime paths fail."""
    session = _FakeSession(
        {
            "/meters": _FakeResponse(
                {"error": {"details": "No meter asset ID returned"}},
                status=424,
            )
        }
    )
    opower = _coned(session)

    async def fail_graphql(
        query: str,
        headers: dict[str, str],
        variables: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        del query, headers, variables
        raise ApiException("GraphQL failed", url="https://example.test/graphql")

    monkeypatch.setattr(opower, "_async_post_graphql", fail_graphql)

    with pytest.raises(ApiException) as exc_info:
        await opower.async_get_realtime_usage_reads(_realtime_account())

    assert exc_info.value.status == 424
    assert "No meter asset ID returned" in (exc_info.value.response_text or "")


def test_select_utility_accepts_name_and_class_name() -> None:
    """Utilities can be selected by display name or class name, case insensitively."""
    assert select_utility("pge") is PGE
    assert select_utility("PGE") is PGE
    assert select_utility("Pacific Gas and Electric Company (PG&E)") is PGE
    with pytest.raises(ValueError, match="not found"):
        select_utility("Not A Utility")


def test_supported_utility_names_are_sorted_and_unique() -> None:
    """Every supported utility contributes exactly one, sorted, display name."""
    names = get_supported_utility_names()

    assert names == sorted(names)
    assert len(names) == len(set(names))
    assert len(names) == len(get_supported_utilities())
    assert "Pacific Gas and Electric Company (PG&E)" in names
