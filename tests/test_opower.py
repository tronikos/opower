"""Tests for Opower."""

import asyncio
import dataclasses
import json
from datetime import date, datetime, timedelta
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


async def _no_register_streams(*args: object, **kwargs: object) -> None:
    """Stand in for the registers probe in tests whose fixtures are REST-only."""
    return


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
        # Daily reads are enriched from GraphQL; these fixtures are REST-only.
        monkeypatch.setattr(opower, "_async_get_register_streams", _no_register_streams)

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
        # Daily reads are enriched from GraphQL; these fixtures are REST-only.
        monkeypatch.setattr(opower, "_async_get_register_streams", _no_register_streams)

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
        # Daily reads are enriched from GraphQL; these fixtures are REST-only.
        monkeypatch.setattr(opower, "_async_get_register_streams", _no_register_streams)

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
async def test_cost_reads_parse_tiered_read_components(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Parse readComponents on a tiered rate, and treat a null readComponents as empty."""
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
            meter_type=MeterType.GAS,
            read_resolution=ReadResolution.DAY,
        )

        async def fake_get_dated_data(*args: object, **kwargs: object) -> list[dict[str, object]]:
            return [
                # Real (redacted) PG&E gas reads on a tiered rate: tierNumber is an
                # integer and dayPart is null, the mirror image of a time-of-use rate.
                {
                    "startTime": "2026-07-23T00:00:00.000-07:00",
                    "endTime": "2026-07-24T00:00:00.000-07:00",
                    "value": 1.055975,
                    "readType": "ACTUAL",
                    "providedCost": 2.5,
                    "readComponents": [
                        {
                            "tierType": "ORDINAL",
                            "tierNumber": 1,
                            "season": "SUMMER",
                            "dayPart": None,
                            "cost": 2.5,
                            "value": 1.055975,
                        }
                    ],
                    "rebateAmount": 0,
                    "milesDriven": 0,
                    "isPeakPeriod": False,
                },
                # A day that starts a tier accounting segment carries both tiers.
                {
                    "startTime": "2026-06-30T00:00:00.000-07:00",
                    "endTime": "2026-07-01T00:00:00.000-07:00",
                    "value": 1.062021,
                    "readType": "ACTUAL",
                    "providedCost": 2.7,
                    "readComponents": [
                        {
                            "tierType": "ORDINAL",
                            "tierNumber": 2,
                            "season": "SUMMER",
                            "dayPart": None,
                            "cost": 1.1,
                            "value": 0.388,
                        },
                        {
                            "tierType": "ORDINAL",
                            "tierNumber": 1,
                            "season": "SUMMER",
                            "dayPart": None,
                            "cost": 1.6,
                            "value": 0.674021,
                        },
                    ],
                    "rebateAmount": 0,
                    "milesDriven": 0,
                    "isPeakPeriod": False,
                },
                # Bill-level reads return readComponents as null rather than a list.
                {
                    "startTime": "2026-06-13T00:00:00.000-07:00",
                    "endTime": "2026-07-15T00:00:00.000-07:00",
                    "value": 10.0,
                    "readType": "ACTUAL",
                    "providedCost": 25.51,
                    "readComponents": None,
                    "rebateAmount": None,
                    "milesDriven": None,
                    "isPeakPeriod": None,
                },
            ]

        monkeypatch.setattr(opower, "_async_get_dated_data", fake_get_dated_data)
        monkeypatch.setattr(opower, "_async_get_register_streams", _no_register_streams)

        result = await opower.async_get_cost_reads(account, AggregateType.DAY, None, None)
        assert len(result) == 3

        components = result[0].read_components
        assert len(components) == 1
        assert components[0].tier_type == "ORDINAL"
        assert components[0].tier_number == 1
        assert components[0].day_part is None
        assert components[0].consumption == 1.055975
        assert components[0].cost == 2.5

        components = result[1].read_components
        assert [c.tier_number for c in components] == [2, 1]
        assert sum(c.consumption for c in components) == pytest.approx(result[1].consumption)
        assert sum(c.cost for c in components) == pytest.approx(result[1].provided_cost)

        assert result[2].read_components == []


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
        # Daily reads are enriched from GraphQL; these fixtures are REST-only.
        monkeypatch.setattr(opower, "_async_get_register_streams", _no_register_streams)

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
                if getattr(route, "wants_request", False):
                    result = route(kwargs)
                elif callable(route):
                    result = route(kwargs.get("params") or {})
                else:
                    result = route
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
    session = _FakeSession(
        {
            # REST-only fixture: no registers to enrich the daily reads with.
            "dsm-graphql-v1": _NO_REGISTERS_RESPONSE,
            "cost/utilityAccount": cost_response,
        }
    )
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
    session = _FakeSession(
        {
            # REST-only fixture: no registers to enrich the daily reads with.
            "dsm-graphql-v1": _NO_REGISTERS_RESPONSE,
            "cost/utilityAccount": cost_response,
            "/reads": usage_response,
        }
    )
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
        # Then the registers probe, which this meter answers with a net register only.
        "dsm-graphql-v1/cws/graphql",
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
    session = _FakeSession({"/reads": usage_response, "dsm-graphql-v1": _NO_REGISTERS_RESPONSE})
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


_ELEC_UTILITY_ACCOUNT_ID = "1000000003"
_SERVICE_POINT_UUID = "44444444-4444-11e5-bf2b-000000000004"

# Shape of a dsm-graphql-v1 registers response for a meter with no export register.
_NO_REGISTERS_RESPONSE = {
    "data": {
        "billingAccountByAuthContext": {
            "serviceAgreementsConnection": {
                "edges": [
                    {
                        "node": {
                            "utilityId": _ELEC_UTILITY_ACCOUNT_ID,
                            "serviceType": "ELECTRICITY",
                            "servicePointsConnection": {
                                "edges": [
                                    {
                                        "node": {
                                            "uuid": _SERVICE_POINT_UUID,
                                            "registers": [
                                                {
                                                    "serviceQuantityIdentifier": "NET_USAGE",
                                                    "unitOfMeasure": "KWH",
                                                    "availableReadsTimeInterval": (
                                                        "2024-04-15T00:00:00-07:00/2026-09-01T00:00:00-07:00"
                                                    ),
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


def _registers_response(utility_id: str = _ELEC_UTILITY_ACCOUNT_ID) -> dict[str, Any]:
    """Return a registers response for a meter that does publish import/export."""
    return {
        "data": {
            "billingAccountByAuthContext": {
                "serviceAgreementsConnection": {
                    "edges": [
                        {
                            "node": {
                                "utilityId": utility_id,
                                "serviceType": "ELECTRICITY",
                                "servicePointsConnection": {
                                    "edges": [
                                        {
                                            "node": {
                                                "uuid": _SERVICE_POINT_UUID,
                                                "registers": [
                                                    {
                                                        "serviceQuantityIdentifier": sqi,
                                                        "unitOfMeasure": "KWH",
                                                        "availableReadsTimeInterval": (
                                                            "2024-04-15T00:00:00-07:00/2027-01-01T00:00:00-08:00"
                                                        ),
                                                    }
                                                    for sqi in ("DELIVERED", "RECEIVED", "NET_USAGE")
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


def _register_reads_response(
    reads: dict[tuple[str, str], tuple[float | None, float | None]],
) -> dict[str, Any]:
    """Build a readStreams response from {(start_iso, end_iso): (imported, exported)}.

    Each direction is a list of streams, one per register behind it, which is how
    the API returns it even when there is only one.
    """

    def stream(index: int) -> list[dict[str, Any]]:
        return [
            {
                "reads": [
                    {
                        "timeInterval": f"{start}/{end}",
                        "measuredAmount": None if values[index] is None else {"value": values[index]},
                    }
                    for (start, end), values in reads.items()
                ]
            }
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
                                                "readStreams": {
                                                    "energyDelivered": stream(0),
                                                    "energyReceived": stream(1),
                                                }
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


def _elec_account() -> Account:
    """Return the electric account used by the import/export tests."""
    return Account(
        customer=Customer(uuid=_CUSTOMER_UUID),
        uuid=_ELEC_ACCOUNT_UUID,
        utility_account_id=_ELEC_UTILITY_ACCOUNT_ID,
        id=_ELEC_UTILITY_ACCOUNT_ID,
        meter_type=MeterType.ELEC,
        read_resolution=ReadResolution.QUARTER_HOUR,
    )


class _GraphQLRouter:
    """Route the two GraphQL queries by their content rather than by call order.

    The registers probe and the interval reads POST to the same URL, and the probe
    is repeated on every call, so ordering alone cannot tell them apart.
    """

    wants_request = True

    def __init__(self, registers: Any, reads: Any = None) -> None:
        """Serve `registers` for the probe and `reads` for interval read windows."""
        self.registers = registers
        self.reads = reads
        self.register_queries = 0
        self.read_queries = 0
        self.window_counts: list[int] = []

    def __call__(self, request: dict[str, Any]) -> Any:
        body = request.get("json") or {}
        query = body.get("query", "")
        if "registers" in query:
            self.register_queries += 1
            return self.registers
        self.read_queries += 1
        # Counts the readStreams fields in the document, not the variables, so a
        # reintroduced alias batch trips the guard in
        # test_register_windows_are_fetched_one_per_request.
        self.window_counts.append(query.count("readStreams("))
        if callable(self.reads):
            return self.reads(body.get("variables") or {})
        return self.reads


@pytest.mark.asyncio
async def test_cost_reads_carry_import_export_split() -> None:
    """Interval reads get the gross import/export from the per-register streams."""
    cost = {
        "reads": [
            {
                "startTime": "2026-08-31T12:00:00.000-07:00",
                "endTime": "2026-08-31T13:00:00.000-07:00",
                "value": -5.3404,
                "providedCost": -1.61,
            },
            {
                "startTime": "2026-08-31T13:00:00.000-07:00",
                "endTime": "2026-08-31T14:00:00.000-07:00",
                "value": -3.9012,
                "providedCost": -1.18,
            },
        ]
    }
    reads = _register_reads_response(
        {
            ("2026-08-31T19:00:00Z", "2026-08-31T20:00:00Z"): (0.0, 5.3404),
            ("2026-08-31T20:00:00Z", "2026-08-31T21:00:00Z"): (0.2462, 4.1474),
        }
    )
    session = _FakeSession(
        {
            "cost/utilityAccount": cost,
            "dsm-graphql-v1": _GraphQLRouter(_registers_response(), reads),
        }
    )

    result = await _pge(session).async_get_cost_reads(
        _elec_account(), AggregateType.HOUR, datetime(2026, 8, 31), datetime(2026, 8, 31)
    )

    assert [(r.imported, r.exported) for r in result] == [(0.0, 5.3404), (0.2462, 4.1474)]
    # The net is untouched; the split is additional information, not a replacement.
    assert [r.consumption for r in result] == [-5.3404, -3.9012]
    assert [r.provided_cost for r in result] == [-1.61, -1.18]


@pytest.mark.asyncio
async def test_import_export_left_unset_without_export_register() -> None:
    """A meter without an export register is fetched exactly as before."""
    cost = {
        "reads": [
            {
                "startTime": "2026-08-31T12:00:00.000-07:00",
                "endTime": "2026-08-31T13:00:00.000-07:00",
                "value": 1.5,
                "providedCost": 0.5,
            }
        ]
    }
    session = _FakeSession({"cost/utilityAccount": cost, "dsm-graphql-v1": _NO_REGISTERS_RESPONSE})
    opower = _pge(session)

    result = await opower.async_get_cost_reads(
        _elec_account(), AggregateType.HOUR, datetime(2026, 8, 31), datetime(2026, 8, 31)
    )

    assert [(r.imported, r.exported) for r in result] == [(None, None)]
    graphql_requests = [r for r in session.requests if "dsm-graphql-v1" in r["url"]]
    assert len(graphql_requests) == 1, "should probe once and not ask for reads"

    # The probe result is cached, so a second fetch makes no further GraphQL calls.
    await opower.async_get_cost_reads(_elec_account(), AggregateType.HOUR, datetime(2026, 8, 31), datetime(2026, 8, 31))
    assert len([r for r in session.requests if "dsm-graphql-v1" in r["url"]]) == 1


@pytest.mark.asyncio
async def test_import_export_skipped_for_bill_aggregation() -> None:
    """The read streams have no bill resolution, so a bill aggregate must not ask."""
    cost = {
        "reads": [
            {
                "startTime": "2026-08-01T00:00:00.000-07:00",
                "endTime": "2026-09-01T00:00:00.000-07:00",
                "value": -673.272,
                "providedCost": -198.14,
            }
        ]
    }
    session = _FakeSession({"cost/utilityAccount": cost})

    await _pge(session).async_get_cost_reads(_elec_account(), AggregateType.BILL, datetime(2026, 8, 1), datetime(2026, 8, 31))

    assert not [r for r in session.requests if "dsm-graphql-v1" in r["url"]]


@pytest.mark.asyncio
async def test_daily_reads_carry_import_export_split() -> None:
    """Daily reads are enriched too, and it is the resolution that needs it most.

    A day on a solar site is usually net-export, so splitting the daily net on its
    sign reports almost no grid import at all.
    """
    cost = {
        "reads": [
            {
                "startTime": "2026-08-05T00:00:00.000-07:00",
                "endTime": "2026-08-06T00:00:00.000-07:00",
                "value": -38.0691,
                "providedCost": -11.42,
            }
        ]
    }
    reads = _register_reads_response({("2026-08-05T07:00:00Z", "2026-08-06T07:00:00Z"): (5.6558, 43.7249)})
    router = _GraphQLRouter(_registers_response(), reads)
    session = _FakeSession({"cost/utilityAccount": cost, "dsm-graphql-v1": router})

    result = await _pge(session).async_get_cost_reads(
        _elec_account(), AggregateType.DAY, datetime(2026, 8, 5), datetime(2026, 8, 5)
    )

    assert [(r.imported, r.exported) for r in result] == [(5.6558, 43.7249)]
    assert router.read_queries == 1
    variables = [r["json"]["variables"] for r in session.requests if "dsm-graphql-v1" in r["url"]]
    assert variables[-1]["resolution"] == "DAY"


@pytest.mark.asyncio
async def test_import_export_ignores_graphql_errors() -> None:
    """A GraphQL failure must not lose the cost reads that already succeeded."""
    cost = {
        "reads": [
            {
                "startTime": "2026-08-31T12:00:00.000-07:00",
                "endTime": "2026-08-31T13:00:00.000-07:00",
                "value": -5.3404,
                "providedCost": -1.61,
            }
        ]
    }
    session = _FakeSession(
        {
            "cost/utilityAccount": cost,
            "dsm-graphql-v1": {"errors": [{"message": "Not authorized"}]},
        }
    )

    result = await _pge(session).async_get_cost_reads(
        _elec_account(), AggregateType.HOUR, datetime(2026, 8, 31), datetime(2026, 8, 31)
    )

    assert len(result) == 1
    assert (result[0].imported, result[0].exported) == (None, None)
    assert result[0].consumption == -5.3404


@pytest.mark.asyncio
async def test_import_export_survives_an_unexpected_response_shape() -> None:
    """A response shaped differently must not fail the reads it was enriching.

    The streams have only been seen on one utility. If another serves, say, a list
    where a dict is expected, the parser raises - and the cost reads it was
    decorating are already complete and correct.
    """
    cost = {
        "reads": [
            {
                "startTime": "2026-08-31T12:00:00.000-07:00",
                "endTime": "2026-08-31T13:00:00.000-07:00",
                "value": -5.3404,
                "providedCost": -1.61,
            }
        ]
    }
    malformed: dict[str, Any] = {
        "data": {
            "billingAccountByAuthContext": {
                "serviceAgreementsConnection": {
                    "edges": [
                        {
                            "node": {
                                "servicePointsConnection": {"edges": [{"node": {"readStreams": [{"energyDelivered": []}]}}]}
                            }
                        }
                    ]
                }
            }
        }
    }
    session = _FakeSession(
        {
            "cost/utilityAccount": cost,
            "dsm-graphql-v1": _GraphQLRouter(_registers_response(), malformed),
        }
    )

    result = await _pge(session).async_get_cost_reads(
        _elec_account(), AggregateType.HOUR, datetime(2026, 8, 31), datetime(2026, 8, 31)
    )

    assert [(r.consumption, r.imported, r.exported) for r in result] == [(-5.3404, None, None)]


@pytest.mark.asyncio
async def test_import_export_skips_intervals_the_utility_left_null() -> None:
    """An interval the utility has not published keeps only the net."""
    cost = {
        "reads": [
            {
                "startTime": "2026-03-08T00:00:00.000-08:00",
                "endTime": "2026-03-08T01:00:00.000-08:00",
                "value": 0.3807,
                "providedCost": 0.12,
            },
            {
                "startTime": "2026-03-08T03:00:00.000-07:00",
                "endTime": "2026-03-08T04:00:00.000-07:00",
                "value": 0.3052,
                "providedCost": 0.1,
            },
            {
                "startTime": "2026-03-08T04:00:00.000-07:00",
                "endTime": "2026-03-08T05:00:00.000-07:00",
                "value": 0.5,
                "providedCost": 0.16,
            },
        ]
    }
    reads = _register_reads_response(
        {
            ("2026-03-08T08:00:00Z", "2026-03-08T09:00:00Z"): (None, None),
            ("2026-03-08T10:00:00Z", "2026-03-08T11:00:00Z"): (None, None),
            ("2026-03-08T11:00:00Z", "2026-03-08T12:00:00Z"): (0.5, 0.0),
        }
    )
    session = _FakeSession(
        {
            "cost/utilityAccount": cost,
            "dsm-graphql-v1": _GraphQLRouter(_registers_response(), reads),
        }
    )

    result = await _pge(session).async_get_cost_reads(
        _elec_account(), AggregateType.HOUR, datetime(2026, 3, 8), datetime(2026, 3, 8)
    )

    assert [(r.imported, r.exported) for r in result] == [(None, None), (None, None), (0.5, 0.0)]


@pytest.mark.asyncio
async def test_import_export_keeps_both_halves_of_a_dst_fall_back_hour() -> None:
    """The repeated local hour on a fall-back day must not collapse into one read.

    The two 01:00 reads are equal as local datetimes under PEP 495, so anything
    keyed on the local wall clock would merge them.
    """
    cost = {
        "reads": [
            {
                "startTime": "2025-11-02T01:00:00.000-07:00",
                "endTime": "2025-11-02T01:00:00.000-08:00",
                "value": 0.5055,
                "providedCost": 0.16,
            },
            {
                "startTime": "2025-11-02T01:00:00.000-08:00",
                "endTime": "2025-11-02T02:00:00.000-08:00",
                "value": 0.3929,
                "providedCost": 0.12,
            },
        ]
    }
    reads = _register_reads_response(
        {
            ("2025-11-02T08:00:00Z", "2025-11-02T09:00:00Z"): (0.5055, 0.0),
            ("2025-11-02T09:00:00Z", "2025-11-02T10:00:00Z"): (0.3929, 0.0),
        }
    )
    session = _FakeSession(
        {
            "cost/utilityAccount": cost,
            "dsm-graphql-v1": _GraphQLRouter(_registers_response(), reads),
        }
    )

    result = await _pge(session).async_get_cost_reads(
        _elec_account(), AggregateType.HOUR, datetime(2025, 11, 2), datetime(2025, 11, 2)
    )

    assert len(result) == 2
    assert [r.imported for r in result] == [0.5055, 0.3929]


def _hourly_cost_reads(start: datetime, hours: int) -> dict[str, Any]:
    """Return an hourly cost response of `hours` reads starting at `start` (PDT)."""
    return {
        "reads": [
            {
                "startTime": (start + timedelta(hours=n)).strftime("%Y-%m-%dT%H:%M:%S.000-07:00"),
                "endTime": (start + timedelta(hours=n + 1)).strftime("%Y-%m-%dT%H:%M:%S.000-07:00"),
                "value": 1.0,
                "providedCost": 0.3,
            }
            for n in range(hours)
        ]
    }


@pytest.mark.asyncio
async def test_register_windows_are_fetched_one_per_request() -> None:
    """A window is chunked to the cap, and each chunk is its own request.

    The hourly cap is 720 hours, so five days is a single request. Aliasing the
    field to batch several windows into one request looks like it works, but the
    server does not isolate arguments per alias: every alias returns the same
    payload, drawn from a mix of the windows. See the comment on
    _REGISTER_READS_QUERY.
    """

    async def fetch(days: int) -> _GraphQLRouter:
        router = _GraphQLRouter(_registers_response(), _register_reads_response({}))
        session = _FakeSession(
            {
                "cost/utilityAccount": _hourly_cost_reads(datetime(2026, 6, 1), 24 * days),
                "dsm-graphql-v1": router,
            }
        )
        await _pge(session).async_get_cost_reads(
            _elec_account(), AggregateType.HOUR, datetime(2026, 6, 1), datetime(2026, 6, 1) + timedelta(days=days)
        )
        return router

    assert (await fetch(5)).read_queries == 1, "five days of hours fit in one request"

    router = await fetch(70)
    assert router.read_queries == 3, "70 days needs three chunks of at most 720 hours"
    assert router.window_counts == [1, 1, 1], "never more than one window per request"


@pytest.mark.asyncio
async def test_one_unserved_window_does_not_lose_the_others() -> None:
    """A window the utility has no data for must not discard the rest."""

    def reads(variables: dict[str, Any]) -> Any:
        if variables["timeInterval"].startswith("2026-01-31"):
            return {"errors": [{"message": "No data returned from API"}]}
        return _register_reads_response({("2026-08-05T07:00:00Z", "2026-08-05T08:00:00Z"): (0.25, 4.15)})

    router = _GraphQLRouter(_registers_response(), reads)
    session = _FakeSession({"cost/utilityAccount": {"reads": []}, "dsm-graphql-v1": router})

    result = await _pge(session).async_get_interval_register_reads(
        _elec_account(),
        AggregateType.HOUR,
        datetime(2026, 1, 1, tzinfo=ZoneInfo("America/Los_Angeles")),
        datetime(2026, 4, 1, tzinfo=ZoneInfo("America/Los_Angeles")),
    )

    assert router.read_queries == 3
    assert result, "the windows either side of the bad one must still be returned"


@pytest.mark.asyncio
async def test_register_availability_is_reread_on_every_call() -> None:
    """The available range must not be cached; it moves and it gates the request.

    PG&E's availableReadsTimeInterval ends around the previous midnight. Caching it
    for the life of the session would clamp away the newest hours - exactly the ones
    a caller asks for - and after a while would exclude everything.
    """
    router = _GraphQLRouter(_registers_response(), _register_reads_response({}))
    session = _FakeSession(
        {
            "cost/utilityAccount": _hourly_cost_reads(datetime(2026, 8, 1), 24),
            "dsm-graphql-v1": router,
        }
    )
    opower = _pge(session)

    for _ in range(3):
        await opower.async_get_cost_reads(_elec_account(), AggregateType.HOUR, datetime(2026, 8, 1), datetime(2026, 8, 1))

    assert router.register_queries == 3, "availability must be re-read, not cached"


@pytest.mark.asyncio
async def test_sub_hourly_reads_ask_for_the_matching_resolution() -> None:
    """The registers are served at the requested resolution, sub-hourly included."""
    reads = _register_reads_response({("2026-08-31T07:00:00Z", "2026-08-31T07:15:00Z"): (0.1208, 0.0)})
    router = _GraphQLRouter(_registers_response(), reads)
    session = _FakeSession(
        {
            "cost/utilityAccount": {
                "reads": [
                    {
                        "startTime": "2026-08-31T00:00:00.000-07:00",
                        "endTime": "2026-08-31T00:15:00.000-07:00",
                        "value": 0.1208,
                        "providedCost": 0.04,
                    }
                ]
            },
            "dsm-graphql-v1": router,
        }
    )

    result = await _pge(session).async_get_cost_reads(
        _elec_account(), AggregateType.QUARTER_HOUR, datetime(2026, 8, 31), datetime(2026, 8, 31)
    )

    assert (result[0].imported, result[0].exported) == (0.1208, 0.0)
    variables = [r["json"]["variables"] for r in session.requests if "dsm-graphql-v1" in r["url"]]
    assert variables[-1]["resolution"] == "QUARTER_HOUR"


@pytest.mark.asyncio
async def test_import_export_requires_the_spans_to_match() -> None:
    """A register read only enriches a cost read covering exactly the same span.

    Otherwise a whole hour's import could be attached to a read covering part of it,
    breaking imported - exported == consumption.
    """
    cost = {
        "reads": [
            {
                # 30 minutes, while the register stream is hourly.
                "startTime": "2026-08-31T12:00:00.000-07:00",
                "endTime": "2026-08-31T12:30:00.000-07:00",
                "value": -2.0,
                "providedCost": -0.6,
            }
        ]
    }
    reads = _register_reads_response({("2026-08-31T19:00:00Z", "2026-08-31T20:00:00Z"): (0.25, 4.15)})
    session = _FakeSession({"cost/utilityAccount": cost, "dsm-graphql-v1": _GraphQLRouter(_registers_response(), reads)})

    result = await _pge(session).async_get_cost_reads(
        _elec_account(), AggregateType.HOUR, datetime(2026, 8, 31), datetime(2026, 8, 31)
    )

    assert (result[0].imported, result[0].exported) == (None, None)


async def _probe_twice(first: Any) -> int:
    """Run two hourly fetches, serving `first` to the first probe. Return probe count."""
    attempts = {"n": 0}

    def registers(request: dict[str, Any]) -> Any:
        attempts["n"] += 1
        return first if attempts["n"] == 1 else _registers_response()

    registers.wants_request = True  # type: ignore[attr-defined]
    session = _FakeSession(
        {
            "cost/utilityAccount": _hourly_cost_reads(datetime(2026, 8, 1), 1),
            "dsm-graphql-v1": registers,
        }
    )
    opower = _pge(session)
    for _ in range(2):
        await opower.async_get_cost_reads(_elec_account(), AggregateType.HOUR, datetime(2026, 8, 1), datetime(2026, 8, 1))
    return attempts["n"]


@pytest.mark.asyncio
async def test_transient_probe_failure_is_not_cached_as_no_registers() -> None:
    """A 5xx must not disable the split for the rest of the session."""
    assert await _probe_twice(_FakeResponse({"error": "boom"}, status=500)) >= 2


@pytest.mark.asyncio
async def test_empty_probe_response_is_not_cached_as_no_registers() -> None:
    """An empty body is a hiccup, not a meter without registers."""
    assert await _probe_twice({"data": {"billingAccountByAuthContext": None}}) >= 2


@pytest.mark.asyncio
async def test_missing_graphql_endpoint_is_cached_as_no_registers() -> None:
    """A 4xx is structural: the endpoint is absent for this utility, so stop asking."""
    assert await _probe_twice(_FakeResponse({"error": "not found"}, status=404)) == 1


@pytest.mark.asyncio
async def test_partial_rest_split_still_asks_for_the_registers() -> None:
    """A utility publishing `imported` but not `exported` has given us nothing usable."""
    usage = {
        "reads": [
            {
                "startTime": "2026-08-31T12:00:00.000-07:00",
                "endTime": "2026-08-31T13:00:00.000-07:00",
                "consumption": {"value": -3.9, "type": "ACTUAL"},
                "imported": 0.25,
                "exported": None,
            }
        ]
    }
    reads = _register_reads_response({("2026-08-31T19:00:00Z", "2026-08-31T20:00:00Z"): (0.25, 4.15)})
    router = _GraphQLRouter(_registers_response(), reads)
    session = _FakeSession({"utilityAccounts": usage, "dsm-graphql-v1": router})

    result = await _pge(session).async_get_cost_reads(
        _elec_account(), AggregateType.HOUR, datetime(2026, 8, 31), datetime(2026, 8, 31), usage_only=True
    )

    assert router.read_queries == 1, "a half-populated split is not a split"
    assert (result[0].imported, result[0].exported) == (0.25, 4.15)


@pytest.mark.asyncio
async def test_import_export_matches_the_requested_service_agreement() -> None:
    """A customer's other service agreement must not supply the registers."""
    cost = {
        "reads": [
            {
                "startTime": "2026-08-31T12:00:00.000-07:00",
                "endTime": "2026-08-31T13:00:00.000-07:00",
                "value": -5.3404,
                "providedCost": -1.61,
            }
        ]
    }
    session = _FakeSession(
        {
            "cost/utilityAccount": cost,
            # Registers exist, but on a different service agreement.
            "dsm-graphql-v1": _registers_response(utility_id="9999999999"),
        }
    )

    result = await _pge(session).async_get_cost_reads(
        _elec_account(), AggregateType.HOUR, datetime(2026, 8, 31), datetime(2026, 8, 31)
    )

    assert (result[0].imported, result[0].exported) == (None, None)


@pytest.mark.asyncio
async def test_usage_endpoint_import_export_used_without_graphql() -> None:
    """When the utility publishes the split over REST, no GraphQL call is made."""
    usage = {
        "reads": [
            {
                "startTime": "2026-08-31T12:00:00.000-07:00",
                "endTime": "2026-08-31T13:00:00.000-07:00",
                "consumption": {"value": -5.3404, "type": "ACTUAL"},
                "imported": 0.0,
                # Exports are reported negative by some utilities; normalized to a magnitude.
                "exported": -5.3404,
            }
        ]
    }
    session = _FakeSession({"utilityAccounts": usage})

    result = await _pge(session).async_get_cost_reads(
        _elec_account(), AggregateType.HOUR, datetime(2026, 8, 31), datetime(2026, 8, 31), usage_only=True
    )

    assert (result[0].imported, result[0].exported) == (0.0, 5.3404)
    assert not [r for r in session.requests if "dsm-graphql-v1" in r["url"]]


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

    session = _FakeSession({"cost/utilityAccount": cost, "dsm-graphql-v1": _NO_REGISTERS_RESPONSE})
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
        "data": {
            "billingAccountsConnection": {
                "pageInfo": {"hasNextPage": False},
                "edges": [{"node": billing_account} for billing_account in billing_accounts],
            }
        }
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
            "pageInfo": {"hasNextPage": False},
            "edges": [
                {
                    "node": {
                        "uuid": service_agreement_uuid,
                        "utilityId": service_agreement_utility_id,
                        "serviceType": "ELECTRICITY",
                        "servicePointsConnection": {
                            "pageInfo": {"hasNextPage": False},
                            "edges": [
                                {
                                    "node": {
                                        "uuid": f"sp-{service_agreement_uuid}",
                                        "serviceType": "ELECTRICITY",
                                    }
                                }
                            ],
                        },
                    }
                }
            ],
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


def test_realtime_graphql_mapping_requires_service_agreement_identifier() -> None:
    """A billing-account match alone cannot identify a service agreement."""
    opower = _coned(_FakeSession({}))
    account = _realtime_account()
    topology = _realtime_topology(
        _realtime_billing_account(
            account.uuid,
            "unmatched-service-agreement",
            account_number=account.utility_account_id,
        )
    )

    assert opower._realtime_graphql_mappings(account, topology) == []


@pytest.mark.parametrize(
    ("connection_name", "page_info"),
    [
        ("billing_accounts", {"hasNextPage": True}),
        ("billing_accounts", None),
        ("service_agreements", {"hasNextPage": True}),
        ("service_agreements", None),
        ("service_points", {"hasNextPage": True}),
        ("service_points", None),
    ],
)
def test_realtime_graphql_mapping_requires_complete_connections(
    connection_name: str,
    page_info: dict[str, bool] | None,
) -> None:
    """A truncated or malformed topology cannot establish a safe mapping."""
    opower = _coned(_FakeSession({}))
    account = _realtime_account()
    topology = _realtime_topology(
        _realtime_billing_account(
            "selected-billing-account",
            "selected-service-agreement",
            service_agreement_utility_id=account.utility_account_id,
        )
    )
    billing_accounts = topology["data"]["billingAccountsConnection"]
    service_agreements = billing_accounts["edges"][0]["node"]["serviceAgreementsConnection"]
    service_points = service_agreements["edges"][0]["node"]["servicePointsConnection"]
    connection = {
        "billing_accounts": billing_accounts,
        "service_agreements": service_agreements,
        "service_points": service_points,
    }[connection_name]
    if page_info is None:
        connection.pop("pageInfo")
    else:
        connection["pageInfo"] = page_info

    assert opower._realtime_graphql_mappings(account, topology) == []


@pytest.mark.parametrize("duplicate_edge", ["service_agreement", "service_point"])
def test_realtime_graphql_mapping_ignores_duplicate_edges(
    duplicate_edge: str,
) -> None:
    """Duplicate edges for the same UUID do not make a mapping ambiguous."""
    opower = _coned(_FakeSession({}))
    account = _realtime_account()
    topology = _realtime_topology(
        _realtime_billing_account(
            "selected-billing-account",
            "selected-service-agreement",
            service_agreement_utility_id=account.utility_account_id,
        )
    )
    billing_account = topology["data"]["billingAccountsConnection"]["edges"][0]["node"]
    service_agreement_edges = billing_account["serviceAgreementsConnection"]["edges"]
    if duplicate_edge == "service_agreement":
        service_agreement_edges.append(service_agreement_edges[0])
    else:
        service_point_edges = service_agreement_edges[0]["node"]["servicePointsConnection"]["edges"]
        service_point_edges.append(service_point_edges[0])

    assert opower._realtime_graphql_mappings(account, topology) == [
        (
            "urn:opower:v1:account:cned:uuid:selected-billing-account",
            "selected-service-agreement",
            "sp-selected-service-agreement",
        )
    ]


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
            _realtime_billing_account(
                "billing-1",
                "service-agreement-1",
                service_agreement_utility_id=account.utility_account_id,
            ),
            _realtime_billing_account(
                "billing-2",
                "service-agreement-2",
                service_agreement_utility_id=account.utility_account_id,
            ),
        )

    monkeypatch.setattr(opower, "_async_post_graphql", fake_post_graphql)

    first = await opower.async_get_realtime_usage_reads(account)
    second = await opower.async_get_realtime_usage_reads(account)

    assert [read.consumption for read in first] == [0.4]
    assert second == first
    assert topology_calls == 1
    assert [request["method"] for request in session.requests] == ["GET", "GET", "GET"]


@pytest.mark.asyncio
async def test_realtime_discovery_is_not_disabled_by_an_empty_response(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """An empty topology body is a hiccup, not an account without a stream.

    Caching it would pin the utility to the legacy REST endpoint - the one that
    now returns 424 - until the next restart.
    """
    meters_response = {"meters_ids": ["KWH:NET_USAGE"]}
    rest_usage = {"reads": [{"startTime": "2026-09-01T10:00:00-04:00", "endTime": "2026-09-01T10:15:00-04:00", "value": 0.4}]}
    session = _FakeSession({"/meters/": rest_usage, "/meters": meters_response})
    opower = _coned(session)
    account = _realtime_account()
    calls = 0

    async def fake_post_graphql(
        query: str,
        headers: dict[str, str],
        variables: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        nonlocal calls
        del headers, variables
        calls += 1
        if calls == 1:
            return {"data": {"billingAccountsConnection": None}}
        if "WRTAMI_GetTopology" in query:
            return _realtime_topology(
                _realtime_billing_account(
                    "billing-1",
                    "service-agreement-1",
                    service_agreement_utility_id=account.utility_account_id,
                )
            )
        if "WRTAMI_GetRegisters" in query:
            return _realtime_registers("KWH:NET_USAGE")
        return _realtime_usage(
            {
                "timeInterval": "2026-09-01T14:00:00Z/2026-09-01T14:15:00Z",
                "measuredAmount": {"value": 0.25},
            }
        )

    monkeypatch.setattr(opower, "_async_post_graphql", fake_post_graphql)

    first = await opower.async_get_realtime_usage_reads(account)
    second = await opower.async_get_realtime_usage_reads(account)

    assert [read.consumption for read in first] == [0.4], "empty body falls back to REST"
    assert [read.consumption for read in second] == [0.25], "and must retry GraphQL next time"


@pytest.mark.asyncio
async def test_realtime_usage_reads_rediscover_after_the_mapping_changes(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A cached mapping that stops resolving is dropped, not retried forever."""
    meters_response = {"meters_ids": ["KWH:NET_USAGE"]}
    rest_usage = {"reads": [{"startTime": "2026-09-01T10:00:00-04:00", "endTime": "2026-09-01T10:15:00-04:00", "value": 0.4}]}
    session = _FakeSession({"/meters/": rest_usage, "/meters": meters_response})
    opower = _coned(session)
    account = _realtime_account()
    topology_calls = 0
    usage_calls = 0

    async def fake_post_graphql(
        query: str,
        headers: dict[str, str],
        variables: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        nonlocal topology_calls, usage_calls
        del headers, variables
        if "WRTAMI_GetTopology" in query:
            topology_calls += 1
            return _realtime_topology(
                _realtime_billing_account(
                    "billing-1",
                    "service-agreement-1",
                    service_agreement_utility_id=account.utility_account_id,
                )
            )
        if "WRTAMI_GetRegisters" in query:
            return _realtime_registers("KWH:NET_USAGE")
        usage_calls += 1
        if usage_calls == 1:
            # The register the mapping was built on has gone away.
            return {"data": {"billingAccountByAuthContext": {"serviceAgreementsConnection": {"edges": []}}}}
        return _realtime_usage(
            {
                "timeInterval": "2026-09-01T14:00:00Z/2026-09-01T14:15:00Z",
                "measuredAmount": {"value": 0.25},
            }
        )

    monkeypatch.setattr(opower, "_async_post_graphql", fake_post_graphql)

    first = await opower.async_get_realtime_usage_reads(account)
    second = await opower.async_get_realtime_usage_reads(account)

    assert [read.consumption for read in first] == [0.4], "a changed mapping falls back to REST"
    assert [read.consumption for read in second] == [0.25]
    assert topology_calls == 2, "the stale mapping must be rediscovered, not reused"


@pytest.mark.asyncio
async def test_realtime_usage_reads_skip_graphql_for_non_electric_meters(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """Both GraphQL queries ask for KWH, so a gas meter must not pay for them."""
    meters_response = {"meters_ids": ["THERM:NET_USAGE"]}
    rest_usage = {"reads": [{"startTime": "2026-09-01T10:00:00-04:00", "endTime": "2026-09-01T10:15:00-04:00", "value": 0.4}]}
    session = _FakeSession({"/meters/": rest_usage, "/meters": meters_response})
    opower = _coned(session)
    gas_account = dataclasses.replace(_realtime_account(), meter_type=MeterType.GAS)
    calls = 0

    async def fake_post_graphql(
        query: str,
        headers: dict[str, str],
        variables: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        nonlocal calls
        del query, headers, variables
        calls += 1
        return {}

    monkeypatch.setattr(opower, "_async_post_graphql", fake_post_graphql)

    result = await opower.async_get_realtime_usage_reads(gas_account)

    assert [read.consumption for read in result] == [0.4]
    assert calls == 0, "no GraphQL round trip for a meter the queries cannot serve"


@pytest.mark.asyncio
async def test_realtime_usage_reads_fall_back_on_an_unparsable_read(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A read that will not parse must fall back, not raise at the caller."""
    meters_response = {"meters_ids": ["KWH:NET_USAGE"]}
    rest_usage = {"reads": [{"startTime": "2026-09-01T10:00:00-04:00", "endTime": "2026-09-01T10:15:00-04:00", "value": 0.4}]}
    session = _FakeSession({"/meters/": rest_usage, "/meters": meters_response})
    opower = _coned(session)
    account = _realtime_account()

    async def fake_post_graphql(
        query: str,
        headers: dict[str, str],
        variables: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        del headers, variables
        if "WRTAMI_GetTopology" in query:
            return _realtime_topology(
                _realtime_billing_account(
                    "billing-1",
                    "service-agreement-1",
                    service_agreement_utility_id=account.utility_account_id,
                )
            )
        if "WRTAMI_GetRegisters" in query:
            return _realtime_registers("KWH:NET_USAGE")
        return _realtime_usage(
            {
                "timeInterval": "not-a-timestamp/also-not-a-timestamp",
                "measuredAmount": {"value": 0.25},
            }
        )

    monkeypatch.setattr(opower, "_async_post_graphql", fake_post_graphql)

    result = await opower.async_get_realtime_usage_reads(account)

    assert [read.consumption for read in result] == [0.4]


@pytest.mark.asyncio
async def test_realtime_usage_reads_select_net_usage_register(
    monkeypatch: pytest.MonkeyPatch,
) -> None:
    """A NET_USAGE register is selected from a net-metered register set."""
    opower = _coned(_FakeSession({}))
    account = _realtime_account()
    usage_variables: dict[str, Any] | None = None

    async def fake_post_graphql(
        query: str,
        headers: dict[str, str],
        variables: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        nonlocal usage_variables
        del headers
        if "WRTAMI_GetTopology" in query:
            return _realtime_topology(
                _realtime_billing_account(
                    "selected-billing-account",
                    "selected-service-agreement",
                    service_agreement_utility_id=account.utility_account_id,
                )
            )
        if "WRTAMI_GetRegisters" in query:
            return _realtime_registers(
                "KWH:DELIVERED",
                "KWH:RECEIVED",
                "KWH:NET_USAGE",
            )
        usage_variables = variables
        return _realtime_usage(
            {
                "timeInterval": "2026-09-01T10:00:00-04:00/2026-09-01T10:15:00-04:00",
                "measuredAmount": {"value": -0.4},
            }
        )

    monkeypatch.setattr(opower, "_async_post_graphql", fake_post_graphql)

    result = await opower.async_get_realtime_usage_reads(account)

    assert [read.consumption for read in result] == [-0.4]
    assert usage_variables is not None
    assert usage_variables["registerId"] == "KWH:NET_USAGE"


@pytest.mark.parametrize(
    "graphql_reads",
    [
        (),
        (
            {
                "timeInterval": "2026-09-01T10:00:00-04:00/2026-09-01T10:15:00-04:00",
                "measuredAmount": None,
            },
        ),
    ],
)
@pytest.mark.asyncio
async def test_realtime_usage_reads_return_empty_for_valid_no_data(
    monkeypatch: pytest.MonkeyPatch,
    graphql_reads: tuple[dict[str, Any], ...],
) -> None:
    """A valid empty or null-only GraphQL stream does not use REST fallback."""
    opower = _coned(_FakeSession({}))
    account = _realtime_account()

    async def fake_post_graphql(
        query: str,
        headers: dict[str, str],
        variables: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        del headers, variables
        if "WRTAMI_GetTopology" in query:
            return _realtime_topology(
                _realtime_billing_account(
                    "selected-billing-account",
                    "selected-service-agreement",
                    service_agreement_utility_id=account.utility_account_id,
                )
            )
        if "WRTAMI_GetRegisters" in query:
            return _realtime_registers("opaque-register")
        return _realtime_usage(*graphql_reads)

    monkeypatch.setattr(opower, "_async_post_graphql", fake_post_graphql)

    assert await opower.async_get_realtime_usage_reads(account) == []


@pytest.mark.parametrize(
    "register_ids",
    [
        ("opaque-register-1", "opaque-register-2"),
        ("KWH:DELIVERED",),
        ("KWH:RECEIVED",),
    ],
)
@pytest.mark.asyncio
async def test_realtime_usage_reads_fall_back_when_register_mapping_is_ambiguous(
    monkeypatch: pytest.MonkeyPatch,
    register_ids: tuple[str, ...],
) -> None:
    """Unidentified or directional GraphQL registers use compatibility REST."""
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
    account = _realtime_account()
    graphql_calls = 0

    async def fake_post_graphql(
        query: str,
        headers: dict[str, str],
        variables: dict[str, Any] | None = None,
    ) -> dict[str, Any]:
        nonlocal graphql_calls
        del headers, variables
        graphql_calls += 1
        if "WRTAMI_GetTopology" in query:
            return _realtime_topology(
                _realtime_billing_account(
                    "selected-billing-account",
                    "selected-service-agreement",
                    service_agreement_utility_id=account.utility_account_id,
                )
            )
        if "WRTAMI_GetRegisters" in query:
            return _realtime_registers(*register_ids)
        pytest.fail("GraphQL usage must not be queried for ambiguous registers")

    monkeypatch.setattr(opower, "_async_post_graphql", fake_post_graphql)

    first = await opower.async_get_realtime_usage_reads(account)
    second = await opower.async_get_realtime_usage_reads(account)

    assert [read.consumption for read in first] == [0.4]
    assert second == first
    assert graphql_calls == 2
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
