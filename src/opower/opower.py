"""Implementation of opower.com JSON API."""

import dataclasses
import json
import logging
from collections.abc import Iterator
from datetime import UTC, date, datetime, timedelta
from enum import Enum
from typing import Any
from urllib.parse import urlencode
from zoneinfo import ZoneInfo

import aiohttp
import aiozoneinfo
import arrow
from aiohttp.client_exceptions import ClientError, ClientResponseError

from .const import USER_AGENT
from .exceptions import ApiException, CannotConnect, InvalidAuth
from .utilities import UtilityBase

_LOGGER = logging.getLogger(__name__)


def _parse_read_time(value: str, tz: ZoneInfo) -> datetime:
    """Parse an ISO 8601 timestamp returned by the Opower API.

    Some utilities (e.g. City of Austin) return timestamps without a UTC
    offset. Consumers such as Home Assistant's recorder require timezone-aware
    timestamps for statistics, so assume the utility's local timezone when the
    parsed value is naive.
    """
    parsed = datetime.fromisoformat(value)
    if parsed.tzinfo is None:
        parsed = parsed.replace(tzinfo=tz)
    return parsed


class MeterType(Enum):
    """Meter type."""

    ELEC = "ELEC"
    GAS = "GAS"
    WATER = "WATER"

    def __str__(self) -> str:
        """Return the value of the enum."""
        return self.value


class UnitOfMeasure(Enum):
    """Unit of measure for the associated meter type. kWh for electricity or Therm/CCF for gas."""

    KWH = "KWH"
    THERM = "THERM"
    CCF = "CCF"

    def __str__(self) -> str:
        """Return the value of the enum."""
        return self.value


class AggregateType(Enum):
    """How to aggregate historical data."""

    BILL = "bill"
    DAY = "day"
    HOUR = "hour"
    HALF_HOUR = "half_hour"
    QUARTER_HOUR = "quarter_hour"

    def __str__(self) -> str:
        """Return the value of the enum."""
        return self.value


class ReadResolution(Enum):
    """Minimum supported resolution."""

    BILLING = "BILLING"
    DAY = "DAY"
    HOUR = "HOUR"
    HALF_HOUR = "HALF_HOUR"
    QUARTER_HOUR = "QUARTER_HOUR"
    FIVE_MINUTE = "FIVE_MINUTE"

    def __str__(self) -> str:
        """Return the value of the enum."""
        return self.value


SUPPORTED_AGGREGATE_TYPES = {
    ReadResolution.BILLING: [AggregateType.BILL],
    ReadResolution.DAY: [AggregateType.BILL, AggregateType.DAY],
    ReadResolution.HOUR: [AggregateType.BILL, AggregateType.DAY, AggregateType.HOUR],
    ReadResolution.HALF_HOUR: [
        AggregateType.BILL,
        AggregateType.DAY,
        AggregateType.HOUR,
        AggregateType.HALF_HOUR,
    ],
    ReadResolution.QUARTER_HOUR: [
        AggregateType.BILL,
        AggregateType.DAY,
        AggregateType.HOUR,
        AggregateType.HALF_HOUR,
        AggregateType.QUARTER_HOUR,
    ],
    ReadResolution.FIVE_MINUTE: [
        AggregateType.BILL,
        AggregateType.DAY,
        AggregateType.HOUR,
        AggregateType.HALF_HOUR,
        AggregateType.QUARTER_HOUR,
    ],
}


_DSS_SERVICE_TYPE_TO_METER = {
    "ELECTRICITY": "ELEC",
    "ELECTRIC": "ELEC",
    "ELEC": "ELEC",
    "ELECTRICITY_NET_METERING": "ELEC",
    "SOLAR": "ELEC",
    "SOLAR_PV": "ELEC",
    "RESIDENTIAL_ELECTRIC": "ELEC",
    "COMMERCIAL_ELECTRIC": "ELEC",
    "NATURAL_GAS": "GAS",
    "GAS": "GAS",
    "WATER": "WATER",
    "WASTE_WATER": "WATER",
    "WASTEWATER": "WATER",
    "WASTEWATER_SERVICE": "WATER",
    "RESIDENTIAL_WATER": "WATER",
    "COMMERCIAL_WATER": "WATER",
    "IRRIGATION": "WATER",
    "RECLAIMED_WATER": "WATER",
}


def _get_value(data: dict[str, Any] | None, key: str = "value", default: float = 0) -> float:
    """Extract `key` from a dict, returning default if missing or None."""
    val = (data or {}).get(key)
    return float(val) if val is not None else default


def _abs_or_none(value: Any) -> float | None:
    """Normalize a directional quantity to a positive magnitude.

    Utilities are inconsistent about whether energy sent to the grid is reported as
    a positive or a negative number. `imported` and `exported` name their direction,
    so both are always positive and a caller can add them without checking signs.
    """
    return abs(float(value)) if value is not None else None


# Interval reads carry one stream per meter register. A register is identified as
# "<unit>:<serviceQuantityIdentifier>", e.g. "KWH:DELIVERED". DELIVERED is energy
# the grid delivered to the customer (import) and RECEIVED is energy the grid
# received from the customer (export).
_IMPORTED_SQI = "DELIVERED"
_EXPORTED_SQI = "RECEIVED"

# Read streams are named by direction rather than by register id.
_IMPORTED_STREAM = "energyDelivered"
_EXPORTED_STREAM = "energyReceived"

# Opower caps how much a single request may cover, and the cap depends on the
# resolution asked for: "Provided range must be no more than 720 hours." for the
# sub-daily resolutions, "Provided range must be no more than 365 days." for daily.
# Both are absolute durations, so a local calendar chunk is the wrong unit - a DST
# fall-back day is 25 hours long. The window's start is inclusive and its end
# exclusive; a start that is not on a read boundary rounds up to the next one.
_READ_RESOLUTIONS: dict[AggregateType, tuple[str, timedelta]] = {
    AggregateType.DAY: ("DAY", timedelta(days=365)),
    AggregateType.HOUR: ("HOUR", timedelta(hours=720)),
    AggregateType.HALF_HOUR: ("HALF_HOUR", timedelta(hours=720)),
    AggregateType.QUARTER_HOUR: ("QUARTER_HOUR", timedelta(hours=720)),
}

_REGISTER_METADATA_QUERY = """
query OpowerRegisters($customerUrn: ID) {
  billingAccountByAuthContext(singlePremise: $customerUrn) {
    serviceAgreementsConnection(first: 25, onlyActive: true) {
      edges { node { utilityId serviceType
        servicePointsConnection(first: 25) { edges { node { uuid
          registers { serviceQuantityIdentifier unitOfMeasure availableReadsTimeInterval }
        } } }
      } }
    }
  }
}
"""

# `readStreams`, not `intervalReads`.
#
# `intervalReads` looks like the field to use, but it is the one the utility's own
# web app never calls, and it behaves badly. It caps a request at 24 absolute hours,
# which makes a DST fall-back day impossible to ask for in one piece, and it returns
# nulls for the few hours around either transition. `readStreams` takes the
# resolution as an argument, serves 30 days of hourly - or a year of daily - per
# request, and returns 23- and 25-read days across the transitions with no nulls.
#
# Do not batch several windows into one request by aliasing the field. The server
# does not isolate arguments per alias: every alias comes back with the same payload,
# and the registers within it are drawn from a mix of the requested windows.
_REGISTER_READS_QUERY = """
query OpowerRegisterReads($customerUrn: ID, $spUuid: String, $timeInterval: TimeInterval, $resolution: ReadResolution) {
  billingAccountByAuthContext(singlePremise: $customerUrn) {
    serviceAgreementsConnection(onlyActive: true) {
      edges { node {
        servicePointsConnection(matching: $spUuid) { edges { node {
          readStreams(timeInterval: $timeInterval, readResolution: $resolution) {
            energyDelivered { reads { timeInterval measuredAmount { value } } }
            energyReceived { reads { timeInterval measuredAmount { value } } }
          }
        } } }
      } }
    }
  }
}
"""


# Distinguishes "not probed yet" from a cached "this account has no registers".
_UNPROBED = object()


@dataclasses.dataclass
class _RegisterStreams:
    """A service point that publishes separate import and export registers.

    `available_start`/`available_end` bound the range the utility will serve.
    Requesting outside it returns nothing, so clamping to it is an optimization: it
    keeps a first run from asking for the years before the meter existed.

    `available_end` moves: PG&E's sits around the previous midnight. It is therefore
    re-read on every call rather than cached with the service point. A stale end is
    not a wasted-request problem, it is a correctness one - it clamps away the newest
    hours, which are exactly the ones the caller is asking about, and after about a
    month of uptime it excludes everything.
    """

    service_point_uuid: str
    available_start: datetime | None
    available_end: datetime | None


def _parse_time_interval(value: str | None) -> tuple[datetime | None, datetime | None]:
    """Parse an ISO 8601 "<start>/<end>" interval into aware UTC datetimes."""
    if not value or "/" not in value:
        return None, None
    start_str, end_str = value.split("/", 1)
    try:
        start = datetime.fromisoformat(start_str.replace("Z", "+00:00"))
        end = datetime.fromisoformat(end_str.replace("Z", "+00:00"))
    except ValueError:
        return None, None
    if start.tzinfo is None or end.tzinfo is None:
        return None, None
    return start.astimezone(UTC), end.astimezone(UTC)


def _iter_register_reads(result: Any) -> Iterator[tuple[str, datetime, datetime, float | None]]:
    """Yield (stream name, start, end, value) from a read streams response."""
    billing_account = (result.get("data") or {}).get("billingAccountByAuthContext") or {}
    for agreement in (billing_account.get("serviceAgreementsConnection") or {}).get("edges") or []:
        node = agreement.get("node") or {}
        for point in (node.get("servicePointsConnection") or {}).get("edges") or []:
            streams = (point.get("node") or {}).get("readStreams") or {}
            for name in (_IMPORTED_STREAM, _EXPORTED_STREAM):
                # One entry per register behind the direction. It is a list even
                # when, as everywhere seen so far, there is exactly one register.
                entries = streams.get(name) or []
                if isinstance(entries, dict):
                    entries = [entries]
                for entry in entries:
                    for read in (entry or {}).get("reads") or []:
                        start, end = _parse_time_interval(read.get("timeInterval"))
                        if start is None or end is None:
                            continue
                        measured = read.get("measuredAmount")
                        yield name, start, end, measured.get("value") if measured else None


@dataclasses.dataclass
class Customer:
    """Data about a customer."""

    uuid: str


@dataclasses.dataclass
class Account:
    """Data about an account."""

    customer: Customer
    uuid: str
    utility_account_id: str
    # utility_account_id if unique or uuid
    # https://github.com/home-assistant/core/issues/108260
    id: str
    meter_type: MeterType
    read_resolution: ReadResolution | None


@dataclasses.dataclass
class Forecast:
    """Forecast data for an account."""

    account: Account
    start_date: date
    end_date: date
    current_date: date
    unit_of_measure: UnitOfMeasure
    usage_to_date: float
    cost_to_date: float
    forecasted_usage: float
    forecasted_cost: float
    typical_usage: float
    typical_cost: float


@dataclasses.dataclass
class ReadComponent:
    """A per-rate-period component of a cost read.

    Utilities on time-of-use rates return one component per TOU period
    (e.g. on-peak/off-peak) and utilities on tiered rates return one
    component per tier. Not all utilities return components.
    """

    tier_type: str | None  # e.g. "ORDINAL"
    tier_number: int | None  # populated for tiered rates
    season: str | None  # e.g. "SUMMER"
    day_part: str | None  # e.g. "ON_PEAK+RT02/TOD"; TOU period is before the "+"
    cost: float  # in $
    consumption: float  # taken from value field, in KWH or THERM/CCF


@dataclasses.dataclass
class CostRead:
    """A read from the meter that has both consumption and cost data."""

    start_time: datetime
    end_time: datetime
    consumption: float  # taken from value field, in KWH or THERM/CCF
    provided_cost: float  # in $
    read_components: list[ReadComponent] = dataclasses.field(default_factory=list)
    # Gross energy taken from and delivered to the grid during the interval, for
    # meters that expose a separate register per direction. `consumption` is the
    # net of the two. On a net-metered (solar) site the net hides any import that
    # happens inside an interval that is net-export, so when these are populated
    # they are strictly more accurate than splitting `consumption` on its sign.
    # None when the utility does not publish the split.
    imported: float | None = None  # in KWH or THERM/CCF
    exported: float | None = None  # in KWH or THERM/CCF


@dataclasses.dataclass
class UsageRead:
    """A read from the meter that has consumption data."""

    start_time: datetime
    end_time: datetime
    consumption: float  # taken from consumption.value field, in KWH or THERM/CCF
    # See CostRead.imported / CostRead.exported.
    imported: float | None = None  # in KWH or THERM/CCF
    exported: float | None = None  # in KWH or THERM/CCF


@dataclasses.dataclass(frozen=True)
class _RealtimeGraphQLMetadata:
    """Identifiers needed to query one account's realtime GraphQL reads."""

    selected_account: str
    service_agreement_uuid: str
    service_point_uuid: str
    register_id: str


def get_supported_utilities() -> list[type["UtilityBase"]]:
    """Return a list of all supported utilities."""
    return UtilityBase.subclasses


def get_supported_utility_names() -> list[str]:
    """Return a sorted list of names of all supported utilities."""
    return sorted([utility.name() for utility in UtilityBase.subclasses])


def select_utility(name: str) -> type[UtilityBase]:
    """Return the utility with the given name."""
    for utility in UtilityBase.subclasses:
        if name.lower() in [utility.name().lower(), utility.__name__.lower()]:
            return utility
    raise ValueError(f"Utility {name} not found")


class Opower:
    """Class that can get historical and forecasted usage/cost from an utility."""

    def __init__(
        self,
        session: aiohttp.ClientSession,
        utility: str,
        username: str,
        password: str,
        optional_totp_secret: str | None = None,
        login_data: dict[str, Any] | None = None,
    ) -> None:
        """Initialize."""
        # Note: Do not modify default headers since Home Assistant that uses this library needs to use
        # a default session for all integrations. Instead specify the headers for each request.
        self._session: aiohttp.ClientSession = session
        self.utility: UtilityBase = select_utility(utility)()
        self._username: str = username
        self._password: str = password
        self._optional_totp_secret: str | None = optional_totp_secret
        if self.utility.accepts_totp_secret() and self._optional_totp_secret:
            self.utility.set_totp_secret(self._optional_totp_secret.strip())
        self._login_data: dict[str, Any] = login_data or {}
        self._access_token: str | None = None
        self._customers: list[Any] = []
        self._user_accounts: list[Any] = []
        # Keyed by account uuid: meters are fetched per account, so a single
        # list would serve one account's meters for every other account.
        self._meters: dict[str, list[str]] = {}
        self._realtime_graphql_metadata: dict[tuple[str, str, str, str], _RealtimeGraphQLMetadata | None] = {}
        # Keyed by account uuid. None means "probed, this account has no separate
        # import/export registers", so we only ever probe once per account.
        self._register_streams: dict[str, _RegisterStreams | None] = {}

    async def async_login(self) -> None:
        """Login to the utility website and authorize opower.com for access.

        :raises InvalidAuth: if login information is incorrect
        :raises MfaChallenge: if interactive MFA is required
        :raises CannotConnect: if we receive any HTTP error
        """
        try:
            self._access_token = await self.utility.async_login(
                self._session, self._username, self._password, self._login_data
            )
        except ClientResponseError as err:
            if err.status in (401, 403):
                raise InvalidAuth(err) from err
            raise CannotConnect(err) from err
        except ClientError as err:
            raise CannotConnect(err) from err

    async def async_get_accounts(self) -> list[Account]:
        """Get a list of accounts for the signed in user.

        Typically one account for electricity and one for gas.
        """
        accounts: list[Account] = []
        for customer in await self._async_get_customers():
            utility_accounts: list[Any] = []
            utility_account_ids: list[str] = []
            for account in customer["utilityAccounts"]:
                utility_accounts.append(account)
                utility_account_ids.append(account["preferredUtilityAccountId"])
            for account in utility_accounts:
                utility_account_id = account["preferredUtilityAccountId"]
                account_uuid = account["uuid"]
                account_id = utility_account_id if utility_account_ids.count(utility_account_id) == 1 else account_uuid
                accounts.append(
                    Account(
                        customer=Customer(uuid=customer["uuid"]),
                        uuid=account_uuid,
                        utility_account_id=utility_account_id,
                        id=account_id,
                        meter_type=MeterType(account["meterType"]),
                        read_resolution=ReadResolution(account["readResolution"]),
                    )
                )
        return accounts

    async def async_get_forecast(self) -> list[Forecast]:
        """Get current and forecasted usage and cost for the current monthly bill.

        One forecast for each account, typically one for electricity, one for gas.
        """
        # Fetch all accounts first to create a lookup map (UUID -> Account).
        # This ensures we use the exact same IDs/MeterTypes as the rest of the library.
        accounts = await self.async_get_accounts()
        account_map = {account.uuid: account for account in accounts}

        forecasts: list[Forecast] = []

        # GraphQL query to fetch bill forecast data
        query = """
        query GetBillForecast {
          billingAccountsConnection(first: 100) {
            edges {
              node {
                billForecast {
                  timeInterval
                  currentDateTime
                  segments {
                    serviceAgreement {
                      uuid
                    }
                    estimatedUsage { value, unit }
                    estimatedUsageCharges { value }
                    soFarUsage { value }
                    soFarUsageCharges { value }
                    priorYearUsage { value }
                    priorYearUsageCharges { value }
                  }
                }
              }
            }
          }
        }
        """

        for customer in await self._async_get_customers():
            customer_uuid = customer["uuid"]
            headers = self._get_headers(customer_uuid)

            try:
                result = await self._async_post_graphql(query, headers)
            except ApiException as err:
                _LOGGER.debug("Ignoring GraphQL bill forecast error: %s", err)
                continue

            edges = result.get("data", {}).get("billingAccountsConnection", {}).get("edges", [])

            for edge in edges:
                bill_forecast = edge.get("node", {}).get("billForecast")
                if not bill_forecast:
                    _LOGGER.debug("No bill forecast for billing account")
                    continue

                # Parse time interval (ISO 8601 format: "start/end")
                time_interval = bill_forecast.get("timeInterval", "")
                if "/" not in time_interval:
                    _LOGGER.debug("Invalid time interval format: %s", time_interval)
                    continue

                start_str, end_str = time_interval.split("/", 1)
                # Parse ISO 8601 datetime strings, extracting just the date portion
                start_date = datetime.fromisoformat(start_str).date()
                end_date = datetime.fromisoformat(end_str).date()
                current_date = datetime.fromisoformat(bill_forecast.get("currentDateTime", start_str)).date()

                for segment in bill_forecast.get("segments", []):
                    service_agreement: dict[str, Any] = segment.get("serviceAgreement") or {}
                    account_uuid = str(service_agreement.get("uuid", ""))

                    # Match the GraphQL data to an existing Account
                    account = account_map.get(account_uuid)
                    if not account:
                        _LOGGER.debug("Forecast found for unknown account UUID: %s", account_uuid)
                        continue

                    estimated_usage: dict[str, Any] = segment.get("estimatedUsage") or {}
                    unit_val = estimated_usage.get("unit")
                    default_unit = UnitOfMeasure.THERM if account.meter_type == MeterType.GAS else UnitOfMeasure.KWH
                    if not unit_val:
                        _LOGGER.warning("Missing unit of measure, defaulting to %s", default_unit)
                        unit_of_measure = default_unit
                    else:
                        unit_str = str(unit_val)
                        if unit_str == "TH":
                            unit_str = "THERM"
                        try:
                            unit_of_measure = UnitOfMeasure(unit_str)
                        except ValueError:
                            _LOGGER.warning("Unknown unit of measure: %s, defaulting to %s", unit_str, default_unit)
                            unit_of_measure = default_unit

                    forecasts.append(
                        Forecast(
                            account=account,
                            start_date=start_date,
                            end_date=end_date,
                            current_date=current_date,
                            unit_of_measure=unit_of_measure,
                            usage_to_date=_get_value(segment.get("soFarUsage")),
                            cost_to_date=_get_value(segment.get("soFarUsageCharges")),
                            forecasted_usage=_get_value(segment.get("estimatedUsage")),
                            forecasted_cost=_get_value(segment.get("estimatedUsageCharges")),
                            typical_usage=_get_value(segment.get("priorYearUsage")),
                            typical_cost=_get_value(segment.get("priorYearUsageCharges")),
                        )
                    )
        return forecasts

    async def _async_get_customers(self) -> list[Any]:
        """Get customers associated to the user."""
        # Cache the customers
        if not self._customers:
            if self.utility.is_dss() and not self._user_accounts:
                await self._async_get_user_accounts()

            try:
                self._customers.extend(await self._async_fetch_multi_account_customers())
            except ApiException as err:
                if self.utility.is_dss():
                    _LOGGER.debug(
                        "Failed to fetch customers from multi-account-v1, falling back to service agreements: %s",
                        err,
                    )
                    self._customers = []
                    await self._async_get_dss_customers()
                else:
                    raise

        if not self._customers:
            raise CannotConnect(f"No utility customers found for {self.utility.name()}")
        return self._customers

    async def _async_fetch_multi_account_customers(self) -> list[Any]:
        """Fetch customers from the multi-account-v1 endpoint.

        :raises ApiException: if the request fails or the response has no
            "customers" key, so that DSS callers can fall back.
        """
        url = (
            f"https://{self._get_subdomain()}.opower.com/{self._get_api_root()}"
            f"/edge/apis/multi-account-v1/cws/{self.utility.utilitycode()}"
            "/customers?offset=0&batchSize=100&addressFilter="
        )
        result = await self._async_get_request(url, {}, self._get_headers())
        if "customers" not in result:
            raise ApiException("No 'customers' in the multi-account-v1 response", url=url)
        return list(result["customers"])

    async def _async_get_dss_customers(self) -> None:
        """Populate self._customers for DSS utilities via service agreements.

        DSS portals expose service/meter data through bill-trends-v1 rather than
        the multi-account-v1/customers endpoint. We fetch service agreements,
        map their service types to MeterType values, and construct synthetic
        customer records that the rest of the library can consume.
        """
        if not self._user_accounts:
            await self._async_get_user_accounts()

        account_id = self._get_account_id()

        # Use the webUserId stored during login as the customer UUID (it is the
        # only UUID-format identifier the identity-management API exposes via
        # Bearer token auth). Fall back to accountId if unavailable.
        customer_uuid: str = self.utility.customer_uuid() or account_id

        sa_url = (
            f"https://{self._get_subdomain()}.opower.com/{self._get_api_root()}/edge/apis/bill-trends-v1/cws/serviceAgreements"
        )
        sa_result = await self._async_get_request(sa_url, {}, self._get_headers())

        utility_accounts: list[Any] = []
        for sa in sa_result.get("serviceAgreements", []):
            service_type = sa.get("serviceType", "")
            meter_type = _DSS_SERVICE_TYPE_TO_METER.get(service_type)
            if meter_type is None:
                _LOGGER.debug("Skipping unknown DSS serviceType %r (saId=%s)", service_type, sa.get("saId"))
                continue
            utility_accounts.append(
                {
                    "uuid": sa["saId"],
                    "preferredUtilityAccountId": account_id,
                    "meterType": meter_type,
                    "readResolution": "DAY",
                }
            )

        if utility_accounts:
            self._customers.append({"uuid": customer_uuid, "utilityAccounts": utility_accounts})

        if not self._customers:
            _LOGGER.warning(
                "No utility customers found for %s. This may indicate that the "
                "service agreements endpoint returned unrecognized service types. "
                "Check debug logs for 'Skipping unknown DSS serviceType' entries.",
                self.utility.name(),
            )

    async def _async_get_user_accounts(self) -> list[Any]:
        """Get accounts associated to the user."""
        # Cache the accounts
        if not self._user_accounts:
            url = (
                "https://"
                f"{self._get_subdomain()}"
                ".opower.com/"
                f"{self._get_api_root()}"
                "/edge/apis/dss-invite-v1/cws/v1/utilities/connectedaccounts?"
                "pageOffset=0&pageLimit=100"
            )
            result = await self._async_get_request(url, {}, self._get_headers())
            for account in result["accounts"]:
                self._user_accounts.append(account)

        if not self._user_accounts:
            raise CannotConnect(f"No user accounts found for {self.utility.name()}")
        return self._user_accounts

    async def async_get_cost_reads(
        self,
        account: Account,
        aggregate_type: AggregateType,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        usage_only: bool = False,
    ) -> list[CostRead]:
        """Get usage and cost data for the selected account in the given date range aggregated by bill/day/hour.

        The resolution for gas is typically 'day' while for electricity it's hour or quarter hour.
        Opower typically keeps historical cost data for 3 years.
        """
        try:
            reads = await self._async_get_dated_data(account, aggregate_type, start_date, end_date, usage_only)
        except ApiException:
            # Some utilities (e.g. ConEd) return HTTP 500 from the cost endpoint
            # for daily/hourly aggregation. Fall back to usage-only reads.
            if aggregate_type != AggregateType.BILL and not usage_only:
                _LOGGER.debug("Cost endpoint failed. Falling back to just usage data.")
                return await self.async_get_cost_reads(account, aggregate_type, start_date, end_date, usage_only=True)
            raise
        tz = await aiozoneinfo.async_get_time_zone(self.utility.timezone())
        result: list[CostRead] = []
        for read in reads:
            result.append(
                CostRead(
                    start_time=_parse_read_time(read["startTime"], tz),
                    end_time=_parse_read_time(read["endTime"], tz),
                    consumption=(read["value"] if "value" in read else read["consumption"]["value"]),
                    provided_cost=read.get("providedCost", 0) or 0,
                    read_components=[
                        ReadComponent(
                            tier_type=component.get("tierType"),
                            tier_number=component.get("tierNumber"),
                            season=component.get("season"),
                            day_part=component.get("dayPart"),
                            cost=_get_value(component, key="cost"),
                            consumption=_get_value(component),
                        )
                        for component in read.get("readComponents") or []
                    ],
                    imported=_abs_or_none(read.get("imported")),
                    exported=_abs_or_none(read.get("exported")),
                )
            )
        # Remove last entries with 0 values
        while result:
            last = result.pop()
            if last.provided_cost != 0 or last.consumption != 0:
                result.append(last)
                break
        # Some utilities provide usage at hourly/daily resolution but only provide cost at bill resolution.
        # They don't return any data when hitting the cost endpoint so try again with the usage only endpoint.
        if aggregate_type != AggregateType.BILL and not result and not usage_only:
            _LOGGER.debug("Got no usage/cost data. Falling back to just usage data.")
            return await self.async_get_cost_reads(account, aggregate_type, start_date, end_date, usage_only=True)
        await self._async_add_import_export(account, aggregate_type, result)
        return result

    async def async_get_usage_reads(
        self,
        account: Account,
        aggregate_type: AggregateType,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> list[UsageRead]:
        """Get usage data for the selected account in the given date range aggregated by bill/day/hour.

        The resolution for gas is typically 'day' while for electricity it's hour or quarter hour.
        Opower typically keeps historical usage data for a bit over 3 years.
        """
        reads = await self._async_get_dated_data(account, aggregate_type, start_date, end_date, usage_only=True)
        tz = await aiozoneinfo.async_get_time_zone(self.utility.timezone())
        result: list[UsageRead] = []
        for read in reads:
            result.append(
                UsageRead(
                    start_time=_parse_read_time(read["startTime"], tz),
                    end_time=_parse_read_time(read["endTime"], tz),
                    consumption=read["consumption"]["value"],
                    imported=_abs_or_none(read.get("imported")),
                    exported=_abs_or_none(read.get("exported")),
                )
            )
        await self._async_add_import_export(account, aggregate_type, result)
        return result

    async def _async_get_register_streams(self, account: Account) -> "_RegisterStreams | None":
        """Find the service point that publishes separate import/export registers.

        Returns None when the account has no such registers: a site without
        generation only ever has a net register, and utilities other than the ones
        exposing dsm-graphql-v1 have none at all. That answer is cached for the life
        of the session, so those accounts pay one GraphQL request and no more. A
        newly interconnected system is therefore picked up on the next restart.

        Accounts that DO have registers are re-probed on every call, because the
        available range moves - PG&E's end sits around the previous midnight - and a
        stale end silently excludes the newest hours, which are exactly the ones the
        caller is asking about.

        This is the meter's `registers` view while the reads come from `readStreams`,
        and the two are assumed to agree about which directions exist and over what
        range. They do on PG&E. A utility that described a register here but served
        no matching stream would pass the probe and then return nothing from every
        window: wasted requests, but never wrong values.
        """
        cached = self._register_streams.get(account.uuid, _UNPROBED)
        if cached is None:
            return None
        headers = self._get_headers(account.customer.uuid)
        customer_urn = f"urn:opower:customer:uuid:{account.customer.uuid}"
        try:
            result = await self._async_post_graphql(_REGISTER_METADATA_QUERY, headers, {"customerUrn": customer_urn})
        except ApiException as err:
            # Only cache "no registers" for an answer that is structural. A 4xx means
            # the endpoint is absent or not authorized for this utility and will stay
            # that way; a 5xx or a connection error is transient and must not disable
            # the split for the rest of the session.
            if err.status is not None and 400 <= err.status < 500:
                self._register_streams[account.uuid] = None
            _LOGGER.debug("Could not read interval registers for %s: %s", account.utility_account_id, err)
            return None
        billing_account = (result.get("data") or {}).get("billingAccountByAuthContext") or {}
        agreements = (billing_account.get("serviceAgreementsConnection") or {}).get("edges") or []
        for agreement in agreements:
            node = agreement.get("node") or {}
            # A customer can hold several service agreements (e.g. electric and
            # gas). The GraphQL serviceAgreement utilityId is the same identifier
            # the REST API calls utility_account_id, so match on it rather than
            # assuming the first agreement is the right one.
            if str(node.get("utilityId") or "") != str(account.utility_account_id):
                continue
            for point in (node.get("servicePointsConnection") or {}).get("edges") or []:
                point_node = point.get("node") or {}
                registers = point_node.get("registers") or []
                identifiers = {r.get("serviceQuantityIdentifier") for r in registers}
                if not {_IMPORTED_SQI, _EXPORTED_SQI} <= identifiers:
                    continue
                start, end = _parse_time_interval(
                    next(
                        (
                            r.get("availableReadsTimeInterval")
                            for r in registers
                            if r.get("serviceQuantityIdentifier") == _IMPORTED_SQI
                        ),
                        None,
                    )
                )
                streams = _RegisterStreams(
                    service_point_uuid=point_node["uuid"],
                    available_start=start,
                    available_end=end,
                )
                _LOGGER.debug(
                    "Account %s publishes import/export registers on service point %s (%s..%s)",
                    account.utility_account_id,
                    streams.service_point_uuid,
                    start,
                    end,
                )
                self._register_streams[account.uuid] = streams
                return streams
        _LOGGER.debug("Account %s has no import/export registers", account.utility_account_id)
        # Only remember that when the response actually described the account. An
        # empty body is more likely a server hiccup than a meter without registers,
        # and caching it would disable the split until the next restart.
        if agreements:
            self._register_streams[account.uuid] = None
        return None

    async def async_get_interval_register_reads(
        self,
        account: Account,
        aggregate_type: AggregateType,
        start_date: datetime,
        end_date: datetime,
    ) -> dict[tuple[float, float], tuple[float | None, float | None]]:
        """Get gross import/export per interval, keyed by (start, end) POSIX timestamps.

        Only meters that publish a separate register per direction return anything;
        everything else returns an empty dict, as does a bill-level aggregation,
        which the read streams do not serve.

        Reads are keyed by POSIX timestamps rather than datetimes on purpose: on a
        DST fall-back day the repeated local hour produces two datetimes that compare
        equal under PEP 495, which would silently collapse the two reads into one.
        The end is part of the key so a caller cannot attach an hour's worth of
        import/export to a read covering a different span.
        """
        resolution = _READ_RESOLUTIONS.get(aggregate_type)
        if resolution is None:
            return {}
        read_resolution, max_window = resolution
        streams = await self._async_get_register_streams(account)
        if streams is None:
            return {}
        tz = await aiozoneinfo.async_get_time_zone(self.utility.timezone())
        start = start_date.astimezone(UTC)
        end = end_date.astimezone(UTC)
        # Skip the part of the range the utility will not serve. A request outside it
        # returns nothing rather than failing, so this only saves requests - notably
        # the years before the meter existed on a first run.
        if streams.available_start:
            start = max(start, streams.available_start)
        if streams.available_end:
            end = min(end, streams.available_end)
        if start >= end:
            return {}

        # Walk the range in absolute windows no larger than the resolution's cap.
        # Chunking by local calendar unit would break on DST fall-back days, which
        # are 25 hours long and can push a chunk over the cap.
        windows: list[tuple[datetime, datetime]] = []
        window_start = start
        while window_start < end:
            window_end = min(end, window_start + max_window)
            windows.append((window_start, window_end))
            window_start = window_end

        reads: dict[tuple[float, float], tuple[float | None, float | None]] = {}
        for window in windows:
            await self._async_fetch_register_window(account, streams, read_resolution, window, tz, reads)
        return reads

    async def _async_fetch_register_window(
        self,
        account: Account,
        streams: "_RegisterStreams",
        read_resolution: str,
        window: tuple[datetime, datetime],
        tz: ZoneInfo,
        reads: dict[tuple[float, float], tuple[float | None, float | None]],
    ) -> None:
        """Fetch one window of read streams and merge its registers into `reads`."""
        window_start, window_end = window
        time_interval = f"{window_start.astimezone(tz).isoformat()}/{window_end.astimezone(tz).isoformat()}"
        try:
            result = await self._async_post_graphql(
                _REGISTER_READS_QUERY,
                self._get_headers(account.customer.uuid),
                {
                    "customerUrn": f"urn:opower:customer:uuid:{account.customer.uuid}",
                    "spUuid": streams.service_point_uuid,
                    "timeInterval": time_interval,
                    "resolution": read_resolution,
                },
            )
        except ApiException as err:
            # One failed window must not cost the others, so this is swallowed here
            # rather than at the top of the walk. The caller keeps the net.
            _LOGGER.debug("No register reads for %s at %s: %s", time_interval, read_resolution, err)
            return
        for stream_name, interval_start, interval_end, value in _iter_register_reads(result):
            key = (interval_start.timestamp(), interval_end.timestamp())
            imported, exported = reads.get(key, (None, None))
            if stream_name == _IMPORTED_STREAM:
                imported = _abs_or_none(value)
            elif stream_name == _EXPORTED_STREAM:
                exported = _abs_or_none(value)
            else:
                continue
            reads[key] = (imported, exported)

    async def _async_add_import_export(
        self,
        account: Account,
        aggregate_type: AggregateType,
        reads: list[CostRead] | list[UsageRead],
    ) -> None:
        """Populate imported/exported on interval reads from the per-register streams.

        This never replaces anything the endpoint already returned, and never
        raises: the import/export split is an enrichment on top of data that is
        already complete and correct on its own.

        Every aggregation but bill: the read streams take the resolution as an
        argument and return the registers already aggregated to it, so a daily read
        is enriched as cheaply as an hourly one. That matters most at daily
        resolution, where netting hides nearly all of a solar site's grid import.
        """
        if aggregate_type not in _READ_RESOLUTIONS:
            return
        # Both fields, not just `imported`: a utility that publishes one without the
        # other has not given the caller a usable split, so the registers are still
        # worth asking for.
        if not reads or all(read.imported is not None and read.exported is not None for read in reads):
            return
        try:
            register_reads = await self.async_get_interval_register_reads(
                account,
                aggregate_type,
                min(read.start_time for read in reads),
                max(read.end_time for read in reads),
            )
        except Exception as err:
            # Deliberately everything, not just ApiException. This is optional
            # garnish on reads that are already complete, so no failure of it may
            # reach the caller - including a response shaped differently by some
            # other utility, which would otherwise surface as an AttributeError
            # from the parser and fail every cost read for that user. The public
            # async_get_interval_register_reads still raises for direct callers.
            _LOGGER.debug("Skipping import/export split: %s", err)
            return
        if not register_reads:
            return
        matched = 0
        for read in reads:
            if read.imported is not None and read.exported is not None:
                continue
            # Keyed on both bounds: a register read only describes this read if it
            # covers exactly the same span, otherwise a whole hour's import could be
            # attached to a read covering part of it.
            imported, exported = register_reads.get((read.start_time.timestamp(), read.end_time.timestamp()), (None, None))
            if imported is None or exported is None:
                continue
            read.imported = imported
            read.exported = exported
            matched += 1
        _LOGGER.debug("Added import/export split to %d of %d reads", matched, len(reads))

    async def _async_get_meters(self, account: Account) -> list[str]:
        """Get the list of meters for the selected account.

        Each meter is a string key for fetching from the realtime data API.
        """
        if account.uuid not in self._meters:
            url = (
                f"https://{self._get_subdomain()}.opower.com/{self._get_api_root()}"
                f"/edge/apis/cws-real-time-ami-v1/cws/{self.utility.utilitycode()}"
                f"/accounts/{account.uuid}/meters"
            )
            headers = self._get_headers(account.customer.uuid)
            result = await self._async_get_request(url, {}, headers)
            self._meters[account.uuid] = list(result["meters_ids"])
        return self._meters[account.uuid]

    async def _async_get_legacy_realtime_usage_reads(
        self,
        account: Account,
    ) -> list[UsageRead]:
        """Get recent legacy REST usage from the account's first meter."""
        meters = await self._async_get_meters(account)
        if not meters:
            raise CannotConnect(f"No meters found for account {account.id}")
        meter = meters[0]

        url = (
            f"https://{self._get_subdomain()}.opower.com/{self._get_api_root()}"
            f"/edge/apis/cws-real-time-ami-v1/cws/{self.utility.utilitycode()}"
            f"/accounts/{account.uuid}/meters/{meter}/usage"
        )
        headers = self._get_headers(account.customer.uuid)
        result = await self._async_get_request(url, {}, headers)
        tz = await aiozoneinfo.async_get_time_zone(self.utility.timezone())
        return [
            UsageRead(
                start_time=_parse_read_time(read["startTime"], tz),
                end_time=_parse_read_time(read["endTime"], tz),
                consumption=read["value"],
            )
            for read in result["reads"]
        ]

    def _normalized_account_identifiers(self, account: Account) -> set[str]:
        """Return account identifiers in the forms used by Opower APIs."""
        identifiers = {
            identifier
            for identifier in (
                account.uuid,
                account.utility_account_id,
                account.id,
            )
            if identifier
        }
        for customer in self._customers:
            if str(customer.get("uuid", "")) != account.customer.uuid:
                continue
            for utility_account in customer.get("utilityAccounts", []):
                if str(utility_account.get("uuid", "")) != account.uuid:
                    continue
                identifiers |= {
                    str(utility_account[key])
                    for key in (
                        "uuid",
                        "utilityAccountId",
                        "utilityAccountId2",
                        "preferredUtilityAccountId",
                        "servicePointId",
                    )
                    if utility_account.get(key) is not None
                }
        return identifiers | {identifier.lstrip("0") or "0" for identifier in identifiers}

    @staticmethod
    def _matches_meter_type(node: dict[str, Any], meter_type: MeterType) -> bool:
        """Return whether a GraphQL service entity matches a meter type."""
        service_type = str(node.get("serviceType", "")).upper()
        return _DSS_SERVICE_TYPE_TO_METER.get(service_type) == meter_type.value

    @staticmethod
    def _graphql_identifiers(
        node: dict[str, Any],
        keys: tuple[str, ...],
    ) -> set[str]:
        """Return normalized identifiers from a GraphQL entity."""
        identifiers = {str(node[key]) for key in keys if node.get(key)}
        return identifiers | {identifier.lstrip("0") or "0" for identifier in identifiers}

    @staticmethod
    def _graphql_connection_is_complete(connection: dict[str, Any]) -> bool:
        """Return whether a requested GraphQL connection is not truncated."""
        return (connection.get("pageInfo") or {}).get("hasNextPage") is False

    @staticmethod
    def _deduplicate_graphql_nodes_by_uuid(
        nodes: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """Deduplicate GraphQL nodes only when they share a non-empty UUID."""
        unique_nodes: list[dict[str, Any]] = []
        seen_uuids: set[str] = set()
        for node in nodes:
            uuid = str(node.get("uuid") or "")
            if uuid and uuid in seen_uuids:
                continue
            unique_nodes.append(node)
            if uuid:
                seen_uuids.add(uuid)
        return unique_nodes

    def _realtime_graphql_mappings(
        self,
        account: Account,
        result: dict[str, Any],
    ) -> list[tuple[str, str, str]]:
        """Return GraphQL account paths that safely match a REST account."""
        account_identifiers = self._normalized_account_identifiers(account)
        mappings: list[tuple[str, str, str]] = []
        billing_accounts_connection = (result.get("data") or {}).get("billingAccountsConnection") or {}
        if not self._graphql_connection_is_complete(billing_accounts_connection):
            return []

        for edge in billing_accounts_connection.get("edges") or []:
            billing_account = edge.get("node") or {}
            selected_account = str(billing_account.get("urn") or "")
            if not selected_account:
                continue

            service_agreements_connection = billing_account.get("serviceAgreementsConnection") or {}
            if not self._graphql_connection_is_complete(service_agreements_connection):
                return []
            service_agreements = [
                service_agreement_edge.get("node") or {}
                for service_agreement_edge in service_agreements_connection.get("edges") or []
                if self._matches_meter_type(service_agreement_edge.get("node") or {}, account.meter_type)
            ]
            service_agreements = [
                service_agreement
                for service_agreement in service_agreements
                if account_identifiers
                & self._graphql_identifiers(
                    service_agreement,
                    ("uuid", "utilityId"),
                )
            ]

            for service_agreement in service_agreements:
                service_points_connection = service_agreement.get("servicePointsConnection") or {}
                if not self._graphql_connection_is_complete(service_points_connection):
                    return []
                service_points = [
                    service_point_edge.get("node") or {}
                    for service_point_edge in service_points_connection.get("edges") or []
                    if self._matches_meter_type(service_point_edge.get("node") or {}, account.meter_type)
                ]
                service_points = self._deduplicate_graphql_nodes_by_uuid(service_points)
                matching_service_points = [
                    service_point
                    for service_point in service_points
                    if account_identifiers
                    & self._graphql_identifiers(
                        service_point,
                        ("uuid", "utilityId"),
                    )
                ]
                if matching_service_points:
                    service_points = matching_service_points
                if len(service_points) != 1:
                    continue
                service_agreement_uuid = str(service_agreement.get("uuid") or "")
                service_point_uuid = str(service_points[0].get("uuid") or "")
                if service_agreement_uuid and service_point_uuid:
                    mappings.append(
                        (
                            selected_account,
                            service_agreement_uuid,
                            service_point_uuid,
                        )
                    )
        return list(dict.fromkeys(mappings))

    @staticmethod
    def _realtime_graphql_cache_key(account: Account) -> tuple[str, str, str, str]:
        """Return the key the discovered realtime mapping is cached under."""
        return (
            account.customer.uuid,
            account.meter_type.value,
            account.uuid,
            account.utility_account_id,
        )

    def _forget_realtime_graphql_metadata(self, account: Account) -> None:
        """Drop the cached mapping so the next call rediscovers it.

        The mapping is discovered once and reused. When the usage query then finds
        it no longer resolves - a replaced meter or service agreement - keeping it
        would repeat the same doomed request on every later call for the life of
        the session, while rediscovery would have fixed it.
        """
        self._realtime_graphql_metadata.pop(self._realtime_graphql_cache_key(account), None)

    async def _async_get_realtime_graphql_metadata(
        self,
        account: Account,
    ) -> _RealtimeGraphQLMetadata | None:
        """Discover and cache an unambiguous GraphQL realtime register mapping."""
        cache_key = self._realtime_graphql_cache_key(account)
        if cache_key in self._realtime_graphql_metadata:
            return self._realtime_graphql_metadata[cache_key]

        topology_query = """
        query WRTAMI_GetTopology($first: Int, $onlyActive: Boolean) {
          billingAccountsConnection(first: $first) {
            pageInfo {
              hasNextPage
            }
            edges {
              node {
                urn
                serviceAgreementsConnection(first: $first, onlyActive: $onlyActive) {
                  pageInfo {
                    hasNextPage
                  }
                  edges {
                    node {
                      uuid
                      utilityId
                      serviceType
                      servicePointsConnection(first: $first) {
                        pageInfo {
                          hasNextPage
                        }
                        edges {
                          node {
                            uuid
                            utilityId
                            serviceType
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
        """
        result = await self._async_post_graphql(
            topology_query,
            self._get_headers(account.customer.uuid),
            {"first": 100, "onlyActive": True},
        )
        mappings = self._realtime_graphql_mappings(account, result)

        if len(mappings) != 1:
            # Only remember "no mapping" when the response actually described the
            # customer. An empty body is more likely a server hiccup than an
            # account without a realtime stream, and caching it would pin this
            # utility to the legacy REST endpoint - the one that now returns 424 -
            # until the next restart.
            if ((result.get("data") or {}).get("billingAccountsConnection") or {}).get("edges"):
                self._realtime_graphql_metadata[cache_key] = None
            return None

        selected_account, service_agreement_uuid, service_point_uuid = mappings[0]
        registers_query = """
        query WRTAMI_GetRegisters(
          $selectedAccount: ID
          $saUuid: String
          $spUuid: String
        ) {
          billingAccountByAuthContext(selectedAccount: $selectedAccount) {
            serviceAgreementsConnection(onlyActive: true, matching: $saUuid) {
              edges {
                node {
                  servicePointsConnection(matching: $spUuid) {
                    edges {
                      node {
                        intervalReads(
                          units: [KWH]
                          serviceQuantityIdentifier: [NET_USAGE]
                          onlyUnverifiedStreams: true
                        ) {
                          registerId
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
        """
        variables = {
            "selectedAccount": selected_account,
            "saUuid": service_agreement_uuid,
            "spUuid": service_point_uuid,
        }
        registers_result = await self._async_post_graphql(
            registers_query,
            self._get_headers(account.customer.uuid),
            variables,
        )
        billing_account = (registers_result.get("data") or {}).get("billingAccountByAuthContext") or {}
        service_agreements_connection = billing_account.get("serviceAgreementsConnection") or {}
        service_agreement_edges = service_agreements_connection.get("edges") or []
        if len(service_agreement_edges) != 1:
            self._realtime_graphql_metadata[cache_key] = None
            return None
        service_agreement = service_agreement_edges[0].get("node") or {}
        service_points_connection = service_agreement.get("servicePointsConnection") or {}
        service_point_edges = service_points_connection.get("edges") or []
        if len(service_point_edges) != 1:
            self._realtime_graphql_metadata[cache_key] = None
            return None
        service_point = service_point_edges[0].get("node") or {}
        interval_reads = service_point.get("intervalReads") or []
        register_ids = tuple(
            dict.fromkeys(
                str(interval_read["registerId"]) for interval_read in interval_reads if interval_read.get("registerId")
            )
        )
        net_usage_register_ids = [
            register_id for register_id in register_ids if "NET_USAGE" in register_id.strip().upper().split(":")
        ]
        if len(net_usage_register_ids) == 1:
            register_id = net_usage_register_ids[0]
        elif len(register_ids) == 1 and not {
            "DELIVERED",
            "RECEIVED",
        } & set(register_ids[0].strip().upper().split(":")):
            register_id = register_ids[0]
        else:
            self._realtime_graphql_metadata[cache_key] = None
            return None

        metadata = _RealtimeGraphQLMetadata(
            selected_account=selected_account,
            service_agreement_uuid=service_agreement_uuid,
            service_point_uuid=service_point_uuid,
            register_id=register_id,
        )
        self._realtime_graphql_metadata[cache_key] = metadata
        return metadata

    async def _async_get_graphql_realtime_usage_reads(
        self,
        account: Account,
    ) -> list[UsageRead] | None:
        """Get recent unverified NET_USAGE reads from the GraphQL WRTAMI API."""
        metadata = await self._async_get_realtime_graphql_metadata(account)
        if metadata is None:
            return None

        # Observed on ConEd 2026-09-01: omitting timeInterval returns the latest
        # ~24 hours; explicit requests are also capped at 24 hours (dasl-/pitools#15).
        #
        # intervalReads on purpose, even though the historical read path deliberately
        # avoids it (see _REGISTER_READS_QUERY). Its two drawbacks - the 24 hour cap
        # and null values around DST transitions - are what rule it out for a long
        # backfill, and neither bites a rolling ~24 hour realtime window. It is also
        # the only field taking onlyUnverifiedStreams, which is what makes these
        # reads ~50 minutes fresh rather than hours. Do not "fix" this to readStreams.
        usage_query = """
        query WRTAMI_GetRegisterUsage(
          $selectedAccount: ID
          $registerId: ID
          $saUuid: String
          $spUuid: String
        ) {
          billingAccountByAuthContext(selectedAccount: $selectedAccount) {
            serviceAgreementsConnection(onlyActive: true, matching: $saUuid) {
              edges {
                node {
                  servicePointsConnection(matching: $spUuid) {
                    edges {
                      node {
                        intervalReads(
                          registerId: $registerId
                          units: [KWH]
                          serviceQuantityIdentifier: [NET_USAGE]
                          onlyUnverifiedStreams: true
                        ) {
                          reads {
                            timeInterval
                            measuredAmount {
                              value
                            }
                          }
                        }
                      }
                    }
                  }
                }
              }
            }
          }
        }
        """
        tz = await aiozoneinfo.async_get_time_zone(self.utility.timezone())
        reads: list[UsageRead] = []
        result = await self._async_post_graphql(
            usage_query,
            self._get_headers(account.customer.uuid),
            {
                "selectedAccount": metadata.selected_account,
                "registerId": metadata.register_id,
                "saUuid": metadata.service_agreement_uuid,
                "spUuid": metadata.service_point_uuid,
            },
        )
        billing_account = (result.get("data") or {}).get("billingAccountByAuthContext") or {}
        service_agreements_connection = billing_account.get("serviceAgreementsConnection") or {}
        service_agreement_edges = service_agreements_connection.get("edges") or []
        if len(service_agreement_edges) != 1:
            self._forget_realtime_graphql_metadata(account)
            raise CannotConnect("GraphQL realtime service agreement mapping changed")
        service_agreement = service_agreement_edges[0].get("node") or {}
        service_points_connection = service_agreement.get("servicePointsConnection") or {}
        service_point_edges = service_points_connection.get("edges") or []
        if len(service_point_edges) != 1:
            self._forget_realtime_graphql_metadata(account)
            raise CannotConnect("GraphQL realtime service point mapping changed")
        service_point = service_point_edges[0].get("node") or {}
        streams = service_point.get("intervalReads") or []
        if len(streams) != 1:
            self._forget_realtime_graphql_metadata(account)
            raise CannotConnect("GraphQL realtime register mapping changed")
        for read in streams[0].get("reads") or []:
            measured_amount = read.get("measuredAmount")
            if not measured_amount or measured_amount.get("value") is None:
                continue
            time_interval = str(read.get("timeInterval") or "")
            if "/" not in time_interval:
                raise CannotConnect("GraphQL realtime read has an invalid time interval")
            start_time, end_time = time_interval.split("/", 1)
            try:
                reads.append(
                    UsageRead(
                        start_time=_parse_read_time(start_time, tz),
                        end_time=_parse_read_time(end_time, tz),
                        consumption=float(measured_amount["value"]),
                    )
                )
            except (TypeError, ValueError) as err:
                # Anything unparsable is a changed contract, not a bad read. Raise
                # so the caller falls back to REST rather than returning a series
                # with holes in it.
                raise CannotConnect(f"GraphQL realtime read could not be parsed: {err}") from err

        reads.sort(key=lambda read: read.start_time)
        return reads

    async def async_get_realtime_usage_reads(
        self,
        account: Account,
    ) -> list[UsageRead]:
        """Get approximately the latest day of realtime usage.

        Interval resolution varies by utility. The compatibility REST path
        queries only the account's first meter.
        """
        # Both GraphQL queries ask for KWH registers, so a gas or water account
        # would spend two round trips to discover nothing; the legacy REST path
        # serves those meters unchanged.
        if self.utility.supports_realtime_usage() and account.meter_type is MeterType.ELEC:
            try:
                graphql_reads = await self._async_get_graphql_realtime_usage_reads(account)
            except (ApiException, CannotConnect) as err:
                _LOGGER.debug(
                    "GraphQL realtime usage failed; falling back to legacy REST: %s",
                    err,
                )
            else:
                if graphql_reads is not None:
                    return graphql_reads
                _LOGGER.debug("GraphQL realtime account mapping was unavailable; falling back to legacy REST.")
        return await self._async_get_legacy_realtime_usage_reads(account)

    async def _async_get_dated_data(
        self,
        account: Account,
        aggregate_type: AggregateType,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
        usage_only: bool = False,
    ) -> list[Any]:
        """Wrap _async_fetch by breaking requests for big date ranges to smaller ones to satisfy opower imposed limits."""
        if account.read_resolution is not None and aggregate_type not in SUPPORTED_AGGREGATE_TYPES[account.read_resolution]:
            raise ValueError(
                f"Requested aggregate_type: {aggregate_type} "
                f"not supported by account's read_resolution: {account.read_resolution}"
            )
        if start_date is None:
            if aggregate_type == AggregateType.BILL:
                reads, _ = await self._async_fetch(account, aggregate_type, start_date, end_date, usage_only)
                return reads
            raise ValueError("start_date is required unless aggregate_type=BILL")
        if end_date is None:
            raise ValueError("end_date is required unless aggregate_type=BILL")

        tzinfo = await aiozoneinfo.async_get_time_zone(self.utility.timezone())
        start = arrow.get(start_date.date(), tzinfo)
        end = arrow.get(end_date.date(), tzinfo).shift(days=1)

        max_request_days = None
        if aggregate_type == AggregateType.DAY:
            max_request_days = 363
        elif aggregate_type == AggregateType.HOUR:
            max_request_days = 26
        elif aggregate_type == AggregateType.HALF_HOUR or aggregate_type == AggregateType.QUARTER_HOUR:
            max_request_days = 6

        # Fetch data in batches in reverse chronological order
        # until we reach start or there is no fetched data
        # (non bill data are available up to 3 years ago).
        result: list[Any] = []
        req_end = end
        while True:
            req_start = start
            if max_request_days is not None:
                req_start = max(start, req_end.shift(days=-max_request_days))
            if req_start >= req_end:
                return result
            reads, from_dss_bills = await self._async_fetch(account, aggregate_type, req_start, req_end, usage_only)
            if from_dss_bills:
                # The bill-trends fallback ignores the requested window and
                # always returns the full bill history, so asking for the
                # remaining windows would return the very same reads again.
                return reads
            if not reads:
                return result
            result = reads + result
            req_end = req_start.shift(days=-1)

    async def _async_fetch_dss_bills(self) -> list[Any]:
        """Fetch bill-level cost data for DSS utilities via bill-trends-v1/billHistory.

        DataBrowser-v1 is not accessible for DSS portals that use SAML-only auth,
        so we fall back here.  Consumption values are set to 0 because the
        billHistory endpoint does not expose metered usage.  Date range filtering
        is intentionally omitted: bill data is always returned in full because
        monthly billing cycles rarely align with the caller's requested window.
        """
        url = f"https://{self._get_subdomain()}.opower.com/{self._get_api_root()}/edge/apis/bill-trends-v1/cws/billHistory"
        result = await self._async_get_request(url, {"numMonths": "36"}, self._get_headers())

        bills = result.get("bills", [])
        if len(bills) < 2:
            return []

        # Bills are newest-first; reverse so we can compute period start dates
        # from the preceding bill's date.
        bills_asc = list(reversed(bills))

        reads: list[Any] = []
        for i in range(1, len(bills_asc)):
            prev_date = datetime.fromisoformat(bills_asc[i - 1]["billDate"])
            bill_date = datetime.fromisoformat(bills_asc[i]["billDate"])
            period_start = prev_date + timedelta(days=1)
            if period_start > bill_date:
                # Two bills share the same date; skip the degenerate entry.
                continue
            reads.append(
                {
                    "startTime": period_start.isoformat(),
                    "endTime": bill_date.isoformat(),
                    "value": 0,
                    "providedCost": bills_asc[i]["cost"],
                }
            )

        return reads

    async def _async_fetch(
        self,
        account: Account,
        aggregate_type: AggregateType,
        start_date: datetime | arrow.Arrow | None = None,
        end_date: datetime | arrow.Arrow | None = None,
        usage_only: bool = False,
    ) -> tuple[list[Any], bool]:
        """Fetch reads for one window.

        Returns the reads and whether they came from the bill-trends fallback,
        which ignores the requested window and returns the full bill history.
        """
        if usage_only:
            url = (
                f"https://{self._get_subdomain()}.opower.com/{self._get_api_root()}"
                f"/edge/apis/DataBrowser-v1/cws/utilities/{self.utility.utilitycode()}"
                f"/utilityAccounts/{account.uuid}/reads"
            )
        else:
            url = (
                f"https://{self._get_subdomain()}.opower.com/{self._get_api_root()}"
                f"/edge/apis/DataBrowser-v1/cws/cost/utilityAccount/{account.uuid}"
            )
        convert_to_date = usage_only
        params = {"aggregateType": aggregate_type.value}
        headers = self._get_headers(account.customer.uuid)
        if start_date:
            params["startDate"] = (start_date.date() if convert_to_date else start_date).isoformat()
        if end_date:
            params["endDate"] = (end_date.date() if convert_to_date else end_date).isoformat()
        try:
            result = await self._async_get_request(url, params, headers)
            return list(result["reads"]), False
        except ApiException as err:
            # Ignore server errors for BILL requests
            # that can happen if end_date is before account activation
            if err.status == 500 and aggregate_type == AggregateType.BILL:
                _LOGGER.debug("Ignoring error while fetching bill data: %s", err)
                return [], False
            # DSS utilities with a bill-trends fallback: if DataBrowser-v1 is
            # inaccessible (403) fall back to monthly bill history.
            if err.status == 403 and self.utility.uses_bill_trends_for_reads() and not usage_only:
                _LOGGER.debug("DataBrowser-v1 returned 403 for DSS, falling back to bill history: %s", err)
                return await self._async_fetch_dss_bills(), True
            raise

    def _get_account_id(self) -> str:
        for user_account in self._user_accounts:
            if len(user_account["premises"]) > 0:
                # Select first account with assigned premises
                # Avoid issue with accounts without premises. They could be moved to other accounts,
                # see https://github.com/tronikos/opower/issues/73 for details
                return str(user_account["accountId"])
        return str(self._user_accounts[0]["accountId"])

    def _get_headers(self, customer_uuid: str | None = None) -> dict[str, str]:
        headers = {"User-Agent": USER_AGENT}
        if self._access_token:
            headers["authorization"] = f"Bearer {self._access_token}"

        opower_selected_entities: list[str] = []
        if self.utility.is_dss():
            if self._user_accounts:
                # Required for DSS endpoints
                opower_selected_entities.append(f"urn:session:account:{self._get_account_id()}")
            # Required for all DSS endpoints; without this the customers endpoint returns
            # 403 EMPTY_AUTHORIZED_CUSTOMERS_LIST (confirmed via browser HAR analysis)
            opower_selected_entities.append("urn:session:account:provider:dsst")

        # For DSS, only include the customer UUID claim when it is a true UUID (the
        # webUserId captured at login).  A numeric CIS accountId is not accepted.
        # Non-DSS utilities always include it (comes from the /customers response).
        if customer_uuid and ("-" in customer_uuid or not self.utility.is_dss()):
            opower_selected_entities.append(f"urn:opower:customer:uuid:{customer_uuid}")
        if opower_selected_entities:
            headers["Opower-Selected-Entities"] = json.dumps(opower_selected_entities)
        return headers

    def _get_subdomain(self) -> str:
        # DSS subdomain have 'dss' as a first part of domain name
        if self.utility.is_dss():
            return "dss-" + self.utility.subdomain()
        return self.utility.subdomain()

    def _get_api_root(self) -> str:
        if self.utility.is_dss():
            return "webcenter"
        return "ei"

    async def _async_get_request(self, url: str, params: dict[str, str], headers: dict[str, str]) -> Any:
        full_url = f"{url}?{urlencode(params)}"
        _LOGGER.debug("Fetching: %s", full_url)
        try:
            async with self._session.get(url, params=params, headers=headers) as resp:
                if not resp.ok:
                    raise ApiException(
                        f"HTTP Error: {resp.status}",
                        url=full_url,
                        status=resp.status,
                        response_text=await resp.text(),
                    )
                result = await resp.json()
                _LOGGER.log(logging.DEBUG - 1, "Fetched: %s", json.dumps(result, indent=2))
                return result
        except ClientError as e:
            raise ApiException(f"Client Error: {e}", url=full_url) from e

    async def _async_post_graphql(
        self,
        query: str,
        headers: dict[str, str],
        variables: dict[str, Any] | None = None,
    ) -> Any:
        """Execute a GraphQL query against the Opower API."""
        url = f"https://{self._get_subdomain()}.opower.com/{self._get_api_root()}/edge/apis/dsm-graphql-v1/cws/graphql"
        _LOGGER.debug("GraphQL query to: %s", url)
        payload: dict[str, Any] = {"query": query}
        if variables is not None:
            payload["variables"] = variables
        try:
            async with self._session.post(
                url,
                headers={**headers, "Content-Type": "application/json"},
                json=payload,
            ) as resp:
                if not resp.ok:
                    raise ApiException(
                        f"HTTP Error: {resp.status}",
                        url=url,
                        status=resp.status,
                        response_text=await resp.text(),
                    )
                result = await resp.json()
                _LOGGER.log(logging.DEBUG - 1, "GraphQL response: %s", json.dumps(result, indent=2))
                if "errors" in result:
                    raise ApiException(
                        f"GraphQL Error: {result['errors']}",
                        url=url,
                    )
                return result
        except ClientError as e:
            raise ApiException(f"Client Error: {e}", url=url) from e
