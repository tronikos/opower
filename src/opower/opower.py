"""Implementation of opower.com JSON API."""

import dataclasses
import json
import logging
from datetime import date, datetime, timedelta
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


@dataclasses.dataclass
class UsageRead:
    """A read from the meter that has consumption data."""

    start_time: datetime
    end_time: datetime
    consumption: float  # taken from consumption.value field, in KWH or THERM/CCF


@dataclasses.dataclass(frozen=True)
class _RealtimeGraphQLMetadata:
    """Identifiers needed to query one account's realtime GraphQL reads."""

    selected_account: str
    service_agreement_uuid: str
    service_point_uuid: str
    register_ids: tuple[str, ...]


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
                )
            )
        return result

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
        """Get recent usage data from the legacy realtime REST API."""
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
        identifiers = {account.uuid, account.utility_account_id, account.id}
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

    def _realtime_graphql_mappings(
        self,
        account: Account,
        result: dict[str, Any],
    ) -> list[tuple[str, str, str]]:
        """Return GraphQL account paths that safely match a REST account."""
        account_identifiers = self._normalized_account_identifiers(account)
        mappings: list[tuple[str, str, str]] = []
        billing_accounts_connection = (result.get("data") or {}).get("billingAccountsConnection") or {}

        for edge in billing_accounts_connection.get("edges") or []:
            billing_account = edge.get("node") or {}
            selected_account = str(billing_account.get("urn", ""))
            if not selected_account:
                continue

            billing_identifiers = self._graphql_identifiers(
                billing_account,
                ("uuid", "accountNumber", "utilityId"),
            )
            billing_account_matches = bool(account_identifiers & billing_identifiers)

            service_agreements_connection = billing_account.get("serviceAgreementsConnection") or {}
            service_agreements = [
                service_agreement_edge.get("node") or {}
                for service_agreement_edge in service_agreements_connection.get("edges") or []
                if self._matches_meter_type(service_agreement_edge.get("node") or {}, account.meter_type)
            ]
            matching_service_agreements = [
                service_agreement
                for service_agreement in service_agreements
                if account_identifiers
                & self._graphql_identifiers(
                    service_agreement,
                    ("uuid", "utilityId"),
                )
            ]
            if matching_service_agreements:
                service_agreements = matching_service_agreements
            elif not billing_account_matches or len(service_agreements) != 1:
                continue

            for service_agreement in service_agreements:
                service_points_connection = service_agreement.get("servicePointsConnection") or {}
                service_points = [
                    service_point_edge.get("node") or {}
                    for service_point_edge in service_points_connection.get("edges") or []
                    if self._matches_meter_type(service_point_edge.get("node") or {}, account.meter_type)
                ]
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
                service_agreement_uuid = str(service_agreement.get("uuid", ""))
                service_point_uuid = str(service_points[0].get("uuid", ""))
                if service_agreement_uuid and service_point_uuid:
                    mappings.append(
                        (
                            selected_account,
                            service_agreement_uuid,
                            service_point_uuid,
                        )
                    )
        return mappings

    async def _async_get_realtime_graphql_metadata(
        self,
        account: Account,
    ) -> _RealtimeGraphQLMetadata | None:
        """Discover and cache an unambiguous GraphQL realtime register mapping."""
        cache_key = (
            account.customer.uuid,
            account.meter_type.value,
            account.uuid,
            account.utility_account_id,
        )
        if cache_key in self._realtime_graphql_metadata:
            return self._realtime_graphql_metadata[cache_key]

        topology_query = """
        query WRTAMI_GetTopology($first: Int, $onlyActive: Boolean) {
          billingAccountsConnection(first: $first) {
            edges {
              node {
                urn
                uuid
                accountNumber
                utilityId
                serviceAgreementsConnection(first: 25, onlyActive: $onlyActive) {
                  edges {
                    node {
                      uuid
                      utilityId
                      serviceType
                      servicePointsConnection(first: 25) {
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
        if not register_ids:
            self._realtime_graphql_metadata[cache_key] = None
            return None

        metadata = _RealtimeGraphQLMetadata(
            selected_account=selected_account,
            service_agreement_uuid=service_agreement_uuid,
            service_point_uuid=service_point_uuid,
            register_ids=register_ids,
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
        for register_id in metadata.register_ids:
            result = await self._async_post_graphql(
                usage_query,
                self._get_headers(account.customer.uuid),
                {
                    "selectedAccount": metadata.selected_account,
                    "registerId": register_id,
                    "saUuid": metadata.service_agreement_uuid,
                    "spUuid": metadata.service_point_uuid,
                },
            )
            billing_account = (result.get("data") or {}).get("billingAccountByAuthContext") or {}
            service_agreements_connection = billing_account.get("serviceAgreementsConnection") or {}
            service_agreement_edges = service_agreements_connection.get("edges") or []
            if len(service_agreement_edges) != 1:
                raise CannotConnect("GraphQL realtime service agreement mapping changed")
            service_agreement = service_agreement_edges[0].get("node") or {}
            service_points_connection = service_agreement.get("servicePointsConnection") or {}
            service_point_edges = service_points_connection.get("edges") or []
            if len(service_point_edges) != 1:
                raise CannotConnect("GraphQL realtime service point mapping changed")
            service_point = service_point_edges[0].get("node") or {}
            for stream in service_point.get("intervalReads") or []:
                for read in stream.get("reads") or []:
                    measured_amount = read.get("measuredAmount")
                    if not measured_amount or measured_amount.get("value") is None:
                        continue
                    time_interval = str(read.get("timeInterval", ""))
                    if "/" not in time_interval:
                        raise CannotConnect("GraphQL realtime read has an invalid time interval")
                    start_time, end_time = time_interval.split("/", 1)
                    reads.append(
                        UsageRead(
                            start_time=_parse_read_time(start_time, tz),
                            end_time=_parse_read_time(end_time, tz),
                            consumption=float(measured_amount["value"]),
                        )
                    )

        if not reads:
            raise CannotConnect("GraphQL realtime API returned no usable reads")
        reads.sort(key=lambda read: read.start_time)
        return reads

    async def async_get_realtime_usage_reads(
        self,
        account: Account,
    ) -> list[UsageRead]:
        """Get approximately the latest day of usage in 15-minute increments."""
        if self.utility.supports_realtime_usage():
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
