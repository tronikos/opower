"""Implementation of opower.com JSON API."""

import dataclasses
import json
import logging
from datetime import date, datetime, timedelta, tzinfo
from enum import Enum
from typing import Any
from urllib.parse import urlencode

import aiohttp
import aiozoneinfo
import arrow
from aiohttp.client_exceptions import ClientError, ClientResponseError

from .const import USER_AGENT
from .exceptions import ApiException, CannotConnect, InvalidAuth
from .utilities import UtilityBase

_LOGGER = logging.getLogger(__file__)


class MeterType(Enum):
    """Meter type. Electric or gas."""

    ELEC = "ELEC"
    GAS = "GAS"

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
}


def _get_value(data: dict[str, Any] | None, default: float = 0) -> float:
    """Extract 'value' from a dict, returning default if missing or None."""
    val = (data or {}).get("value")
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
class CostRead:
    """A read from the meter that has both consumption and cost data."""

    start_time: datetime
    end_time: datetime
    consumption: float  # taken from value field, in KWH or THERM/CCF
    provided_cost: float  # in $
    usage_charges: float | None = None  # energy charges only, in $
    current_amount: float | None = None  # total bill amount incl. delivery + taxes, in $


@dataclasses.dataclass
class UsageRead:
    """A read from the meter that has consumption data."""

    start_time: datetime
    end_time: datetime
    consumption: float  # taken from consumption.value field, in KWH or THERM/CCF


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
        self.session: aiohttp.ClientSession = session
        self.utility: UtilityBase = select_utility(utility)()
        self.username: str = username
        self.password: str = password
        self.optional_totp_secret: str | None = optional_totp_secret
        if self.utility.accepts_totp_secret() and self.optional_totp_secret:
            self.utility.set_totp_secret(self.optional_totp_secret.strip())
        self.login_data: dict[str, Any] = login_data or {}
        self.access_token: str | None = None
        self.customers: list[Any] = []
        self.user_accounts: list[Any] = []
        # Cache: account UUID → (service_point_uuid, register_id)
        self._service_point_cache: dict[str, tuple[str, str]] = {}

    async def async_login(self) -> None:
        """Login to the utility website and authorize opower.com for access.

        :raises InvalidAuth: if login information is incorrect
        :raises MfaChallenge: if interactive MFA is required
        :raises CannotConnect: if we receive any HTTP error
        """
        try:
            self.access_token = await self.utility.async_login(self.session, self.username, self.password, self.login_data)
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
                    unit_str = str(estimated_usage.get("unit", "KWH"))
                    try:
                        unit_of_measure = UnitOfMeasure(unit_str)
                    except ValueError:
                        _LOGGER.debug("Unknown unit of measure: %s, defaulting to KWH", unit_str)
                        unit_of_measure = UnitOfMeasure.KWH

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

    def _segment_matches_meter_type(self, segment: dict[str, Any], account: Account) -> bool:
        """Return True when a GraphQL segment service type matches account meter type."""
        allowed_service_types = {
            MeterType.ELEC: {"ELECTRICITY", "ELEC", "ELECTRIC"},
            MeterType.GAS: {"GAS", "NATURAL_GAS", "NATURALGAS"},
        }.get(account.meter_type, set())
        sa = segment.get("serviceAgreement") or {}
        sa_service_type = str(sa.get("serviceType", "")).upper()
        if not sa_service_type or sa_service_type in allowed_service_types:
            return True
        _LOGGER.debug(
            "Skipping segment: serviceType=%s != meter_type=%s",
            sa_service_type,
            account.meter_type.value,
        )
        return False

    @staticmethod
    def _extract_segment_consumption(segment: dict[str, Any]) -> float:
        """Extract consumption value from segment quantities."""
        sqs = segment.get("serviceQuantities", [])
        for sq in sqs:
            if sq.get("serviceQuantityIdentifier") == "consumption":
                return _get_value(sq.get("serviceQuantity"))
        if len(sqs) == 1:
            return _get_value(sqs[0].get("serviceQuantity"))
        return 0.0

    @staticmethod
    def _extract_segment_interval(segment: dict[str, Any], bill_time_interval: str) -> tuple[str, str] | None:
        """Extract segment interval or fallback to bill interval."""
        usage_interval = segment.get("usageInterval", bill_time_interval)
        if "/" not in usage_interval:
            return None
        return tuple(usage_interval.split("/", 1))

    async def _async_get_bill_cost_reads(
        self,
        account: Account,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> list[CostRead]:
        """Get bill-level cost and usage data via GraphQL.

        Returns actual bill costs (usageCharges and currentAmount) which many
        utilities don't provide through the REST API (providedCost = 0).
        """
        query = """
        query GetCostUsageReadsForBills(
          $last: Int
          $timeInterval: TimeInterval
        ) {
          billingAccountByAuthContext {
            bills(
              last: $last
              during: $timeInterval
              orderBy: ASCENDING
              preserveDuplicateSegments: true
            ) {
              timeInterval
              segments {
                usageInterval
                serviceAgreement {
                  serviceType
                }
                serviceQuantities {
                  serviceQuantityIdentifier
                  serviceQuantity {
                    value
                  }
                }
                usageCharges {
                  value
                }
                currentAmount {
                  value
                }
              }
            }
          }
        }
        """

        tzinfo = await aiozoneinfo.async_get_time_zone(self.utility.timezone())
        if start_date or end_date:
            start = start_date or datetime(2000, 1, 1)
            end = end_date or datetime.now(tz=tzinfo)
        else:
            # Default to ~2 years of bills
            end = datetime.now(tz=tzinfo)
            start = end - timedelta(days=730)
        start_iso = arrow.get(start).to(tzinfo).isoformat()
        end_iso = arrow.get(end).to(tzinfo).isoformat()
        variables: dict[str, Any] = {
            "last": 26,
            "timeInterval": f"{start_iso}/{end_iso}",
        }

        headers = self._get_headers(account.customer.uuid)

        try:
            result = await self._async_post_graphql(query, headers, variables)
        except ApiException as err:
            _LOGGER.debug("GraphQL bill cost query failed: %s", err)
            return []

        billing_account = result.get("data", {}).get("billingAccountByAuthContext")
        if billing_account is None:
            return []

        bills = billing_account.get("bills", [])

        reads: list[CostRead] = []
        for bill in bills:
            time_interval = bill.get("timeInterval", "")
            if "/" not in time_interval:
                _LOGGER.debug("Skipping bill with invalid timeInterval: %s", time_interval)
                continue

            for segment in bill.get("segments", []):
                if not self._segment_matches_meter_type(segment, account):
                    continue

                consumption = self._extract_segment_consumption(segment)
                usage_charges = _get_value(segment.get("usageCharges"))
                current_amount = _get_value(segment.get("currentAmount"))

                segment_interval = self._extract_segment_interval(segment, time_interval)
                if segment_interval is None:
                    _LOGGER.debug("Skipping segment with invalid interval in bill: %s", time_interval)
                    continue
                seg_start, seg_end = segment_interval

                reads.append(
                    CostRead(
                        start_time=datetime.fromisoformat(seg_start),
                        end_time=datetime.fromisoformat(seg_end),
                        consumption=consumption,
                        provided_cost=current_amount,
                        usage_charges=usage_charges,
                        current_amount=current_amount,
                    )
                )

        return reads

    async def _async_discover_service_point(
        self,
        account: Account,
    ) -> tuple[str, str]:
        """Discover service point UUID and register ID for an account via GraphQL.

        Returns (service_point_uuid, register_id) needed for interval reads.
        Results are cached per account UUID.
        """
        if account.uuid in self._service_point_cache:
            return self._service_point_cache[account.uuid]

        if account.meter_type == MeterType.ELEC:
            units_filter = "units: [KWH]"
            sqi_filter = "serviceQuantityIdentifier: [NET_USAGE]"
        else:
            # TODO: Validate gas interval filter variants (e.g. CCF/THERM + SQI) against a live gas utility.
            units_filter = "units: [CCF]"
            sqi_filter = "serviceQuantityIdentifier: [DELIVERED]"

        query = """
        query GetServicePointRegisters($customerURN: ID) {
          billingAccountByAuthContext(singlePremise: $customerURN) {
            serviceAgreementsConnection(onlyActive: true) {
              edges {
                node {
                  uuid
                  serviceType
                  servicePointsConnection {
                    edges {
                      node {
                        uuid
                        intervalReads(
                          __UNITS_FILTER__
                          __SQI_FILTER__
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
        query = query.replace("__UNITS_FILTER__", units_filter).replace("__SQI_FILTER__", sqi_filter)
        customer_urn = f"urn:opower:customer:uuid:{account.customer.uuid}"
        variables: dict[str, Any] = {
            "customerURN": customer_urn,
        }
        headers = self._get_headers(account.customer.uuid)
        result = await self._async_post_graphql(query, headers, variables)

        billing_account = result.get("data", {}).get("billingAccountByAuthContext")
        if billing_account is None:
            raise ApiException(
                "No billing account found for interval read discovery",
                url="graphql",
            )

        for sa_edge in billing_account.get("serviceAgreementsConnection", {}).get("edges", []):
            sa_node = sa_edge.get("node", {})
            for sp_edge in sa_node.get("servicePointsConnection", {}).get("edges", []):
                sp_node = sp_edge.get("node", {})
                sp_uuid = sp_node.get("uuid", "")
                if not sp_uuid:
                    continue

                for interval_read in sp_node.get("intervalReads", []):
                    register_id = interval_read.get("registerId", "")
                    if register_id:
                        self._service_point_cache[account.uuid] = (sp_uuid, register_id)
                        return sp_uuid, register_id

        raise ApiException(
            f"No service point with interval reads found for account {account.uuid}",
            url="graphql",
        )

    async def _async_get_graphql_interval_reads(
        self,
        account: Account,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> list[UsageRead]:
        """Fetch interval usage reads via GraphQL.

        Returns UsageRead objects at the meter's native resolution.
        """
        sp_uuid, register_id = await self._async_discover_service_point(account)
        if account.meter_type == MeterType.ELEC:
            units_filter = "units: [KWH]"
            sqi_filter = "serviceQuantityIdentifier: [NET_USAGE]"
        else:
            # TODO: Validate gas interval filter variants (e.g. CCF/THERM + SQI) against a live gas utility.
            units_filter = "units: [CCF]"
            sqi_filter = "serviceQuantityIdentifier: [DELIVERED]"

        query = """
        query GetRegisterUsage(
          $customerURN: ID
          $registerId: ID
          $timeInterval: TimeInterval
          $spUuid: String
        ) {
          billingAccountByAuthContext(singlePremise: $customerURN) {
            serviceAgreementsConnection(onlyActive: true) {
              edges {
                node {
                  servicePointsConnection(matching: $spUuid) {
                    edges {
                      node {
                        intervalReads(
                          registerId: $registerId
                          __UNITS_FILTER__
                          __SQI_FILTER__
                          timeInterval: $timeInterval
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
        query = query.replace("__UNITS_FILTER__", units_filter).replace("__SQI_FILTER__", sqi_filter)

        tzinfo = await aiozoneinfo.async_get_time_zone(self.utility.timezone())
        customer_urn = f"urn:opower:customer:uuid:{account.customer.uuid}"

        headers = self._get_headers(account.customer.uuid)
        all_reads: list[UsageRead] = []

        # Build list of time intervals to fetch.
        # GraphQL API limits interval reads to 24 hours per request.
        base_variables: dict[str, Any] = {
            "customerURN": customer_urn,
            "registerId": register_id,
            "spUuid": sp_uuid,
        }
        if start_date or end_date:
            start = start_date or datetime(2000, 1, 1)
            end = end_date or datetime.now(tz=tzinfo)
            start_arrow = arrow.get(start).to(tzinfo)
            end_arrow = arrow.get(end).to(tzinfo)
            intervals: list[str] = []
            batch_start = start_arrow
            while batch_start < end_arrow:
                batch_end = min(batch_start.shift(hours=24), end_arrow)
                start_utc = batch_start.to("UTC").strftime("%Y-%m-%dT%H:%M:%SZ")
                end_utc = batch_end.to("UTC").strftime("%Y-%m-%dT%H:%M:%SZ")
                intervals.append(f"{start_utc}/{end_utc}")
                batch_start = batch_end
        else:
            intervals = [""]  # Single request without timeInterval

        for interval in intervals:
            variables = dict(base_variables)
            if interval:
                variables["timeInterval"] = interval
            result = await self._async_post_graphql(query, headers, variables)
            all_reads.extend(self._parse_interval_reads_response(result))

        # Sort by start time ascending
        all_reads.sort(key=lambda r: r.start_time)
        return all_reads

    @staticmethod
    def _parse_interval_reads_response(
        result: dict[str, Any],
    ) -> list[UsageRead]:
        """Parse interval reads from a GraphQL response."""
        reads: list[UsageRead] = []
        billing_account = result.get("data", {}).get("billingAccountByAuthContext")
        if billing_account is None:
            return reads
        for sa_edge in billing_account.get("serviceAgreementsConnection", {}).get("edges", []):
            for sp_edge in sa_edge.get("node", {}).get("servicePointsConnection", {}).get("edges", []):
                for ir in sp_edge.get("node", {}).get("intervalReads", []):
                    for read in ir.get("reads", []):
                        time_interval = read.get("timeInterval", "")
                        if "/" not in time_interval:
                            continue
                        measured = read.get("measuredAmount")
                        if measured is None:
                            continue
                        value = measured.get("value")
                        if value is None:
                            continue
                        start_str, end_str = time_interval.split("/", 1)
                        reads.append(
                            UsageRead(
                                start_time=datetime.fromisoformat(start_str),
                                end_time=datetime.fromisoformat(end_str),
                                consumption=float(value),
                            )
                        )
        return reads

    @staticmethod
    def _aggregate_interval_reads(
        reads: list[UsageRead],
        aggregate_type: AggregateType,
        utility_tz: tzinfo | None = None,
    ) -> list[UsageRead]:
        """Aggregate raw interval reads to the requested resolution.

        Groups reads by time bucket (day/hour/etc) and sums consumption.
        """
        if not reads or aggregate_type == AggregateType.QUARTER_HOUR:
            return reads

        buckets: dict[datetime, float] = {}
        bucket_ends: dict[datetime, datetime] = {}

        for read in reads:
            start_time = read.start_time
            end_time = read.end_time
            if utility_tz is not None and start_time.tzinfo is not None:
                start_time = start_time.astimezone(utility_tz)
                end_time = end_time.astimezone(utility_tz)

            if aggregate_type == AggregateType.DAY:
                bucket = start_time.replace(hour=0, minute=0, second=0, microsecond=0)
            elif aggregate_type == AggregateType.HOUR:
                bucket = start_time.replace(minute=0, second=0, microsecond=0)
            elif aggregate_type == AggregateType.HALF_HOUR:
                bucket = start_time.replace(minute=30 * (start_time.minute // 30), second=0, microsecond=0)
            else:
                bucket = start_time

            buckets[bucket] = buckets.get(bucket, 0.0) + read.consumption
            # Track the latest end_time in each bucket
            if bucket not in bucket_ends or end_time > bucket_ends[bucket]:
                bucket_ends[bucket] = end_time

        return [
            UsageRead(
                start_time=bucket_start,
                end_time=bucket_ends[bucket_start],
                consumption=round(consumption, 3),
            )
            for bucket_start, consumption in sorted(buckets.items())
        ]

    async def _async_get_customers(self) -> list[Any]:
        """Get customers associated to the user."""
        # Cache the customers
        if not self.customers:
            if self.utility.is_dss() and not self.user_accounts:
                await self._async_get_user_accounts()

            url = (
                f"https://{self._get_subdomain()}.opower.com/{self._get_api_root()}"
                f"/edge/apis/multi-account-v1/cws/{self.utility.utilitycode()}"
                "/customers?offset=0&batchSize=100&addressFilter="
            )
            result = await self._async_get_request(url, {}, self._get_headers())
            for customer in result["customers"]:
                self.customers.append(customer)
        assert self.customers
        return self.customers

    async def _async_get_user_accounts(self) -> list[Any]:
        """Get accounts associated to the user."""
        # Cache the accounts
        if not self.user_accounts:
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
                self.user_accounts.append(account)

        assert self.user_accounts
        return self.user_accounts

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
        if account.read_resolution is not None and aggregate_type not in SUPPORTED_AGGREGATE_TYPES[account.read_resolution]:
            raise ValueError(
                f"Requested aggregate_type: {aggregate_type} "
                f"not supported by account's read_resolution: {account.read_resolution}"
            )
        # Bill-level reads have actual cost data from GraphQL.
        if aggregate_type == AggregateType.BILL:
            return await self._async_get_bill_cost_reads(account, start_date, end_date)

        # Interval reads only have usage data; cost is not available at sub-bill resolution.
        utility_tz = await aiozoneinfo.async_get_time_zone(self.utility.timezone())
        usage_reads = await self._async_get_graphql_interval_reads(account, start_date, end_date)
        aggregated = self._aggregate_interval_reads(usage_reads, aggregate_type, utility_tz)
        return [
            CostRead(
                start_time=r.start_time,
                end_time=r.end_time,
                consumption=r.consumption,
                provided_cost=0,
            )
            for r in aggregated
        ]

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
        if account.read_resolution is not None and aggregate_type not in SUPPORTED_AGGREGATE_TYPES[account.read_resolution]:
            raise ValueError(
                f"Requested aggregate_type: {aggregate_type} "
                f"not supported by account's read_resolution: {account.read_resolution}"
            )
        if aggregate_type == AggregateType.BILL:
            # For bill-level usage, return consumption from bill cost reads.
            bill_reads = await self._async_get_bill_cost_reads(account, start_date, end_date)
            return [
                UsageRead(
                    start_time=r.start_time,
                    end_time=r.end_time,
                    consumption=r.consumption,
                )
                for r in bill_reads
            ]
        usage_reads = await self._async_get_graphql_interval_reads(account, start_date, end_date)
        utility_tz = await aiozoneinfo.async_get_time_zone(self.utility.timezone())
        return self._aggregate_interval_reads(usage_reads, aggregate_type, utility_tz)

    async def async_get_realtime_usage_reads(
        self,
        account: Account,
    ) -> list[UsageRead]:
        """Get recent usage data at the meter's native resolution.

        Returns approximately the last day of data in 15-minute increments.
        """
        tzinfo = await aiozoneinfo.async_get_time_zone(self.utility.timezone())
        end = datetime.now(tz=tzinfo)
        start = end - timedelta(days=2)
        return await self._async_get_graphql_interval_reads(account, start, end)

    def _get_account_id(self) -> str:
        for user_account in self.user_accounts:
            if len(user_account["premises"]) > 0:
                # Select first account with assigned premises
                # Avoid issue with accounts without premises. They could be moved to other accounts,
                # see https://github.com/tronikos/opower/issues/73 for details
                return str(user_account["accountId"])
        return str(self.user_accounts[0]["accountId"])

    def _get_headers(self, customer_uuid: str | None = None) -> dict[str, str]:
        headers = {"User-Agent": USER_AGENT}
        if self.access_token:
            headers["authorization"] = f"Bearer {self.access_token}"

        opower_selected_entities: list[str] = []
        if self.utility.is_dss() and self.user_accounts:
            # Required for DSS endpoints
            opower_selected_entities.append(f"urn:session:account:{self._get_account_id()}")

        if customer_uuid:
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
            async with self.session.get(url, params=params, headers=headers) as resp:
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

    async def _async_post_graphql(self, query: str, headers: dict[str, str], variables: dict[str, Any] | None = None) -> Any:
        """Execute a GraphQL query against the Opower API."""
        url = f"https://{self._get_subdomain()}.opower.com/{self._get_api_root()}/edge/apis/dsm-graphql-v1/cws/graphql"
        _LOGGER.debug("GraphQL query to: %s", url)
        body: dict[str, Any] = {"query": query}
        if variables:
            body["variables"] = variables
        try:
            async with self.session.post(
                url,
                headers={**headers, "Content-Type": "application/json"},
                json=body,
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
