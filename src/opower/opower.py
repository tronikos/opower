"""Implementation of opower.com JSON API."""

import dataclasses
import json
import logging
from datetime import date, datetime
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
        headless_login_service_url: str | None = None,
    ) -> None:
        """Initialize."""
        # Note: Do not modify default headers since Home Assistant that uses this library needs to use
        # a default session for all integrations. Instead specify the headers for each request.
        self.session: aiohttp.ClientSession = session
        self.utility: type[UtilityBase] = select_utility(utility)
        self.username: str = username
        self.password: str = password
        self.optional_totp_secret: str | None = optional_totp_secret
        self.headless_login_service_url: str | None = headless_login_service_url
        self.access_token: str | None = None
        self.customers: list[Any] = []
        self.user_accounts: list[Any] = []
        self.meters: list[str] = []

    async def async_login(self) -> None:
        """Login to the utility website and authorize opower.com for access.

        :raises InvalidAuth: if login information is incorrect
        :raises MfaChallenge: if interactive MFA is required
        :raises CannotConnect: if we receive any HTTP error
        """
        try:
            if self.utility.accepts_totp_secret() and self.optional_totp_secret:
                self.utility.set_totp_secret(self.optional_totp_secret.strip())
            if self.utility.requires_headless_login_service():
                if not self.headless_login_service_url:
                    raise ValueError("Headless login service URL is required for this utility but was not provided.")
                self.utility.set_headless_login_service_url(self.headless_login_service_url.rstrip("/"))
            self.access_token = await self.utility.async_login(self.session, self.username, self.password)

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
        accounts = []
        for customer in await self._async_get_customers():
            utility_accounts = []
            utility_account_ids = []
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
        forecasts = []
        for customer in await self._async_get_customers():
            customer_uuid = customer["uuid"]
            url = (
                f"https://{self._get_subdomain()}.opower.com/{self._get_api_root()}"
                f"/edge/apis/bill-forecast-cws-v1/cws/{self.utility.utilitycode()}"
                f"/customers/{customer_uuid}/combined-forecast"
            )
            try:
                result = await self._async_get_request(url, {}, self._get_headers())
            except ApiException as err:
                # For some customers utilities don't provide forecast
                _LOGGER.debug("Ignoring combined-forecast error: %s", err)
                continue
            if (
                all(x in result["totalMetadata"] for x in ["NO_FORECASTED_COST", "NO_FORECASTED_USAGE"])
                and "DATA_COVERAGE_QUALITY_CHECK_FAILED" not in result["totalMetadata"]
            ):
                _LOGGER.debug(
                    "Ignoring combined-forecast since there is no usage or cost. metadata: %s",
                    result["totalMetadata"],
                )
                continue
            account_forecasts = []
            utility_account_ids = []
            for forecast in result["accountForecasts"]:
                account_forecasts.append(forecast)
                utility_account_ids.append(str(forecast["preferredUtilityAccountId"]))
            for forecast in account_forecasts:
                utility_account_id = str(forecast["preferredUtilityAccountId"])
                if not forecast["accountUuids"]:
                    continue
                account_uuid = forecast["accountUuids"][0]
                account_id = utility_account_id if utility_account_ids.count(utility_account_id) == 1 else account_uuid
                forecasts.append(
                    Forecast(
                        account=Account(
                            customer=Customer(uuid=customer["uuid"]),
                            uuid=account_uuid,
                            utility_account_id=utility_account_id,
                            id=account_id,
                            meter_type=MeterType(forecast["meterType"]),
                            read_resolution=None,
                        ),
                        start_date=date.fromisoformat(forecast["startDate"]),
                        end_date=date.fromisoformat(forecast["endDate"]),
                        current_date=date.fromisoformat(forecast["currentDate"]),
                        unit_of_measure=UnitOfMeasure(forecast["unitOfMeasure"]),
                        usage_to_date=float(forecast.get("usageToDate", 0)),
                        cost_to_date=float(forecast.get("costToDate", 0)),
                        forecasted_usage=float(forecast.get("forecastedUsage", 0)),
                        forecasted_cost=float(forecast.get("forecastedCost", 0)),
                        typical_usage=float(forecast.get("typicalUsage", 0)),
                        typical_cost=float(forecast.get("typicalCost", 0)),
                    )
                )
        return forecasts

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
        reads = await self._async_get_dated_data(account, aggregate_type, start_date, end_date, usage_only)
        result = []
        for read in reads:
            result.append(
                CostRead(
                    start_time=datetime.fromisoformat(read["startTime"]),
                    end_time=datetime.fromisoformat(read["endTime"]),
                    consumption=(read["value"] if "value" in read else read["consumption"]["value"]),
                    provided_cost=read.get("providedCost", 0) or 0,
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
        result = []
        for read in reads:
            result.append(
                UsageRead(
                    start_time=datetime.fromisoformat(read["startTime"]),
                    end_time=datetime.fromisoformat(read["endTime"]),
                    consumption=read["consumption"]["value"],
                )
            )
        return result

    async def _async_get_meters(self, account: Account) -> list[str]:
        """Get the list of meters for the selected account.

        Each meter is a string key for fetching from the realtime data API.
        """
        if not self.meters:
            url = (
                f"https://{self._get_subdomain()}.opower.com/{self._get_api_root()}"
                f"/edge/apis/cws-real-time-ami-v1/cws/{self.utility.utilitycode()}"
                f"/accounts/{account.uuid}/meters"
            )
            headers = self._get_headers(account.customer.uuid)
            result = await self._async_get_request(url, {}, headers)
            self.meters = list(result["meters_ids"])
        return self.meters

    async def async_get_realtime_usage_reads(
        self,
        account: Account,
    ) -> list[UsageRead]:
        """Get recent usage data from the "Real Time Usage" API.

        The realtime API returns data in approximately the last day in 15
        minute increments. Based on requests from ConEd, the API does not
        accept any parameters.

        Even though each account may have multiple meters, for now this
        function only queries data for the first meter on the account.
        """
        meters = await self._async_get_meters(account)
        assert len(meters) > 0
        meter = meters[0]

        url = (
            f"https://{self._get_subdomain()}.opower.com/{self._get_api_root()}"
            f"/edge/apis/cws-real-time-ami-v1/cws/{self.utility.utilitycode()}"
            f"/accounts/{account.uuid}/meters/{meter}/usage"
        )
        headers = self._get_headers(account.customer.uuid)
        result = await self._async_get_request(url, {}, headers)
        return [
            UsageRead(
                start_time=datetime.fromisoformat(read["startTime"]),
                end_time=datetime.fromisoformat(read["endTime"]),
                consumption=read["value"],
            )
            for read in result["reads"]
        ]

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
                return await self._async_fetch(account, aggregate_type, start_date, end_date, usage_only)
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
            reads = await self._async_fetch(account, aggregate_type, req_start, req_end, usage_only)
            if not reads:
                return result
            result = reads + result
            req_end = req_start.shift(days=-1)

    async def _async_fetch(
        self,
        account: Account,
        aggregate_type: AggregateType,
        start_date: datetime | arrow.Arrow | None = None,
        end_date: datetime | arrow.Arrow | None = None,
        usage_only: bool = False,
    ) -> list[Any]:
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
            return list(result["reads"])
        except ApiException as err:
            # Ignore server errors for BILL requests
            # that can happen if end_date is before account activation
            if err.status == 500 and aggregate_type == AggregateType.BILL:
                _LOGGER.debug("Ignoring error while fetching bill data: %s", err)
                return []
            raise

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

        opower_selected_entities = []
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
