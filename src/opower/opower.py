"""Implementation of opower.com JSON API."""

import dataclasses
from datetime import date, datetime
from enum import Enum
import json
import logging
from typing import Any
from urllib.parse import urlencode

import aiohttp
from aiohttp.client_exceptions import ClientResponseError
import arrow
from multidict import CIMultiDict

from .exceptions import CannotConnect, InvalidAuth
from .utilities import UtilityBase

_LOGGER = logging.getLogger(__file__)
DEBUG_LOG_RESPONSE = False


class MeterType(Enum):
    """Meter type. Electric or gas."""

    ELEC = "ELEC"
    GAS = "GAS"

    def __str__(self):
        """Return the value of the enum."""
        return self.value


class UnitOfMeasure(Enum):
    """Unit of measure for the associated meter type. kWh for electricity or Therm for gas,."""

    KWH = "KWH"
    THERM = "THERM"

    def __str__(self):
        """Return the value of the enum."""
        return self.value


class AggregateType(Enum):
    """How to aggregate historical data."""

    BILL = "bill"
    DAY = "day"
    HOUR = "hour"

    def __str__(self):
        """Return the value of the enum."""
        return self.value


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
    meter_type: MeterType


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
    consumption: float  # taken from value field, in KWH or THERM
    provided_cost: float  # in $


@dataclasses.dataclass
class UsageRead:
    """A read from the meter that has consumption data."""

    start_time: datetime
    end_time: datetime
    consumption: float  # taken from consumption.value field, in KWH or THERM


def get_supported_utilities() -> list[type["UtilityBase"]]:
    """Return a list of all supported utilities."""
    return UtilityBase.subclasses


def get_supported_utility_names() -> list[str]:
    """Return a list of names of all supported utilities."""
    return [utility.name() for utility in UtilityBase.subclasses]


def _select_utility(name_or_subdomain: str) -> type[UtilityBase]:
    """Return the utility with the given name or subdomain."""
    for utility in UtilityBase.subclasses:
        if name_or_subdomain.lower() in [
            utility.name().lower(),
            utility.__name__.lower(),
            utility.subdomain().lower(),
        ]:
            return utility
    raise ValueError(f"Utility {name_or_subdomain} not found")


class Opower:
    """Class that can get historical and forecasted usage/cost from an utility."""

    def __init__(
        self, session: aiohttp.ClientSession, utility: str, username: str, password: str
    ) -> None:
        """Initialize."""
        self.session = session
        self.session._default_headers = CIMultiDict({"User-Agent": "Mozilla/5.0"})
        self.session._raise_for_status = True
        self.utility: type[UtilityBase] = _select_utility(utility)
        self.username = username
        self.password = password
        self.customers = []

    async def async_login(self) -> None:
        """Login to the utility website and authorize opower.com for access.

        :raises InvalidAuth: if login information is incorrect
        :raises CannotConnect: if we receive any HTTP error
        """
        try:
            await self.utility.async_login(self.session, self.username, self.password)
        except ClientResponseError as err:
            if err.status in (401, 403):
                raise InvalidAuth(err)
            else:
                raise CannotConnect(err)

    async def async_get_forecast(self) -> list[Forecast]:
        """Get current and forecasted usage and cost for the current monthly bill.

        One forecast for each account, typically one for electricity, one for gas.
        """
        forecasts = []
        for customer in await self._async_get_customers():
            url = (
                "https://"
                f"{self.utility.subdomain()}"
                ".opower.com/ei/edge/apis/bill-forecast-cws-v1/cws/"
                f"{self.utility.subdomain()}"
                "/customers/"
                f"{customer.uuid}"
                "/combined-forecast"
            )
            _LOGGER.debug("Fetching: %s", url)
            async with self.session.get(url) as resp:
                result = await resp.json()
                if DEBUG_LOG_RESPONSE:
                    _LOGGER.debug("Fetched: %s", json.dumps(result, indent=2))
            for forecast in result["accountForecasts"]:
                forecasts.append(
                    Forecast(
                        account=Account(
                            customer=customer,
                            uuid=forecast["accountUuids"][0],
                            utility_account_id=str(
                                forecast["preferredUtilityAccountId"]
                            ),
                            meter_type=MeterType(forecast["meterType"]),
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

    async def _async_get_customers(self) -> list[Customer]:
        """Get customers associated to the user."""
        # Cache the customers
        if not self.customers:
            url = (
                "https://"
                f"{self.utility.subdomain()}"
                ".opower.com/ei/edge/apis/multi-account-v1/cws/"
                f"{self.utility.subdomain()}"
                "/customers?offset=0&batchSize=100&addressFilter="
            )
            _LOGGER.debug("Fetching: %s", url)
            async with self.session.get(url) as resp:
                result = await resp.json()
                if DEBUG_LOG_RESPONSE:
                    _LOGGER.debug("Fetched: %s", json.dumps(result, indent=2))
            for customer in result["customers"]:
                self.customers.append(Customer(uuid=customer["uuid"]))
        assert self.customers
        return self.customers

    async def async_get_cost_reads(
        self,
        account: Account,
        aggregate_type: AggregateType,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> list[CostRead]:
        """Get cost data for the selected account in the given date range aggregated by bill/day/hour.

        The resolution for gas is typically 'day' while for electricity it's hour or quarter hour.
        Opower typically keeps historical cost data for 3 years.
        """
        url = (
            "https://"
            f"{self.utility.subdomain()}"
            ".opower.com/ei/edge/apis/DataBrowser-v1/cws/cost/utilityAccount/"
            f"{account.uuid}"
        )
        reads = await self._async_get_dated_data(
            account.customer, url, aggregate_type, start_date, end_date
        )
        result = []
        for read in reads:
            result.append(
                CostRead(
                    start_time=datetime.fromisoformat(read["startTime"]),
                    end_time=datetime.fromisoformat(read["endTime"]),
                    consumption=read["value"],
                    provided_cost=read["providedCost"] or 0,
                )
            )
        # Remove last entries with 0 values
        while result:
            last = result.pop()
            if last.provided_cost != 0 or last.consumption != 0:
                result.append(last)
                break
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
        url = (
            "https://"
            f"{self.utility.subdomain()}"
            ".opower.com/ei/edge/apis/DataBrowser-v1/cws/utilities/"
            f"{self.utility.subdomain()}"
            "/utilityAccounts/"
            f"{account.uuid}"
            "/reads"
        )
        reads = await self._async_get_dated_data(
            account.customer, url, aggregate_type, start_date, end_date
        )
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

    async def _async_get_dated_data(
        self,
        customer: Customer,
        url: str,
        aggregate_type: AggregateType,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> list[Any]:
        """Wrap _async_fetch by breaking requests for big date ranges to smaller ones to satisfy opower imposed limits."""
        if start_date is None:
            if aggregate_type == AggregateType.BILL:
                return await self._async_fetch(
                    customer, url, aggregate_type, start_date, end_date
                )
            raise ValueError("start_date is required unless aggregate_type=BILL")
        if end_date is None:
            raise ValueError("end_date is required unless aggregate_type=BILL")

        start = arrow.get(start_date.date(), self.utility.timezone())
        end = arrow.get(end_date.date(), self.utility.timezone()).shift(days=1)

        max_request_days = None
        if aggregate_type == AggregateType.DAY:
            max_request_days = 363
        elif aggregate_type == AggregateType.HOUR:
            max_request_days = 26

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
            reads = await self._async_fetch(
                customer, url, aggregate_type, req_start, req_end
            )
            if not reads:
                return result
            result = reads + result
            req_end = req_start.shift(days=-1)

    async def _async_fetch(
        self,
        customer: Customer,
        url: str,
        aggregate_type: AggregateType,
        start_date: datetime | arrow.Arrow | None = None,
        end_date: datetime | arrow.Arrow | None = None,
    ) -> list[Any]:
        convert_to_date = "/cws/utilities/" in url
        params = {"aggregateType": aggregate_type.value}
        headers = {
            "Opower-Selected-Entities": f'["urn:opower:customer:uuid:{customer.uuid}"]'
        }
        if start_date:
            params["startDate"] = (
                start_date.date() if convert_to_date else start_date
            ).isoformat()
        if end_date:
            params["endDate"] = (
                end_date.date() if convert_to_date else end_date
            ).isoformat()
        _LOGGER.debug("Fetching: %s?%s", url, urlencode(params))
        try:
            async with self.session.get(url, params=params, headers=headers) as resp:
                result = await resp.json()
                if DEBUG_LOG_RESPONSE:
                    _LOGGER.debug("Fetched: %s", json.dumps(result, indent=2))
                return result["reads"]
        except ClientResponseError as err:
            # Ignore server errors for BILL requests
            # that can happen if end_date is before account activation
            if err.status == 500 and aggregate_type == AggregateType.BILL:
                return []
            raise err
