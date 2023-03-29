"""Implementation of opower.com JSON API."""

import dataclasses
from datetime import date, datetime
from enum import Enum
import json
import logging
import re
from typing import Any
from urllib.parse import urlencode

import aiohttp
import arrow
from multidict import CIMultiDict

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
class Account:
    """Data about an account."""

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


def get_supported_utility_names() -> list[str]:
    """Return a list of names of all supported utilities."""
    return [utility.name() for utility in UtilityBase.subclasses]


def get_supported_utility_subdomains() -> list[str]:
    """Return a list of subdomains of all supported utilities."""
    return [utility.subdomain() for utility in UtilityBase.subclasses]


def _select_utility(name_or_subdomain: str) -> type[UtilityBase]:
    """Return the utility with the given name or subdomain."""
    for utility in UtilityBase.subclasses:
        if name_or_subdomain in [utility.name(), utility.subdomain()]:
            return utility
    raise ValueError(f"Utility {name_or_subdomain} not found")


def _get_form_action_url_and_hidden_inputs(html: str):
    """Return the URL and hidden inputs from the single form in a page."""
    match = re.search(r'action="([^"]*)"', html)
    if not match:
        return None, None
    action_url = match.group(1)
    inputs = {}
    for match in re.finditer(
        r'input\s*type="hidden"\s*name="([^"]*)"\s*value="([^"]*)"', html
    ):
        inputs[match.group(1)] = match.group(2)
    return action_url, inputs


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
        self.customer = None

    async def async_login(self) -> None:
        """Login to the utility website and authorize opower.com for access."""
        url = await self.utility.login(self.session, self.username, self.password)
        await self._async_authorize(url)

    async def _async_authorize(self, url: str) -> None:
        # Fetch the URL on the utility website to get RelayState and SAMLResponse.
        async with self.session.get(url) as resp:
            result = await resp.text()
        action_url, hidden_inputs = _get_form_action_url_and_hidden_inputs(result)
        assert action_url == "https://sso2.opower.com/sp/ACS.saml2"
        assert set(hidden_inputs.keys()) == {"RelayState", "SAMLResponse"}

        # Pass them to https://sso2.opower.com/sp/ACS.saml2 to get opentoken.
        async with self.session.post(action_url, data=hidden_inputs) as resp:
            result = await resp.text()
        action_url, hidden_inputs = _get_form_action_url_and_hidden_inputs(result)
        assert set(hidden_inputs.keys()) == {"opentoken"}

        # Pass it back to the utility website.
        async with self.session.post(action_url, data=hidden_inputs) as resp:
            pass

    async def async_get_accounts(self) -> list[Account]:
        """Get a list of accounts for the signed in user.

        Typically one account for electricity and one for gas.
        """
        customer = await self._async_get_customer()
        accounts = []
        for account in customer["utilityAccounts"]:
            accounts.append(
                Account(
                    uuid=account["uuid"],
                    utility_account_id=account["preferredUtilityAccountId"],
                    meter_type=MeterType(account["meterType"]),
                )
            )
        return accounts

    async def async_get_forecast(self) -> list[Forecast]:
        """Get current and forecasted usage and cost for the current monthly bill.

        One forecast for each account, typically one for electricity, one for gas.
        """
        customer = await self._async_get_customer()
        customer_uuid = customer["uuid"]
        url = (
            "https://"
            f"{self.utility.subdomain()}"
            ".opower.com/ei/edge/apis/bill-forecast-cws-v1/cws/"
            f"{self.utility.subdomain()}"
            "/customers/"
            f"{customer_uuid}"
            "/combined-forecast"
        )
        _LOGGER.debug("Fetching: %s", url)
        async with self.session.get(url) as resp:
            result = await resp.json()
            if DEBUG_LOG_RESPONSE:
                _LOGGER.debug("Fetched: %s", json.dumps(result, indent=2))
        forecasts = []
        for forecast in result["accountForecasts"]:
            forecasts.append(
                Forecast(
                    account=Account(
                        uuid=forecast["accountUuids"][0],
                        utility_account_id=str(forecast["preferredUtilityAccountId"]),
                        meter_type=MeterType(forecast["meterType"]),
                    ),
                    start_date=date.fromisoformat(forecast["startDate"]),
                    end_date=date.fromisoformat(forecast["endDate"]),
                    current_date=date.fromisoformat(forecast["currentDate"]),
                    unit_of_measure=UnitOfMeasure(forecast["unitOfMeasure"]),
                    usage_to_date=float(forecast["usageToDate"]),
                    cost_to_date=float(forecast["costToDate"]),
                    forecasted_usage=float(forecast["forecastedUsage"]),
                    forecasted_cost=float(forecast["forecastedCost"]),
                    typical_usage=float(forecast["typicalUsage"]),
                    typical_cost=float(forecast["typicalCost"]),
                )
            )
        return forecasts

    async def _async_get_customer(self):
        """Get information about the current customer."""
        # Cache the customer data
        if not self.customer:
            async with self.session.get(
                "https://"
                f"{self.utility.subdomain()}"
                ".opower.com/ei/edge/apis/multi-account-v1/cws/"
                f"{self.utility.subdomain()}"
                # Alternative to get multiple accounts:
                # /customers?offset=0&batchSize=100&addressFilter=
                "/customers/current"
            ) as resp:
                self.customer = await resp.json()
                if DEBUG_LOG_RESPONSE:
                    _LOGGER.debug("Fetched: %s", json.dumps(self.customer, indent=2))
        assert self.customer
        return self.customer

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
            url, aggregate_type, start_date, end_date
        )
        result = []
        for read in reads:
            result.append(
                CostRead(
                    start_time=datetime.fromisoformat(read["startTime"]),
                    end_time=datetime.fromisoformat(read["endTime"]),
                    consumption=read["value"],
                    provided_cost=read["providedCost"],
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
            url, aggregate_type, start_date, end_date
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
        url: str,
        aggregate_type: AggregateType,
        start_date: datetime | None = None,
        end_date: datetime | None = None,
    ) -> list[Any]:
        """Wrap _async_fetch by breaking requests for big date ranges to smaller ones to satisfy opower imposed limits."""
        if start_date is None:
            if aggregate_type == AggregateType.BILL:
                return await self._async_fetch(
                    url, aggregate_type, start_date, end_date
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
            reads = await self._async_fetch(url, aggregate_type, req_start, req_end)
            if not reads:
                return result
            result = reads + result
            req_end = req_start.shift(days=-1)

    async def _async_fetch(
        self,
        url: str,
        aggregate_type: AggregateType,
        start_date: datetime | arrow.Arrow | None = None,
        end_date: datetime | arrow.Arrow | None = None,
    ) -> list[Any]:
        convert_to_date = "/cws/utilities/" in url
        params = {"aggregateType": aggregate_type.value}
        if start_date:
            params["startDate"] = (
                start_date.date() if convert_to_date else start_date
            ).isoformat()
        if end_date:
            params["endDate"] = (
                end_date.date() if convert_to_date else end_date
            ).isoformat()
        _LOGGER.debug("Fetching: %s?%s", url, urlencode(params))
        async with self.session.get(url, params=params) as resp:
            result = await resp.json()
            if DEBUG_LOG_RESPONSE:
                _LOGGER.debug("Fetched: %s", json.dumps(result, indent=2))
            return result["reads"]
