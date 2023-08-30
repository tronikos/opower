"""Demo usage of Opower library."""

import argparse
import asyncio
from datetime import datetime, timedelta
from getpass import getpass
import logging
from typing import Optional

import aiohttp

from opower import (
    AggregateType,
    Opower,
    ReadResolution,
    get_supported_utilities,
    select_utility,
)


async def _main() -> None:
    supported_utilities = [
        utility.__name__.lower() for utility in get_supported_utilities()
    ]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--utility",
        help="Utility. If not provided, you will be asked for it",
        choices=supported_utilities,
        type=str.lower,
    )
    parser.add_argument(
        "--username",
        help="Username for logging into the utility's website. "
        "If not provided, you will be asked for it",
    )
    parser.add_argument(
        "--password",
        help="Password for logging into the utility's website. "
        "If not provided, you will be asked for it",
    )
    parser.add_argument(
        "--mfa_secret",
        help="MFA secret for logging into the utility's website.",
    )
    parser.add_argument(
        "--aggregate_type",
        help="How to aggregate historical data. Defaults to day",
        choices=list(AggregateType),
        type=AggregateType,
        default=AggregateType.DAY,
    )
    parser.add_argument(
        "--start_date",
        help="Start datetime for historical data. Defaults to 7 days ago",
        type=lambda s: datetime.fromisoformat(s),
        default=datetime.now() - timedelta(days=7),
    )
    parser.add_argument(
        "--end_date",
        help="end datetime for historical data. Defaults to now",
        type=lambda s: datetime.fromisoformat(s),
        default=datetime.now(),
    )
    parser.add_argument(
        "--usage_only",
        help="If true will output usage only, not cost",
        action="store_true",
    )
    parser.add_argument(
        "-v", "--verbose", help="enable verbose logging", action="store_true"
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG if args.verbose else logging.INFO)

    utility = args.utility or input(f"Utility, one of {supported_utilities}: ")
    username = args.username or input("Username: ")
    password = args.password or getpass("Password: ")
    mfa_secret = args.mfa_secret or (
        input("2FA secret: ") if select_utility(utility).accepts_mfa() else None
    )

    async with aiohttp.ClientSession() as session:
        opower = Opower(session, utility, username, password, mfa_secret)
        await opower.async_login()
        # Re-login to make sure code handles already logged in sessions.
        await opower.async_login()
        for forecast in await opower.async_get_forecast():
            print("\nCurrent bill forecast:", forecast)
        for account in await opower.async_get_accounts():
            aggregate_type = args.aggregate_type
            if (
                aggregate_type == AggregateType.HOUR
                and account.read_resolution == ReadResolution.DAY
            ):
                aggregate_type = AggregateType.DAY
            elif (
                aggregate_type != AggregateType.BILL
                and account.read_resolution == ReadResolution.BILLING
            ):
                aggregate_type = AggregateType.BILL
            print(
                "\nGetting historical data: account=",
                account,
                "aggregate_type=",
                aggregate_type,
                "start_date=",
                args.start_date,
                "end_date=",
                args.end_date,
            )
            prev_end: Optional[datetime] = None
            if args.usage_only:
                usage_data = await opower.async_get_usage_reads(
                    account,
                    aggregate_type,
                    args.start_date,
                    args.end_date,
                )
                print(
                    "start_time\tend_time\tconsumption"
                    "\tstart_minus_prev_end\tend_minus_prev_end"
                )
                for usage_read in usage_data:
                    start_minus_prev_end = (
                        None if prev_end is None else usage_read.start_time - prev_end
                    )
                    end_minus_prev_end = (
                        None if prev_end is None else usage_read.end_time - prev_end
                    )
                    prev_end = usage_read.end_time
                    print(
                        f"{usage_read.start_time}"
                        f"\t{usage_read.end_time}"
                        f"\t{usage_read.consumption}"
                        f"\t{start_minus_prev_end}"
                        f"\t{end_minus_prev_end}"
                    )
            else:
                cost_data = await opower.async_get_cost_reads(
                    account,
                    aggregate_type,
                    args.start_date,
                    args.end_date,
                )
                print(
                    "start_time\tend_time\tconsumption\tprovided_cost"
                    "\tstart_minus_prev_end\tend_minus_prev_end"
                )
                for cost_read in cost_data:
                    start_minus_prev_end = (
                        None if prev_end is None else cost_read.start_time - prev_end
                    )
                    end_minus_prev_end = (
                        None if prev_end is None else cost_read.end_time - prev_end
                    )
                    prev_end = cost_read.end_time
                    print(
                        f"{cost_read.start_time}"
                        f"\t{cost_read.end_time}"
                        f"\t{cost_read.consumption}"
                        f"\t{cost_read.provided_cost}"
                        f"\t{start_minus_prev_end}"
                        f"\t{end_minus_prev_end}"
                    )
            print()


asyncio.run(_main())
