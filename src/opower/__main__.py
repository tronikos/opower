# ruff: noqa: T201, ASYNC230, ASYNC250, PLR0912, PLR0915
"""Demo usage of Opower library."""

import argparse
import asyncio
import csv
import json
import logging
from collections.abc import Sequence
from datetime import datetime, timedelta
from getpass import getpass

import aiohttp

from opower import (
    AggregateType,
    InvalidAuth,
    MfaChallenge,
    Opower,
    ReadResolution,
    create_cookie_jar,
    get_supported_utilities,
    select_utility,
)
from opower.opower import CostRead, UsageRead


def _output_usage_reads(usage_data: Sequence[UsageRead], csv_file_path: str | None) -> None:
    """Write usage reads to CSV or stdout."""
    if csv_file_path:
        with open(csv_file_path, "w", newline="") as csv_file:
            writer = csv.writer(csv_file)
            writer.writerow(["start_time", "end_time", "consumption"])
            for read in usage_data:
                writer.writerow([read.start_time, read.end_time, read.consumption])
    else:
        print("start_time\tend_time\tconsumption\tstart_minus_prev_end\tend_minus_prev_end")
        prev_end: datetime | None = None
        for read in usage_data:
            start_minus_prev_end = None if prev_end is None else read.start_time - prev_end
            end_minus_prev_end = None if prev_end is None else read.end_time - prev_end
            prev_end = read.end_time
            print(f"{read.start_time}\t{read.end_time}\t{read.consumption}\t{start_minus_prev_end}\t{end_minus_prev_end}")
        print()


def _output_cost_reads(cost_data: Sequence[CostRead], csv_file_path: str | None, is_bill: bool) -> None:
    """Write cost reads to CSV or stdout."""
    if csv_file_path:
        with open(csv_file_path, "w", newline="") as csv_file:
            writer = csv.writer(csv_file)
            if is_bill:
                writer.writerow(["start_time", "end_time", "consumption", "provided_cost", "usage_charges", "current_amount"])
            else:
                writer.writerow(["start_time", "end_time", "consumption", "provided_cost"])
            for read in cost_data:
                row = [read.start_time, read.end_time, read.consumption, read.provided_cost]
                if is_bill:
                    row.extend([read.usage_charges, read.current_amount])
                writer.writerow(row)
    else:
        if is_bill:
            print(
                "start_time\tend_time\tconsumption\tprovided_cost"
                "\tusage_charges\tcurrent_amount\tstart_minus_prev_end\tend_minus_prev_end"
            )
        else:
            print("start_time\tend_time\tconsumption\tprovided_cost\tstart_minus_prev_end\tend_minus_prev_end")
        prev_end: datetime | None = None
        for read in cost_data:
            start_minus_prev_end = None if prev_end is None else read.start_time - prev_end
            end_minus_prev_end = None if prev_end is None else read.end_time - prev_end
            prev_end = read.end_time
            line = f"{read.start_time}\t{read.end_time}\t{read.consumption}\t{read.provided_cost}"
            if is_bill:
                line += f"\t{read.usage_charges}\t{read.current_amount}"
            line += f"\t{start_minus_prev_end}\t{end_minus_prev_end}"
            print(line)
        print()


async def _main() -> None:
    supported_utilities = [utility.__name__.lower() for utility in get_supported_utilities()]
    parser = argparse.ArgumentParser()
    parser.add_argument(
        "--utility",
        help="Utility. If not provided, you will be asked for it",
        choices=supported_utilities,
        type=str.lower,
    )
    parser.add_argument(
        "--username",
        help="Username for logging into the utility's website. If not provided, you will be asked for it",
    )
    parser.add_argument(
        "--password",
        help="Password for logging into the utility's website. If not provided, you will be asked for it",
    )
    parser.add_argument(
        "--totp_secret",
        help="TOTP secret for logging into the utility's website (for TOTP-based MFA).",
    )
    parser.add_argument(
        "--login_data_file",
        help="Where to store login data from MFA. If not provided, login data will not be saved.",
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
        type=datetime.fromisoformat,
        default=datetime.now() - timedelta(days=7),
    )
    parser.add_argument(
        "--end_date",
        help="end datetime for historical data. Defaults to now",
        type=datetime.fromisoformat,
        default=datetime.now(),
    )
    parser.add_argument(
        "--usage_only",
        help="If true will output usage only, not cost",
        action="store_true",
    )
    parser.add_argument(
        "--csv",
        help="csv file to store data",
    )
    parser.add_argument("-v", "--verbose", help="enable verbose logging", action="count", default=0)
    parser.add_argument(
        "--realtime",
        help="If true, fetches usage-only data from the realtime API. Not all utilities support the realtime API.",
        action="store_true",
    )
    args = parser.parse_args()

    logging.basicConfig(level=logging.DEBUG - args.verbose + 1 if args.verbose > 0 else logging.INFO)

    utility = args.utility or input(f"Utility, one of {supported_utilities}: ")
    utility_class = select_utility(utility)
    username = args.username or input("Username: ")
    password = args.password or getpass("Password: ")
    totp_secret = args.totp_secret or (getpass("TOTP secret: ") if utility_class.accepts_totp_secret() else None)
    login_data = None
    if args.login_data_file:
        try:
            with open(args.login_data_file) as file:
                login_data = json.load(file)
        except (FileNotFoundError, json.JSONDecodeError):
            pass

    async with aiohttp.ClientSession(cookie_jar=create_cookie_jar()) as session:
        opower = Opower(
            session,
            utility,
            username,
            password,
            totp_secret,
            login_data,
        )
        try:
            await opower.async_login()
        except MfaChallenge as e:
            handler = e.handler
            print(f"MFA Challenge: {e}")
            options = await handler.async_get_mfa_options()
            if options:
                print("Please select an MFA option:")
                for i, (_, value) in enumerate(options.items()):
                    print(f"  [{i + 1}] {value}")
                choice_index = int(input("Enter the number for your choice: ")) - 1
                choice_key = list(options.keys())[choice_index]
                await handler.async_select_mfa_option(choice_key)
                print(f"A security code has been sent via {options[choice_key]}.")
            code = input("Enter the security code: ")
            try:
                login_data = await handler.async_submit_mfa_code(code)
            except InvalidAuth:
                logging.exception("MFA failed")
                return
            else:
                print("MFA validation successful.")
                if args.login_data_file:
                    with open(args.login_data_file, "w") as file:
                        json.dump(login_data, file, indent=4)
                opower.login_data = login_data
                await opower.async_login()
        except InvalidAuth:
            logging.exception("Login failed")
            return

        if not args.csv:
            for forecast in await opower.async_get_forecast():
                print("\nCurrent bill forecast:", forecast)
        for account in await opower.async_get_accounts():
            aggregate_type = args.aggregate_type
            if aggregate_type == AggregateType.HOUR and account.read_resolution == ReadResolution.DAY:
                aggregate_type = AggregateType.DAY
            elif aggregate_type != AggregateType.BILL and account.read_resolution == ReadResolution.BILLING:
                aggregate_type = AggregateType.BILL
            if not args.csv:
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
            # Realtime data does not include cost data, so effectively --realtime implies --usage_only.
            if args.usage_only or args.realtime:
                if args.realtime:
                    usage_data = await opower.async_get_realtime_usage_reads(account)
                else:
                    usage_data = await opower.async_get_usage_reads(
                        account,
                        aggregate_type,
                        args.start_date,
                        args.end_date,
                    )
                _output_usage_reads(usage_data, args.csv)
            else:
                cost_data = await opower.async_get_cost_reads(
                    account,
                    aggregate_type,
                    args.start_date,
                    args.end_date,
                )
                _output_cost_reads(cost_data, args.csv, aggregate_type == AggregateType.BILL)


if __name__ == "__main__":
    asyncio.run(_main())
