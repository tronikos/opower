# ruff: noqa: T201, ASYNC230, ASYNC250, PLR0915
"""Demo usage of Opower library."""

import argparse
import asyncio
import csv
import json
import logging
import os
from datetime import datetime, timedelta
from getpass import getpass
from pathlib import Path

import aiohttp

from opower import (
    Account,
    AggregateType,
    InvalidAuth,
    MfaChallenge,
    Opower,
    ReadResolution,
    create_cookie_jar,
    get_supported_utilities,
    select_utility,
)


def _unquote(value: str) -> str:
    """Remove one matching pair of surrounding quotes, leaving the value otherwise intact.

    Stripping every quote character instead would corrupt a value that
    legitimately starts or ends with one, such as a password of ``"secret``.
    """
    if len(value) >= 2 and value[0] == value[-1] and value[0] in "\"'":
        return value[1:-1]
    return value


def _load_dotenv(path: Path = Path(".env")) -> dict[str, str]:
    """Read simple KEY=VALUE lines from a .env file, if one exists."""
    values: dict[str, str] = {}
    if not path.is_file():
        return values
    for raw_line in path.read_text().splitlines():
        line = raw_line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        values[key.strip()] = _unquote(value.strip())
    return values


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

    dotenv = _load_dotenv()

    def env(key: str) -> str | None:
        """Return key from the real environment, else from the .env file.

        A real environment variable wins over the .env file, matching python-dotenv.
        """
        return os.environ.get(key) or dotenv.get(key)

    def resolve(arg: str | None, key: str, prompt: str, secret: bool = False) -> str:
        """Return the command line argument, else the environment, else ask for it."""
        value = arg or env(key)
        if value:
            return value
        return getpass(prompt) if secret else input(prompt)

    utility = resolve(args.utility, "OPOWER_UTILITY", f"Utility, one of {supported_utilities}: ")
    utility_class = select_utility(utility)
    username = resolve(args.username, "OPOWER_USERNAME", "Username: ")
    password = resolve(args.password, "OPOWER_PASSWORD", "Password: ", secret=True)
    totp_secret = (
        resolve(args.totp_secret, "OPOWER_TOTP_SECRET", "TOTP secret: ", secret=True)
        if utility_class.accepts_totp_secret()
        else None
    )
    login_data_file = args.login_data_file or env("OPOWER_LOGIN_DATA_FILE")
    login_data = None
    if login_data_file:
        try:
            with open(login_data_file) as file:
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
                if login_data_file:
                    with open(login_data_file, "w") as file:
                        json.dump(login_data, file, indent=4)
                opower = Opower(session, utility, username, password, totp_secret, login_data)
                await opower.async_login()
        except InvalidAuth:
            logging.exception("Login failed")
            return

        if not args.csv:
            for forecast in await opower.async_get_forecast():
                print("\nCurrent bill forecast:", forecast)

        accounts = await opower.async_get_accounts()
        for account in accounts:
            await _output_account(opower, account, args, _csv_path(args.csv, account, len(accounts)))


def _csv_path(csv_arg: str | None, account: Account, num_accounts: int) -> Path | None:
    """Return the CSV file to write for an account, or None when not writing CSV.

    A single account keeps the requested filename. Multiple accounts each get
    their own file, since one shared file could not tell their rows apart.
    """
    if not csv_arg:
        return None
    path = Path(csv_arg)
    if num_accounts == 1:
        return path
    return path.with_name(f"{path.stem}-{account.id}{path.suffix}")


def _resolve_aggregate_type(requested: AggregateType, read_resolution: ReadResolution | None) -> AggregateType:
    """Downgrade the requested aggregation to what the account actually supports."""
    if requested == AggregateType.HOUR and read_resolution == ReadResolution.DAY:
        return AggregateType.DAY
    if requested != AggregateType.BILL and read_resolution == ReadResolution.BILLING:
        return AggregateType.BILL
    return requested


async def _output_account(
    opower: Opower,
    account: Account,
    args: argparse.Namespace,
    csv_path: Path | None,
) -> None:
    """Fetch and print (or write) the historical data for a single account."""
    aggregate_type = _resolve_aggregate_type(args.aggregate_type, account.read_resolution)
    if not csv_path:
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
        rows = [(read.start_time, read.end_time, [read.consumption, read.imported, read.exported]) for read in usage_data]
        headers = ["consumption", "imported", "exported"]
    else:
        cost_data = await opower.async_get_cost_reads(
            account,
            aggregate_type,
            args.start_date,
            args.end_date,
        )
        rows = [
            (read.start_time, read.end_time, [read.consumption, read.provided_cost, read.imported, read.exported])
            for read in cost_data
        ]
        headers = ["consumption", "provided_cost", "imported", "exported"]

    if csv_path:
        with csv_path.open("w", newline="") as csv_file:
            csv_writer = csv.writer(csv_file)
            csv_writer.writerow(["start_time", "end_time", *headers])
            for start_time, end_time, values in rows:
                csv_writer.writerow([start_time, end_time, *values])
        return

    print("\t".join(["start_time", "end_time", *headers, "start_minus_prev_end", "end_minus_prev_end"]))
    prev_end: datetime | None = None
    for start_time, end_time, values in rows:
        start_minus_prev_end = None if prev_end is None else start_time - prev_end
        end_minus_prev_end = None if prev_end is None else end_time - prev_end
        prev_end = end_time
        print("\t".join(str(v) for v in [start_time, end_time, *values, start_minus_prev_end, end_minus_prev_end]))
    print()


if __name__ == "__main__":
    asyncio.run(_main())
