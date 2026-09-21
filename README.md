# opower

[![PyPI Version](https://img.shields.io/pypi/v/opower.svg)](https://pypi.org/project/opower/)

A Python library and command-line tool for getting historical and forecasted usage/cost data from utilities that use opower.com.

This library is used by the [Opower integration in Home Assistant](https://www.home-assistant.io/integrations/opower/).

## Completed bills

`Opower.async_get_bills()` returns completed bills, newest first, with a default
limit of 25 per billing account. Bill-level `usage_charges` remain separate from
each service agreement's `current_amount` and service quantities because a bill
can cover more than one utility account. Missing values are returned as `None`;
the library does not estimate or distribute bill totals across daily or interval
usage. A bill is omitted when any of its segments cannot be mapped safely to a
known account. Segments can repeat an account. Results are best-effort: a
customer-specific request failure does not discard other customers' bills, and
an empty result can also mean the completed-bills endpoint is unavailable or
unauthorized.

Use `async_get_cost_reads(account, AggregateType.BILL)` for the utility's existing
per-account billing cost series. Use `async_get_bills()` when the distinct
GraphQL bill totals and service-agreement quantities are needed.
Run `python -m opower --bills` to inspect completed bills from the command line.
This mode ignores other data-output options and cannot be combined with `--csv`.

On net-metered accounts, energy charges may be deferred to an annual true-up.
In that case, `usage_charges` can be `None` on monthly bills and
`current_amount` can contain only the amount invoiced that month, such as a base
charge. Neither value should be treated as the cost of energy used. Use
`async_get_cost_reads(account, AggregateType.BILL)` when that per-account cost
series is available.

## Supported Utilities

- AES Indiana
- American Electric Power (AEP) subsidiaries
  - AEP Ohio
  - AEP Texas
  - Appalachian Power
  - Indiana Michigan Power
  - Kentucky Power
  - Public Service Company of Oklahoma (PSO)
  - Southwestern Electric Power Company (SWEPCO)
- Burbank Water and Power (BWP)
- City of Austin Utilities
- Clark Public Utilities
- Consolidated Edison (ConEd) and subsidiaries
  - Orange & Rockland Utilities (ORU)
- Duquesne Light Company (DQE)
- Evergy
- Eversource
- Exelon subsidiaries
  - Atlantic City Electric
  - Baltimore Gas and Electric (BGE)
  - Commonwealth Edison (ComEd)
  - Delmarva Power
  - PECO Energy Company (PECO)
  - Potomac Electric Power Company (Pepco)
- Glendale Water and Power (GWP)
- Northern Indiana Public Service Company (NIPSCO)
- Pacific Gas & Electric (PG&E)
- Puget Sound Energy (PSE)
- Rhode Island Energy (RIEnergy)
- Sacramento Municipal Utility District (SMUD)
- Seattle City Light (SCL)
- Southern Maryland Electric Cooperative (SMECO)
- Southwest Gas

## Contributing

Contributions are welcome! Please feel free to submit a pull request.

### Adding a New Utility

To add support for a new Opower-based utility, follow these steps:

1. **Verify it's an Opower utility:** Use your browser's developer tools on your utility's website. If the network tab shows requests to a domain like `utility.opower.com`, it's a good candidate.
2. **Create a utility file:** Add a new file in `src/opower/utilities` that inherits from `UtilityBase`. Name the file after the utility's website (e.g., `newutility.py` for `newutility.com`).
3. **Respect scraping limitations:** This library is used by Home Assistant and must adhere to its [architecture rules](https://github.com/home-assistant/architecture/blob/master/adr/0004-webscraping.md). A headless browser cannot be a dependency, and HTML parsing is only allowed for the authentication phase.
    > An exception is made for the authentication phase. An integration is allowed to extract fields from forms. To make it more robust, data should not be gathered by scraping individual fields but instead scrape all fields at once.

## Development environment

```sh
python3 -m venv .venv
source .venv/bin/activate
# for Windows CMD:
# .venv\Scripts\activate.bat
# for Windows PowerShell:
# .venv\Scripts\Activate.ps1

# Install dependencies
python -m pip install --upgrade pip
python -m pip install -e .

# Run pre-commit
python -m pip install pre-commit
pre-commit install
pre-commit run --all-files

# Run tests
python -m pip install -e ".[test]"
pytest

# Run command line
python -m opower --help
# To output debug logs and API responses to a file run:
python -m opower -vv 2> out.txt
```

Instead of passing credentials on the command line or typing them at the prompts,
you can put them in the environment or in a `.env` file in the current directory:

```sh
OPOWER_UTILITY=pge
OPOWER_USERNAME=user@example.com
OPOWER_PASSWORD=secret
# Only for utilities with TOTP-based MFA
OPOWER_TOTP_SECRET=...
# Only for utilities with interactive MFA, e.g. PG&E
OPOWER_LOGIN_DATA_FILE=login_data.txt
```

Real environment variables take precedence over the `.env` file, and command line
arguments take precedence over both.

```sh
# Build package
python -m pip install build
python -m build
```
