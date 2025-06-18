# opower

A Python library for getting historical and forecasted usage/cost from utilities that use opower.com such as PG&amp;E.

Supported utilities (in alphabetical order):

- American Electric Power (AEP) subsidiaries
  - AEP Ohio
  - AEP Texas
  - Appalachian Power
  - Indiana Michigan Power
  - Kentucky Power
  - Public Service Company of Oklahoma (PSO)
  - Southwestern Electric Power Company (SWEPCO)
- Arizona Public Service (APS)
- Burbank Water and Power (BWP)
- City of Austin Utilities
- Consolidated Edison (ConEd)
  - Orange & Rockland Utilities (ORU)
- Duquesne Light Company (DQE)
- Enmax Energy
- Evergy
- Exelon subsidiaries
  - Atlantic City Electric
  - Baltimore Gas and Electric (BGE)
  - Commonwealth Edison (ComEd)
  - Delmarva Power
  - PECO Energy Company (PECO)
  - Potomac Electric Power Company (Pepco)
- Glendale Water and Power (GWP)
- Mercury NZ Limited
- National Grid subsidiaries
  - National Grid Massachusetts
  - National Grid NY Long Island
  - National Grid NY Metro
  - National Grid NY Upstate
- Pacific Gas & Electric (PG&E)
- Portland General Electric (PGE)
- Puget Sound Energy (PSE)
- Sacramento Municipal Utility District (SMUD)
- Seattle City Light (SCL)

## Support a new utility

To add support for a new utility that uses opower JSON API (you can tell if the energy dashboard of your utility makes network requests to opower.com, e.g. pge.opower.com in the network tab of your browser's developer tools) add a file similar to
[pge.py](https://github.com/tronikos/opower/blob/main/src/opower/utilities/pge.py)
or [pse.py](https://github.com/tronikos/opower/blob/main/src/opower/utilities/pse.py)
or [bge.py](https://github.com/tronikos/opower/blob/main/src/opower/utilities/bge.py)
etc.

Name the file after the utility website, e.g. pge.py for pge.com.

Since this library is used by Home Assistant, see <https://www.home-assistant.io/integrations/opower/>, per <https://github.com/home-assistant/architecture/blob/master/adr/0004-webscraping.md> we cannot have a dependency on a headless browser and we can only parse HTML during login.

> An exception is made for the authentication phase. An integration is allowed to extract fields from forms. To make it more robust, data should not be gathered by scraping individual fields but instead scrape all fields at once.

So follow that advice and try to scrape all fields at once, similar to the `get_form_action_url_and_hidden_inputs` in helpers.py.

## Example Usage - CLI

The opower library comes with a CLI interface to get familiar with the library and read actual data from your utility.

```sh
# Show information on how to call the library CLI interface
python -m opower --help

# Example: show recent usage only, for all accounts:
python -m opower --utility comed --username <username> --password <password> --usage_only --aggregate_type day
[...]
start_time	end_time	consumption	start_minus_prev_end	end_minus_prev_end
2025-06-10 00:00:00-05:00	2025-06-11 00:00:00-05:00	-9.44	None	None
2025-06-11 00:00:00-05:00	2025-06-12 00:00:00-05:00	-3.825	0:00:00	1 day, 0:00:00
2025-06-12 00:00:00-05:00	2025-06-13 00:00:00-05:00	9.6225	0:00:00	1 day, 0:00:00
2025-06-13 00:00:00-05:00	2025-06-14 00:00:00-05:00	13.6575	0:00:00	1 day, 0:00:00
2025-06-14 00:00:00-05:00	2025-06-15 00:00:00-05:00	-0.665	0:00:00	1 day, 0:00:00
2025-06-15 00:00:00-05:00	2025-06-16 00:00:00-05:00	-4.5125	0:00:00	1 day, 0:00:00

```

## Example Usage - in Python

```python
#!/usr/bin/env python3

import asyncio
import datetime
from aiohttp import ClientSession
from opower import Opower, AggregateType
from opower.helpers import create_cookie_jar

async def main():
    # Replace these with your actual utility login credentials
    utility = "comed"  # e.g., "comed", "pgande", "bge"
    username = "your_username"
    password = "your_password"

    # Create a session with a cookie jar required by Opower
    async with ClientSession(cookie_jar=create_cookie_jar()) as session:
        opw = Opower(
            session=session,
            utility=utility,
            username=username,
            password=password,
        )

        # Log in to the utility account
        await opw.async_login()

        # Get all associated accounts (usually just one)
        accounts = await opw.async_get_accounts()

        # Define the date range for usage data
        end_date = datetime.datetime.now() - datetime.timedelta(days=1)
        start_date = end_date - datetime.timedelta(days=7)

        # Fetch and print daily usage data
        for account in accounts:
            print(account)
            usage_data = await opw.async_get_usage_reads(
                account,
                AggregateType.DAY,
                start_date,
                end_date,
            )

            for usage_read in usage_data:
                print(f"{usage_read.start_time.date()}: {usage_read.consumption:.2f} kWh")

asyncio.run(main())
```


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

# Alternative: run formatter, lint, and type checking
python -m pip install isort black flake8 ruff mypy pytest-mypy
isort . ; black . ; flake8 . ; ruff check . --fix ; mypy --install-types .

# Run tests
python -m pip install pytest pytest-asyncio python-dotenv
pytest

# Run command line
python -m opower --help
# To output debug logs and API responses to a file run:
python -m opower -vv 2> out.txt

# Build package
python -m pip install build
python -m build
```
