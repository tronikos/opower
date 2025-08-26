# opower

[![PyPI Version](https://img.shields.io/pypi/v/opower.svg)](https://pypi.org/project/opower/)

A Python library and command-line tool for getting historical and forecasted usage/cost data from utilities that use opower.com.

This library is used by the [Opower integration in Home Assistant](https://www.home-assistant.io/integrations/opower/).

## Supported Utilities

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
- Southern Maryland Electric Cooperative (SMECO)

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

# Build package
python -m pip install build
python -m build
```
