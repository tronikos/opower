# opower

A Python library for getting historical and forecasted usage/cost from utilities that use opower.com such as PG&amp;E.

Supported utilities:

- American Electric Power (AEP) subsidiaries
  - AEP Ohio
- Consolidated Edison (ConEd)
  - Orange & Rockland Utilities (ORU)
- Enmax Energy
- Evergy
- Exelon subsidiaries
  - Atlantic City Electric
  - Baltimore Gas and Electric (BGE)
  - Commonwealth Edison (ComEd)
  - Delmarva Power
  - PECO Energy Company (PECO)
  - Potomac Electric Power Company (Pepco)
- Pacific Gas & Electric (PG&E)
- Portland General Electric (PGE)
- Puget Sound Energy (PSE)
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

So follow that advice and try to scrape all fields at once, similar to the `_get_form_action_url_and_hidden_inputs` in pge.py.

## Example

See [demo.py](https://github.com/tronikos/opower/blob/main/src/demo.py)

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
python -m pip install .

# Run pre-commit
python -m pip install pre-commit
pre-commit install
pre-commit run --all-files

# Alternative: run formatter, lint, and type checking
python -m pip install isort black flake8 ruff mypy pydantic
isort . ; black . ; flake8 . ; ruff . --fix ; mypy --install-types .

# Run tests
python -m pip install pytest
pytest

# Run demo
python src/demo.py --help
# To output debug logs to a file, change DEBUG_LOG_RESPONSE to True in opower.py and run:
python src/demo.py --verbose 2> out.txt

# Build package
python -m pip install build
python -m build
```
