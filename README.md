# opower

A Python library for getting historical and forecasted usage/cost from utilities that use opower.com such as PG&amp;E.

To add support for a new utility that uses opower JSON API (you can tell if the energy dashboard of your utility makes network requests to opower.com, e.g. pge.opower.com) add a file similar to
[pge.py](https://github.com/tronikos/opower/blob/main/src/opower/utilities/pge.py)
or [pse.py](https://github.com/tronikos/opower/blob/main/src/opower/utilities/pse.py)
or [bge.py](https://github.com/tronikos/opower/blob/main/src/opower/utilities/bge.py)
etc.
.

Supported utilities:

- Pacific Gas & Electric (PG&E)
- Puget Sound Energy (PSE)
- Evergy
- Exelon subsidiaries
  - Atlantic City Electric
  - Baltimore Gas and Electric (BGE)
  - Commonwealth Edison (ComEd)
  - Delmarva Power
  - PECO Energy Company (PECO)
  - Potomac Electric Power Company (Pepco)

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

# Run formatter
python -m pip install isort black
isort .
black .

# Run lint
python -m pip install flake8 ruff
flake8 .
ruff .

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
