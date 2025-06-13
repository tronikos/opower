"""Helper functions."""

import aiohttp


def create_cookie_jar() -> aiohttp.CookieJar:
    """Create a cookie jar for Opower."""
    # Disable cookie quoting because some utilities do not support it.
    return aiohttp.CookieJar(quote_cookie=False)
