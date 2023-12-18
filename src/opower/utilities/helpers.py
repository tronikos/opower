"""Helper functions."""

import re

import aiohttp

from ..const import USER_AGENT


def get_form_action_url_and_hidden_inputs(html: str) -> tuple[str, dict[str, str]]:
    """Return the URL and hidden inputs from the single form in a page."""
    match = re.search(r'action="([^"]*)"', html)
    if not match:
        return "", {}
    action_url = match.group(1)
    inputs = {}
    for match in re.finditer(
        r'input\s*type="hidden"\s*name="([^"]*)"\s*value="([^"]*)"', html
    ):
        inputs[match.group(1)] = match.group(2)
    return action_url, inputs


async def async_auth_saml(session: aiohttp.ClientSession, url: str) -> None:
    """Authenticate with Opower using SAML."""
    # Fetch the URL on the utility website to get RelayState and SAMLResponse.
    async with session.get(url) as resp:
        result = await resp.text()
    action_url, hidden_inputs = get_form_action_url_and_hidden_inputs(result)
    assert action_url.endswith(".opower.com/sp/ACS.saml2")
    assert set(hidden_inputs.keys()) == {"RelayState", "SAMLResponse"}

    # Pass them to opower.com/sp/ACS.saml2 to get opentoken.
    async with session.post(
        action_url,
        data=hidden_inputs,
        headers={"User-Agent": USER_AGENT},
        raise_for_status=True,
    ) as resp:
        result = await resp.text()
    action_url, hidden_inputs = get_form_action_url_and_hidden_inputs(result)
    if action_url == "":
        return
    assert set(hidden_inputs.keys()) == {"opentoken"}

    # Pass it back to the utility website.
    async with session.post(
        action_url,
        data=hidden_inputs,
        headers={"User-Agent": USER_AGENT},
        raise_for_status=True,
    ) as resp:
        pass
