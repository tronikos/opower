"""Helper functions."""

import re


def get_form_action_url_and_hidden_inputs(html: str) -> tuple[str, dict[str, str]]:
    """Return the URL and hidden inputs from the single form in a page."""
    match = re.search(r'action="([^"]*)"', html, re.IGNORECASE)
    if not match:
        return "", {}
    action_url = match.group(1)
    inputs: dict[str, str] = {}
    for match in re.finditer(r'input\s*type="hidden"\s*name="([^"]*)"\s*value="([^"]*)"', html, re.IGNORECASE):
        inputs[match.group(1)] = match.group(2)
    return action_url, inputs
