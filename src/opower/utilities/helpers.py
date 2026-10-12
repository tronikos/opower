"""Helper functions."""

import hashlib
import threading
from asyncio import sleep
from html.parser import HTMLParser
from time import time

from pyotp import TOTP

# Keyed by a digest of the TOTP secret so raw secrets are not retained.
_issued_totp_steps: dict[str, int] = {}
_issued_totp_steps_lock = threading.Lock()


async def async_unused_totp_code(secret: str) -> str:
    """Return a TOTP code for a time step not already handed out in this process.

    Verifiers may reject a code that was already accepted (RFC 6238 section 5.2),
    so two logins within one 30s step (e.g. a credentials check followed by a
    fresh client) would fail the second time. Waits for the next step instead.
    """
    totp = TOTP(secret)
    key = hashlib.sha256(secret.encode()).hexdigest()
    while True:
        # A threading lock: callers may be on different event loops.
        with _issued_totp_steps_lock:
            step = int(time() // totp.interval)
            for stale in [k for k, s in _issued_totp_steps.items() if s < step]:
                del _issued_totp_steps[stale]
            if key not in _issued_totp_steps:
                _issued_totp_steps[key] = step
                return totp.generate_otp(step)
            next_step_at = (_issued_totp_steps[key] + 1) * totp.interval
        await sleep(max(next_step_at - time(), 0) + 0.1)


class Form:
    """A parsed HTML form: its action and the fields a browser would submit."""

    def __init__(self, action: str | None) -> None:
        """Initialize."""
        self.action = action
        self.inputs: dict[str, str] = {}
        self.hidden_inputs: dict[str, str] = {}
        self.has_password = False
        self._submit_seen = False

    def add_input(self, attrs: dict[str, str | None]) -> None:
        """Add an input field, applying browser form-submission rules."""
        name = attrs.get("name")
        input_type = (attrs.get("type") or "text").lower()
        if input_type == "password":
            self.has_password = True
        if not name:
            return
        # Match what a browser submits: skip non-submitting controls,
        # unchecked boxes, and all but the activated (first) submit button.
        if input_type in ("button", "reset", "image"):
            return
        if input_type in ("checkbox", "radio") and "checked" not in attrs:
            return
        if input_type == "submit":
            if self._submit_seen:
                return
            self._submit_seen = True
        value = attrs.get("value") or ""
        self.inputs[name] = value
        if input_type == "hidden":
            self.hidden_inputs[name] = value


class FormsParser(HTMLParser):
    """HTML parser that captures every form on the page with its input fields.

    Inputs are only collected while their form is open, so a page containing
    more than one form cannot mix another form's fields into the result.
    """

    def __init__(self) -> None:
        """Initialize."""
        super().__init__()
        self.forms: list[Form] = []
        self._current: Form | None = None

    def handle_starttag(self, tag: str, attrs: list[tuple[str, str | None]]) -> None:
        """Track forms and collect their inputs."""
        attrs_dict = dict(attrs)
        if tag == "form":
            self._current = Form(attrs_dict.get("action"))
            self.forms.append(self._current)
        elif tag == "input" and self._current is not None:
            self._current.add_input(attrs_dict)

    def handle_endtag(self, tag: str) -> None:
        """Close the current form."""
        if tag == "form":
            self._current = None


def parse_forms(html: str) -> list[Form]:
    """Parse all forms out of an HTML page."""
    parser = FormsParser()
    parser.feed(html)
    parser.close()
    return parser.forms


def get_form_action_url_and_hidden_inputs(html: str) -> tuple[str, dict[str, str]]:
    """Return the URL and hidden inputs from the first form in a page."""
    forms = parse_forms(html)
    if not forms:
        return "", {}
    return forms[0].action or "", forms[0].hidden_inputs
