"""Tests for the shared form-parsing helpers."""

import asyncio
import unittest
from unittest.mock import patch

from pyotp import TOTP

from opower.utilities import helpers
from opower.utilities.helpers import async_unused_totp_code, get_form_action_url_and_hidden_inputs, parse_forms

TOTP_SECRET = "JBSWY3DPEHPK3PXP"  # noqa: S105
OTHER_SECRET = "KRSXG5CTMVRXEZLU"  # noqa: S105

LOGIN_PAGE_HTML = """
<form method="get" action="/search" id="siteSearch">
  <input type="text" name="q" />
  <input type="submit" name="searchButton" value="Search" />
</form>
<form method="post" action="./?ReturnURL=%2fSAML%2fssoservice.aspx" id="Form1">
  <input type="hidden" name="__VIEWSTATE" value="viewstate123" />
  <input type="hidden" name="__VIEWSTATEGENERATOR" value="ABCD1234" />
  <input type="hidden" name="__EVENTVALIDATION" value="ev456" />
  <input type="text" name="ctl00$phMainColumn$ctl00$iplLogin$UserName" />
  <input type="password" name="ctl00$phMainColumn$ctl00$iplLogin$Password" />
  <input type="checkbox" name="ctl00$phMainColumn$ctl00$iplLogin$cbRemember" />
  <input type="submit" name="ctl00$phMainColumn$ctl00$iplLogin$LoginButton" value="Log In" />
  <input type="submit" name="ctl00$phMainColumn$ctl00$iplLogin$ForgotButton" value="Forgot?" />
</form>
"""

SAML_AUTOSUBMIT_HTML = """
<html><body onload="document.forms[0].submit()">
<form method="post" action="https://idcs-abc.identity.oraclecloud.com/fed/v1/sp/sso">
  <input type="hidden" name="SAMLResponse" value="c2FtbA==" />
  <input type="hidden" name="RelayState" value="xyz" />
</form>
</body></html>
"""

SELF_POST_HTML = """
<form method="post" action="">
  <input type="hidden" name="__VIEWSTATE" value="vs" />
</form>
"""


class TestFormsParser(unittest.TestCase):
    """Test the multi-form HTML parsing."""

    def test_login_form_selected_by_password_field(self) -> None:
        """The login form is found by its password input, not document order."""
        forms = parse_forms(LOGIN_PAGE_HTML)
        self.assertEqual(2, len(forms))
        login = next(f for f in forms if f.has_password)
        self.assertEqual("./?ReturnURL=%2fSAML%2fssoservice.aspx", login.action)
        self.assertIn("__VIEWSTATE", login.inputs)
        self.assertIn("__EVENTVALIDATION", login.inputs)
        self.assertIn("ctl00$phMainColumn$ctl00$iplLogin$UserName", login.inputs)
        self.assertIn("ctl00$phMainColumn$ctl00$iplLogin$Password", login.inputs)

    def test_browser_submission_rules(self) -> None:
        """Unchecked checkboxes and extra submit buttons are not submitted."""
        login = next(f for f in parse_forms(LOGIN_PAGE_HTML) if f.has_password)
        self.assertNotIn("ctl00$phMainColumn$ctl00$iplLogin$cbRemember", login.inputs)
        self.assertIn("ctl00$phMainColumn$ctl00$iplLogin$LoginButton", login.inputs)
        self.assertNotIn("ctl00$phMainColumn$ctl00$iplLogin$ForgotButton", login.inputs)

    def test_forms_are_isolated(self) -> None:
        """Inputs from one form do not leak into another."""
        forms = parse_forms(LOGIN_PAGE_HTML)
        search = next(f for f in forms if not f.has_password)
        self.assertEqual("/search", search.action)
        self.assertNotIn("__VIEWSTATE", search.inputs)
        login = next(f for f in forms if f.has_password)
        self.assertNotIn("q", login.inputs)

    def test_saml_autosubmit_form(self) -> None:
        """The SAML auto-submit form is detected with its assertion payload."""
        forms = parse_forms(SAML_AUTOSUBMIT_HTML)
        self.assertEqual(1, len(forms))
        self.assertEqual("https://idcs-abc.identity.oraclecloud.com/fed/v1/sp/sso", forms[0].action)
        self.assertEqual("c2FtbA==", forms[0].inputs["SAMLResponse"])
        self.assertEqual("xyz", forms[0].inputs["RelayState"])
        self.assertFalse(forms[0].has_password)

    def test_empty_action_self_post_form(self) -> None:
        """A form with an empty action parses with its fields intact."""
        forms = parse_forms(SELF_POST_HTML)
        self.assertEqual(1, len(forms))
        self.assertEqual("", forms[0].action)
        self.assertEqual({"__VIEWSTATE": "vs"}, forms[0].inputs)

    def test_hidden_inputs_tracked_separately(self) -> None:
        """Hidden inputs are available on their own, excluding visible fields."""
        login = next(f for f in parse_forms(LOGIN_PAGE_HTML) if f.has_password)
        self.assertEqual(
            {"__VIEWSTATE", "__VIEWSTATEGENERATOR", "__EVENTVALIDATION"},
            set(login.hidden_inputs),
        )


class TestGetFormActionUrlAndHiddenInputs(unittest.TestCase):
    """Test the single-form convenience wrapper."""

    def test_single_form(self) -> None:
        """The action and hidden inputs of the form are returned."""
        action, inputs = get_form_action_url_and_hidden_inputs(SAML_AUTOSUBMIT_HTML)
        self.assertEqual("https://idcs-abc.identity.oraclecloud.com/fed/v1/sp/sso", action)
        self.assertEqual({"SAMLResponse": "c2FtbA==", "RelayState": "xyz"}, inputs)

    def test_first_form_only(self) -> None:
        """Only the first form is used; later forms' fields cannot leak in."""
        action, inputs = get_form_action_url_and_hidden_inputs(LOGIN_PAGE_HTML)
        self.assertEqual("/search", action)
        self.assertEqual({}, inputs)

    def test_no_form(self) -> None:
        """A page without forms returns empty values."""
        action, inputs = get_form_action_url_and_hidden_inputs("<html><body>hi</body></html>")
        self.assertEqual("", action)
        self.assertEqual({}, inputs)


class _FakeClock:
    """A clock for the TOTP gate whose sleep advances time instead of waiting."""

    def __init__(self, now: float) -> None:
        self.now = now
        self.sleeps: list[float] = []

    def time(self) -> float:
        return self.now

    async def sleep(self, delay: float) -> None:
        self.sleeps.append(delay)
        self.now += delay
        await asyncio.sleep(0)


class TestUnusedTotpCode(unittest.IsolatedAsyncioTestCase):
    """Test that TOTP codes are not handed out twice for the same time step."""

    def setUp(self) -> None:
        """Start each test with an empty gate and a fake clock mid-step."""
        helpers._issued_totp_steps.clear()
        self.addCleanup(helpers._issued_totp_steps.clear)
        self.clock = _FakeClock(1_000_000 * 30 + 5)
        for name in ("time", "sleep"):
            patcher = patch.object(helpers, name, getattr(self.clock, name))
            patcher.start()
            self.addCleanup(patcher.stop)

    def _step(self) -> int:
        return int(self.clock.now // 30)

    async def test_first_call_does_not_wait(self) -> None:
        """The first code for a secret is the current one, without waiting."""
        code = await async_unused_totp_code(TOTP_SECRET)
        self.assertEqual(code, TOTP(TOTP_SECRET).generate_otp(self._step()))
        self.assertEqual(self.clock.sleeps, [])

    async def test_same_step_waits_for_next_step(self) -> None:
        """A second request in the same step waits and gets the next step's code."""
        first = await async_unused_totp_code(TOTP_SECRET)
        start_step = self._step()
        second = await async_unused_totp_code(TOTP_SECRET)
        self.assertNotEqual(first, second)
        self.assertEqual(self._step(), start_step + 1)
        self.assertEqual(second, TOTP(TOTP_SECRET).generate_otp(start_step + 1))
        self.assertEqual(len(self.clock.sleeps), 1)
        self.assertLessEqual(self.clock.sleeps[0], 26)

    async def test_concurrent_callers_get_distinct_steps(self) -> None:
        """Concurrent callers are serialized onto consecutive steps."""
        start_step = self._step()
        codes = await asyncio.gather(*(async_unused_totp_code(TOTP_SECRET) for _ in range(3)))
        totp = TOTP(TOTP_SECRET)
        self.assertCountEqual(codes, [totp.generate_otp(start_step + i) for i in range(3)])

    async def test_different_secret_does_not_wait(self) -> None:
        """Codes for another secret are independent."""
        await async_unused_totp_code(TOTP_SECRET)
        await async_unused_totp_code(OTHER_SECRET)
        self.assertEqual(self.clock.sleeps, [])

    async def test_clock_going_backwards_never_reissues_a_step(self) -> None:
        """After the clock steps back, the gate waits past the last issued step."""
        start_step = self._step()
        await async_unused_totp_code(TOTP_SECRET)
        self.clock.now -= 60
        code = await async_unused_totp_code(TOTP_SECRET)
        self.assertEqual(code, TOTP(TOTP_SECRET).generate_otp(start_step + 1))

    async def test_stale_entries_are_pruned(self) -> None:
        """Entries for past steps are dropped and no raw secret is kept."""
        await async_unused_totp_code(TOTP_SECRET)
        self.clock.now += 30
        await async_unused_totp_code(OTHER_SECRET)
        self.assertEqual(len(helpers._issued_totp_steps), 1)
        self.assertNotIn(OTHER_SECRET, next(iter(helpers._issued_totp_steps)))
        self.assertEqual(self.clock.sleeps, [])
