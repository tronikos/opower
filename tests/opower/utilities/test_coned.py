"""Tests for Consolidated Edison (ConEd)."""

import socket
import unittest
from typing import Any

import aiohttp
from aiohttp import web
from aiohttp.abc import AbstractResolver, ResolveResult
from aiohttp.test_utils import TestServer
from yarl import URL

from opower.exceptions import CannotConnect, InvalidAuth
from opower.utilities.coned import ConEd

LOGIN_API = "/sitecore/api/ssc/ConEdWeb-Foundation-Login-Areas-LoginAPI/User/0"
TOKEN_API = "/sitecore/api/ssc/ConEd-Cms-Services-Controllers-Opower/OpowerService/0/GetOPowerToken"  # noqa: S105
ENERGY_USE = "/en/accounts-billing/my-account/energy-use"
# Base64-style value: aiohttp's default cookie jar would send it quoted.
DEVICE_ID = "dev+ice/id=="
TOTP_SECRET = "JBSWY3DPEHPK3PXP"  # noqa: S105


class _FakeConEd:
    """Serves the coned.com + Okta login flow as observed in September 2026.

    The authorization-code exchange only succeeds when the device cookie comes
    back byte-for-byte (unquoted); otherwise, like coned.com, it expires the
    session cookies. The Opower token is only minted after the energy-use page
    runs the second (state=opower|...) authorization round.
    """

    def __init__(
        self,
        *,
        mfa: bool = True,
        token: Any = "opower-token",  # noqa: S107
        login_ok: bool = True,
        set_device: bool = True,
    ) -> None:
        """Configure the scenario.

        With set_device=False the login page does not issue the device cookie,
        so the code exchange only succeeds if the caller's session supplied it.
        """
        self.mfa = mfa
        self.set_device = set_device
        self.device_attrs = ""
        self.code_device_cookies: list[str | None] = []
        self.token = token
        self.login_ok = login_ok
        self.requests: list[str] = []
        self.login_bodies: list[dict[str, Any]] = []
        self.app = web.Application()
        r = self.app.router
        r.add_get("/en/login", self.login_page)
        r.add_get("/login", self.plain_login)
        r.add_get("/en/accounts-billing/my-account", self.my_account)
        r.add_post(LOGIN_API + "/Login", self.login)
        r.add_post(LOGIN_API + "/VerifyFactor", self.verify)
        r.add_get("/oauth2/authorize", self.authorize)
        r.add_get("/", self.home)
        r.add_get(ENERGY_USE, self.energy_use)
        r.add_get(TOKEN_API, self.get_token)

    def _raw_cookie(self, request: web.Request, name: str) -> str | None:
        # Read the raw header: aiohttp's request.cookies would unquote for us.
        for part in request.headers.get("Cookie", "").split(";"):
            key, _, value = part.strip().partition("=")
            if key == name:
                return value
        return None

    async def login_page(self, request: web.Request) -> web.Response:
        self.requests.append("login_page")
        resp = web.Response(text="<html>login</html>")
        # Raw header, as coned.com sends it (set_cookie() would quote the value).
        if self.set_device:
            resp.headers.add("Set-Cookie", f"CE_DEVICE_ID={DEVICE_ID}; Path=/{self.device_attrs}")
        return resp

    async def my_account(self, request: web.Request) -> web.Response:
        return web.Response(text="<html>my account</html>")

    async def plain_login(self, request: web.Request) -> web.Response:
        self.requests.append("redirected_to_login")
        return web.Response(text="<html>please log in</html>")

    async def login(self, request: web.Request) -> web.Response:
        self.requests.append("Login")
        self.login_bodies.append(await request.json())
        if not self.login_ok:
            return web.json_response({"login": False})
        if not self.mfa:
            return web.json_response(
                {
                    "login": True,
                    "authRedirectUrl": str(request.url.with_path("/oauth2/authorize").with_query(state="no_redirect")),
                }
            )
        return web.json_response({"login": True, "newDevice": True, "noMfa": False})

    async def verify(self, request: web.Request) -> web.Response:
        self.requests.append("VerifyFactor")
        self.login_bodies.append(await request.json())
        return web.json_response(
            {"code": True, "authRedirectUrl": str(request.url.with_path("/oauth2/authorize").with_query(state="no_redirect"))}
        )

    async def authorize(self, request: web.Request) -> web.Response:
        self.requests.append(f"authorize:{request.query['state']}")
        raise web.HTTPFound(f"/?code=abc&state={request.query['state']}")

    async def home(self, request: web.Request) -> web.Response:
        if "code" not in request.query:
            return web.Response(text="home")
        state = request.query["state"]
        self.requests.append(f"code:{state}")
        self.code_device_cookies.append(self._raw_cookie(request, "CE_DEVICE_ID"))
        if self._raw_cookie(request, "CE_DEVICE_ID") != DEVICE_ID:
            resp = web.Response(text="home")
            resp.set_cookie("CE_AUTH", "", expires="Sat, 27-Sep-2025 13:13:03 GMT")
            return resp
        target = "/en/accounts-billing/my-account" if state == "no_redirect" else ENERGY_USE
        resp = web.HTTPFound(target)
        resp.set_cookie("CE_AUTH", "session")
        if state.startswith("opower|"):
            resp.set_cookie("OPOWER_AUTH_TOKEN", "minted")
        raise resp

    async def energy_use(self, request: web.Request) -> web.Response:
        self.requests.append("energy_use")
        if self._raw_cookie(request, "CE_AUTH") != "session":
            raise web.HTTPFound("/login?url=" + ENERGY_USE)
        if self._raw_cookie(request, "OPOWER_AUTH_TOKEN") is None:
            raise web.HTTPFound("/oauth2/authorize?state=opower%7C%2Faccounts-billing%2Fmy-account%2Fenergy-use")
        return web.Response(text="energy use")

    async def get_token(self, request: web.Request) -> web.Response:
        self.requests.append("GetOPowerToken")
        if self._raw_cookie(request, "OPOWER_AUTH_TOKEN") is None:
            return web.json_response(None)
        return web.json_response(self.token)


def _local_coned(base: str, totp_secret: str | None = TOTP_SECRET) -> ConEd:
    """Return a ConEd instance pointed at the local fake server.

    Patched on the instance rather than subclassed: utilities are discovered via
    subclasses, so a test subclass would register as a second ConEd.
    """
    utility = ConEd()
    utility._totp_secret = totp_secret
    utility.base_url = lambda: base  # type: ignore[method-assign]
    return utility


class _LoopbackResolver(AbstractResolver):
    """Resolve every host name to 127.0.0.1, so www.localhost reaches the fake."""

    async def resolve(self, host: str, port: int = 0, family: int = 0) -> list[ResolveResult]:
        return [{"hostname": host, "host": "127.0.0.1", "port": port, "family": socket.AF_INET, "proto": 0, "flags": 0}]

    async def close(self) -> None:
        pass


class TestConEdLogin(unittest.IsolatedAsyncioTestCase):
    """ConEd login flow against a local fake coned.com."""

    async def _login(
        self,
        fake: _FakeConEd,
        totp_secret: str | None = TOTP_SECRET,
        device_cookie: str | None = None,
        host: str = "localhost",
    ) -> tuple[str, aiohttp.ClientSession]:
        server = TestServer(fake.app, host="127.0.0.1")
        await server.start_server()
        self.addAsyncCleanup(server.close)
        base = f"http://{host}:{server.port}"
        # The caller's session uses aiohttp's default (quoting) cookie jar,
        # as Home Assistant's does. Its connector resolves any name locally.
        session = aiohttp.ClientSession(connector=aiohttp.TCPConnector(resolver=_LoopbackResolver()))
        self.addAsyncCleanup(session.close)
        if device_cookie is not None:
            session.cookie_jar.update_cookies_from_headers([device_cookie], URL(base))
        utility = _local_coned(base, totp_secret)
        token = await utility.async_login(session, "user@example.com", "pw", {})
        return token, session

    async def test_login_returns_opower_token(self) -> None:
        """The full two-round flow ends with the Opower token."""
        fake = _FakeConEd()
        token, _ = await self._login(fake)
        self.assertEqual(token, "opower-token")
        self.assertEqual(
            fake.requests,
            [
                "login_page",
                "Login",
                "VerifyFactor",
                "authorize:no_redirect",
                "code:no_redirect",
                "energy_use",
                "authorize:opower|/accounts-billing/my-account/energy-use",
                "code:opower|/accounts-billing/my-account/energy-use",
                "energy_use",
                "GetOPowerToken",
            ],
        )

    async def test_login_sends_the_website_login_body(self) -> None:
        """Login and VerifyFactor send the body the website sends."""
        fake = _FakeConEd()
        await self._login(fake)
        login, verify = fake.login_bodies
        self.assertEqual(login["ReturnUrl"], "")
        self.assertEqual(login["FromURI"], "")
        self.assertEqual(verify["ReturnUrl"], "")
        self.assertEqual(len(verify["MFACode"]), 6)

    async def test_device_cookie_is_copied_back_unquoted(self) -> None:
        """The remembered-device cookie reaches the caller's session intact."""
        fake = _FakeConEd()
        _, session = await self._login(fake)
        device = [c.value for c in session.cookie_jar if c.key == "CE_DEVICE_ID"]
        self.assertEqual(device, [DEVICE_ID])

    async def test_remembered_device_cookie_is_used(self) -> None:
        """A device cookie already in the caller's session reaches the login."""
        fake = _FakeConEd(mfa=False, set_device=False)
        token, _ = await self._login(fake, totp_secret=None, device_cookie=f"CE_DEVICE_ID={DEVICE_ID}; Path=/")
        self.assertEqual(token, "opower-token")

    async def test_parent_domain_device_cookie_is_used(self) -> None:
        """A device cookie set for the parent domain (like .coned.com for www.coned.com) is used."""
        fake = _FakeConEd(mfa=False, set_device=False)
        token, _ = await self._login(
            fake,
            totp_secret=None,
            device_cookie=f"CE_DEVICE_ID={DEVICE_ID}; Domain=localhost; Path=/",
            host="www.localhost",
        )
        self.assertEqual(token, "opower-token")

    async def test_device_cookie_keeps_its_attributes(self) -> None:
        """Copying the device cookie back keeps attributes such as max-age."""
        fake = _FakeConEd()
        fake.device_attrs = "; Max-Age=31536000"
        _, session = await self._login(fake)
        (cookie,) = [c for c in session.cookie_jar if c.key == "CE_DEVICE_ID"]
        self.assertEqual(cookie["max-age"], "31536000")

    async def test_login_reuses_the_callers_connector(self) -> None:
        """The login borrows the caller's connector (here, its resolver) and leaves it open."""
        fake = _FakeConEd()
        _, session = await self._login(fake, host="coned.test")
        assert session.connector is not None
        self.assertFalse(session.connector.closed)
        self.assertFalse(session.closed)

    async def test_login_without_mfa(self) -> None:
        """A remembered device skips VerifyFactor."""
        fake = _FakeConEd(mfa=False)
        token, _ = await self._login(fake, totp_secret=None)
        self.assertEqual(token, "opower-token")
        self.assertNotIn("VerifyFactor", fake.requests)

    async def test_missing_totp_secret_raises(self) -> None:
        """An MFA account without a TOTP secret fails clearly."""
        with self.assertRaises(InvalidAuth):
            await self._login(_FakeConEd(), totp_secret=None)

    async def test_bad_password_raises(self) -> None:
        """Rejected credentials raise InvalidAuth."""
        with self.assertRaises(InvalidAuth):
            await self._login(_FakeConEd(login_ok=False))

    async def test_null_token_raises_instead_of_returning_none(self) -> None:
        """A null token raises instead of becoming the string 'None'."""
        with self.assertRaises(CannotConnect):
            await self._login(_FakeConEd(token=None))

    async def test_quoting_cookie_jar_breaks_the_code_exchange(self) -> None:
        """Guard the root cause: a quoting cookie jar breaks the code exchange.

        With aiohttp's default jar the device cookie goes back quoted and
        coned.com rejects the authorization code.
        """
        fake = _FakeConEd()
        server = TestServer(fake.app, host="127.0.0.1")
        await server.start_server()
        self.addAsyncCleanup(server.close)
        utility = _local_coned(f"http://localhost:{server.port}")
        connector = aiohttp.TCPConnector(resolver=_LoopbackResolver())
        async with aiohttp.ClientSession(connector=connector) as quoting_session:
            with self.assertRaises(CannotConnect):
                await utility._async_login(quoting_session, utility.base_url(), "user@example.com", "pw")
        # The cookie did arrive, just quoted: that is what the site rejects.
        self.assertEqual(fake.code_device_cookies, [f'"{DEVICE_ID}"'])
