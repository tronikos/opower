"""Email-based MFA code retrieval, inspired by pyaarlo.

When MFA is required, the code is read by polling an email inbox via IMAP:
the mailbox is checked for new messages and a 6-digit code is extracted.
The module also provides Console and REST API sources for programmatic use.
"""

import asyncio
import contextlib
import functools
import imaplib
import logging
import re
from typing import Protocol

import aiohttp

_LOGGER = logging.getLogger(__name__)

# Common pattern for 6-digit MFA codes (e.g. PG&E, many utilities).
DEFAULT_MFA_CODE_PATTERN = re.compile(r"\b(\d{6})\b")


class MfaCodeSource(Protocol):
    """Protocol for obtaining an MFA code from some source."""

    async def get_mfa_code(self, *, option_sent_via: str | None = None) -> str:
        """Return the MFA code (e.g. from console, email, or REST API).

        :param option_sent_via: Optional hint describing how the code was sent (e.g. "Email").
        :returns: The code string entered or retrieved.
        """
        ...


class ConsoleMfaCodeSource:
    """Read the MFA code from the console (stdin)."""

    async def get_mfa_code(self, *, option_sent_via: str | None = None) -> str:
        """Prompt the user to enter the security code."""
        loop = asyncio.get_running_loop()
        return await loop.run_in_executor(None, lambda: input("Enter the security code: "))


class ImapMfaCodeSource:
    """Read the MFA code from an email inbox via IMAP.

    Polls the mailbox for new messages and extracts a code matching the given regex.
    Compatible with utilities that send the code by email (e.g. PG&E email option).
    """

    def __init__(
        self,
        host: str,
        username: str,
        password: str,
        *,
        port: int | None = None,
        code_pattern: re.Pattern[str] = DEFAULT_MFA_CODE_PATTERN,
        timeout_seconds: int = 120,
        poll_interval_seconds: float = 5.0,
        mailbox: str = "INBOX",
    ) -> None:
        """Initialize the IMAP source.

        :param host: IMAP server host (e.g. imap.gmail.com).
        :param username: IMAP login username.
        :param password: IMAP login password.
        :param port: IMAP port (default 993 for SSL).
        :param code_pattern: Regex with one group capturing the code (default 6 digits).
        :param timeout_seconds: Max time to wait for the email.
        :param poll_interval_seconds: Seconds between mailbox checks.
        :param mailbox: Mailbox name (default INBOX).
        """
        self._host = host
        self._username = username
        self._password = password
        self._port = port or 993
        self._code_pattern = code_pattern
        self._timeout_seconds = timeout_seconds
        self._poll_interval_seconds = poll_interval_seconds
        self._mailbox = mailbox

    async def get_mfa_code(self, *, option_sent_via: str | None = None) -> str:
        """Poll IMAP for a new message containing the code."""
        loop = asyncio.get_running_loop()
        try:
            return await asyncio.wait_for(
                self._poll_for_code(loop),
                timeout=float(self._timeout_seconds),
            )
        except TimeoutError as err:
            raise TimeoutError(f"No MFA code found in mailbox within {self._timeout_seconds}s") from err

    async def _poll_for_code(self, loop: asyncio.AbstractEventLoop) -> str:
        """Poll the mailbox until a matching code is found."""
        seen_uids: set[bytes] = set()
        while True:
            fetch = functools.partial(
                _fetch_code_from_imap,
                host=self._host,
                port=self._port,
                username=self._username,
                password=self._password,
                mailbox=self._mailbox,
                code_pattern=self._code_pattern,
                seen_uids=seen_uids,
            )
            code = await loop.run_in_executor(None, fetch)
            if code:
                return code
            await asyncio.sleep(self._poll_interval_seconds)


def _fetch_code_from_imap(
    *,
    host: str,
    port: int,
    username: str,
    password: str,
    mailbox: str,
    code_pattern: re.Pattern[str],
    seen_uids: set[bytes],
) -> str | None:
    """Connect via IMAP, fetch recent messages, extract code. Runs in executor."""
    conn = imaplib.IMAP4_SSL(host, port=port) if port == 993 else imaplib.IMAP4(host, port=port)
    try:
        conn.login(username, password)
        conn.select(mailbox, readonly=True)
        _, data = conn.search(None, "UNSEEN")
        uids = data[0].split() if data[0] else []
        for uid in reversed(uids):  # Newest first.
            if uid in seen_uids:
                continue
            seen_uids.add(uid)
            _, msg_data = conn.fetch(uid, "(BODY.PEEK[])")
            for part in msg_data:
                if not isinstance(part, tuple):
                    continue
                raw = part[1]
                text = raw.decode("utf-8", errors="replace") if isinstance(raw, bytes) else str(raw)
                match = code_pattern.search(text)
                if match:
                    return match.group(1)
    finally:
        with contextlib.suppress(OSError, imaplib.IMAP4.error):
            conn.logout()
    return None


class RestApiMfaCodeSource:
    """Read the MFA code from a REST API (pyaarlo-tfa style).

    Performs GET requests to a configurable URL; expects JSON with the code
    in data.code (e.g. {"meta":{"code":200},"data":{"code":"123456"}}).
    """

    def __init__(
        self,
        session: aiohttp.ClientSession,
        url: str,
        *,
        params: dict[str, str] | None = None,
        timeout_seconds: int = 120,
        poll_interval_seconds: float = 5.0,
    ) -> None:
        """Initialize the REST API source.

        :param session: aiohttp session for requests.
        :param url: Full URL for the GET request (e.g. https://host/get).
        :param params: Optional query params (e.g. email, token).
        :param timeout_seconds: Max time to wait for a valid response.
        :param poll_interval_seconds: Seconds between GET requests.
        """
        self._session = session
        self._url = url
        self._params = params or {}
        self._timeout_seconds = timeout_seconds
        self._poll_interval_seconds = poll_interval_seconds

    async def get_mfa_code(self, *, option_sent_via: str | None = None) -> str:
        """Poll the REST API until data.code is present."""
        try:
            return await asyncio.wait_for(
                self._poll_for_code(),
                timeout=float(self._timeout_seconds),
            )
        except TimeoutError as err:
            raise TimeoutError(f"No MFA code from REST API within {self._timeout_seconds}s") from err

    async def _poll_for_code(self) -> str:
        """Poll the API until we get a successful response with a code."""
        while True:
            try:
                async with self._session.get(self._url, params=self._params, timeout=aiohttp.ClientTimeout(total=30)) as resp:
                    if resp.status != 200:
                        _LOGGER.debug("REST MFA endpoint returned %s", resp.status)
                        await asyncio.sleep(self._poll_interval_seconds)
                        continue
                    data = await resp.json()
            except (aiohttp.ClientError, ValueError) as err:
                _LOGGER.debug("REST MFA request failed: %s", err)
                await asyncio.sleep(self._poll_interval_seconds)
                continue
            if isinstance(data, dict):
                inner = data.get("data") or data
                if isinstance(inner, dict):
                    code = inner.get("code")
                    if isinstance(code, str) and code.strip():
                        return code.strip()
            await asyncio.sleep(self._poll_interval_seconds)
