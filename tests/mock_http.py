"""Shared mock aiohttp response/session stand-ins for unit tests."""

import json
from typing import Any
from urllib.parse import urlencode

from aiohttp import ContentTypeError, RequestInfo
from multidict import CIMultiDict, CIMultiDictProxy
from yarl import URL


class MockResponse:
    """Minimal stand-in for aiohttp.ClientResponse."""

    def __init__(
        self,
        *,
        status: int = 200,
        text: str = "",
        payload: Any = None,
        raw_json: str | None = None,
        content_type: str = "application/json",
        real_url: str = "",
    ) -> None:
        """Set raw_json to have json() parse that string instead of returning payload."""
        self.status = status
        self._text = text
        self._payload = payload
        self._raw_json = raw_json
        self._content_type = content_type
        self.real_url = URL(real_url)

    @property
    def ok(self) -> bool:
        """Mimic aiohttp.ClientResponse.ok."""
        return self.status < 400

    async def text(self) -> str:
        """Return the canned text body."""
        return self._text

    async def json(self, *, content_type: str | None = "application/json") -> Any:
        """Return the canned JSON body."""
        # Mimic aiohttp: reject mismatched content types unless the check is disabled.
        if content_type is not None and "json" not in self._content_type:
            raise ContentTypeError(
                RequestInfo(URL(""), "POST", CIMultiDictProxy(CIMultiDict()), URL("")),
                (),
                message=f"Attempt to decode JSON with unexpected mimetype: {self._content_type}",
            )
        if self._raw_json is not None:
            return json.loads(self._raw_json)
        return self._payload

    async def __aenter__(self) -> "MockResponse":
        """Enter the response context."""
        return self

    async def __aexit__(self, *args: object) -> None:
        """Exit the response context."""
        return


class MockSession:
    """Records requests and returns canned responses keyed by URL.

    A response keyed by the URL plus its encoded query params (e.g.
    "https://host/path?page=2") takes precedence over one keyed by the bare URL.
    """

    def __init__(self, responses: dict[str, MockResponse]) -> None:
        """Serve the given responses."""
        self.responses = responses
        self.requests: list[dict[str, Any]] = []

    def _handle(self, method: str, url: str, **kwargs: Any) -> MockResponse:
        self.requests.append({"method": method, "url": url, **kwargs})
        if params := kwargs.get("params"):
            url_with_params = f"{url}?{urlencode(params)}"
            if url_with_params in self.responses:
                return self.responses[url_with_params]
        return self.responses[url]

    def get(self, url: str, **kwargs: Any) -> MockResponse:
        """Record a GET and return its canned response."""
        return self._handle("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> MockResponse:
        """Record a POST and return its canned response."""
        return self._handle("POST", url, **kwargs)
