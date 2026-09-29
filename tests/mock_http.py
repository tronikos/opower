"""Shared mock aiohttp response/session stand-ins for unit tests."""

from typing import Any

from aiohttp import ContentTypeError, RequestInfo
from multidict import CIMultiDict, CIMultiDictProxy
from yarl import URL


class _MockResponse:
    """Minimal stand-in for aiohttp.ClientResponse."""

    def __init__(
        self, *, text: str = "", payload: Any = None, content_type: str = "application/json", real_url: str = ""
    ) -> None:
        self.status = 200
        self._text = text
        self._payload = payload
        self._content_type = content_type
        self.real_url = URL(real_url)

    @property
    def ok(self) -> bool:
        """Mimic aiohttp.ClientResponse.ok."""
        return self.status < 400

    async def text(self) -> str:
        return self._text

    async def json(self, *, content_type: str | None = "application/json") -> Any:
        # Mimic aiohttp: reject mismatched content types unless the check is disabled.
        if content_type is not None and "json" not in self._content_type:
            raise ContentTypeError(
                RequestInfo(URL(""), "POST", CIMultiDictProxy(CIMultiDict()), URL("")),
                (),
                message=f"Attempt to decode JSON with unexpected mimetype: {self._content_type}",
            )
        return self._payload

    async def __aenter__(self) -> "_MockResponse":
        return self

    async def __aexit__(self, *args: object) -> None:
        return None


class _MockSession:
    """Records requests and returns canned responses keyed by URL."""

    def __init__(self, responses: dict[str, _MockResponse]) -> None:
        self._responses = responses
        self.requests: list[dict[str, Any]] = []

    def _handle(self, method: str, url: str, **kwargs: Any) -> _MockResponse:
        self.requests.append({"method": method, "url": url, **kwargs})
        return self._responses[url]

    def get(self, url: str, **kwargs: Any) -> _MockResponse:
        return self._handle("GET", url, **kwargs)

    def post(self, url: str, **kwargs: Any) -> _MockResponse:
        return self._handle("POST", url, **kwargs)
