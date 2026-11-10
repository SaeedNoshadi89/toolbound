"""An in-memory transport for tests, examples and offline development."""

from __future__ import annotations

import json
import re
from collections.abc import Callable
from dataclasses import dataclass, field
from typing import Any

from toolbound.core.network import check_ip
from toolbound.core.ports import HttpRequest, HttpResponse

Handler = Callable[[HttpRequest], "HttpResponse | MockResponse | Any"]


@dataclass(slots=True)
class MockResponse:
    status: int = 200
    json: Any = None
    body: bytes | None = None
    headers: dict[str, str] = field(default_factory=dict)

    def to_http(self, url: str) -> HttpResponse:
        headers = {k.lower(): v for k, v in self.headers.items()}
        if self.body is not None:
            body = self.body
        elif self.json is not None:
            body = json.dumps(self.json).encode()
            headers.setdefault("content-type", "application/json")
        else:
            body = b""
        return HttpResponse(status=self.status, headers=headers, body=body, url=url)


class MockTransport:
    """Route requests to Python handlers. Records every request it receives.

    ``mock.route("GET", "https://api.example.com/items/{id}", handler)`` where the
    handler returns a :class:`MockResponse`, an :class:`HttpResponse`, or any
    JSON-serializable value (sent as ``200 application/json``).

    IP-literal targets are still checked with :func:`check_ip`, but DNS is not
    resolved, so use :class:`SecureTransport` for end-to-end network tests.
    """

    def __init__(self) -> None:
        self._routes: list[tuple[str, re.Pattern[str], Handler]] = []
        self.requests: list[HttpRequest] = []
        self.closed = False

    def route(self, method: str, url_template: str, handler: Handler | Any) -> MockTransport:
        pattern = re.escape(url_template)
        pattern = re.sub(r"\\\{[A-Za-z_][A-Za-z0-9_]*\\\}", r"[^/?#]+", pattern)
        if callable(handler):
            fn: Handler = handler
        else:
            value = handler

            def fn(_request: HttpRequest) -> Any:
                return value

        self._routes.append((method.upper(), re.compile(f"^{pattern}(?:\\?.*)?$"), fn))
        return self

    async def send(self, request: HttpRequest) -> HttpResponse:
        self.requests.append(request)
        from urllib.parse import urlsplit

        host = urlsplit(request.url).hostname or ""
        try:
            import ipaddress

            ipaddress.ip_address(host)
            check_ip(host, request.network)
        except ValueError:
            pass
        for method, pattern, handler in self._routes:
            if method == request.method and pattern.match(request.url):
                result = handler(request)
                if isinstance(result, HttpResponse):
                    return result
                if isinstance(result, MockResponse):
                    return result.to_http(request.url)
                return MockResponse(json=result).to_http(request.url)
        return MockResponse(404, json={"message": "no mock route"}).to_http(request.url)

    async def aclose(self) -> None:
        self.closed = True
