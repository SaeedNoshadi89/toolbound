"""Shared fixtures for the security regression suite.

Every test under ``tests/security`` is marked ``security`` automatically, so the
suite runs with ``pytest -m security`` (see CONTRIBUTING.md). Each regression
test names the finding it guards (for example ``C1``) in its docstring.
"""

from __future__ import annotations

import contextlib
import json
import threading
from collections.abc import Callable, Iterator
from dataclasses import dataclass, field
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from typing import Any

import pytest

from toolbound import BearerAuth, Limits, NetworkPolicy, Service


def pytest_collection_modifyitems(items: list[pytest.Item]) -> None:
    for item in items:
        if "tests/security/" in item.nodeid.replace("\\", "/"):
            item.add_marker(pytest.mark.security)


@dataclass
class Seen:
    method: str
    path: str
    headers: dict[str, str]
    body: bytes


Responder = Callable[["LocalAPI", Seen], tuple[int, dict[str, str], bytes]]


@dataclass
class LocalAPI:
    """A real HTTP server on 127.0.0.1 whose behavior each test scripts."""

    port: int = 0
    seen: list[Seen] = field(default_factory=list)
    responder: Responder | None = None

    @property
    def base_url(self) -> str:
        return f"http://127.0.0.1:{self.port}"

    def service(self, **kw: Any) -> Service:
        kw.setdefault("limits", Limits(timeout=2.0))
        return Service(
            name=kw.pop("name", "local"),
            base_url=self.base_url,
            network=NetworkPolicy(
                allow_http=True,
                allow_ports=(self.port,),
                allow_networks=("127.0.0.1/32",),
            ),
            auth=kw.pop("auth", BearerAuth("t")),
            **kw,
        )


def _json(status: int, payload: Any, **headers: str) -> tuple[int, dict[str, str], bytes]:
    return status, {"Content-Type": "application/json", **headers}, json.dumps(payload).encode()


@pytest.fixture
def local_api() -> Iterator[LocalAPI]:
    api = LocalAPI()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *args: object) -> None:
            pass

        def _handle(self) -> None:
            length = int(self.headers.get("Content-Length") or 0)
            seen = Seen(
                self.command,
                self.path,
                {k.lower(): v for k, v in self.headers.items()},
                self.rfile.read(length) if length else b"",
            )
            api.seen.append(seen)
            status, headers, body = (
                api.responder(api, seen) if api.responder else _json(200, {"ok": True})
            )
            self.send_response(status)
            for key, value in headers.items():
                self.send_header(key, value)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            with contextlib.suppress(OSError):
                self.wfile.write(body)

        do_GET = do_POST = do_PUT = do_PATCH = do_DELETE = _handle

    server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    api.port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        yield api
    finally:
        server.shutdown()
        server.server_close()


json_response = _json
