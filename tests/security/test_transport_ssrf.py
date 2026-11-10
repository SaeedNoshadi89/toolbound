"""SecureTransport against a real local HTTP server (no internet needed)."""

from __future__ import annotations

import gzip
import json
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

from toolbound import (
    BearerAuth,
    ErrorCode,
    Gateway,
    Limits,
    NetworkPolicy,
    Operation,
    Service,
    StaticCredentials,
    allow_all,
)
from toolbound.transport import SecureTransport

BOMB = gzip.compress(b"\0" * (20 * 1024 * 1024))


class Handler(BaseHTTPRequestHandler):
    def log_message(self, *args):  # silence
        pass

    def _send(self, status, body: bytes, headers=None):
        self.send_response(status)
        for key, value in (headers or {"Content-Type": "application/json"}).items():
            self.send_header(key, value)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def do_GET(self):
        if self.path == "/json":
            self._send(
                200,
                json.dumps(
                    {
                        "ok": True,
                        "host": self.headers["Host"],
                        "auth": self.headers.get("Authorization"),
                    }
                ).encode(),
            )
        elif self.path == "/big":
            self._send(200, json.dumps({"x": "y" * 10_000}).encode())
        elif self.path == "/bomb":
            self._send(200, BOMB, {"Content-Type": "application/json", "Content-Encoding": "gzip"})
        elif self.path == "/slow":
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.end_headers()
            try:
                for _ in range(50):
                    self.wfile.write(b" ")
                    self.wfile.flush()
                    time.sleep(0.1)
            except OSError:
                pass
        elif self.path == "/to-metadata":
            self._send(302, b"", {"Location": "http://169.254.169.254/latest/meta-data/"})
        else:
            self._send(404, b"{}")


@pytest.fixture(scope="module")
def server():
    httpd = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
    thread = threading.Thread(target=httpd.serve_forever, daemon=True)
    thread.start()
    yield httpd.server_address[1]
    httpd.shutdown()


def local_service(port, *, trusted=True, host="127.0.0.1", **kw):
    network = NetworkPolicy(
        allow_http=True,
        allow_hosts=(host,),
        allow_ports=(port,),
        allow_networks=("127.0.0.0/8", "::1/128") if trusted else (),
        **kw,
    )
    return Service(
        name="local",
        base_url=f"http://{host}:{port}",
        network=network,
        auth=BearerAuth("t"),
        limits=Limits(timeout=1.0, max_response_bytes=4096),
    )


async def call(service, path, ctx, **gateway_kw):
    op = Operation(name="op", description="d", service=service, path=path)
    async with Gateway(
        authorize=allow_all,
        credentials=StaticCredentials({"t": "tok-12345678"}),
        secret=b"k" * 32,
        **gateway_kw,
    ).register(op) as gw:
        return await gw.call("op", {}, ctx=ctx)


async def test_trusted_internal_service(server, ctx):
    result = await call(local_service(server), "/json", ctx)
    assert result.ok, result.error
    assert result.data["host"] == f"127.0.0.1:{server}"
    assert result.data["auth"] == "Bearer [REDACTED]"  # echoed credential scrubbed


async def test_loopback_blocked_without_explicit_trust(server, ctx):
    result = await call(local_service(server, trusted=False), "/json", ctx)
    assert result.error and result.error.code is ErrorCode.NETWORK_BLOCKED


async def test_hostname_resolving_to_loopback_blocked(server, ctx):
    result = await call(local_service(server, trusted=False, host="localhost"), "/json", ctx)
    assert result.error and result.error.code is ErrorCode.NETWORK_BLOCKED


async def test_hostname_to_loopback_allowed_when_trusted(server, ctx):
    result = await call(local_service(server, host="localhost"), "/json", ctx)
    assert result.ok and result.data["host"] == f"localhost:{server}"


async def test_response_size_limit(server, ctx):
    result = await call(local_service(server), "/big", ctx)
    assert result.error and result.error.code is ErrorCode.RESPONSE_TOO_LARGE


async def test_decompression_bomb_stopped(server, ctx):
    result = await call(local_service(server), "/bomb", ctx)
    assert result.error and result.error.code is ErrorCode.RESPONSE_TOO_LARGE


async def test_slow_drip_hits_total_deadline(server, ctx):
    started = time.perf_counter()
    service = local_service(server)
    op = Operation(name="op", description="d", service=service, path="/slow")
    from toolbound import RetryPolicy

    service = Service(
        name="local",
        base_url=service.base_url,
        network=service.network,
        limits=Limits(timeout=0.5),
        retry=RetryPolicy(max_attempts=1),
    )
    op = Operation(name="op", description="d", service=service, path="/slow")
    async with Gateway(authorize=allow_all, secret=b"k" * 32).register(op) as gw:
        result = await gw.call("op", {}, ctx=ctx)
    assert result.error and result.error.code is ErrorCode.TIMEOUT
    assert time.perf_counter() - started < 3


async def test_redirect_to_metadata_blocked_end_to_end(server, ctx):
    result = await call(local_service(server, follow_redirects=True), "/to-metadata", ctx)
    assert result.error and result.error.code is ErrorCode.NETWORK_BLOCKED


async def test_connection_refused_is_upstream_unavailable(ctx):
    service = local_service(1)  # nothing listens on port 1
    from toolbound import RetryPolicy

    service = Service(
        name="local",
        base_url=service.base_url,
        network=service.network,
        retry=RetryPolicy(max_attempts=1),
    )
    op = Operation(name="op", description="d", service=service, path="/x")
    async with Gateway(authorize=allow_all, secret=b"k" * 32).register(op) as gw:
        result = await gw.call("op", {}, ctx=ctx)
    # Linux/macOS refuse immediately; Windows may retry the SYN until the deadline.
    assert result.error and result.error.code in (ErrorCode.UPSTREAM_UNAVAILABLE, ErrorCode.TIMEOUT)
    assert result.error.retryable


async def test_concurrent_requests_share_transport(server, ctx):
    import asyncio

    op = Operation(name="op", description="d", service=local_service(server), path="/json")
    transport = SecureTransport()
    gw = Gateway(
        authorize=allow_all,
        credentials=StaticCredentials({"t": "tok-12345678"}),
        transport=transport,
        secret=b"k" * 32,
    ).register(op)
    results = await asyncio.gather(*(gw.call("op", {}, ctx=ctx) for _ in range(30)))
    assert all(r.ok for r in results)
    await gw.aclose()  # caller-owned transport stays open
    await transport.aclose()


def test_tls_verification_cannot_be_disabled():
    with pytest.raises(ValueError):
        SecureTransport(verify=False)


@pytest.mark.network
async def test_real_https_with_pinned_ip(ctx):
    import os

    if os.environ.get("TOOLBOUND_NETWORK_TESTS") != "1":
        pytest.skip("set TOOLBOUND_NETWORK_TESTS=1")
    service = Service(name="gh", base_url="https://api.github.com")
    op = Operation(
        name="zen",
        description="d",
        service=service,
        path="/zen",
        output=__import__("toolbound").Output(accept_text=True),
    )
    async with Gateway(authorize=allow_all, secret=b"k" * 32).register(op) as gw:
        result = await gw.call("zen", {}, ctx=ctx)
    assert result.ok or (result.error and result.error.code is ErrorCode.RATE_LIMITED)


@pytest.mark.network
async def test_pinned_ip_still_verifies_certificate_hostname():
    """Connecting to a pinned IP must not weaken TLS: a wrong host name fails."""
    import os
    import socket

    if os.environ.get("TOOLBOUND_NETWORK_TESTS") != "1":
        pytest.skip("set TOOLBOUND_NETWORK_TESTS=1")
    from toolbound import ToolFailure
    from toolbound.core.ports import HttpRequest

    github_ip = socket.gethostbyname("api.github.com")

    class Resolver:
        async def resolve(self, host, port):
            return [github_ip]

    transport = SecureTransport(resolver=Resolver())
    request = HttpRequest(
        method="GET",
        url="https://example.com/",
        headers=(),
        body=None,
        network=NetworkPolicy(allow_hosts=("example.com",), allow_ports=(443,)),
        timeout=5,
        connect_timeout=3,
        max_response_bytes=10_000,
    )
    with pytest.raises(ToolFailure) as info:
        await transport.send(request)
    assert info.value.code is ErrorCode.UPSTREAM_UNAVAILABLE
    await transport.aclose()
