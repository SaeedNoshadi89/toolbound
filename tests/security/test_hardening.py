"""M5 and Low findings: pinning, warnings, reprs, limits, redaction, offsets, IP ranges."""

from __future__ import annotations

import socket
import threading
import warnings
from http.server import BaseHTTPRequestHandler, HTTPServer

import pytest

from toolbound import (
    ByteEstimator,
    ErrorCode,
    ExecutionContext,
    Gateway,
    HttpRequest,
    NetworkPolicy,
    Operation,
    Output,
    Pagination,
    Service,
    StaticCredentials,
    ToolboundWarning,
    allow_all,
)
from toolbound.core.contracts import RateLimit
from toolbound.core.network import check_ip
from toolbound.core.ratelimit import RateLimiter
from toolbound.core.schema import normalize_input_schema
from toolbound.core.shaping import compile_output, process
from toolbound.transport import SecureTransport

SVC = Service(name="api", base_url="https://api.example.com")


class CountingResolver:
    def __init__(self, answers):
        self.answers = answers
        self.calls = 0

    async def resolve(self, host, port):
        self.calls += 1
        return list(self.answers)


def _named_service(port: int, host: str = "rebind.invalid") -> Service:
    return Service(
        name="named",
        base_url=f"http://{host}:{port}",
        network=NetworkPolicy(
            allow_http=True,
            allow_ports=(port,),
            allow_networks=("127.0.0.1/32", "::1/128"),
        ),
    )


async def test_dns_answer_is_pinned_no_second_lookup(local_api):
    """DNS rebinding: the checked answer is the one used; nothing re-resolves the name.

    ``rebind.invalid`` cannot be resolved by the OS, so the request only succeeds
    if the connection goes to the address our resolver returned and we checked.
    """
    resolver = CountingResolver(["127.0.0.1"])
    op = Operation(name="get", description="d", service=_named_service(local_api.port), path="/x")
    async with Gateway(
        authorize=allow_all, secret=b"k" * 32, transport=SecureTransport(resolver=resolver)
    ).register(op) as gw:
        result = await gw.call("get", {}, ctx=ExecutionContext(actor="a"))
    assert result.ok, result.to_json()
    assert resolver.calls == 1
    assert local_api.seen[0].headers["host"] == f"rebind.invalid:{local_api.port}"


async def test_rebinding_to_private_answer_is_blocked():
    """Second lookup returns a private address: that request is blocked, nothing sent."""
    answers = iter([["93.184.216.34"], ["169.254.169.254"]])

    class Rebinding:
        async def resolve(self, host, port):
            return next(answers)

    svc = Service(name="pub", base_url="https://example.com")
    op = Operation(name="get", description="d", service=svc, path="/")
    transport = SecureTransport(resolver=Rebinding())
    request = HttpRequest(
        method="GET",
        url="https://example.com/",
        headers=(),
        body=None,
        network=svc.network,
        timeout=1,
        connect_timeout=1,
        max_response_bytes=10,
    )
    first = await transport._addresses("example.com", 443, request)
    assert first == ["93.184.216.34"]
    with pytest.raises(Exception) as info:
        await transport._addresses("example.com", 443, request)
    assert getattr(info.value, "code", None) is ErrorCode.NETWORK_BLOCKED
    assert op.name == "get"


def _ipv6_loopback_available() -> bool:
    try:
        with socket.socket(socket.AF_INET6) as s:
            s.bind(("::1", 0))
        return True
    except OSError:
        return False


@pytest.mark.skipif(not _ipv6_loopback_available(), reason="no IPv6 loopback")
async def test_l4_falls_back_to_next_checked_address():
    class V6Server(HTTPServer):
        address_family = socket.AF_INET6

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, *a):
            pass

        def do_GET(self):
            body = b'{"ok": true}'
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

    server = V6Server(("::1", 0), Handler)
    port = server.server_address[1]
    threading.Thread(target=server.serve_forever, daemon=True).start()
    try:
        resolver = CountingResolver(["127.0.0.1", "::1"])  # IPv4 tried first and refused
        op = Operation(name="get", description="d", service=_named_service(port), path="/x")
        async with Gateway(
            authorize=allow_all, secret=b"k" * 32, transport=SecureTransport(resolver=resolver)
        ).register(op) as gw:
            result = await gw.call("get", {}, ctx=ExecutionContext(actor="a"))
        assert result.ok, result.to_json()
    finally:
        server.shutdown()
        server.server_close()


async def test_m5_ephemeral_secret_warns_once_when_tokens_are_issued(mock):
    mock.route("GET", "https://api.example.com/items", [{"id": 1}])
    op = Operation(
        name="items",
        description="d",
        service=SVC,
        path="/items",
        pagination=Pagination(type="page", param="page"),
    )
    gw = Gateway(authorize=allow_all, transport=mock).register(op)
    ctx = ExecutionContext(actor="a")
    with pytest.warns(ToolboundWarning, match="secret="):
        await gw.call("items", {}, ctx=ctx)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        await gw.call("items", {}, ctx=ctx)  # only once


async def test_m5_no_warning_with_configured_secret(mock):
    mock.route("GET", "https://api.example.com/items", [{"id": 1}])
    op = Operation(
        name="items",
        description="d",
        service=SVC,
        path="/items",
        pagination=Pagination(type="page", param="page"),
    )
    gw = Gateway(authorize=allow_all, transport=mock, secret=b"k" * 32).register(op)
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        await gw.call("items", {}, ctx=ExecutionContext(actor="a"))


async def test_l1_request_and_response_reprs_hide_credentials(make_gateway, mock, ctx):
    from toolbound import ApiKeyAuth, BearerAuth

    svc = Service(name="s", base_url="https://api.example.com", auth=BearerAuth("t"))
    keyed = Service(
        name="k", base_url="https://api.example.com", auth=ApiKeyAuth("t", header=None, query="key")
    )
    mock.route("GET", "https://api.example.com/a", {"ok": 1})
    mock.route("POST", "https://api.example.com/b", {"ok": 1})
    gw = make_gateway(credentials=StaticCredentials({"t": "SECRET-VALUE-123"})).register(
        Operation(name="a", description="d", service=svc, path="/a"),
        Operation(
            name="b",
            description="d",
            service=keyed,
            method="POST",
            path="/b",
            input={"note": {"type": "string"}},
        ),
    )
    await gw.call("a", {}, ctx=ctx)
    await gw.call("b", {"note": "private body"}, ctx=ctx)
    for request in mock.requests:
        text = repr(request)
        assert "SECRET-VALUE-123" not in text
        assert "private body" not in text


def test_l2_rate_limiter_forgets_idle_callers():
    limiter = RateLimiter()
    limit = RateLimit(calls=5, per_seconds=0.01)
    for i in range(2048):
        limiter.check("t", limit, ExecutionContext(actor=f"user{i}"))
    import time

    time.sleep(0.03)
    steady = RateLimit(calls=10_000, per_seconds=60)
    for _ in range(1024):
        limiter.check("t", steady, ExecutionContext(actor="steady"))
    assert len(limiter) < 50


def test_l5_renamed_sensitive_field_is_still_redacted():
    out = process(
        compile_output(Output(shape={"api": "credentials.api_key", "owner": "credentials.owner"})),
        {"credentials": {"api_key": "abc-not-a-pattern", "owner": "ann"}},
        estimator=ByteEstimator(),
    )
    assert out.data == {"api": "[REDACTED]", "owner": "ann"}
    assert out.report.redacted == 1


def test_l6_non_object_items_reported_and_offsets_stay_aligned():
    compiled = compile_output(Output(shape={"id": "id"}, max_items=3, max_tokens=None))
    upstream = [1, {"id": 1}, "x", {"id": 2}, {"id": 3}]
    first = process(compiled, upstream, estimator=ByteEstimator())
    assert first.data == [{"id": 1}]
    assert {(o.reason, o.count) for o in first.report.omissions()} >= {("not_object", 2)}
    second = process(compiled, upstream, estimator=ByteEstimator(), offset=first.next_offset)
    assert second.data == [{"id": 2}, {"id": 3}]  # no duplicate of id 1


@pytest.mark.parametrize(
    "address",
    [
        "192.0.0.8",
        "192.0.0.170",
        "198.18.0.1",
        "100.64.0.1",
        "2001:db8::1",
        "3fff::1",
        "100::1",
        "5f00::1",
        "fec0::1",
        "::ffff:169.254.169.254",
        "64:ff9b::a9fe:a9fe",
    ],
)
def test_l7_special_purpose_ranges_blocked_on_every_python(address):
    with pytest.raises(Exception) as info:
        check_ip(address, NetworkPolicy())
    assert getattr(info.value, "code", None) is ErrorCode.NETWORK_BLOCKED


def test_l7_public_addresses_still_allowed():
    for address in ("8.8.8.8", "1.1.1.1", "2606:4700:4700::1111"):
        check_ip(address, NetworkPolicy())


def test_l8_unenforced_format_warns():
    with pytest.warns(ToolboundWarning, match="uri"):
        normalize_input_schema("t", {"u": {"type": "string", "format": "uri"}})
