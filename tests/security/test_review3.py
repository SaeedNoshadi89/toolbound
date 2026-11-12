"""Regressions for the third security review. ``r<N>`` = finding number."""

from __future__ import annotations

import gzip
import zlib
from urllib.parse import parse_qs, urlsplit

import pytest

from toolbound import (
    ConfigurationError,
    ErrorCode,
    MockResponse,
    NetworkPolicy,
    Operation,
    Pagination,
    Service,
    ToolFailure,
)
from toolbound.transport.http import _BoundedDecoder

SVC = Service(name="tracker", base_url="https://api.example.com")


# --------------------------------------------------------------------------- r1


def test_r1_bound_value_outside_explicit_query_is_rejected(make_gateway):
    op = Operation(
        name="list_issues",
        description="d",
        service=SVC,
        path="/issues",
        input={"state": {"type": "string"}},
        query=("state",),
        bind={"org": "ctx.tenant"},
    )
    with pytest.raises(ConfigurationError, match=r"\['org'\] would never be sent"):
        make_gateway().register(op)


def test_r1_bound_value_outside_explicit_query_and_body_is_rejected(make_gateway):
    op = Operation(
        name="create_issue",
        description="d",
        service=SVC,
        method="POST",
        path="/issues",
        input={"title": {"type": "string"}},
        query=(),
        body=("title",),
        bind={"org": "ctx.tenant"},
    )
    with pytest.raises(ConfigurationError, match="would never be sent"):
        make_gateway().register(op)


@pytest.mark.parametrize(
    ("method", "kwargs"),
    [
        ("GET", {}),  # automatic placement: query
        ("GET", {"query": ("state", "org")}),
        ("POST", {"body": ("state",)}),  # the rest goes to the query string
        ("POST", {"query": ()}),  # the rest goes to the body
    ],
)
async def test_r1_placed_bindings_are_sent(make_gateway, mock, ctx, method, kwargs):
    mock.route(method, "https://api.example.com/issues", MockResponse(200, json=[]))
    op = Operation(
        name="issues",
        description="d",
        service=SVC,
        method=method,
        path="/issues",
        input={"state": {"type": "string"}},
        bind={"org": "ctx.tenant"},
        **kwargs,
    )
    gw = make_gateway().register(op)
    result = await gw.call("issues", {"state": "open"}, ctx=ctx, call_id="c1")
    assert result.ok, result.error
    sent = mock.requests[-1]
    assert "org=acme" in sent.url or b'"org": "acme"' in (sent.body or b"")


# --------------------------------------------------------------------------- r2


async def test_r2_link_cursor_reapplies_bound_query_values(make_gateway, mock, ctx):
    def handler(request):
        if "page=2" in request.url:
            return MockResponse(200, json=[{"id": 2}])
        # The upstream (or anything rewriting its headers) swaps the tenant filter.
        next_url = "https://api.example.com/items?org=globex&org=other&page=2"
        return MockResponse(200, json=[{"id": 1}], headers={"Link": f'<{next_url}>; rel="next"'})

    mock.route("GET", "https://api.example.com/items", handler)
    op = Operation(
        name="items",
        description="d",
        service=SVC,
        path="/items",
        bind={"org": "ctx.tenant"},
        pagination=Pagination(type="link"),
    )
    gw = make_gateway().register(op)
    first = await gw.call("items", {}, ctx=ctx)
    assert first.meta.next_cursor
    second = await gw.call("items", {"cursor": first.meta.next_cursor}, ctx=ctx)
    assert second.ok, second.error
    query = parse_qs(urlsplit(mock.requests[-1].url).query)
    assert query["org"] == ["acme"]
    assert query["page"] == ["2"]


# --------------------------------------------------------------------------- r3


def _redirecting_service() -> Service:
    return Service(
        name="s",
        base_url="https://api.example.com",
        headers={"X-Tenant-Key": "tenant-secret-123"},
        network=NetworkPolicy(
            follow_redirects=True, allow_hosts=("api.example.com", "cdn.example.com")
        ),
    )


async def test_r3_cross_origin_redirect_drops_static_headers(make_gateway, mock, ctx):
    mock.route(
        "GET",
        "https://api.example.com/x",
        MockResponse(302, headers={"Location": "https://cdn.example.com/blob"}),
    )
    mock.route("GET", "https://cdn.example.com/blob", {"ok": True})
    op = Operation(
        name="op",
        description="d",
        service=_redirecting_service(),
        path="/x",
        headers={"X-Op-Secret": "op-secret-456"},
    )
    result = await make_gateway().register(op).call("op", {}, ctx=ctx)
    assert result.ok, result.error
    first, second = mock.requests
    first_names = {k.lower() for k, _ in first.headers}
    second_headers = {k.lower(): v for k, v in second.headers}
    assert {"x-tenant-key", "x-op-secret"} <= first_names
    assert "x-tenant-key" not in second_headers
    assert "x-op-secret" not in second_headers
    assert second_headers["accept"] == "application/json"
    assert "user-agent" in second_headers


async def test_r3_same_origin_redirect_keeps_static_headers(make_gateway, mock, ctx):
    mock.route(
        "GET",
        "https://api.example.com/x",
        MockResponse(302, headers={"Location": "https://api.example.com/y"}),
    )
    mock.route("GET", "https://api.example.com/y", {"ok": True})
    op = Operation(name="op", description="d", service=_redirecting_service(), path="/x")
    result = await make_gateway().register(op).call("op", {}, ctx=ctx)
    assert result.ok, result.error
    assert ("X-Tenant-Key", "tenant-secret-123") in mock.requests[-1].headers


# --------------------------------------------------------------------------- r4

PAYLOAD = b'{"hello": "world"}' * 1000


def _decode(encoding: str, data: bytes, limit: int = 1 << 20, chunk: int = 7) -> bytes:
    decoder = _BoundedDecoder(encoding, limit)
    out = [decoder.feed(data[i : i + chunk]) for i in range(0, len(data), chunk)]
    out.append(decoder.finish())
    return b"".join(out)


def _raw_deflate(data: bytes) -> bytes:
    obj = zlib.compressobj(wbits=-zlib.MAX_WBITS)
    return obj.compress(data) + obj.flush()


@pytest.mark.parametrize(
    ("encoding", "compress"),
    [
        ("", lambda d: d),
        ("identity", lambda d: d),
        ("gzip", gzip.compress),
        ("x-gzip", gzip.compress),
        ("deflate", zlib.compress),  # RFC 9110: zlib-wrapped
        ("deflate", _raw_deflate),  # what many servers actually send
        ("GZIP, identity", gzip.compress),
    ],
)
def test_r4_decoder_round_trips(encoding, compress):
    assert _decode(encoding, compress(PAYLOAD)) == PAYLOAD


def test_r4_bomb_stops_one_byte_past_the_limit():
    limit = 64 * 1024
    bomb = gzip.compress(b"\0" * (20 * 1024 * 1024))
    decoder = _BoundedDecoder("gzip", limit)
    produced = 0
    with pytest.raises(ToolFailure) as info:
        # One feed with the whole bomb: httpx would inflate all 20 MiB here.
        produced += len(decoder.feed(bomb))
    assert info.value.code is ErrorCode.RESPONSE_TOO_LARGE
    assert decoder._size <= limit + 1
    assert produced == 0


@pytest.mark.parametrize("encoding", ["br", "zstd", "gzip, gzip", "compress"])
def test_r4_unrequested_encodings_are_refused(encoding):
    with pytest.raises(ToolFailure) as info:
        _BoundedDecoder(encoding, 1024)
    assert info.value.code is ErrorCode.UPSTREAM_ERROR


def test_r4_corrupt_body_is_undecodable():
    with pytest.raises(ToolFailure) as info:
        _decode("gzip", b"\x1f\x8b" + b"not gzip at all" * 10)
    assert info.value.code is ErrorCode.UPSTREAM_ERROR
