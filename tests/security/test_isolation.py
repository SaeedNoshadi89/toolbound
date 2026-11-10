"""Multi-user / multi-tenant isolation, concurrency and event-loop safety."""

from __future__ import annotations

import asyncio
import threading

import pytest

from toolbound import (
    ErrorCode,
    ExecutionContext,
    Gateway,
    MemoryStateStore,
    Operation,
    Output,
    Pagination,
    RateLimit,
    StaticCredentials,
    allow_all,
    from_ctx,
)
from toolbound.sync import SyncGateway
from toolbound.transport import SecureTransport

from .conftest import json_response

KEY = b"k" * 32


def _gateway(api, *ops, **kw):
    kw.setdefault("credentials", StaticCredentials({"t": "tok-12345678"}))
    return Gateway(authorize=allow_all, secret=KEY, **kw).register(*ops)


async def test_c1_upstream_cookie_never_reaches_another_user(local_api):
    """C1: a Set-Cookie from Alice's call must not be sent on Bob's call."""

    def responder(api, seen):
        if seen.path.startswith("/alice"):
            return json_response(200, {"ok": 1}, **{"Set-Cookie": "session=ALICE; Path=/"})
        return json_response(200, {"ok": 1})

    local_api.responder = responder
    op = Operation(
        name="get",
        description="d",
        service=local_api.service(),
        path="/{who}",
        input={"who": {"type": "string"}},
    )
    async with _gateway(local_api, op) as gw:
        await gw.call("get", {"who": "alice"}, ctx=ExecutionContext(actor="alice"))
        await gw.call("get", {"who": "bob"}, ctx=ExecutionContext(actor="bob"))
        await gw.call("get", {"who": "alice"}, ctx=ExecutionContext(actor="alice"))
    assert [s.headers.get("cookie") for s in local_api.seen] == [None, None, None]


async def test_c1_cookie_header_from_redirect_is_not_stored(local_api):
    """C1: cookies set on a redirect hop are not replayed either."""

    def responder(api, seen):
        if seen.path == "/start":
            return 302, {"Location": "/end", "Set-Cookie": "sid=X; Path=/"}, b""
        return json_response(200, {"ok": 1})

    local_api.responder = responder
    from toolbound import NetworkPolicy, Service

    svc = Service(
        name="r",
        base_url=local_api.base_url,
        network=NetworkPolicy(
            allow_http=True,
            allow_ports=(local_api.port,),
            allow_networks=("127.0.0.1/32",),
            follow_redirects=True,
        ),
    )
    op = Operation(name="start", description="d", service=svc, path="/start")
    async with _gateway(local_api, op) as gw:
        result = await gw.call("start", {}, ctx=ExecutionContext(actor="a"))
    assert result.ok
    assert all("cookie" not in s.headers for s in local_api.seen)


async def test_concurrent_tenants_each_get_their_own_binding(local_api):
    """Many tenants in parallel: every request carries only its own bound tenant."""

    def responder(api, seen):
        return json_response(200, {"tenant": seen.path.split("/")[2]})

    local_api.responder = responder
    op = Operation(
        name="org",
        description="d",
        service=local_api.service(),
        path="/orgs/{org}",
        bind={"org": from_ctx("tenant")},
        output=Output(shape={"tenant": "tenant"}),
    )
    async with _gateway(local_api, op) as gw:
        tenants = [f"t{i}" for i in range(40)]
        results = await asyncio.gather(
            *(gw.call("org", {}, ctx=ExecutionContext(actor=f"u-{t}", tenant=t)) for t in tenants)
        )
    assert [r.data["tenant"] for r in results] == tenants


async def test_cursor_from_one_tenant_rejected_for_another(make_gateway, mock):
    op = Operation(
        name="items",
        description="d",
        service=_svc(),
        path="/items",
        pagination=Pagination(type="page", param="page"),
    )
    mock.route("GET", "https://api.example.com/items", [{"id": 1}])
    gw = make_gateway().register(op)
    first = await gw.call("items", {}, ctx=ExecutionContext(actor="a", tenant="t1"))
    cursor = first.meta.next_cursor
    assert cursor
    other = await gw.call("items", {"cursor": cursor}, ctx=ExecutionContext(actor="a", tenant="t2"))
    assert other.error.code is ErrorCode.INVALID_CURSOR


async def test_rate_limits_are_isolated_per_actor(make_gateway, mock):
    op = Operation(
        name="items",
        description="d",
        service=_svc(),
        path="/items",
        rate_limit=RateLimit(calls=1, per_seconds=60),
    )
    mock.route("GET", "https://api.example.com/items", [])
    gw = make_gateway().register(op)
    assert (await gw.call("items", {}, ctx=ExecutionContext(actor="a"))).ok
    assert not (await gw.call("items", {}, ctx=ExecutionContext(actor="a"))).ok
    assert (await gw.call("items", {}, ctx=ExecutionContext(actor="b"))).ok


def test_secure_transport_works_across_event_loops(local_api):
    """M6: one gateway used by successive event loops (e.g. FastAPI TestClient)."""
    op = Operation(name="get", description="d", service=local_api.service(), path="/x")
    gw = _gateway(local_api, op)
    for _ in range(3):  # each asyncio.run() is a brand-new loop
        result = asyncio.run(gw.call("get", {}, ctx=ExecutionContext(actor="a")))
        assert result.ok, result.to_json()


def test_gateway_usable_from_several_threads_and_loops(local_api):
    """Concurrency limits and replay state are not bound to a single loop."""
    op = Operation(
        name="w",
        description="d",
        service=local_api.service(),
        method="POST",
        path="/w",
        input={"n": {"type": "integer"}},
    )
    gw = _gateway(local_api, op, state=MemoryStateStore())
    errors: list[str] = []

    def worker(i: int) -> None:
        with SyncGateway(gw) as sync:
            for j in range(5):
                r = sync.call("w", {"n": j}, ctx=ExecutionContext(actor="a"), call_id=f"{i}-{j}")
                if not r.ok:
                    errors.append(r.to_json())
            dup = sync.call("w", {"n": 0}, ctx=ExecutionContext(actor="a"), call_id=f"{i}-0")
            if dup.ok or dup.error.code is not ErrorCode.DUPLICATE_CALL:
                errors.append("duplicate executed")

    threads = [threading.Thread(target=worker, args=(i,)) for i in range(4)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert errors == []
    assert len(local_api.seen) == 20


async def test_secure_transport_aclose_only_closes_current_loop():
    transport = SecureTransport()
    await transport.aclose()  # nothing open: must not fail


def _svc():
    from toolbound import Service

    return Service(name="api", base_url="https://api.example.com")


@pytest.mark.parametrize("scope", ["actor", "tenant"])
async def test_rate_limit_scope_isolation(make_gateway, mock, scope):
    op = Operation(
        name="items",
        description="d",
        service=_svc(),
        path="/items",
        rate_limit=RateLimit(calls=1, per_seconds=60, scope=scope),
    )
    mock.route("GET", "https://api.example.com/items", [])
    gw = make_gateway().register(op)
    a = ExecutionContext(actor="a", tenant="t1")
    b = ExecutionContext(actor="b", tenant="t2")
    assert (await gw.call("items", {}, ctx=a)).ok
    assert (await gw.call("items", {}, ctx=b)).ok
