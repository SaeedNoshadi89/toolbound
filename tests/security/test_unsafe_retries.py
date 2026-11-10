"""M2 / L3: writes with an unknown outcome are never presented as safe to retry."""

from __future__ import annotations

import asyncio

import pytest

from toolbound import (
    Effect,
    ErrorCode,
    Gateway,
    Limits,
    MockResponse,
    Operation,
    PythonTool,
    RetryPolicy,
    Service,
    allow_all,
)
from toolbound.core.errors import ToolFailure

SVC = Service(name="api", base_url="https://api.example.com")


class FailingTransport:
    """Raises the given failure on every send and counts attempts."""

    def __init__(self, failure: ToolFailure) -> None:
        self.failure = failure
        self.sent = 0

    async def send(self, request):
        self.sent += 1
        raise self.failure

    async def aclose(self) -> None:
        pass


def _op(method="POST", **kw):
    return Operation(
        name="op", description="d", service=kw.pop("service", SVC), method=method, path="/x", **kw
    )


@pytest.mark.parametrize(
    "failure",
    [
        ToolFailure(ErrorCode.TIMEOUT, "t", request_sent=None),
        ToolFailure(ErrorCode.UPSTREAM_UNAVAILABLE, "reset", request_sent=None),
    ],
)
async def test_m2_write_with_unknown_outcome_is_not_retryable(make_gateway, ctx, failure):
    """The original failure: a timed-out POST told the model retryable=true."""
    transport = FailingTransport(failure)
    gw = make_gateway(transport=transport).register(_op())
    result = await gw.call("op", {}, ctx=ctx, call_id="c1")
    assert result.error.code is ErrorCode.OUTCOME_UNKNOWN
    assert result.error.retryable is False
    assert "retryable" not in result.to_model()["error"]
    assert transport.sent == 1  # never retried automatically


async def test_m2_unknown_outcome_even_with_idempotency_header(make_gateway, ctx):
    transport = FailingTransport(ToolFailure(ErrorCode.TIMEOUT, "t", request_sent=None))
    gw = make_gateway(transport=transport).register(_op(idempotency_header="Idempotency-Key"))
    result = await gw.call("op", {}, ctx=ctx, call_id="c1")
    assert result.error.code is ErrorCode.OUTCOME_UNKNOWN
    assert result.error.retryable is False
    assert transport.sent == 3  # internal retries reuse one idempotency key


async def test_m2_internal_retries_reuse_idempotency_key(make_gateway, mock, ctx):
    calls = []

    def handler(request):
        calls.append(dict(request.headers)["Idempotency-Key"])
        return MockResponse(503) if len(calls) < 3 else MockResponse(201, json={"id": 1})

    mock.route("POST", "https://api.example.com/x", handler)
    gw = make_gateway().register(_op(idempotency_header="Idempotency-Key"))
    result = await gw.call("op", {}, ctx=ctx, call_id="c1")
    assert result.ok
    assert len(calls) == 3 and len(set(calls)) == 1


async def test_m2_not_sent_failure_stays_retryable(make_gateway, ctx):
    transport = FailingTransport(
        ToolFailure(ErrorCode.UPSTREAM_UNAVAILABLE, "refused", request_sent=False)
    )
    gw = make_gateway(transport=transport).register(_op())
    result = await gw.call("op", {}, ctx=ctx, call_id="c1")
    assert result.error.code is ErrorCode.UPSTREAM_UNAVAILABLE
    assert result.error.retryable is True


async def test_m2_post_without_idempotency_is_never_retried(make_gateway, mock, ctx):
    mock.route("POST", "https://api.example.com/x", MockResponse(503))
    gw = make_gateway().register(_op())
    result = await gw.call("op", {}, ctx=ctx)
    assert len(mock.requests) == 1
    assert result.error.retryable is False
    assert "may or may not have been applied" in result.error.message


async def test_m2_reads_remain_retryable(make_gateway, ctx):
    transport = FailingTransport(ToolFailure(ErrorCode.TIMEOUT, "t", request_sent=None))
    gw = make_gateway(transport=transport).register(_op("GET"))
    result = await gw.call("op", {}, ctx=ctx)
    assert result.error.code is ErrorCode.TIMEOUT
    assert result.error.retryable is True
    assert transport.sent == 3


async def test_m2_python_write_timeout_is_outcome_unknown(make_gateway, ctx):
    async def slow():
        await asyncio.sleep(1)
        return {}

    tool = PythonTool(name="w", description="d", effect=Effect.WRITE, handler=slow, timeout=0.05)
    gw = make_gateway().register(tool)
    result = await gw.call("w", {}, ctx=ctx)
    assert result.error.code is ErrorCode.OUTCOME_UNKNOWN
    assert result.error.retryable is False


async def test_m2_real_transport_read_timeout_on_post(local_api, ctx):
    """End to end: a POST whose response never arrives is outcome_unknown."""
    import time

    def responder(api, seen):
        time.sleep(1.5)
        return 200, {"Content-Type": "application/json"}, b"{}"

    local_api.responder = responder
    svc = local_api.service(limits=Limits(timeout=0.3, connect_timeout=0.3))
    gw = Gateway(authorize=allow_all, secret=b"k" * 32, credentials=_creds()).register(
        _op(service=svc)
    )
    async with gw:
        result = await gw.call("op", {}, ctx=ctx, call_id="c")
    assert result.error.code is ErrorCode.OUTCOME_UNKNOWN
    assert len(local_api.seen) == 1


async def test_m2_connection_refused_on_post_is_safe_to_retry(ctx):
    import socket

    from toolbound import NetworkPolicy

    sock = socket.socket()
    sock.bind(("127.0.0.1", 0))
    port = sock.getsockname()[1]
    sock.close()  # nothing listens here
    svc = Service(
        name="dead",
        base_url=f"http://127.0.0.1:{port}",
        network=NetworkPolicy(
            allow_http=True, allow_ports=(port,), allow_networks=("127.0.0.1/32",)
        ),
    )
    async with Gateway(authorize=allow_all, secret=b"k" * 32).register(_op(service=svc)) as gw:
        result = await gw.call("op", {}, ctx=ctx)
    assert result.error.code is ErrorCode.UPSTREAM_UNAVAILABLE
    assert result.error.retryable is True


async def test_l3_total_deadline_bounds_retries_and_retry_after(ctx):
    class SlowTransport:
        async def send(self, request):
            await asyncio.sleep(0.2)
            raise ToolFailure(ErrorCode.TIMEOUT, "t", request_sent=None)

        async def aclose(self):
            pass

    svc = Service(
        name="api",
        base_url="https://api.example.com",
        limits=Limits(timeout=0.2, total_timeout=0.3),
        retry=RetryPolicy(max_attempts=10, backoff_base=0.01, backoff_max=0.01),
    )
    gw = Gateway(authorize=allow_all, secret=b"k" * 32, transport=SlowTransport()).register(
        _op("GET", service=svc)
    )
    loop = asyncio.get_running_loop()
    started = loop.time()
    result = await gw.call("op", {}, ctx=ctx)
    assert loop.time() - started < 0.6
    assert result.error.code is ErrorCode.TIMEOUT


async def test_l3_retry_after_beyond_deadline_is_not_waited_for(make_gateway, mock, ctx):
    slept = []

    async def sleep(seconds):
        slept.append(seconds)

    mock.route("GET", "https://api.example.com/x", MockResponse(503, headers={"Retry-After": "20"}))
    svc = Service(name="api", base_url="https://api.example.com", limits=Limits(total_timeout=15))
    gw = make_gateway(sleep=sleep).register(_op("GET", service=svc))
    result = await gw.call("op", {}, ctx=ctx)
    assert slept == []
    assert result.http_status == 503


def _creds():
    from toolbound import StaticCredentials

    return StaticCredentials({"t": "tok-12345678"})
