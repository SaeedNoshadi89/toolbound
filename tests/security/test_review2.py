"""Regressions for the second (adversarial) review of 0.2.0. ``r<N>`` = finding number."""

from __future__ import annotations

import asyncio
import json
import threading
import time
import warnings
from urllib.parse import quote

import pytest

from toolbound import (
    ApiKeyAuth,
    ByteEstimator,
    Effect,
    ErrorCode,
    ExecutionContext,
    Gateway,
    Limits,
    MemoryStateStore,
    MockResponse,
    MockTransport,
    NetworkPolicy,
    Operation,
    Output,
    Pagination,
    PythonTool,
    RateLimit,
    Service,
    StaticCredentials,
    ToolboundWarning,
    allow_all,
    from_ctx,
)
from toolbound.adapters import anthropic as tb_anthropic
from toolbound.core.errors import ToolFailure
from toolbound.core.network import check_ip
from toolbound.core.schema import ArgumentValidator, normalize_input_schema
from toolbound.core.shaping import compile_output, process

SVC = Service(name="api", base_url="https://api.example.com")
KEY = b"k" * 32


# --------------------------------------------------------------------------- r1


ADVERSARIAL = {
    "pem_unterminated": "-----BEGIN RSA PRIVATE KEY-----" * 30_000,
    "jwt_runs": "-eyJ" * 250_000,
    "jwt_dots": "eyJaaaaaaaaa." * 80_000,
    "bearer": "bearer " * 150_000,
    "sk": "-sk-" * 250_000,
    "ghp": "_ghp_" * 200_000,
}


@pytest.mark.parametrize("name", sorted(ADVERSARIAL))
def test_r1_secret_patterns_are_linear(name):
    """The original failure: 800 KB of BEGIN markers froze the process for 71 s."""
    compiled = compile_output(Output(max_tokens=None, max_chars=10_000_000))
    started = time.perf_counter()
    process(compiled, {"a": ADVERSARIAL[name]}, estimator=ByteEstimator())
    assert time.perf_counter() - started < 1.0


def test_r1_default_output_bounds_redaction_work():
    started = time.perf_counter()
    process(
        compile_output(Output()),
        {"a": "-----BEGIN RSA PRIVATE KEY-----" * 160_000},  # ~5 MB, the default cap
        estimator=ByteEstimator(),
    )
    assert time.perf_counter() - started < 1.0


def test_r1_secrets_still_redacted():
    out = process(
        compile_output(Output(max_tokens=None)),
        {
            "pem": "k: -----BEGIN RSA PRIVATE KEY-----\nMIIabc\n-----END RSA PRIVATE KEY----- ok",
            "cut": "-----BEGIN EC PRIVATE KEY-----\nMIIabc (truncated, no END)",
            "jwt": "eyJhbGciOiJIUzI1.eyJzdWIiOiIxMjM0.sigsigsigsig",
            "bearer": "Authorization: Bearer abcdefghijklmnopqrstu",
            "gh": "token ghp_" + "A" * 36,
        },
        estimator=ByteEstimator(),
    )
    assert out.data == {
        "pem": "k: [REDACTED] ok",
        "cut": "[REDACTED]",
        "jwt": "[REDACTED]",
        "bearer": "Authorization: [REDACTED]",
        "gh": "token [REDACTED]",
    }


async def test_r1_event_loop_not_frozen_by_hostile_body(make_gateway, mock, ctx):
    body = json.dumps({"x": "-eyJ" * 200_000}).encode()
    mock.route("GET", "https://api.example.com/h", MockResponse(200, body=body))
    gw = make_gateway().register(
        Operation(name="h", description="d", service=SVC, path="/h", output=Output(max_tokens=None))
    )
    started = time.perf_counter()
    await gw.call("h", {}, ctx=ctx)
    assert time.perf_counter() - started < 1.0


# --------------------------------------------------------------------------- r2 / r4 / r5


class Scripted:
    """Transport that plays a script of failures/responses and counts sends."""

    def __init__(self, *steps):
        self.steps = list(steps)
        self.sent = 0

    async def send(self, request):
        self.sent += 1
        step = self.steps.pop(0)
        if isinstance(step, ToolFailure):
            raise step
        return step.to_http(request.url)

    async def aclose(self):
        pass


def _write(**kw):
    return Operation(
        name="w",
        description="d",
        service=kw.pop("service", SVC),
        method="POST",
        path="/w",
        idempotency_header="Idempotency-Key",
        **kw,
    )


@pytest.mark.parametrize(
    "first",
    [
        ToolFailure(ErrorCode.TIMEOUT, "read timeout", request_sent=None),
        MockResponse(502),
    ],
    ids=["timeout-then-refused", "502-then-refused"],
)
async def test_r2_earlier_attempt_that_may_have_landed_wins(make_gateway, ctx, first):
    """The original failure: last attempt 'not sent' hid an applied first attempt."""
    refused = ToolFailure(ErrorCode.UPSTREAM_UNAVAILABLE, "refused", request_sent=False)
    transport = Scripted(first, refused)
    svc = Service(
        name="api",
        base_url="https://api.example.com",
        retry=__import__("toolbound").RetryPolicy(max_attempts=2),
    )
    gw = make_gateway(transport=transport).register(_write(service=svc))
    result = await gw.call("w", {}, ctx=ctx, call_id="c")
    assert transport.sent == 2
    assert result.error.code is ErrorCode.OUTCOME_UNKNOWN
    assert result.error.retryable is False


async def test_r4_destructive_get_is_never_retried(make_gateway, ctx):
    op = Operation(
        name="cancel",
        description="d",
        service=SVC,
        path="/rpc/cancel",
        effect="destructive",
        requires_approval=False,
    )
    transport = Scripted(MockResponse(503), MockResponse(200, json={}))
    gw = make_gateway(transport=transport).register(op)
    result = await gw.call("cancel", {}, ctx=ctx, call_id="c")
    assert transport.sent == 1
    assert result.error.retryable is False


async def test_r5_redirect_after_write_is_outcome_unknown(make_gateway, ctx):
    transport = Scripted(MockResponse(303, headers={"Location": "/done"}))
    gw = make_gateway(transport=transport).register(
        Operation(name="w", description="d", service=SVC, method="POST", path="/w")
    )
    result = await gw.call("w", {}, ctx=ctx, call_id="c")
    assert result.error.code is ErrorCode.OUTCOME_UNKNOWN


async def test_r5_blocked_redirect_hop_after_write_is_outcome_unknown(make_gateway, ctx):
    svc = Service(
        name="api", base_url="https://api.example.com", network=NetworkPolicy(follow_redirects=True)
    )
    transport = Scripted(MockResponse(307, headers={"Location": "https://api.example.com:8443/x"}))
    gw = make_gateway(transport=transport).register(
        Operation(name="w", description="d", service=svc, method="POST", path="/w")
    )
    result = await gw.call("w", {}, ctx=ctx, call_id="c")
    assert result.error.code is ErrorCode.OUTCOME_UNKNOWN


async def test_r5_reads_keep_their_old_errors(make_gateway, ctx):
    transport = Scripted(MockResponse(303, headers={"Location": "/x"}))
    gw = make_gateway(transport=transport).register(
        Operation(name="r", description="d", service=SVC, path="/r")
    )
    result = await gw.call("r", {}, ctx=ctx)
    assert result.error.code is ErrorCode.UPSTREAM_ERROR


# --------------------------------------------------------------------------- r3


async def test_r3_encoded_and_key_echoes_are_scrubbed(make_gateway, ctx):
    secret = "Zm9v+YmFy/YmF6=="
    svc = Service(
        name="s",
        base_url="https://api.example.com",
        auth=ApiKeyAuth("k", header=None, query="api_key"),
    )
    mock = MockTransport().route(
        "GET",
        "https://api.example.com/me",
        lambda req: {
            "request_url": req.url,
            "pct": quote(secret, safe=""),
            "json": json.dumps(secret),
            "by_key": {secret: "seen"},
            "accessToken": "opaque-1",
            "clientSecret": "opaque-2",
            "privateKey": "opaque-3",
            "x-api-key": "opaque-4",
        },
    )
    gw = make_gateway(transport=mock, credentials=StaticCredentials({"k": secret})).register(
        Operation(name="me", description="d", service=svc, path="/me")
    )
    result = await gw.call("me", {}, ctx=ctx)
    text = result.to_json()
    for leaked in (secret, quote(secret, safe=""), "opaque-1", "opaque-2", "opaque-3", "opaque-4"):
        assert leaked not in text, leaked


# --------------------------------------------------------------------------- r6


async def test_r6_cursor_bound_to_trusted_values(make_gateway, mock):
    mock.route(
        "GET",
        "https://api.example.com/docs",
        lambda req: MockResponse(
            200,
            json=[{"id": 1}],
            headers={"Link": f'<{req.url.split("&page")[0]}&page=2>; rel="next"'},
        ),
    )
    op = Operation(
        name="docs",
        description="d",
        service=SVC,
        path="/docs",
        bind={"org": from_ctx("attributes.org")},
        query=("org",),
        pagination=Pagination(type="link"),
    )
    gw = make_gateway().register(op)
    as_a = ExecutionContext(actor="u", attributes={"org": "A"})
    cursor = (await gw.call("docs", {}, ctx=as_a)).meta.next_cursor
    as_b = ExecutionContext(actor="u", attributes={"org": "B"})
    result = await gw.call("docs", {"cursor": cursor}, ctx=as_b)
    assert result.error.code is ErrorCode.INVALID_CURSOR
    assert len(mock.requests) == 1


# --------------------------------------------------------------------------- r7


async def test_r7_one_actor_cannot_exhaust_replay_store_for_others(make_gateway, mock):
    mock.route("POST", "https://api.example.com/w", {"ok": 1})
    store = MemoryStateStore(max_per_partition=50)
    gw = make_gateway(state=store).register(
        Operation(name="w", description="d", service=SVC, method="POST", path="/w")
    )
    attacker = ExecutionContext(actor="mallory", tenant="evil")
    for i in range(60):
        last = await gw.call("w", {}, ctx=attacker, call_id=f"x{i}")
    assert last.error.code is ErrorCode.INTERNAL_ERROR
    assert last.error.retryable is False
    victim = await gw.call("w", {}, ctx=ExecutionContext(actor="alice", tenant="acme"), call_id="1")
    assert victim.ok


# --------------------------------------------------------------------------- r8


@pytest.mark.parametrize(
    "prop",
    [
        {"type": ["object", "null"], "properties": {"name": {"type": "string"}}},
        {"properties": {"name": {"type": "string"}}},
        {"anyOf": [{"type": "object", "properties": {"name": {"type": "string"}}}]},
    ],
)
def test_r8_nested_objects_with_properties_are_closed(prop):
    validator = ArgumentValidator(
        normalize_input_schema("t", {"profile": prop}), max_argument_bytes=10_000
    )
    with pytest.raises(ToolFailure):
        validator.validate({"profile": {"name": "x", "role": "admin"}})


def test_r8_open_objects_warn():
    with pytest.warns(ToolboundWarning, match="accepts any keys"):
        normalize_input_schema("t", {"meta": {"type": "object"}})
    with warnings.catch_warnings():
        warnings.simplefilter("error")
        normalize_input_schema("t", {"meta": {"type": "object", "additionalProperties": True}})


# --------------------------------------------------------------------------- r10 / r11


async def test_r10_actor_rate_limit_is_tenant_qualified(make_gateway, mock):
    mock.route("GET", "https://api.example.com/x", {})
    gw = make_gateway().register(
        Operation(
            name="x",
            description="d",
            service=SVC,
            path="/x",
            rate_limit=RateLimit(calls=1, per_seconds=60),
        )
    )
    assert (await gw.call("x", {}, ctx=ExecutionContext(actor="admin", tenant="evil"))).ok
    assert (await gw.call("x", {}, ctx=ExecutionContext(actor="admin", tenant="victim"))).ok
    assert (await gw.call("x", {}, ctx=ExecutionContext(actor="admin", tenant=None))).ok
    assert (await gw.call("x", {}, ctx=ExecutionContext(actor="admin", tenant="None"))).ok


async def test_r11_hidden_group_action_looks_like_missing_one(make_gateway, ctx):
    gw = make_gateway().register(
        Operation(name="list_users", description="d", service=SVC, path="/u", group="admin"),
        Operation(
            name="purge",
            description="d",
            service=SVC,
            path="/p",
            group="admin",
            required_scopes=("root",),
        ),
    )
    hidden = await gw.call("admin", {"action": "purge"}, ctx=ctx)
    missing = await gw.call("admin", {"action": "nope"}, ctx=ctx)
    assert hidden.to_model() == missing.to_model()


# --------------------------------------------------------------------------- r12


DROP = Operation(
    name="drop",
    description="d",
    service=SVC,
    method="DELETE",
    path="/d/{id}",
    input={"id": {"type": "integer"}},
)


async def test_r12_duplicate_call_id_does_not_burn_the_approval(make_gateway, mock, ctx):
    mock.route("DELETE", "https://api.example.com/d/{id}", MockResponse(204))
    gw = make_gateway().register(DROP)
    first = (await gw.call("drop", {"id": 9}, ctx=ctx, call_id="dup")).approval
    assert (await gw.resume(first, ctx=ctx, approved_by="a", call_id="dup")).ok
    pending = (await gw.call("drop", {"id": 2}, ctx=ctx)).approval
    grant = gw.grant(pending, approved_by="a")
    clash = await gw.call("drop", {"id": 2}, ctx=ctx, approval=grant, call_id="dup")
    assert clash.error.code is ErrorCode.DUPLICATE_CALL
    retry = await gw.call("drop", {"id": 2}, ctx=ctx, approval=grant, call_id="fresh")
    assert retry.ok


async def test_r12_pre_send_failure_does_not_burn_the_approval(mock, ctx):
    from toolbound import BearerAuth

    svc = Service(name="api", base_url="https://api.example.com", auth=BearerAuth("missing"))
    op = Operation(
        name="drop",
        description="d",
        service=svc,
        method="DELETE",
        path="/d/{id}",
        input={"id": {"type": "integer"}},
    )
    mock.route("DELETE", "https://api.example.com/d/{id}", MockResponse(204))
    creds: dict[str, str] = {}

    class Live:  # reads the current value on every call
        def get(self, name, ctx):
            return creds.get(name)

    gw = Gateway(authorize=allow_all, secret=KEY, transport=mock, credentials=Live()).register(op)
    pending = (await gw.call("drop", {"id": 1}, ctx=ctx)).approval
    grant = gw.grant(pending, approved_by="a")
    failed = await gw.call("drop", {"id": 1}, ctx=ctx, approval=grant)
    assert failed.error.code is ErrorCode.INTERNAL_ERROR  # credential not configured
    creds["missing"] = "now-configured-123"
    assert (await gw.call("drop", {"id": 1}, ctx=ctx, approval=grant)).ok


async def test_r9_denied_request_can_never_be_approved(make_gateway, mock, ctx):
    mock.route("DELETE", "https://api.example.com/d/{id}", MockResponse(204))
    gw = make_gateway().register(DROP)
    pending = (await gw.call("drop", {"id": 1}, ctx=ctx)).approval
    await gw.deny(pending.token)
    result = await gw.resume(pending.token, ctx=ctx, approved_by="a")
    assert result.error.code is ErrorCode.APPROVAL_INVALID
    assert mock.requests == []


# --------------------------------------------------------------------------- r13 / r15


def test_r13_ipv4_translated_addresses_blocked():
    with pytest.raises(ToolFailure):
        check_ip("::ffff:0:a9fe:a9fe", NetworkPolicy())


async def test_r13_concurrency_limit_is_per_service_endpoint(ctx):
    started = asyncio.Event()
    release = asyncio.Event()

    class Slow:
        async def send(self, request):
            if "a.example.com" in request.url:
                started.set()
                await release.wait()
            return MockResponse(200, json={}).to_http(request.url)

        async def aclose(self):
            pass

    one = Service(
        name="tenant-api", base_url="https://a.example.com", limits=Limits(max_concurrency=1)
    )
    two = Service(
        name="tenant-api", base_url="https://b.example.com", limits=Limits(max_concurrency=1)
    )
    gw = Gateway(authorize=allow_all, secret=KEY, transport=Slow()).register(
        Operation(name="a", description="d", service=one, path="/"),
        Operation(name="b", description="d", service=two, path="/"),
    )
    blocked = asyncio.create_task(gw.call("a", {}, ctx=ctx))
    await started.wait()
    other = await asyncio.wait_for(gw.call("b", {}, ctx=ctx), timeout=2)
    assert other.ok
    release.set()
    assert (await blocked).ok


async def test_r13_sync_handlers_use_a_private_pool(make_gateway, ctx):
    seen = []
    tool = PythonTool(
        name="t",
        description="d",
        effect=Effect.READ,
        handler=lambda: seen.append(threading.current_thread().name) or {},
    )
    gw = make_gateway().register(tool)
    await gw.call("t", {}, ctx=ctx)
    assert seen[0].startswith("toolbound-tool")


async def test_r15_missing_provider_ids_are_not_all_the_same(make_gateway, mock, ctx):
    mock.route("POST", "https://api.example.com/w", {"ok": 1})
    gw = make_gateway().register(
        Operation(name="w", description="d", service=SVC, method="POST", path="/w")
    )
    message = {
        "content": [
            {"type": "tool_use", "name": "w", "input": {}},
            {"type": "tool_use", "name": "w", "input": {}},
        ]
    }
    batch = await tb_anthropic.run_tool_calls(gw, message, ctx)
    assert [r.ok for r in batch.results] == [True, True]


def test_r1_token_patterns_start_only_at_run_boundaries():
    """Without the lookbehind every '-eyJ' restarts a 4 KB scan (~8x slower)."""
    compiled = compile_output(Output(max_tokens=None, max_chars=20_000_000))
    started = time.perf_counter()
    process(compiled, {"a": "-eyJ" * 1_000_000}, estimator=ByteEstimator())
    assert time.perf_counter() - started < 1.5
