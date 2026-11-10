"""H2 / M4: approval requests are gateway-issued, tamper-proof and fully displayed."""

from __future__ import annotations

import asyncio
import dataclasses
import json
import time

import pytest

from toolbound import (
    ApprovalInvalid,
    Effect,
    ErrorCode,
    ExecutionContext,
    Gateway,
    MockResponse,
    MockTransport,
    Operation,
    PythonTool,
    Service,
    allow_all,
    from_ctx,
)
from toolbound.core.approval import approval_digest

SVC = Service(name="api", base_url="https://api.example.com")
DROP = Operation(
    name="drop",
    description="Delete a record.",
    service=SVC,
    method="DELETE",
    path="/orgs/{org}/records/{id}",
    input={"id": {"type": "integer"}, "reason": {"type": "string", "default": ""}},
    bind={"org": from_ctx("tenant")},
)


@pytest.fixture
def gw(make_gateway, mock):
    mock.route("DELETE", "https://api.example.com/orgs/{org}/records/{id}", MockResponse(204))
    return make_gateway().register(DROP)


async def pending_for(gw, ctx, **args):
    result = await gw.call("drop", {"id": 1, **args}, ctx=ctx)
    assert result.error.code is ErrorCode.APPROVAL_REQUIRED
    return result.approval


async def test_h2_forged_pending_object_cannot_be_granted(gw, ctx, mock):
    """The original failure: grant() signed a hand-built PendingApproval for id=999."""
    real = await pending_for(gw, ctx)
    fingerprint = gw._tools["drop"].fingerprint
    forged = dataclasses.replace(
        real,
        arguments={"id": 999, "reason": ""},
        digest=approval_digest(
            tool="drop",
            fingerprint=fingerprint,
            ctx=ctx,
            arguments={"id": 999, "reason": ""},
            bound={"org": "acme"},
        ),
        token="tbr1.forged",
    )
    with pytest.raises(ApprovalInvalid):
        gw.grant(forged, approved_by="alice")
    result = await gw.resume(forged, ctx=ctx, approved_by="alice")
    assert result.error.code is ErrorCode.APPROVAL_INVALID
    assert mock.requests == []


async def test_h2_object_fields_are_ignored_only_token_counts(gw, ctx, mock):
    """Changing the dataclass fields but keeping the real token runs the *approved* call."""
    real = await pending_for(gw, ctx)
    tampered = dataclasses.replace(real, arguments={"id": 999, "reason": ""})
    result = await gw.resume(tampered, ctx=ctx, approved_by="alice")
    assert result.ok
    assert "/orgs/acme/records/1?" in mock.requests[0].url


async def test_h2_altered_token_rejected(gw, ctx):
    real = await pending_for(gw, ctx)
    head, body = real.token.split(".", 1)
    flipped = body[:-2] + ("A" if body[-2] != "A" else "B") + body[-1]
    for bad in (f"{head}.{flipped}", real.token + "x", "tbr1." + body[5:], "", "tba2.x.y"):
        with pytest.raises(ApprovalInvalid):
            gw.grant(bad, approved_by="alice")


async def test_h2_token_from_other_gateway_rejected(gw, ctx):
    real = await pending_for(gw, ctx)
    other = Gateway(authorize=allow_all, secret=b"z" * 32, transport=MockTransport()).register(DROP)
    with pytest.raises(ApprovalInvalid):
        other.grant(real.token, approved_by="alice")


async def test_h2_request_token_round_trips_through_json(gw, ctx, mock):
    """A web app can store/send to_dict() and resume later from the token alone."""
    real = await pending_for(gw, ctx, reason="cleanup")
    stored = json.loads(json.dumps(real.to_dict()))
    shown = gw.pending_approval(stored["token"])
    assert shown.arguments == {"id": 1, "reason": "cleanup"}
    assert shown.bound == {"org": "acme"}
    assert shown.target["url"] == "https://api.example.com/orgs/acme/records/1?reason=cleanup"
    result = await gw.resume(stored["token"], ctx=ctx, approved_by="alice")
    assert result.ok
    assert len(mock.requests) == 1


async def test_h2_token_contents_are_encrypted(gw, ctx):
    real = await pending_for(gw, ctx, reason="TOP-SECRET-REASON")
    assert "TOP-SECRET-REASON" not in real.token
    import base64

    raw = base64.urlsafe_b64decode(real.token.split(".", 1)[1] + "==")
    assert b"TOP-SECRET-REASON" not in raw
    assert b"acme" not in raw


async def test_h2_other_actor_cannot_use_request(gw, ctx, mock):
    real = await pending_for(gw, ctx)
    mallory = ExecutionContext(actor="mallory", tenant="acme")
    result = await gw.resume(real.token, ctx=mallory, approved_by="mallory")
    assert result.error.code is ErrorCode.APPROVAL_INVALID
    other_tenant = ExecutionContext(actor=ctx.actor, tenant="globex")
    result = await gw.resume(real.token, ctx=other_tenant, approved_by="alice")
    assert result.error.code is ErrorCode.APPROVAL_INVALID
    assert mock.requests == []


async def test_h2_expired_request_rejected(make_gateway, mock, ctx):
    mock.route("DELETE", "https://api.example.com/orgs/{org}/records/{id}", MockResponse(204))
    gw = make_gateway(approval_ttl=1).register(DROP)
    real = await pending_for(gw, ctx)
    original = time.time
    try:
        time.time = lambda: original() + 5  # type: ignore[assignment]
        with pytest.raises(ApprovalInvalid):
            gw.grant(real, approved_by="alice")
    finally:
        time.time = original  # type: ignore[assignment]


async def test_h2_concurrent_resumes_execute_once(gw, ctx, mock):
    real = await pending_for(gw, ctx)
    grant = gw.grant(real, approved_by="alice")
    results = await asyncio.gather(
        *(gw.call("drop", {"id": 1}, ctx=ctx, approval=grant) for _ in range(10))
    )
    assert sum(r.ok for r in results) == 1
    assert len(mock.requests) == 1


async def test_m4_summary_shows_target_bound_values_and_all_arguments(gw, ctx):
    real = await pending_for(gw, ctx, reason="r")
    assert real.target == {
        "kind": "rest",
        "service": "api",
        "method": "DELETE",
        "url": "https://api.example.com/orgs/acme/records/1?reason=r",
        "body_fields": [],
    }
    assert "DELETE https://api.example.com/orgs/acme/records/1" in real.summary
    assert '"org": "acme"' in real.summary
    assert real.summary_truncated is False


async def test_m4_long_arguments_are_flagged_not_silently_cut(gw, ctx):
    hidden_tail = "DROP-EVERYTHING"
    real = await pending_for(gw, ctx, reason="x" * 3000 + hidden_tail)
    assert real.summary_truncated is True
    assert "review the full arguments" in real.summary
    assert real.arguments["reason"].endswith(hidden_tail)  # full value is available


async def test_m4_control_and_bidi_characters_are_escaped(gw, ctx):
    real = await pending_for(gw, ctx, reason="ok‮\n\x1b[2Jfake")
    assert "‮" not in real.summary and "\x1b" not in real.summary
    assert "\\u202e" in real.summary


async def test_m4_python_tool_target(make_gateway, ctx):
    tool = PythonTool(
        name="wipe", description="Wipe.", effect=Effect.DESTRUCTIVE, handler=lambda: {"ok": 1}
    )
    gw = make_gateway().register(tool)
    result = await gw.call("wipe", {}, ctx=ctx)
    assert result.approval.target == {"kind": "python", "tool": "wipe"}
