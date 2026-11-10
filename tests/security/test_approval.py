"""Destructive operations, approval binding, replay protection and idempotency."""

from __future__ import annotations

import time

import pytest

from toolbound import (
    Effect,
    ErrorCode,
    ExecutionContext,
    Operation,
    PythonTool,
    Service,
)
from toolbound.transport.mock import MockResponse

SERVICE = Service(name="repo", base_url="https://api.example.com")


def delete_op(**kw):
    kw.setdefault("name", "delete_comment")
    return Operation(
        description="Delete a comment.",
        service=SERVICE,
        method="DELETE",
        path="/comments/{comment_id}",
        effect="destructive",
        input={"comment_id": {"type": "integer", "minimum": 1}},
        **kw,
    )


@pytest.fixture
def routed(mock):
    mock.route("DELETE", "https://api.example.com/comments/{id}", MockResponse(204))
    return mock


async def test_destructive_requires_approval_and_does_not_execute(make_gateway, routed, ctx):
    gw = make_gateway().register(delete_op())
    result = await gw.call("delete_comment", {"comment_id": 5}, ctx=ctx)
    assert result.error and result.error.code is ErrorCode.APPROVAL_REQUIRED
    assert result.approval is not None
    assert result.approval.arguments == {"comment_id": 5}
    assert routed.requests == []
    model_view = result.to_model()
    assert "approval" not in model_view and result.approval.id not in result.to_json()


async def test_grant_executes_once(make_gateway, routed, ctx):
    gw = make_gateway().register(delete_op())
    pending = (await gw.call("delete_comment", {"comment_id": 5}, ctx=ctx)).approval
    token = gw.grant(pending, approved_by="alice")
    first = await gw.call("delete_comment", {"comment_id": 5}, ctx=ctx, approval=token)
    assert first.ok
    replay = await gw.call("delete_comment", {"comment_id": 5}, ctx=ctx, approval=token)
    assert replay.error and replay.error.code is ErrorCode.APPROVAL_INVALID
    assert len(routed.requests) == 1


async def test_grant_bound_to_arguments(make_gateway, routed, ctx):
    gw = make_gateway().register(delete_op())
    pending = (await gw.call("delete_comment", {"comment_id": 5}, ctx=ctx)).approval
    token = gw.grant(pending, approved_by="alice")
    swapped = await gw.call("delete_comment", {"comment_id": 6}, ctx=ctx, approval=token)
    assert swapped.error and swapped.error.code is ErrorCode.APPROVAL_INVALID
    assert routed.requests == []


async def test_grant_bound_to_actor_and_tenant(make_gateway, routed, ctx):
    gw = make_gateway().register(delete_op())
    pending = (await gw.call("delete_comment", {"comment_id": 5}, ctx=ctx)).approval
    token = gw.grant(pending, approved_by="alice")
    other_actor = ExecutionContext(actor="mallory", tenant="acme")
    other_tenant = ExecutionContext(actor="alice", tenant="globex")
    for other in (other_actor, other_tenant):
        result = await gw.call("delete_comment", {"comment_id": 5}, ctx=other, approval=token)
        assert result.error and result.error.code is ErrorCode.APPROVAL_INVALID
    assert routed.requests == []


async def test_grant_bound_to_tool_and_contract(make_gateway, routed, ctx, mock):
    gw = make_gateway().register(delete_op(), delete_op(name="delete_comment_v2"))
    pending = (await gw.call("delete_comment", {"comment_id": 5}, ctx=ctx)).approval
    token = gw.grant(pending, approved_by="alice")
    result = await gw.call("delete_comment_v2", {"comment_id": 5}, ctx=ctx, approval=token)
    assert result.error and result.error.code is ErrorCode.APPROVAL_INVALID
    # Same tool name, changed contract (different path) in a new gateway with the same key.
    from ..conftest import HMAC_KEY

    changed = Operation(
        name="delete_comment",
        description="Delete a comment.",
        service=SERVICE,
        method="DELETE",
        path="/v2/comments/{comment_id}",
        effect="destructive",
        input={"comment_id": {"type": "integer", "minimum": 1}},
    )
    gw2 = make_gateway(secret=HMAC_KEY).register(changed)
    result = await gw2.call("delete_comment", {"comment_id": 5}, ctx=ctx, approval=token)
    assert result.error and result.error.code is ErrorCode.APPROVAL_INVALID


async def test_forged_and_expired_grants(make_gateway, routed, ctx):
    gw = make_gateway(approval_ttl=0.05).register(delete_op())
    forged = await gw.call("delete_comment", {"comment_id": 5}, ctx=ctx, approval="tba1.x.y")
    assert forged.error and forged.error.code is ErrorCode.APPROVAL_INVALID
    pending = (await gw.call("delete_comment", {"comment_id": 5}, ctx=ctx)).approval
    token = gw._signer.sign("tba1", {"i": pending.id, "d": pending.digest, "by": "a"}, -5)
    expired = await gw.call("delete_comment", {"comment_id": 5}, ctx=ctx, approval=token)
    assert expired.error and expired.error.code is ErrorCode.APPROVAL_INVALID
    time.sleep(0.06)
    from toolbound import ToolFailure

    with pytest.raises(ToolFailure):
        gw.grant(pending, approved_by="alice")
    assert routed.requests == []


async def test_grant_from_other_gateway_secret_rejected(make_gateway, routed, ctx):
    gw_a = make_gateway(secret=b"a" * 32).register(delete_op())
    gw_b = make_gateway(secret=b"b" * 32).register(delete_op())
    pending = (await gw_a.call("delete_comment", {"comment_id": 5}, ctx=ctx)).approval
    token = gw_a.grant(pending, approved_by="alice")
    result = await gw_b.call("delete_comment", {"comment_id": 5}, ctx=ctx, approval=token)
    assert result.error and result.error.code is ErrorCode.APPROVAL_INVALID


async def test_model_cannot_pass_approval_in_arguments(make_gateway, routed, ctx):
    gw = make_gateway().register(delete_op())
    pending = (await gw.call("delete_comment", {"comment_id": 5}, ctx=ctx)).approval
    token = gw.grant(pending, approved_by="alice")
    result = await gw.call("delete_comment", {"comment_id": 5, "approval": token}, ctx=ctx)
    assert result.error and result.error.code is ErrorCode.INVALID_ARGUMENTS
    assert routed.requests == []


async def test_inline_approver(make_gateway, routed, ctx):
    asked = []

    async def approver(pending):
        asked.append(pending.summary)
        return pending.arguments["comment_id"] == 5

    gw = make_gateway(approver=approver).register(delete_op())
    assert (await gw.call("delete_comment", {"comment_id": 5}, ctx=ctx)).ok
    denied = await gw.call("delete_comment", {"comment_id": 6}, ctx=ctx)
    assert denied.error and denied.error.code is ErrorCode.APPROVAL_DENIED
    assert len(asked) == 2 and "delete_comment" in asked[0]
    assert len(routed.requests) == 1


async def test_resume_helper(make_gateway, routed, ctx):
    gw = make_gateway().register(delete_op())
    pending = (await gw.call("delete_comment", {"comment_id": 5}, ctx=ctx)).approval
    assert (await gw.resume(pending, ctx=ctx, approved_by="alice")).ok


async def test_duplicate_call_id_never_executes_twice(make_gateway, mock, ctx):
    mock.route("POST", "https://api.example.com/payments", MockResponse(201, json={"id": 1}))
    pay = Operation(
        name="pay",
        description="Send a payment.",
        service=SERVICE,
        method="POST",
        path="/payments",
        effect="write",
        input={"cents": {"type": "integer"}},
    )
    gw = make_gateway().register(pay)
    first = await gw.call("pay", {"cents": 100}, ctx=ctx, call_id="toolu_1")
    second = await gw.call("pay", {"cents": 100}, ctx=ctx, call_id="toolu_1")
    assert first.ok
    assert second.error and second.error.code is ErrorCode.DUPLICATE_CALL
    assert len(mock.requests) == 1


async def test_call_id_dedupe_does_not_apply_to_reads(make_gateway, mock, ctx):
    mock.route("GET", "https://api.example.com/r", {"a": 1})
    gw = make_gateway().register(
        Operation(name="r", description="read", service=SERVICE, path="/r")
    )
    assert (await gw.call("r", {}, ctx=ctx, call_id="c")).ok
    assert (await gw.call("r", {}, ctx=ctx, call_id="c")).ok


async def test_approval_flow_with_call_id(make_gateway, routed, ctx):
    gw = make_gateway().register(delete_op())
    pending = (await gw.call("delete_comment", {"comment_id": 5}, ctx=ctx, call_id="c1")).approval
    token = gw.grant(pending, approved_by="alice")
    assert (
        await gw.call("delete_comment", {"comment_id": 5}, ctx=ctx, call_id="c1", approval=token)
    ).ok


async def test_write_can_opt_into_approval_and_python_destructive(make_gateway, ctx):
    calls = []
    tool = PythonTool(
        name="wipe",
        description="Wipe cache.",
        effect=Effect.DESTRUCTIVE,
        handler=lambda: calls.append(1) or {"done": True},
    )
    gw = make_gateway().register(tool)
    result = await gw.call("wipe", {}, ctx=ctx)
    assert result.error and result.error.code is ErrorCode.APPROVAL_REQUIRED
    assert calls == []
    assert (await gw.resume(result.approval, ctx=ctx, approved_by="alice")).ok
    assert calls == [1]


async def test_idempotency_key_derived_from_approval(make_gateway, mock, ctx):
    mock.route("DELETE", "https://api.example.com/comments/{id}", MockResponse(204))
    gw = make_gateway().register(delete_op(idempotency_header="Idempotency-Key"))
    pending = (await gw.call("delete_comment", {"comment_id": 5}, ctx=ctx)).approval
    await gw.resume(pending, ctx=ctx, approved_by="alice")
    assert dict(mock.requests[0].headers)["Idempotency-Key"] == pending.id
