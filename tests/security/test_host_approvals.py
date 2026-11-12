"""Regressions found while integrating Toolbound into a host application.

``h<N>`` = finding number:

- h1: a model tool call sealed for approval twice (a retry, a re-run graph node)
  produced two approval requests that both executed.
- h3: ``resume`` under a context with fresh bound values failed as
  ``approval_invalid`` without saying which value changed, and hosts had to keep
  every bound value to rebuild the context.
- h4: one ``approval_ttl`` per gateway; a short-lived chat card and a long-lived
  review queue item needed different lifetimes.
"""

from __future__ import annotations

import asyncio
import time

import pytest

from toolbound import (
    ConfigurationError,
    ErrorCode,
    ExecutionContext,
    MockResponse,
    Operation,
    PythonTool,
    Service,
    from_ctx,
)

SVC = Service(name="repo", base_url="https://api.example.com")
EMPTY = {"type": "object", "properties": {}}


def recorder():
    runs: list[str] = []

    async def write(op: str) -> dict[str, bool]:
        runs.append(op)
        return {"done": True}

    return runs, write


def sealed_write(handler, **kw):
    kw.setdefault("bind", {"op": from_ctx("attributes.op")})
    return PythonTool(
        name="write",
        description="A write that needs approval.",
        handler=handler,
        effect="write",
        input=EMPTY,
        requires_approval=True,
        **kw,
    )


def ctx_with(op: str = "A", **kw) -> ExecutionContext:
    kw.setdefault("actor", "alice")
    kw.setdefault("tenant", "acme")
    return ExecutionContext(attributes={"op": op}, **kw)


# --------------------------------------------------------------------------- h1


async def test_h1_one_call_id_sealed_twice_executes_once(make_gateway):
    """Two approval requests from the same model tool call: only the first runs."""
    runs, write = recorder()
    gw = make_gateway().register(sealed_write(write))
    ctx = ctx_with()
    first = await gw.call("write", {}, ctx=ctx, call_id="toolu_1")
    second = await gw.call("write", {}, ctx=ctx, call_id="toolu_1")
    assert first.approval.id != second.approval.id
    assert first.approval.call_id == second.approval.call_id == "toolu_1"
    ran = await gw.resume(first.approval, ctx=ctx, approved_by="alice", call_id="r1")
    again = await gw.resume(second.approval, ctx=ctx, approved_by="alice", call_id="r2")
    assert ran.ok
    assert again.error.code is ErrorCode.DUPLICATE_CALL
    assert runs == ["A"]


async def test_h1_rest_destructive_sealed_twice_sends_once(make_gateway, mock, ctx):
    mock.route("DELETE", "https://api.example.com/comments/{id}", MockResponse(204))
    gw = make_gateway().register(
        Operation(
            name="delete_comment",
            description="Delete a comment.",
            service=SVC,
            method="DELETE",
            path="/comments/{comment_id}",
            input={"comment_id": {"type": "integer"}},
        )
    )
    args = {"comment_id": 7}
    one = (await gw.call("delete_comment", args, ctx=ctx, call_id="c1")).approval
    two = (await gw.call("delete_comment", args, ctx=ctx, call_id="c1")).approval
    results = [
        await gw.resume(p, ctx=ctx, approved_by="alice", call_id=f"r{i}")
        for i, p in enumerate((one, two))
    ]
    assert [r.ok for r in results] == [True, False]
    assert len(mock.requests) == 1


async def test_h1_concurrent_resumes_of_two_requests_run_once(make_gateway):
    runs, write = recorder()
    gw = make_gateway().register(sealed_write(write))
    ctx = ctx_with()
    pendings = [(await gw.call("write", {}, ctx=ctx, call_id="toolu_1")).approval for _ in range(5)]
    results = await asyncio.gather(*(gw.resume(p, ctx=ctx, approved_by="alice") for p in pendings))
    assert sum(r.ok for r in results) == 1
    assert runs == ["A"]


async def test_h1_direct_call_after_approved_run_is_duplicate(make_gateway):
    runs, write = recorder()
    gw = make_gateway().register(sealed_write(write))
    ctx = ctx_with()
    pending = (await gw.call("write", {}, ctx=ctx, call_id="toolu_1")).approval
    assert (await gw.resume(pending, ctx=ctx, approved_by="alice")).ok
    again = await gw.call("write", {}, ctx=ctx, call_id="toolu_1")
    assert again.error.code in (ErrorCode.DUPLICATE_CALL, ErrorCode.APPROVAL_REQUIRED)
    if again.approval is not None:  # sealed again: it can never run
        late = await gw.resume(again.approval, ctx=ctx, approved_by="alice")
        assert late.error.code is ErrorCode.DUPLICATE_CALL
    assert runs == ["A"]


async def test_h1_resume_with_the_requesting_call_id_still_runs(make_gateway):
    """The originating id and the resume id are claimed once each, not twice."""
    runs, write = recorder()
    gw = make_gateway().register(sealed_write(write))
    ctx = ctx_with()
    pending = (await gw.call("write", {}, ctx=ctx, call_id="toolu_1")).approval
    assert (await gw.resume(pending, ctx=ctx, approved_by="alice", call_id="toolu_1")).ok
    assert runs == ["A"]


async def test_h1_call_id_survives_the_token_round_trip(make_gateway):
    _, write = recorder()
    gw = make_gateway().register(sealed_write(write))
    pending = (await gw.call("write", {}, ctx=ctx_with(), call_id="toolu_9")).approval
    assert gw.pending_approval(pending.token).call_id == "toolu_9"
    assert pending.to_dict()["call_id"] == "toolu_9"
    without = (await gw.call("write", {}, ctx=ctx_with())).approval
    assert without.call_id is None
    assert (await gw.resume(without, ctx=ctx_with(), approved_by="alice")).ok


async def test_h1_inline_approver_with_a_call_id_runs_once(make_gateway):
    runs, write = recorder()
    gw = make_gateway(approver=lambda pending: True).register(sealed_write(write))
    ctx = ctx_with()
    assert (await gw.call("write", {}, ctx=ctx, call_id="toolu_1")).ok
    again = await gw.call("write", {}, ctx=ctx, call_id="toolu_1")
    assert again.error.code is ErrorCode.DUPLICATE_CALL
    assert runs == ["A"]


# --------------------------------------------------------------------------- h3


async def test_h3_live_resume_names_the_changed_bound_values(make_gateway):
    runs, write = recorder()
    gw = make_gateway().register(sealed_write(write))
    pending = (await gw.call("write", {}, ctx=ctx_with("A"), call_id="c1")).approval
    result = await gw.resume(pending, ctx=ctx_with("B"), approved_by="alice")
    assert result.error.code is ErrorCode.APPROVAL_INVALID
    assert result.error.details == {"changed_bound": ["op"]}
    assert "B" not in result.error.message and "'A'" not in result.error.message
    assert runs == []


async def test_h3_live_resume_names_a_missing_bound_value(make_gateway):
    _, write = recorder()
    gw = make_gateway().register(sealed_write(write))
    pending = (await gw.call("write", {}, ctx=ctx_with("A"))).approval
    bare = ExecutionContext(actor="alice", tenant="acme")
    result = await gw.resume(pending, ctx=bare, approved_by="alice")
    assert result.error.details == {"changed_bound": ["op"]}


async def test_h3_sealed_resume_uses_the_values_the_human_saw(make_gateway):
    runs, write = recorder()
    gw = make_gateway().register(sealed_write(write))
    pending = (await gw.call("write", {}, ctx=ctx_with("A"), call_id="c1")).approval
    result = await gw.resume(pending, ctx=ctx_with("B"), approved_by="alice", bound="sealed")
    assert result.ok
    assert runs == ["A"]


async def test_h3_sealed_resume_never_changes_the_actor_or_tenant(make_gateway):
    runs, write = recorder()
    gw = make_gateway().register(sealed_write(write))
    pending = (await gw.call("write", {}, ctx=ctx_with("A"))).approval
    for other in (ctx_with("A", actor="mallory"), ctx_with("A", tenant="globex")):
        result = await gw.resume(pending, ctx=other, approved_by="mallory", bound="sealed")
        assert result.error.code is ErrorCode.APPROVAL_INVALID
    assert runs == []


async def test_h3_sealed_resume_keeps_actor_bindings_live(make_gateway):
    runs: list[str] = []

    async def write(who: str) -> dict[str, bool]:
        runs.append(who)
        return {"done": True}

    gw = make_gateway().register(sealed_write(write, bind={"who": from_ctx("actor")}))
    pending = (await gw.call("write", {}, ctx=ctx_with())).approval
    other = ctx_with(actor="mallory")
    result = await gw.resume(pending, ctx=other, approved_by="mallory", bound="sealed")
    assert result.error.code is ErrorCode.APPROVAL_INVALID
    assert runs == []


async def test_h3_sealed_resume_still_checks_live_scopes(make_gateway):
    runs, write = recorder()
    gw = make_gateway().register(sealed_write(write, required_scopes=("records:write",)))
    granted = ctx_with(scopes=frozenset({"records:write"}))
    pending = (await gw.call("write", {}, ctx=granted)).approval
    revoked = ctx_with("B")
    result = await gw.resume(pending, ctx=revoked, approved_by="alice", bound="sealed")
    assert not result.ok and result.error.code is ErrorCode.UNKNOWN_TOOL
    assert runs == []


async def test_h3_bound_mode_is_checked(make_gateway):
    _, write = recorder()
    gw = make_gateway().register(sealed_write(write))
    pending = (await gw.call("write", {}, ctx=ctx_with())).approval
    with pytest.raises(ValueError):
        await gw.resume(pending, ctx=ctx_with(), approved_by="alice", bound="model")  # type: ignore[arg-type]


# --------------------------------------------------------------------------- h4


async def test_h4_tool_and_call_override_the_gateway_lifetime(make_gateway):
    _, write = recorder()
    gw = make_gateway(approval_ttl=600).register(sealed_write(write, approval_ttl=3600))
    now = time.time()
    by_tool = (await gw.call("write", {}, ctx=ctx_with())).approval
    by_call = (await gw.call("write", {}, ctx=ctx_with(), approval_ttl=60)).approval
    assert 3590 < by_tool.expires_at - now <= 3601
    assert 50 < by_call.expires_at - now <= 61


async def test_h4_a_short_lived_request_expires(make_gateway):
    runs, write = recorder()
    gw = make_gateway(approval_ttl=3600).register(sealed_write(write))
    pending = (await gw.call("write", {}, ctx=ctx_with(), approval_ttl=0.2)).approval
    await asyncio.sleep(1.1)  # sealed expiry has one-second resolution
    result = await gw.resume(pending, ctx=ctx_with(), approved_by="alice")
    assert result.error.code is ErrorCode.APPROVAL_INVALID
    assert runs == []


@pytest.mark.parametrize("ttl", [0, -1, 7 * 24 * 3600 + 1, True])
async def test_h4_lifetimes_are_bounded(make_gateway, ttl):
    _, write = recorder()
    with pytest.raises(ConfigurationError):
        sealed_write(write, approval_ttl=ttl)
    gw = make_gateway().register(sealed_write(write))
    with pytest.raises(ValueError):
        await gw.call("write", {}, ctx=ctx_with(), approval_ttl=ttl)


async def test_h1_reusing_a_used_token_is_still_approval_invalid(make_gateway):
    """The fix must not change the code hosts see for a replayed token."""
    _, write = recorder()
    gw = make_gateway().register(sealed_write(write))
    ctx = ctx_with()
    pending = (await gw.call("write", {}, ctx=ctx, call_id="toolu_1")).approval
    assert (await gw.resume(pending, ctx=ctx, approved_by="alice", call_id="r1")).ok
    again = await gw.resume(pending, ctx=ctx, approved_by="alice", call_id="r2")
    assert again.error.code is ErrorCode.APPROVAL_INVALID
