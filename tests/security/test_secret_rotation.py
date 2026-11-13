"""Gateway secret rotation (issue found while integrating Toolbound into a host app).

Before: ``Gateway(secret=...)`` took exactly one key, so changing it (after a leak, or
on a schedule) invalidated every open approval request, grant and cursor at once.
Now ``secret`` may be a list: the first key signs and seals new tokens, every key is
accepted when a token is checked. The tests guard both halves: old tokens keep working
while their key is listed, and stop working once it is dropped.
"""

from __future__ import annotations

import pytest

from toolbound import (
    ConfigurationError,
    ErrorCode,
    ExecutionContext,
    Gateway,
    MemoryStateStore,
    Output,
    PythonTool,
    allow_all,
    from_ctx,
)
from toolbound.core.signing import Signer

OLD = b"old-gateway-secret-of-32-bytes!!"
NEW = b"new-gateway-secret-of-32-bytes!!"
OTHER = b"some-other-secret-of-32-bytes!!!"


def tools():
    runs: list[str] = []

    async def write(op: str) -> dict[str, bool]:
        runs.append(op)
        return {"done": True}

    async def read() -> list[dict[str, int]]:
        return [{"n": i} for i in range(30)]

    return runs, [
        PythonTool(
            name="write",
            description="A write that needs approval.",
            handler=write,
            effect="write",
            input={"type": "object", "properties": {}},
            requires_approval=True,
            bind={"op": from_ctx("attributes.op")},
        ),
        PythonTool(
            name="read",
            description="A list.",
            handler=read,
            effect="read",
            input={"type": "object", "properties": {}},
            output=Output(max_items=10, continuation=True),
        ),
    ]


def gateway(secret, state=None):
    runs, specs = tools()
    # Not `state or ...`: an empty MemoryStateStore is falsy (it has a length).
    store = state if state is not None else MemoryStateStore()
    gw = Gateway(authorize=allow_all, secret=secret, state=store)
    return runs, gw.register(*specs)


CTX = ExecutionContext(actor="alice", attributes={"op": "A"})


async def test_an_approval_issued_before_rotation_still_runs():
    state = MemoryStateStore()
    _, before = gateway(OLD, state)
    pending = (await before.call("write", {}, ctx=CTX)).approval
    runs, after = gateway([NEW, OLD], state)
    assert (await after.resume(pending.token, ctx=CTX, approved_by="alice")).ok
    assert runs == ["A"]


async def test_new_tokens_are_issued_with_the_first_key():
    _, rotated = gateway([NEW, OLD])
    pending = (await rotated.call("write", {}, ctx=CTX)).approval
    _, only_new = gateway(NEW)
    _, only_old = gateway(OLD)
    assert only_new.pending_approval(pending.token).tool == "write"
    result = await only_old.resume(pending.token, ctx=CTX, approved_by="alice")
    assert result.error.code is ErrorCode.APPROVAL_INVALID


async def test_dropping_a_key_invalidates_its_tokens():
    _, before = gateway(OLD)
    pending = (await before.call("write", {}, ctx=CTX)).approval
    runs, after = gateway([NEW])
    result = await after.resume(pending.token, ctx=CTX, approved_by="alice")
    assert result.error.code is ErrorCode.APPROVAL_INVALID
    assert runs == []


async def test_a_token_from_an_unlisted_key_is_refused():
    _, foreign = gateway(OTHER)
    pending = (await foreign.call("write", {}, ctx=CTX)).approval
    runs, gw = gateway([NEW, OLD])
    result = await gw.resume(pending.token, ctx=CTX, approved_by="alice")
    assert result.error.code is ErrorCode.APPROVAL_INVALID
    assert runs == []


async def test_a_grant_and_a_cursor_from_the_old_key_are_accepted():
    _, before = gateway(OLD)
    pending = (await before.call("write", {}, ctx=CTX)).approval
    grant = before.grant(pending, approved_by="alice")
    cursor = (await before.call("read", {}, ctx=CTX)).meta.next_cursor
    runs, after = gateway([NEW, OLD])
    assert (await after.call("write", {}, ctx=CTX, approval=grant)).ok
    assert runs == ["A"]
    page = await after.call("read", {"cursor": cursor}, ctx=CTX)
    assert page.ok and page.data[0] == {"n": 10}


async def test_a_used_approval_stays_used_across_rotation():
    """Replay protection is per request id, not per key: rotation cannot revive it."""
    state = MemoryStateStore()
    _, before = gateway(OLD, state)
    pending = (await before.call("write", {}, ctx=CTX)).approval
    assert (await before.resume(pending, ctx=CTX, approved_by="alice")).ok
    runs, after = gateway([NEW, OLD], state)
    again = await after.resume(pending, ctx=CTX, approved_by="alice")
    assert again.error.code is ErrorCode.APPROVAL_INVALID
    assert runs == []


@pytest.mark.parametrize(
    "secret",
    [
        [],
        [NEW, b"short"],
        [NEW, NEW],
        [NEW, 42],
        [bytes([i]) * 32 for i in range(9)],
    ],
)
def test_secret_lists_are_validated(secret):
    with pytest.raises(ConfigurationError):
        Signer(secret)


def test_a_single_secret_and_a_list_of_one_are_the_same_key():
    single, listed = Signer(NEW), Signer([NEW])
    token = single.seal("t", {"a": 1}, 60)
    assert listed.unseal("t", token)["a"] == 1
    assert single.verify("g", listed.sign("g", {"b": 2}, 60))["b"] == 2
    assert "keys=1" in repr(single) and NEW.decode() not in repr(single)
