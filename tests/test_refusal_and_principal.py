"""Python tools: typed business refusals and the trusted principal."""

from __future__ import annotations

import pytest

from toolbound import (
    ErrorCode,
    ExecutionContext,
    PythonTool,
    ToolRefusal,
    from_ctx,
)

EMPTY = {"type": "object", "properties": {}}


def tool(handler, **kw):
    kw.setdefault("effect", "read")
    return PythonTool(name="t", description="A tool.", handler=handler, input=EMPTY, **kw)


# --------------------------------------------------------------------------- refusals


async def test_a_refusal_reaches_host_and_model_with_its_reason(make_gateway, ctx):
    async def handler() -> dict:
        raise ToolRefusal(
            "version_conflict", "The record changed meanwhile.", details={"current_version": 4}
        )

    result = await make_gateway().register(tool(handler)).call("t", {}, ctx=ctx)
    assert not result.ok
    assert result.error.code is ErrorCode.REFUSED
    assert result.error.retryable is False
    assert result.error.details == {"reason": "version_conflict", "current_version": 4}
    model = result.to_model()["error"]
    assert model["code"] == "refused" and model["reason"] == "version_conflict"
    assert model["message"] == "The record changed meanwhile."


async def test_a_refusal_without_a_message_gets_a_neutral_one(make_gateway, ctx):
    async def handler() -> dict:
        raise ToolRefusal("not_found")

    result = await make_gateway().register(tool(handler)).call("t", {}, ctx=ctx)
    assert result.error.message == "the tool refused this call (not_found)"


async def test_sync_handlers_can_refuse_too(make_gateway, ctx):
    def handler() -> dict:
        raise ToolRefusal("closed")

    result = await make_gateway().register(tool(handler)).call("t", {}, ctx=ctx)
    assert result.error.details["reason"] == "closed"


async def test_a_refused_write_uses_up_its_approval(make_gateway, ctx):
    """The action was not applied, but the approval is spent: a refused change
    needs a new request, never a replay of the old one."""

    async def handler() -> dict:
        raise ToolRefusal("version_conflict")

    gw = make_gateway().register(tool(handler, effect="write", requires_approval=True))
    pending = (await gw.call("t", {}, ctx=ctx)).approval
    refused = await gw.resume(pending, ctx=ctx, approved_by="alice")
    assert refused.error.code is ErrorCode.REFUSED
    again = await gw.resume(pending, ctx=ctx, approved_by="alice")
    assert again.error.code is ErrorCode.APPROVAL_INVALID


async def test_other_exceptions_stay_internal(make_gateway, ctx):
    async def handler() -> dict:
        raise RuntimeError("secret detail")

    result = await make_gateway().register(tool(handler)).call("t", {}, ctx=ctx)
    assert result.error.code is ErrorCode.INTERNAL_ERROR
    assert "secret" not in result.error.message


@pytest.mark.parametrize(
    ("reason", "details"),
    [
        ("Version-Conflict", None),
        ("", None),
        ("x" * 65, None),
        (1, None),
        ("ok", {"code": "forged"}),
        ("ok", {"reason": "forged"}),
        ("ok", {"value": object()}),
        ("ok", {"blob": "x" * 3000}),
    ],
)
def test_refusals_are_validated(reason, details):
    with pytest.raises(ValueError):
        ToolRefusal(reason, details=details)  # type: ignore[arg-type]


# --------------------------------------------------------------------------- principal


class User:
    def __init__(self, name: str) -> None:
        self.name = name

    def __repr__(self) -> str:
        return f"User({self.name}) SECRET-REPR"


async def test_the_principal_reaches_handlers_and_authorize(make_gateway):
    seen = []

    async def handler(ctx: ExecutionContext) -> dict:
        return {"user": ctx.principal.name}

    def authorize(request) -> bool:
        seen.append(request.ctx.principal.name)
        return True

    ctx = ExecutionContext(actor="u1", principal=User("sara"))
    gw = make_gateway(authorize=authorize).register(tool(handler))
    result = await gw.call("t", {}, ctx=ctx)
    assert result.data == {"user": "sara"} and seen == ["sara"]


async def test_the_principal_is_never_sealed_logged_or_compared(make_gateway):
    async def handler(ctx: ExecutionContext, op: str) -> dict:
        return {"user": ctx.principal.name, "op": op}

    gw = make_gateway().register(
        tool(
            handler, effect="write", requires_approval=True, bind={"op": from_ctx("attributes.op")}
        )
    )
    ctx = ExecutionContext(actor="u1", attributes={"op": "A"}, principal=User("sara"))
    assert "SECRET-REPR" not in repr(ctx)
    assert ctx == ExecutionContext(
        actor="u1", attributes={"op": "A"}, request_id=ctx.request_id, principal=User("x")
    )
    pending = (await gw.call("t", {}, ctx=ctx)).approval
    assert "SECRET-REPR" not in str(pending.to_dict())
    assert gw.pending_approval(pending.token).bound == {"op": "A"}
    # A different principal object for the same actor still matches the request.
    later = ExecutionContext(actor="u1", attributes={"op": "B"}, principal=User("sara"))
    done = await gw.resume(pending, ctx=later, approved_by="u1", bound="sealed")
    assert done.data == {"user": "sara", "op": "A"}


def test_the_principal_cannot_be_bound():
    from toolbound import ConfigurationError

    with pytest.raises(ConfigurationError):
        from_ctx("principal")
