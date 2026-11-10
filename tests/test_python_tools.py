"""Custom Python tools go through the same pipeline as REST operations."""

from __future__ import annotations

import asyncio
import time
from typing import Annotated, Literal

import pytest

from toolbound import (
    ConfigurationError,
    Decision,
    ErrorCode,
    ExecutionContext,
    Output,
    PythonTool,
    RateLimit,
    ToolFailure,
)


async def test_decorator_infers_schema_and_validates(make_gateway, ctx):
    gw = make_gateway()

    @gw.tool(effect="read")
    def search_docs(
        query: Annotated[str, "Search text", {"maxLength": 100}],
        limit: int = 5,
        kind: Literal["contract", "ruling"] | None = None,
    ) -> list[dict]:
        """Search the document index.

        Longer text that is not part of the description.
        """
        return [{"q": query, "n": limit, "kind": kind}]

    definition = gw.definitions(ctx)[0]
    assert definition.description == "Search the document index."
    props = definition.input_schema["properties"]
    assert props["query"] == {"type": "string", "description": "Search text", "maxLength": 100}
    assert props["limit"] == {"type": "integer", "default": 5}
    assert definition.input_schema["required"] == ["query"]
    ok = await gw.call("search_docs", {"query": "lease"}, ctx=ctx)
    assert ok.data == [{"q": "lease", "n": 5, "kind": None}]
    bad = await gw.call("search_docs", {"query": "x" * 101}, ctx=ctx)
    assert bad.error and bad.error.code is ErrorCode.INVALID_ARGUMENTS
    bad_enum = await gw.call("search_docs", {"query": "x", "kind": "memo"}, ctx=ctx)
    assert bad_enum.error and bad_enum.error.code is ErrorCode.INVALID_ARGUMENTS


async def test_ctx_and_bound_values_injected(make_gateway, ctx):
    gw = make_gateway()

    @gw.tool(effect="read", bind={"tenant": "ctx.tenant"})
    async def whoami(ctx: ExecutionContext, tenant: str) -> dict:
        """Return the caller."""
        return {"actor": ctx.actor, "tenant": tenant}

    assert "tenant" not in gw.definitions(ctx)[0].input_schema["properties"]
    result = await gw.call("whoami", {}, ctx=ctx)
    assert result.data == {"actor": "alice", "tenant": "acme"}
    forged = await gw.call("whoami", {"tenant": "other"}, ctx=ctx)
    assert forged.error and forged.error.code is ErrorCode.INVALID_ARGUMENTS


async def test_authorization_applies_to_python_tools(make_gateway, ctx):
    calls = []

    def policy(request):
        return Decision.deny("no") if request.tool.name == "secret" else True

    gw = make_gateway(authorize=policy)

    @gw.tool(effect="read")
    def secret() -> dict:
        """Secret."""
        calls.append(1)
        return {}

    result = await gw.call("secret", {}, ctx=ctx)
    assert result.error and result.error.code is ErrorCode.FORBIDDEN
    assert calls == []


async def test_output_shaping_and_budget_apply(make_gateway, ctx):
    gw = make_gateway()

    @gw.tool(
        effect="read",
        output=Output(
            shape={"id": "id", "text": "text"}, required=("id",), max_tokens=100, continuation=True
        ),
    )
    def list_docs() -> list[dict]:
        """List documents."""
        return [{"id": i, "text": "lorem ipsum " * 10, "internal": "x"} for i in range(20)]

    result = await gw.call("list_docs", {}, ctx=ctx)
    assert result.ok and result.meta.truncated and result.meta.next_cursor
    assert all(set(item) == {"id", "text"} for item in result.data)
    nxt = await gw.call("list_docs", {"cursor": result.meta.next_cursor}, ctx=ctx)
    assert nxt.data[0]["id"] == len(result.data)


async def test_handler_exceptions_do_not_leak(make_gateway, ctx, caplog):
    gw = make_gateway()

    @gw.tool(effect="read")
    def boom() -> dict:
        """Fails."""
        raise RuntimeError("database password is hunter2")

    result = await gw.call("boom", {}, ctx=ctx)
    assert result.error and result.error.code is ErrorCode.INTERNAL_ERROR
    assert "hunter2" not in result.to_json()


async def test_handler_can_raise_safe_tool_failure(make_gateway, ctx):
    gw = make_gateway()

    @gw.tool(effect="read")
    def lookup(id: str) -> dict:
        """Look up."""
        raise ToolFailure(ErrorCode.UPSTREAM_ERROR, f"record {id} not found", retryable=False)

    result = await gw.call("lookup", {"id": "r1"}, ctx=ctx)
    assert result.error and result.error.message == "record r1 not found"


async def test_timeout(make_gateway, ctx):
    gw = make_gateway()

    @gw.tool(effect="read", timeout=0.05)
    async def slow() -> dict:
        """Slow."""
        await asyncio.sleep(1)
        return {}

    result = await gw.call("slow", {}, ctx=ctx)
    assert result.error and result.error.code is ErrorCode.TIMEOUT


async def test_sync_handler_runs_in_thread(make_gateway, ctx):
    gw = make_gateway()

    @gw.tool(effect="read")
    def blocking() -> dict:
        """Blocking."""
        time.sleep(0.05)
        return {"ok": True}

    results = await asyncio.gather(*(gw.call("blocking", {}, ctx=ctx) for _ in range(5)))
    assert all(r.ok for r in results)


async def test_non_json_result_rejected(make_gateway, ctx):
    gw = make_gateway()

    @gw.tool(effect="read")
    def weird() -> object:
        """Weird."""
        return {"when": object()}

    result = await gw.call("weird", {}, ctx=ctx)
    assert result.error and result.error.code is ErrorCode.INTERNAL_ERROR


async def test_rate_limit_applies(make_gateway, ctx):
    gw = make_gateway()
    gw.register(
        PythonTool(
            name="ping",
            description="Ping.",
            effect="read",
            handler=lambda: {"pong": True},
            rate_limit=RateLimit(calls=1, per_seconds=60),
        )
    )
    assert (await gw.call("ping", {}, ctx=ctx)).ok
    limited = await gw.call("ping", {}, ctx=ctx)
    assert limited.error and limited.error.code is ErrorCode.RATE_LIMITED


def test_registration_errors(make_gateway):
    gw = make_gateway()
    with pytest.raises(ConfigurationError):

        @gw.tool(effect="read")
        def untyped(x):  # type: ignore[no-untyped-def]
            """No hints."""

    with pytest.raises(ConfigurationError):
        gw.register(
            PythonTool(
                name="bad",
                description="d",
                effect="read",
                input={"a": {"type": "string"}},
                handler=lambda b: b,
            )
        )
    with pytest.raises(ConfigurationError):
        gw.register(PythonTool(name="no desc", description="d", effect="read", handler=lambda: 1))
    with pytest.raises(ConfigurationError):
        gw.register(PythonTool(name="x", description="", effect="read", handler=lambda: 1))

    @gw.tool(effect="read")
    def dup() -> dict:
        """Dup."""
        return {}

    with pytest.raises(ConfigurationError):
        gw.register(PythonTool(name="dup", description="d", effect="read", handler=lambda: 1))
    with pytest.raises(ConfigurationError):
        gw.register(
            PythonTool(
                name="r",
                description="d",
                effect="read",
                input={"cursor": {"type": "string"}},
                handler=lambda cursor: 1,
            )
        )
