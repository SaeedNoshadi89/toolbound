"""The LangGraph example: interrupt-based approvals, re-run safety, context isolation."""

from __future__ import annotations

import pytest

pytest.importorskip("langgraph")

from langchain_core.messages import AIMessage, HumanMessage, ToolMessage
from langgraph.types import Command

from toolbound import ExecutionContext

from .conftest import BASE, deletes

pytestmark = pytest.mark.security


def _ctx(actor="alice", tenant="acme"):
    return ExecutionContext(
        actor=actor,
        tenant=tenant,
        scopes=frozenset({"issues:read", "issues:write"}),
        attributes={"repo": "widgets"},
    )


def _calls(*calls):
    return AIMessage(content="", tool_calls=[{"id": i, "name": n, "args": a} for i, n, a in calls])


@pytest.fixture
def gateway(upstream):
    from _tracker import build_gateway

    return build_gateway(BASE, secret=b"s" * 32, transport=upstream)


async def _start(gateway, model_turn, thread="t1", ctx=None):
    from langgraph_agent import AgentContext, build_graph, scripted_model

    app = build_graph(gateway, scripted_model(model_turn))
    config = {"configurable": {"thread_id": thread}}
    run = AgentContext(ctx or _ctx())
    state = await app.ainvoke(
        {"messages": [HumanMessage("go")], "pending": []}, config, context=run
    )
    return app, config, run, state


def _tool_messages(state):
    return {m.tool_call_id: m for m in state["messages"] if isinstance(m, ToolMessage)}


async def test_reads_run_and_destructive_calls_pause(gateway, upstream):
    turn = _calls(("c1", "list_issues", {}), ("c2", "delete_comment", {"comment_id": 7}))
    _, _, _, state = await _start(gateway, turn)
    assert "__interrupt__" in state
    assert "DELETE" in state["__interrupt__"][0].value["summary"]
    assert deletes(upstream) == []
    assert '"ok":true' in _tool_messages(state)["c1"].content


async def test_approval_executes_once_even_if_resumed_twice(gateway, upstream):
    app, config, run, _ = await _start(gateway, _calls(("c2", "delete_comment", {"comment_id": 7})))
    state = await app.ainvoke(Command(resume=True), config, context=run)
    assert '"ok":true' in _tool_messages(state)["c2"].content
    await app.ainvoke(Command(resume=True), config, context=run)  # stray second resume
    assert len(deletes(upstream)) == 1


async def test_denial_executes_nothing(gateway, upstream):
    app, config, run, _ = await _start(gateway, _calls(("c2", "delete_comment", {"comment_id": 7})))
    state = await app.ainvoke(Command(resume=False), config, context=run)
    assert "approval_denied" in _tool_messages(state)["c2"].content
    assert deletes(upstream) == []


async def test_multiple_approvals_wait_for_every_decision(gateway, upstream):
    turn = _calls(
        ("a", "delete_comment", {"comment_id": 1}), ("b", "delete_comment", {"comment_id": 2})
    )
    app, config, run, _ = await _start(gateway, turn)
    state = await app.ainvoke(Command(resume=True), config, context=run)
    assert "__interrupt__" in state  # second question; nothing executed yet
    assert deletes(upstream) == []
    state = await app.ainvoke(Command(resume=False), config, context=run)
    assert [u.rsplit("/", 1)[1] for u in deletes(upstream)] == ["1"]


async def test_resume_under_another_users_context_is_refused(gateway, upstream):
    app, config, _, _ = await _start(gateway, _calls(("c2", "delete_comment", {"comment_id": 7})))
    from langgraph_agent import AgentContext

    mallory = AgentContext(_ctx(actor="mallory", tenant="acme"))
    state = await app.ainvoke(Command(resume=True), config, context=mallory)
    assert "approval_invalid" in _tool_messages(state)["c2"].content
    assert deletes(upstream) == []


async def test_rerun_of_tools_node_cannot_repeat_a_write(gateway, upstream):
    """Crash recovery re-runs a node with the same tool-call id: the write is deduped.

    Even if the re-run asks for (and gets) a second approval, the call id was
    already executed, so the upstream DELETE happens once.
    """
    ctx = _ctx()
    pending = await gateway.call("delete_comment", {"comment_id": 7}, ctx=ctx, call_id="c9")
    assert (await gateway.resume(pending.approval, ctx=ctx, approved_by="alice", call_id="c9")).ok
    rerun = await gateway.call("delete_comment", {"comment_id": 7}, ctx=ctx, call_id="c9")
    second = await gateway.resume(rerun.approval, ctx=ctx, approved_by="alice", call_id="c9")
    assert second.error.code.value == "duplicate_call"
    assert len(deletes(upstream)) == 1


def test_checkpoint_holds_only_the_encrypted_token(gateway):
    import asyncio

    async def run():
        app, config, _, _ = await _start(
            gateway, _calls(("c2", "delete_comment", {"comment_id": 7})), thread="t-ck"
        )
        snapshot = await app.aget_state(config)
        return snapshot.values["pending"]

    pending = asyncio.run(run())
    assert set(pending[0]) == {"call_id", "token", "summary"}
    assert pending[0]["token"].startswith("tbr1.")
