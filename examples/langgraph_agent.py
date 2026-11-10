# requires: langgraph
"""LangGraph: Toolbound tools with human approval through ``interrupt()``.

Patterns shown:

* the graph and the Gateway are built **once**; the trusted ``ExecutionContext``
  arrives per run through LangGraph's ``context=`` (never from state or the model);
* the ``tools`` node passes each tool-call id as ``call_id``, so if a node is
  re-run (crash recovery, retries) a write cannot execute twice;
* calls that need approval are collected, then the ``approve`` node pauses with
  ``interrupt()``. Only the encrypted approval **token** is stored in the
  checkpoint; side effects happen after every interrupt in the node is resolved,
  because LangGraph re-runs a node from the top when it resumes.

The model here is scripted so the example runs offline. In a real app use, for
example, ``ChatAnthropic(model="claude-opus-5-5").bind_tools(tool_specs(gw, ctx))``.
"""

from __future__ import annotations

import asyncio
import json
import secrets
from collections.abc import Awaitable, Callable
from dataclasses import dataclass
from typing import Annotated, Any, TypedDict

from langchain_core.messages import AIMessage, AnyMessage, HumanMessage, ToolMessage
from langgraph.checkpoint.memory import InMemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.message import add_messages
from langgraph.runtime import Runtime
from langgraph.types import Command, interrupt

from toolbound import ExecutionContext, Gateway


@dataclass(frozen=True)
class AgentContext:
    """Per-run trusted context, supplied by your app after authentication."""

    ctx: ExecutionContext


class State(TypedDict):
    messages: Annotated[list[AnyMessage], add_messages]
    pending: list[dict[str, Any]]


Model = Callable[[list[AnyMessage]], Awaitable[AIMessage]]


def tool_specs(gateway: Gateway, ctx: ExecutionContext) -> list[dict[str, Any]]:
    """Tool definitions for ``bind_tools`` (Anthropic-style dicts)."""
    return [
        {"name": d.name, "description": d.description, "input_schema": d.input_schema}
        for d in gateway.definitions(ctx)
    ]


def build_graph(gateway: Gateway, model: Model, *, checkpointer: Any = None) -> Any:
    async def agent(state: State) -> dict[str, Any]:
        return {"messages": [await model(state["messages"])]}

    async def tools(state: State, runtime: Runtime[AgentContext]) -> dict[str, Any]:
        ctx = runtime.context.ctx
        last = state["messages"][-1]
        assert isinstance(last, AIMessage)
        messages: list[ToolMessage] = []
        pending: list[dict[str, Any]] = []
        for call in last.tool_calls:
            result = await gateway.call(call["name"], call["args"], ctx=ctx, call_id=call["id"])
            if result.approval is not None:
                pending.append(
                    {
                        "call_id": call["id"],
                        "token": result.approval.token,
                        "summary": result.approval.summary,
                    }
                )
                continue
            messages.append(_tool_message(call["id"], result.to_json(), result.ok))
        return {"messages": messages, "pending": pending}

    async def approve(state: State, runtime: Runtime[AgentContext]) -> dict[str, Any]:
        ctx = runtime.context.ctx
        # Ask first (this node re-runs from the top on every resume) ...
        decisions = [interrupt(_for_human(gateway, p["token"])) for p in state["pending"]]
        # ... act only once every decision is in.
        messages = []
        for item, decision in zip(state["pending"], decisions, strict=True):
            if decision is True:
                result = await gateway.resume(
                    item["token"], ctx=ctx, approved_by=ctx.actor, call_id=item["call_id"]
                )
                messages.append(_tool_message(item["call_id"], result.to_json(), result.ok))
            else:
                await gateway.deny(item["token"])  # a rejected request stays rejected
                denied = {
                    "ok": False,
                    "error": {
                        "code": "approval_denied",
                        "message": "the user did not approve this action",
                    },
                }
                messages.append(_tool_message(item["call_id"], json.dumps(denied), False))
        return {"messages": messages, "pending": []}

    def after_agent(state: State) -> str:
        last = state["messages"][-1]
        return "tools" if isinstance(last, AIMessage) and last.tool_calls else END

    def after_tools(state: State) -> str:
        return "approve" if state["pending"] else "agent"

    graph = StateGraph(State, context_schema=AgentContext)
    graph.add_node("agent", agent)
    graph.add_node("tools", tools)
    graph.add_node("approve", approve)
    graph.add_edge(START, "agent")
    graph.add_conditional_edges("agent", after_agent, ["tools", END])
    graph.add_conditional_edges("tools", after_tools, ["approve", "agent"])
    graph.add_edge("approve", "agent")
    return graph.compile(checkpointer=checkpointer or InMemorySaver())


def _for_human(gateway: Gateway, token: str) -> dict[str, Any]:
    """Everything a human needs to decide: target, all arguments, trusted values."""
    view = gateway.pending_approval(token).to_dict()
    view.pop("token")
    return view


def _tool_message(call_id: str, content: str, ok: bool) -> ToolMessage:
    return ToolMessage(content=content, tool_call_id=call_id, status="success" if ok else "error")


def scripted_model(*turns: AIMessage) -> Model:
    """A stand-in for a chat model: returns the given messages in order."""
    queue = list(turns)

    async def model(messages: list[AnyMessage]) -> AIMessage:
        return queue.pop(0) if queue else AIMessage(content="Done.")

    return model


async def main() -> None:
    from _demo_api import run_demo_api
    from _tracker import build_gateway

    ctx = ExecutionContext(
        actor="alice",
        tenant="acme",
        scopes=frozenset({"issues:read", "issues:write"}),
        attributes={"repo": "widgets"},
    )
    with run_demo_api() as base_url:
        async with build_gateway(base_url, secret=secrets.token_bytes(32)) as gateway:
            model = scripted_model(
                AIMessage(
                    content="",
                    tool_calls=[
                        {"id": "call_1", "name": "list_issues", "args": {"per_page": 2}},
                        {"id": "call_2", "name": "delete_comment", "args": {"comment_id": 7}},
                    ],
                )
            )
            app = build_graph(gateway, model)
            config = {"configurable": {"thread_id": "demo"}}
            run = AgentContext(ctx)
            state = await app.ainvoke(
                {"messages": [HumanMessage("Clean up spam")], "pending": []}, config, context=run
            )
            question = state["__interrupt__"][0].value
            print("paused for approval:", question["summary"])
            state = await app.ainvoke(Command(resume=True), config, context=run)
            for message in state["messages"]:
                if isinstance(message, ToolMessage):
                    print(f"tool result {message.tool_call_id}: {message.content[:90]}")


if __name__ == "__main__":
    asyncio.run(main())
