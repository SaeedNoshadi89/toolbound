"""OpenAI adapter (Chat Completions and Responses APIs). Does not import ``openai``.

```python
from toolbound.adapters import openai as tb

# Chat Completions
tools = tb.tools(gateway, ctx)
completion = client.chat.completions.create(model=..., messages=messages, tools=tools)
message = completion.choices[0].message
batch = await tb.run_tool_calls(gateway, message, ctx)
messages.append(message)
messages.extend(batch.blocks)          # role="tool" messages

# Responses API
tools = tb.tools(gateway, ctx, api="responses")
response = client.responses.create(model=..., input=items, tools=tools)
batch = await tb.run_tool_calls(gateway, response, ctx)
items.extend(response.output)
items.extend(batch.blocks)             # function_call_output items
```
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any, Literal

from toolbound.core.context import ExecutionContext
from toolbound.core.exposure import Strategy
from toolbound.core.gateway import Gateway

from ._common import Call, ToolCallBatch, execute_calls, get, parse_json_arguments

__all__ = ["run_tool_calls", "tool_calls", "tools"]

Api = Literal["chat", "responses"]


def tools(
    gateway: Gateway,
    ctx: ExecutionContext,
    *,
    api: Api = "chat",
    tags: Iterable[str] | None = None,
    names: Iterable[str] | None = None,
    strategy: Strategy = "direct",
) -> list[dict[str, Any]]:
    """Function-tool definitions for Chat Completions (default) or Responses."""
    out: list[dict[str, Any]] = []
    for d in gateway.definitions(ctx, tags=tags, names=names, strategy=strategy):
        if api == "responses":
            out.append(
                {
                    "type": "function",
                    "name": d.name,
                    "description": d.description,
                    "parameters": d.input_schema,
                }
            )
        else:
            out.append(
                {
                    "type": "function",
                    "function": {
                        "name": d.name,
                        "description": d.description,
                        "parameters": d.input_schema,
                    },
                }
            )
    return out


def tool_calls(obj: Any) -> tuple[list[Call], Api]:
    """Extract calls from a chat message/completion or a Responses API response."""
    output = get(obj, "output")
    if isinstance(output, list):
        calls = []
        for item in output:
            if get(item, "type") != "function_call":
                continue
            arguments, error = parse_json_arguments(get(item, "arguments"))
            calls.append(Call(str(get(item, "call_id")), str(get(item, "name")), arguments, error))
        return calls, "responses"
    choices = get(obj, "choices")
    message = get(choices[0], "message") if choices else obj
    calls = []
    for item in get(message, "tool_calls") or []:
        function = get(item, "function")
        arguments, error = parse_json_arguments(get(function, "arguments"))
        calls.append(Call(str(get(item, "id")), str(get(function, "name")), arguments, error))
    return calls, "chat"


async def run_tool_calls(
    gateway: Gateway, obj: Any, ctx: ExecutionContext, *, parallel: bool = False
) -> ToolCallBatch:
    """Execute every function call and build the matching result items."""
    calls, api = tool_calls(obj)
    results = await execute_calls(gateway, calls, ctx, parallel=parallel)
    batch = ToolCallBatch(results=results)
    for call, result in zip(calls, results, strict=True):
        if api == "responses":
            batch.blocks.append(
                {"type": "function_call_output", "call_id": call.id, "output": result.to_json()}
            )
        else:
            batch.blocks.append(
                {"role": "tool", "tool_call_id": call.id, "content": result.to_json()}
            )
    return batch
