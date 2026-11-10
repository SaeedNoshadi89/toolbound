"""Anthropic Messages API adapter. Does not import the ``anthropic`` package.

```python
from toolbound.adapters import anthropic as tb

tools = tb.tools(gateway, ctx)
response = client.messages.create(model=..., tools=tools, messages=messages, max_tokens=...)
batch = await tb.run_tool_calls(gateway, response, ctx)
messages.append({"role": "assistant", "content": response.content})
messages.append(batch.message)
```
"""

from __future__ import annotations

from collections.abc import Iterable
from typing import Any

from toolbound.core.context import ExecutionContext
from toolbound.core.exposure import Strategy
from toolbound.core.gateway import Gateway

from ._common import Call, ToolCallBatch, execute_calls, get, optional_id, parse_json_arguments

__all__ = ["AnthropicToolCallBatch", "run_tool_calls", "tool_calls", "tools"]


def tools(
    gateway: Gateway,
    ctx: ExecutionContext,
    *,
    tags: Iterable[str] | None = None,
    names: Iterable[str] | None = None,
    strategy: Strategy = "direct",
) -> list[dict[str, Any]]:
    """Tool definitions in Anthropic format, filtered for ``ctx``."""
    return [
        {"name": d.name, "description": d.description, "input_schema": d.input_schema}
        for d in gateway.definitions(ctx, tags=tags, names=names, strategy=strategy)
    ]


def tool_calls(message: Any) -> list[Call]:
    """Extract ``tool_use`` blocks from a Message, a content list, or dicts."""
    content = get(message, "content", message)
    calls: list[Call] = []
    for block in content or []:
        if get(block, "type") != "tool_use":
            continue
        arguments, error = parse_json_arguments(get(block, "input"))
        calls.append(Call(optional_id(get(block, "id")), str(get(block, "name")), arguments, error))
    return calls


class AnthropicToolCallBatch(ToolCallBatch):
    @property
    def message(self) -> dict[str, Any]:
        """A ``user`` message containing every ``tool_result`` block."""
        return {"role": "user", "content": list(self.blocks)}


async def run_tool_calls(
    gateway: Gateway, message: Any, ctx: ExecutionContext, *, parallel: bool = False
) -> AnthropicToolCallBatch:
    """Execute every ``tool_use`` block and build matching ``tool_result`` blocks.

    All results belong in a single user message (see :attr:`message`).
    """
    calls = tool_calls(message)
    results = await execute_calls(gateway, calls, ctx, parallel=parallel)
    batch = AnthropicToolCallBatch(results=results)
    for call, result in zip(calls, results, strict=True):
        block: dict[str, Any] = {
            "type": "tool_result",
            "tool_use_id": call.id,
            "content": result.to_json(),
        }
        if not result.ok:
            block["is_error"] = True
        batch.blocks.append(block)
    return batch
