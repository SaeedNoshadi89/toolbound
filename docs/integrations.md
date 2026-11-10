# Integration cookbook

Toolbound is the **tool layer** of an agent. It does not run the agent loop. These recipes
show how to connect it to common loops. Only the Anthropic and OpenAI adapters ship in 0.1.
Everything else is a short recipe using the public API, marked as such.

| Integration | Status |
|---|---|
| Anthropic Messages API | **adapter shipped** (`toolbound.adapters.anthropic`) |
| OpenAI Chat Completions / Responses | **adapter shipped** (`toolbound.adapters.openai`) |
| Plain custom loop | recipe below |
| LangGraph / LangChain | recipe below; packaged adapter planned (v0.3) |
| MCP (Claude Desktop, IDEs, any MCP client) | recipe below; packaged server planned (v0.2) |
| Claude Agent SDK | via MCP (recipe below) |

## Anthropic (manual loop)

See [`examples/claude_agent.py`](../examples/claude_agent.py) for the full version with
human approval.

```python
import anthropic
from toolbound.adapters import anthropic as tb

client = anthropic.Anthropic()
tools = tb.tools(gateway, ctx)  # only what this user may see
messages = [{"role": "user", "content": task}]
while True:
    response = client.messages.create(
        model="claude-opus-5-5", max_tokens=16000, tools=tools, messages=messages
    )
    messages.append({"role": "assistant", "content": response.content})
    if response.stop_reason != "tool_use":
        break
    batch = await tb.run_tool_calls(gateway, response, ctx)
    messages.append(batch.message)  # all tool_result blocks in ONE message
```

The `tool_use` id is passed as `call_id`, so a write that the model accidentally repeats
with the same id is not executed twice.

## OpenAI

```python
from toolbound.adapters import openai as tb

# Chat Completions
completion = client.chat.completions.create(
    model=MODEL, messages=messages, tools=tb.tools(gateway, ctx)
)
message = completion.choices[0].message
if message.tool_calls:
    batch = await tb.run_tool_calls(gateway, message, ctx)
    messages += [message, *batch.blocks]

# Responses API
response = client.responses.create(
    model=MODEL, input=items, tools=tb.tools(gateway, ctx, api="responses")
)
batch = await tb.run_tool_calls(gateway, response, ctx)
items += [*response.output, *batch.blocks]
```

## Any loop (framework-neutral)

```python
for d in gateway.definitions(ctx):  # name, description, input_schema
    register_with_your_framework(d.name, d.description, d.input_schema)


async def on_tool_call(call_id, name, arguments):  # arguments: dict parsed from the model
    result = await gateway.call(name, arguments, ctx=ctx, call_id=call_id)
    if result.approval:  # destructive: ask a human first
        ...
    return result.to_json()  # the only thing the model should see
```

## LangGraph / LangChain (recipe)

```python
from langchain_core.tools import StructuredTool


def as_langchain_tools(gateway, ctx):
    def make(defn):
        async def run(**kwargs):
            return (await gateway.call(defn.name, kwargs, ctx=ctx)).to_json()

        return StructuredTool.from_function(
            coroutine=run,
            name=defn.name,
            description=defn.description,
            args_schema=defn.input_schema,
        )

    return [make(d) for d in gateway.definitions(ctx)]
```

Build the tools **per request** with the request's `ExecutionContext`, never once
globally, so every user gets only their own tools and bindings. Verified with
`langchain-core` 1.7.7, which accepts a JSON Schema dict as `args_schema`.

## MCP (recipe until the packaged server ships)

An MCP server can expose a gateway in a few lines. The server process owns the
credentials, and the client only sees tool definitions and results. Verified with the
official `mcp` Python SDK **2.3.0**; the 1.x SDK uses a different, decorator-based API.

```python
import mcp.types as types
from mcp.server.lowlevel import Server

ctx = ExecutionContext(actor="local-user")  # a stdio server serves one local user


async def list_tools(request_context, params):
    return types.ListToolsResult(
        tools=[
            types.Tool(name=d.name, description=d.description, input_schema=d.input_schema)
            for d in gateway.definitions(ctx)
        ]
    )


async def call_tool(request_context, params):
    result = await gateway.call(params.name, params.arguments or {}, ctx=ctx)
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=result.to_json())], is_error=not result.ok
    )


server = Server("toolbound", on_list_tools=list_tools, on_call_tool=call_tool)
# run with the SDK's stdio or streamable-HTTP transport (see the MCP SDK docs)
```

Notes:

- For a remote (HTTP) MCP server, derive the `ExecutionContext` from the **authenticated
  MCP session**, never from tool arguments.
- MCP has no standard channel for Toolbound's approval flow yet, so destructive tools
  return `approval_required`. Handle approval out of band, or keep destructive tools off
  MCP servers for now.
- The MCP SDK's API has changed between major versions; a tested, packaged adapter with
  pinned compatibility is planned for v0.2.

## Claude Agent SDK

The Claude Agent SDK can use MCP servers. Run the MCP recipe above as a server and add it
to the SDK's MCP configuration. Toolbound then governs every REST call the agent makes
through it.

## Writing an adapter

An adapter needs to do only three things:

1. convert `gateway.definitions(ctx, ...)` to the platform's tool format;
2. parse the platform's tool calls into `(call_id, name, arguments)`;
3. call `gateway.call(...)` and return `result.to_json()` in the platform's result format.

Adapters must contain **no security logic**: no filtering of arguments, no policy, no
retries. All of that belongs to the core so every integration behaves the same. See
`src/toolbound/adapters/anthropic.py` (about 70 lines) as a template, and add tests that
compare your definitions with `gateway.definitions()`.
