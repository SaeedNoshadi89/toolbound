# Integration cookbook

Toolbound is the **tool layer** of an agent. It does not run the agent loop. These recipes
show how to connect it to common loops and web frameworks. The Anthropic and OpenAI
adapters ship as code; FastAPI and LangGraph are complete, tested examples; the rest are
short recipes using the public API, marked as such.

| Integration | Status |
|---|---|
| Anthropic Messages API | **adapter shipped** (`toolbound.adapters.anthropic`) |
| OpenAI Chat Completions / Responses | **adapter shipped** (`toolbound.adapters.openai`) |
| FastAPI | **tested example** ([`examples/fastapi_app.py`](../examples/fastapi_app.py), `tests/integrations/test_fastapi.py`) |
| LangGraph | **tested example** ([`examples/langgraph_agent.py`](../examples/langgraph_agent.py), `tests/integrations/test_langgraph.py`) |
| Plain custom loop | recipe below |
| MCP (Claude Desktop, IDEs, any MCP client) | recipe below; packaged server planned (v0.3) |
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

## Approvals in multi-step apps

Approval rarely happens inside the same function call. The approval request's `token` is
**encrypted and authenticated** by the gateway, so you can store it in a database, send it
to a browser, or keep it in a workflow checkpoint, and later call
`gateway.resume(token, ctx=ctx, approved_by=...)` with the **live** context of the user who
approves. Changing any part of the request breaks the token. A different actor or tenant
gets `approval_invalid`. A token works only once, and only until it expires (default 10
minutes, `Gateway(approval_ttl=...)`). Use the same `Gateway(secret=...)` on every worker.

- **Values prepared for one request.** If the context binds values that exist only for the
  request (a fresh operation id, the record version the human saw), resume with
  `bound="sealed"`: those `attributes.<key>` values come from the token, while the actor,
  tenant and scopes come from the live context. With the default `bound="live"`, a
  changed value is `approval_invalid` and `error.details["changed_bound"]` names it.
- **Different lifetimes.** A chat card and a review queue item can live for different
  times: set `approval_ttl` on the tool or pass `gateway.call(..., approval_ttl=...)`
  (at most 7 days).
- **One card per model tool call.** `PendingApproval.call_id` is the call that requested
  it. If the model repeats a call, show the existing card; even if both are approved, the
  action runs once.
- **Business refusals.** A Python tool that cannot act (the record changed, it is
  closed) raises `ToolRefusal("version_conflict", "...")`. The result is `refused` with
  `details["reason"]`, so the host can tell the human why, and nothing is retried.
- **Who is signed in.** Pass the user object as `ExecutionContext(principal=user)`;
  handlers and `authorize` read `ctx.principal`. It is never sealed, logged or shown.

## FastAPI (tested example)

[`examples/fastapi_app.py`](../examples/fastapi_app.py) is a tool-execution API for an
agent backend:

- the `Gateway` is created once in `lifespan` (with `secret=` from the environment) and
  closed on shutdown;
- a dependency authenticates the request and builds the `ExecutionContext`. Tenant, scopes
  and bound values never come from the request body;
- `POST /tools/{name}` (agent API key) runs a model tool call with its `call_id`. For a
  destructive tool it returns the model-visible `approval_required` result and only an
  opaque `approval_id`. The approval **token stays on the server**, so neither the agent
  nor a prompt-injected model can approve its own request;
- `GET /approvals` and `POST /approvals/{id}` are the **human** channel: a browser session
  cookie plus a CSRF token. Agent keys are not accepted there. A rejection calls
  `gateway.deny()`, so the request can never be approved later.

`tests/integrations/test_fastapi.py` checks authentication, per-user tool lists, tenant
binding, that the agent never sees the token and cannot approve, CSRF, single execution,
isolation between users, final rejections, and restarts with new event loops.

## LangGraph (tested example)

[`examples/langgraph_agent.py`](../examples/langgraph_agent.py) builds the graph and the
gateway **once**, and passes the trusted context per run with LangGraph's `context=`:

```python
app = build_graph(gateway, model)  # agent -> tools -> approve -> agent
config = {"configurable": {"thread_id": thread_id}}
state = await app.ainvoke(
    {"messages": [HumanMessage(task)], "pending": []}, config, context=AgentContext(ctx)
)
if "__interrupt__" in state:  # a destructive call is waiting
    question = state["__interrupt__"][0].value  # {"summary": ...}
    state = await app.ainvoke(Command(resume=user_said_yes), config, context=AgentContext(ctx))
```

Key points, all covered by `tests/integrations/test_langgraph.py`:

- the `tools` node passes each tool call's `id` as `call_id`, so re-running the node (crash
  recovery) cannot repeat a write;
- calls that need approval are collected in state as **tokens only**, and a separate
  `approve` node calls `interrupt()` for each. LangGraph re-runs a node from the top on
  resume, so the node only acts after **all** decisions are in;
- resuming under another user's context is refused, and a stray second resume executes
  nothing.

To use a real model, bind the tool definitions: `ChatAnthropic(model="claude-opus-5-5")
.bind_tools(tool_specs(gateway, ctx))`, and return its `AIMessage` from the `agent` node.

### Why not LangChain `StructuredTool`s?

The 0.1 docs suggested wrapping each tool in a `StructuredTool`. Don't: a `StructuredTool`
whose `args_schema` is a JSON Schema dict cannot receive the tool-call id
(`InjectedToolCallId` is not injected; checked with `langchain-core` 1.7.7). Without the id,
duplicate-call protection for writes is lost, and `approval_required` ends up in front of
the model with no way to resume. The graph above reads `tool_calls` from the `AIMessage`
directly and has neither problem.

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
# pass params.meta / request ids as call_id if your client provides stable ids
```

Notes:

- For a remote (HTTP) MCP server, derive the `ExecutionContext` from the **authenticated
  MCP session**, never from tool arguments.
- MCP has no standard channel for Toolbound's approval flow yet, so a tool that needs
  approval returns `approval_required` to the client. Never let the MCP client approve:
  it is the agent's side of the boundary (T7). Handle the approval out of band, as the
  FastAPI example does (sketch below), or keep such tools off MCP servers for now.

Out-of-band approval for an MCP server: keep the token on the server and give the model
only an opaque id; the human approves through your own authenticated UI.

```python
pending: dict[str, PendingApproval] = {}  # use a database with several workers


async def call_tool(request_context, params):
    call_id = str(request_context.request_id)  # stable per MCP request
    result = await gateway.call(params.name, params.arguments or {}, ctx=ctx, call_id=call_id)
    if result.approval is not None:
        pending[result.approval.id] = result.approval  # the token never leaves the server
        text = json.dumps({"status": "approval_required", "approval_id": result.approval.id})
    else:
        text = result.to_json()
    return types.CallToolResult(
        content=[types.TextContent(type="text", text=text)], is_error=not result.ok
    )


# In your own web app, behind the human's session (never reachable by the MCP client):
async def approve(approval_id: str, user_ctx: ExecutionContext):
    request = pending.pop(approval_id)
    return await gateway.resume(request, ctx=user_ctx, approved_by=user_ctx.actor)
```

  This sketch is not run in CI (the MCP SDK is not a test dependency); the FastAPI example
  it follows is.
- The MCP SDK's API has changed between major versions; a tested, packaged adapter with
  pinned compatibility is planned for v0.3.

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
