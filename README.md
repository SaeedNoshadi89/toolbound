# Toolbound

**Contract-first, secure-by-default tools for AI agents.** Describe each REST endpoint, or
trusted Python function, your agent may use *once*. Toolbound turns it into a narrow,
well-typed tool. It validates every model call, enforces **your** authorization policy and
network rules, asks a human before destructive actions, and shapes the response into
small, bounded, honest output before it reaches the model.

It is for developers building agents in any domain (support, finance, legal, DevOps,
internal tools) who want the model to *use* APIs without ever *choosing* URLs, credentials,
tenants or policy.

```text
model says:  get_issue({"issue_number": 42})
toolbound:   validate → authorize(ctx) → GET https://api.github.com/repos/acme/widgets/issues/42
             (owner/repo/token from trusted code) → keep 5 allowlisted fields → ≤300 tokens
model gets:  {"ok":true,"data":{"number":42,"title":"…","state":"open","author":"bob","labels":["bug"]},
              "meta":{"truncated":false,"source":{"service":"github","operation":"get_issue","status":200}}}
```

> **Status: alpha (0.1.0).** The core is complete and heavily tested, but the public API may
> still change before 1.0 (see [Versioning](#roadmap-and-versioning)). The package name
> `toolbound` was free on PyPI on 2026-11-10; it has **not been published yet**.

---

## Contents

- [What it is, and what it is not](#what-it-is-and-what-it-is-not)
- [Features and non-goals](#features-and-non-goals)
- [Install](#install)
- [Quickstart](#quickstart)
- [A complete example](#a-complete-example)
- [Security model](#security-model)
- [Customizing input and output](#customizing-input-and-output)
- [Agent integrations](#agent-integrations)
- [Architecture](#architecture)
- [Benchmarks](#benchmarks)
- [Development](#development)
- [Roadmap and versioning](#roadmap-and-versioning)

## What it is, and what it is not

| | |
|---|---|
| **A Python library (SDK)** | Yes. It runs inside your application process. `pip install` and import it. |
| **A contract format** | Yes. A versioned YAML/JSON format for approved operations ([reference](docs/contracts.md)), so contracts can be reviewed like code and reused by future runtimes. |
| **A hosted REST API / gateway service** | No. Nothing to deploy. (An MCP-over-HTTP server that can run as an isolated gateway is on the [roadmap](#roadmap-and-versioning).) |
| **An MCP server** | Not yet. MCP is planned as an *adapter* (v0.2) over the same core and contracts, not as the core itself. |
| **Provider plugins** | Small optional adapters for the Anthropic and OpenAI tool formats ship today. They import no provider SDK and contain no security logic. |
| **An agent framework** | No. Toolbound is the *tool layer*. Use it with your own loop, the Anthropic/OpenAI SDKs, LangGraph, or anything else ([integrations](docs/integrations.md)). |
| **A sandbox for Python code** | No. Python tools are **trusted developer code** and run with your application's privileges. |
| **A fact checker** | No. Schema validation proves *shape*, not *truth*. |

## Features and non-goals

**Features (implemented in 0.1)**

- **One pipeline for every tool.** REST operations and Python functions both go through:
  argument validation → trusted bindings → scopes → your `authorize()` → rate limit →
  human approval → replay check → execution → output shaping → structured result.
- **Narrow, generated tools.** The model sees only a name, a description and a closed JSON
  Schema (`additionalProperties: false` everywhere). Unknown arguments are rejected, never
  ignored.
- **Trusted bindings.** Tenant, user, repository and similar values come from the
  `ExecutionContext` and are *not part of the model's schema*, so they cannot be forged.
- **Default-deny policy.** A `Gateway` cannot be created without an `authorize=` hook;
  required scopes also hide tools from users who lack them.
- **Network security.** HTTPS-only by default, host/port allowlists, strict path encoding,
  DNS resolution with **every** address checked and the connection **pinned** to the checked
  IP (TLS still verifies the real host name), private/link-local/metadata ranges blocked
  unless explicitly trusted, redirects off by default and re-checked per hop with
  credentials dropped across origins, proxy variables ignored, size caps on decompressed
  bodies, and total deadlines.
- **Credential isolation.** Contracts reference credential *names*; values come from a
  `CredentialProvider` (environment, vault, per-user OAuth). Any credential the upstream echoes
  back is scrubbed from results.
- **Human approval bound to the exact call.** Destructive tools return
  `approval_required`. Grants are HMAC-signed, expire, can be used once, and are bound to
  actor, tenant, tool, contract fingerprint and validated arguments.
- **Replay and idempotency safeguards.** Repeated provider call ids never execute a write
  twice. Non-idempotent requests are never retried automatically. Idempotency keys stay
  stable across retries.
- **Output shaping as a first-class feature.** Allowlist projection with a tiny safe path
  language (`user.login`, `labels[].name`), nested shapes, renames, transforms, defaults,
  per-field and global item/character limits, key and secret-pattern redaction, PII hooks,
  output schema checks (`strict` or `warn`), token budgets, and `required` evidence fields
  that are never silently dropped.
- **Transparent incompleteness.** Every result says what was left out and why
  (`omitted: [{path, reason, count}]`), how many items came back, and offers a signed
  `next_cursor` when more data exists.
- **Pagination.** Upstream cursor, `Link` header and page-number pagination, plus local
  continuation when a budget trims a list. Cursors are opaque, signed, and bound to tool,
  user and arguments.
- **Declarative or code-first.** YAML/JSON contracts validated against a published
  meta-schema, a fully typed Python API, and `@gateway.tool` for Python functions (schema
  inferred from type hints).
- **Provider adapters.** Anthropic Messages and OpenAI Chat Completions / Responses formats,
  including helpers that run a whole turn of tool calls.
- **Observability without payloads.** Structured events (no argument or body values) for
  your logging/metrics.

**Deliberate non-goals:** agent loops and planning, generic summarization of upstream data,
verifying that data is true, sandboxing Python, running as a hosted service, GraphQL/gRPC/
streaming responses (for now), and activating OpenAPI specs automatically.

## Install

Requires Python **3.11–3.15**. Runtime dependencies: `httpx` and `jsonschema`.

Until the first PyPI release, install from GitHub:

```bash
pip install "toolbound[yaml] @ git+https://github.com/SaeedNoshadi89/toolbound"
# or
uv add "toolbound[yaml] @ git+https://github.com/SaeedNoshadi89/toolbound"
```

Optional extras: `yaml` (YAML contracts), `tiktoken` (tokenizer-based budgets).

## Quickstart

One safe, shaped tool over the public GitHub API (no token needed). This is
[`examples/quickstart.py`](examples/quickstart.py):

```python
import asyncio

from toolbound import ExecutionContext, Gateway, Operation, Output, Service, allow_all, from_ctx

github = Service(
    name="github",
    base_url="https://api.github.com",
    headers={"Accept": "application/vnd.github+json"},
)

get_issue = Operation(
    name="get_issue",
    description="Get one issue from the current repository by number.",
    service=github,
    path="/repos/{owner}/{repo}/issues/{issue_number}",
    input={"issue_number": {"type": "integer", "minimum": 1}},  # all the model can set
    bind={"owner": from_ctx("attributes.owner"), "repo": from_ctx("attributes.repo")},
    output=Output(
        shape={
            "number": "number",
            "title": "title",
            "state": "state",
            "author": "user.login",
            "labels": "labels[].name",
        },
        required=("number", "title"),
        max_tokens=300,
    ),
)


async def main() -> None:
    ctx = ExecutionContext(actor="demo-user", attributes={"owner": "python", "repo": "cpython"})
    async with Gateway(authorize=allow_all).register(get_issue) as gateway:
        print(gateway.definitions(ctx)[0].input_schema)  # what the model sees

        ok = await gateway.call("get_issue", {"issue_number": 1}, ctx=ctx)
        print(ok.to_json())  # {"ok":true,"data":{"number":1,"title":...},"meta":{...}}

        blocked = await gateway.call(
            "get_issue", {"issue_number": 1, "url": "http://169.254.169.254/"}, ctx=ctx
        )
        print(blocked.to_json())  # {"ok":false,"error":{"code":"invalid_arguments",...}}


if __name__ == "__main__":
    asyncio.run(main())
```

What the model sees is only:

```json
{"type":"object","properties":{"issue_number":{"type":"integer","minimum":1}},
 "required":["issue_number"],"additionalProperties":false}
```

## A complete example

Two unrelated services, with credentials, tenant binding, a policy, output shaping, a
blocked request, and a destructive action that needs approval. Contracts can live in YAML…

```yaml
# contracts/crm.yaml
version: 1
service:
  name: crm
  base_url: https://crm.example.com/api
  auth: {type: bearer, credential: crm_token}     # a credential NAME, never the value
  network: {allow_hosts: [crm.example.com]}
  limits: {timeout: 10, max_response_bytes: 2000000}
operations:
  - name: search_customers
    description: Search customers of the current account by name or email.
    path: /tenants/{tenant_id}/customers
    input:
      query: {type: string, minLength: 2, maxLength: 80}
      limit: {type: integer, minimum: 1, maximum: 50, default: 10}
    bind:
      tenant_id: ctx.tenant                       # from trusted context, invisible to the model
    required_scopes: [crm:read]
    output:
      root: data
      shape:
        id: id
        name: full_name
        email: contact.email
        plan: subscription.plan.name
        open_tickets: {from: tickets, transform: count}
      required: [id]
      max_items: 20
      max_tokens: 800
      continuation: true
  - name: delete_customer
    description: Permanently delete a customer record.
    method: DELETE
    path: /tenants/{tenant_id}/customers/{customer_id}
    effect: destructive                           # approval required
    input:
      customer_id: {type: string, pattern: "^cus_[A-Za-z0-9]{8,32}$"}
    bind: {tenant_id: ctx.tenant}
    required_scopes: [crm:admin]
    idempotency_header: Idempotency-Key
```

…or in Python. Both produce the same objects:

```python
import asyncio
from toolbound import (
    Decision,
    EnvCredentials,
    ExecutionContext,
    Gateway,
    Operation,
    Output,
    Service,
    from_ctx,
)


def policy(request):  # your business rules, in trusted code
    if request.tool.effect == "destructive" and request.ctx.attributes.get("plan") != "admin":
        return Decision.deny("only account admins can delete records")
    return True


weather = Service(name="weather", base_url="https://api.open-meteo.com")
forecast = Operation(
    name="current_weather",
    description="Current temperature for a coordinate.",
    service=weather,
    path="/v1/forecast",
    input={
        "latitude": {"type": "number", "minimum": -90, "maximum": 90},
        "longitude": {"type": "number", "minimum": -180, "maximum": 180},
        "current": {"const": "temperature_2m", "default": "temperature_2m"},
    },
    output=Output(root="current", shape={"temperature_c": "temperature_2m", "time": "time"}),
)


async def main():
    gateway = Gateway(
        authorize=policy,
        credentials=EnvCredentials({"crm_token": "CRM_API_TOKEN"}),
        secret=b"load-a-32-byte-or-longer-secret-from-your-vault!!",  # cursors + approvals
    )
    gateway.load("contracts/").register(forecast)

    ctx = ExecutionContext(
        actor="user_123",
        tenant="acme",  # set by YOUR auth layer
        scopes=frozenset({"crm:read", "crm:admin"}),
        attributes={"plan": "admin"},
    )

    result = await gateway.call("search_customers", {"query": "ada"}, ctx=ctx)
    print(result.data, result.meta.to_dict())  # shaped data + what was omitted and why

    forged = await gateway.call(
        "search_customers", {"query": "ada", "tenant_id": "globex"}, ctx=ctx
    )
    print(forged.error.code)  # invalid_arguments: tenant is not an input

    pending = await gateway.call(
        "delete_customer", {"customer_id": "cus_12345678"}, ctx=ctx, call_id="toolu_01"
    )
    print(pending.error.code)  # approval_required (nothing sent yet)
    # ... show pending.approval.summary to a human; if they approve:
    done = await gateway.resume(
        pending.approval, ctx=ctx, approved_by="user_123", call_id="toolu_01"
    )
    print(done.ok)


asyncio.run(main())
```

More runnable examples, all offline except where noted:

| Example | Shows |
|---|---|
| [`quickstart.py`](examples/quickstart.py) | public API, bound parameters, shaping, a blocked argument (network) |
| [`two_services.py`](examples/two_services.py) | two unrelated APIs from YAML, grouped tools, `Link` pagination (network) |
| [`blocked_requests.py`](examples/blocked_requests.py) | forged tenant, injected URL, type confusion, redirect to cloud metadata, untrusted private address |
| [`approval_flow.py`](examples/approval_flow.py) | approval, single-use grants, replay and argument-swap rejection |
| [`custom_python_tool.py`](examples/custom_python_tool.py) | `@gateway.tool`, business policy, budgets, continuation |
| [`pagination.py`](examples/pagination.py) | upstream pagination + token budgets, no items lost, tampered cursor |
| [`legal_retrieval.py`](examples/legal_retrieval.py) | Persian text, required citation fields, `overflow="reject"` |
| [`claude_agent.py`](examples/claude_agent.py) | full Claude agent loop with approvals (calls the paid API) |

## Security model

Toolbound treats **everything the model produces** (tool choice, arguments, cursors) and
**everything upstream APIs return** as untrusted. Trusted inputs are your contracts, your
code, and the `ExecutionContext` your application builds after authenticating the user.
The four layers are deliberately separate:

| Layer | Guarantees | Does **not** guarantee |
|---|---|---|
| Structural validation | arguments and responses have the declared shape | permission, truth |
| Authorization | this actor/tenant may run this tool on these arguments (your hook) | network safety |
| Network security | requests reach only allowed hosts/ports/addresses; credentials don't leak across origins | that the upstream API is itself safe |
| Factual verification | nothing: out of scope | — |

**Default-deny behavior:** unregistered tools are unknown; hidden tools look identical to
unknown ones; unknown arguments fail; a missing context value fails closed; plain HTTP,
private addresses, redirects and non-JSON content are refused unless the contract allows
them; destructive tools need approval.

**Limitations you must know about.** Toolbound cannot stop a model from being *influenced*
by text in API responses (prompt injection). It limits what that influence can do: less
untrusted text through allowlists, no way for results to change tools or policy, and
approval for dangerous actions. It cannot see sidecar proxies or service meshes, and it
cannot protect against an upstream API that itself fetches URLs. Replay protection is
per-process unless you supply a shared `StateStore`. Python tools are not sandboxed.

**Hardening checklist:** run agents behind an egress firewall; set a persistent `secret`
from your vault; use a shared `StateStore` (e.g. Redis) with multiple workers; give each
user their own credentials where the upstream supports it; prefer explicit `shape`s over
pass-through; keep `allow_networks` narrow.

Full threat model, controls and residual risks: **[docs/security.md](docs/security.md)**.
Report vulnerabilities privately: **[SECURITY.md](SECURITY.md)**.

## Customizing input and output

**Input** is JSON Schema (draft 2020-12) with nested objects, arrays, enums, bounds,
patterns, formats and defaults. Shorthand `{"name": {...}}` makes every property without a
`default` required. Arguments are placed into path, query or body automatically, or
explicitly with `query=`/`body=`. `bind=` injects trusted values. Path values are strictly
encoded, and `/`, `..` and encoded separators are rejected.

**Output** is a pipeline you control per tool:

```python
Output(
    root="items",  # select part of the response
    shape={  # allowlist + rename
        "id": "id",
        "author": "user.login",  # nested path
        "labels": Field("labels[].name", max_items=5),
        "body": Field("body", max_chars=500),
        "state": Field("state", transform="upper", default="unknown"),
        "comments": Field("comments", shape={"by": "user.login", "text": "body"}),
    },
    required=("id",),  # evidence: never dropped; fail rather than lose it
    max_items=50,
    max_chars=4000,
    max_tokens=2000,  # global limits and budget
    overflow="truncate",  # or "reject": never return partial data
    selectable=True,  # model may ask for a subset of fields (enum, not paths)
    continuation=True,  # signed cursor to resume trimmed lists
    redactors=(mask_emails,),  # your PII hooks, after key + secret-pattern redaction
    schema={...},
    schema_mode="strict",  # upstream response contract
    error_shape={"message": "message"},  # short, useful upstream errors
)
```

Reference: [docs/contracts.md](docs/contracts.md) (every field, YAML and Python) and
[docs/output.md](docs/output.md) (pipeline order, budgets, truncation vs rejection,
pagination).

## Agent integrations

```python
from toolbound.adapters import anthropic as tb

tools = tb.tools(gateway, ctx)  # filtered for this user
response = client.messages.create(
    model="claude-opus-5-5", max_tokens=16000, tools=tools, messages=messages
)
batch = await tb.run_tool_calls(gateway, response, ctx)
messages += [{"role": "assistant", "content": response.content}, batch.message]
for pending in batch.pending_approvals:
    ...  # ask a human, then gateway.resume(...)
```

`toolbound.adapters.openai` does the same for Chat Completions and the Responses API. For
LangGraph/LangChain, MCP, the Claude Agent SDK and plain loops, see the cookbook in
**[docs/integrations.md](docs/integrations.md)**. Compatibility with a platform requires a
real adapter. Toolbound only claims what ships with an adapter and tests.

**Extending:** every outside dependency is a small `typing.Protocol` you can replace:
`Transport`, `CredentialProvider`, `authorize`, `approver`, `TokenEstimator`, `Observer`,
`StateStore`. See [docs/api.md](docs/api.md).

## Architecture

```mermaid
flowchart LR
    M[Model tool call<br/>untrusted] --> A[Adapter<br/>Anthropic / OpenAI / MCP*]
    A --> G
    subgraph G[Gateway core - no HTTP or framework imports]
      V[Validate args<br/>closed JSON Schema] --> B[Bind trusted ctx values]
      B --> P[Scopes + authorize hook]
      P --> R[Rate limit]
      R --> H[Approval + replay check]
      H --> X{Tool kind}
      X -->|REST| N[Build URL + URL policy]
      X -->|Python| F[Trusted handler]
      N --> T[[Transport port]]
      T --> O[Output pipeline<br/>project, redact, limit, budget]
      F --> O
      O --> E[Result envelope<br/>data + omitted + cursor + source]
    end
    T -.-> S[SecureTransport<br/>DNS check + IP pinning + caps]
    S -.-> U[(Upstream API)]
    E --> A
```

\* MCP adapter planned. The design is **lightweight hexagonal**: the core depends only on
ports it defines, adapters plug in from outside, and a CI test fails if the core imports
an HTTP client or AI framework. Rationale and rejected alternatives:
[docs/adr/0001-architecture.md](docs/adr/0001-architecture.md) ·
[docs/architecture.md](docs/architecture.md).

## Benchmarks

Measured locally with [`benchmarks/run.py`](benchmarks/run.py) (Apple M4 Pro, CPython
3.13.15, tiktoken 0.14.0 `o200k_base` for token counts, 2026-11-10). Fixtures are
**synthetic** data shaped like real APIs. No model was called. Full method and caveats:
[docs/benchmarks.md](docs/benchmarks.md).

| Case | Raw tokens | Shaped tokens | Items | Required fields kept |
|---|---:|---:|---:|:---:|
| GitHub-shaped issue list (30 items) | 25,936 | 2,717 (−90%) | 30/30 | yes |
| same, 1,500-token budget | 25,936 | 894 (−97%) | 10/30 + cursor | yes |
| Persian legal search (20 rulings) | 23,587 | 4,910 (−79%) | 20/20 | yes |

Tool definitions for 50 registered operations: `direct` 4,252 tokens, compact
`grouped` 2,782 tokens. One generic `http_request` tool is only 67 tokens, but it gives
the model unrestricted reach. Median added latency against a local HTTP server: **0.86 ms**
per call (1.90 ms vs 1.03 ms raw httpx), including validation, DNS check and shaping.

Fewer tokens can mean less evidence. Shaping removes fields by design, and every
benchmark row reports whether the required fields survived.

## Development

```bash
git clone https://github.com/SaeedNoshadi89/toolbound && cd toolbound
uv sync                       # creates .venv with dev tools
uv run pytest                 # unit, security regression, property-based and example tests
uv run ruff check . && uv run ruff format --check .
uv run mypy                   # strict
TOOLBOUND_NETWORK_TESTS=1 uv run pytest   # also hits api.github.com / open-meteo
uv run --with tiktoken python benchmarks/run.py
```

CI ([.github/workflows/ci.yml](.github/workflows/ci.yml)) runs lint, strict typing, tests on
Python 3.11–3.15 (Linux, macOS, Windows), a wheel build with a clean-install smoke test,
and the offline examples. Contributions are welcome: see
[CONTRIBUTING.md](CONTRIBUTING.md). Please report security issues privately via
[SECURITY.md](SECURITY.md).

More docs: [API reference](docs/api.md) · [FAQ & troubleshooting](docs/faq.md) ·
[Release process](docs/releasing.md) · [Changelog](CHANGELOG.md).

## Roadmap and versioning

| Version | Planned |
|---|---|
| **0.1** (this) | core pipeline, contracts (YAML/JSON + Python), secure transport, output shaping, approvals, Anthropic/OpenAI adapters, docs, benchmarks |
| 0.2 | MCP server adapter (stdio + streamable HTTP, deployable as an isolated gateway), `discovery` exposure for large catalogs, OpenTelemetry extra, Redis `StateStore` |
| 0.3 | OpenAPI → reviewed draft contracts (`toolbound import-openapi`), LangGraph/LangChain adapter |
| later | OAuth helpers, multipart uploads, TypeScript runtime for the same contract format |

Toolbound follows [Semantic Versioning](https://semver.org/). Before 1.0, minor releases
may contain breaking changes, always listed in the [changelog](CHANGELOG.md). The contract
file format is versioned separately (`version: 1`) and will keep loading in later releases
or come with a migration tool.

## License

[Apache-2.0](LICENSE). Chosen because it is permissive like MIT and adds an explicit patent
grant, which matters for companies adopting a security-sensitive dependency. This is not
legal advice.
