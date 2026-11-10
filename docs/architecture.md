# Architecture

The decision record with alternatives is [ADR 0001](adr/0001-architecture.md). This page
explains how the code is organized and why.

## Layers

```text
src/toolbound/
  core/            the hexagon: no HTTP client, no AI framework, no YAML imports
    contracts.py   Service, Operation, PythonTool, Output, Field, policies, bindings
    schema.py      input schema normalization + validation (structural only)
    network.py     URL construction, URL policy, IP policy (pure, no I/O)
    paths.py       the safe path language
    shaping.py     output pipeline: project, redact, limit, budget
    budget.py      ByteEstimator, canonical JSON
    approval.py    PendingApproval, grants bound to the exact call
    signing.py     HMAC tokens (cursors, grants)
    ratelimit.py   per-process sliding windows
    pyschema.py    JSON Schema from Python type hints
    exposure.py    ToolDefinition, grouped strategy
    gateway.py     the pipeline that ties everything together
    ports.py       Transport, CredentialProvider, Authorizer, Approver, TokenEstimator,
                   Observer, StateStore
    credentials.py / state.py / observe.py / result.py / context.py / errors.py
  transport/       outbound adapters: SecureTransport (httpx), MockTransport
  adapters/        inbound adapters: anthropic.py, openai.py (no provider SDK imports)
  loaders/         YAML/JSON contract files + published meta-schema
  estimators.py    optional tiktoken estimator
  sync.py          blocking wrapper
  cli.py           validate / preview contracts
```

**Dependency rule:** `core` imports only the standard library, `jsonschema`, and other
`core` modules. Two lazy, function-level imports wire defaults (`SecureTransport` when no
transport is given, and the loader for `Gateway.load`). `tests/test_architecture.py`
enforces this, and also imports the core with `httpx` blocked.

## Why "lightweight" hexagonal

The useful part of ports-and-adapters here is that **security logic lives in one place**
and every integration (Anthropic, OpenAI, MCP, tests) gets it unchanged. Outside
dependencies are swappable without touching that logic. We stop there:

- no separate domain / application / infrastructure packages: the core is one cohesive
  package of small modules;
- no dependency-injection container: the `Gateway` constructor *is* the composition root;
- ports exist only where a second implementation is real (tests, multi-worker state,
  per-user credentials, other tokenizers, other transports).

## The request path

```mermaid
sequenceDiagram
    participant Model
    participant Adapter
    participant Gateway
    participant Policy as Your authorize()
    participant Human as Your approval UI
    participant Transport as SecureTransport
    participant API as Upstream API

    Model->>Adapter: tool_use(name, arguments)
    Adapter->>Gateway: call(name, args, ctx, call_id)
    Gateway->>Gateway: visible? validate (closed schema), bind ctx values
    Gateway->>Policy: AuthorizationRequest(ctx, tool, args, bound)
    Policy-->>Gateway: allow / deny(reason)
    alt destructive and no grant
        Gateway-->>Adapter: approval_required (+ PendingApproval for host)
        Adapter-->>Human: summary
        Human-->>Gateway: resume(pending, approved_by)
    end
    Gateway->>Gateway: claim call_id, build URL, URL policy
    Gateway->>Transport: HttpRequest
    Transport->>Transport: resolve DNS, check every IP, pin
    Transport->>API: HTTPS (SNI = host name)
    API-->>Transport: response (size-capped, deadline)
    Transport-->>Gateway: HttpResponse
    Gateway->>Gateway: redirects (re-check), decode, shape, redact, budget
    Gateway-->>Adapter: ToolResult
    Adapter-->>Model: to_json(): data + meta, or safe error
```

## Design notes

- **One pipeline.** `PythonTool` and `Operation` differ only in the execute step. That
  is what guarantees custom tools get the same authorization, approval and budgets.
- **Errors are values.** `Gateway.call` returns failures as `ToolResult(ok=False)` with a
  stable `ErrorCode`, because an agent loop must hand *something* back to the model.
  Configuration mistakes raise at registration, so they surface at startup.
- **Deterministic output.** Parameters are emitted in schema order, JSON is serialized
  compactly, and budget trimming has a fixed order. The same input always gives the same
  bytes, which helps tests, caching and prompt-cache stability.
- **Redirects in the core, IP checks in the transport.** Redirect handling needs policy
  (allowlists, credential stripping), so it is core logic. Only the transport knows the
  address it actually connects to, so IP checks live there, using the core's pure
  `check_ip`.
- **Signed state instead of server state.** Cursors and grants are self-contained HMAC
  tokens, so the gateway needs no session storage. Only single-use enforcement needs the
  `StateStore`.
