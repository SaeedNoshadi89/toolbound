# ADR 0001: Contract-first engine with a Python core and thin adapters

- **Status:** accepted (2026-11-10)
- **Deciders:** project maintainers
- **Supersedes:** none

## Context

AI agents need to act through REST APIs. The two common approaches both fail:

1. A generic "call any URL" tool gives the model the ability to choose hosts, headers
   and credentials. It is the textbook setup for SSRF, data exfiltration and
   confused-deputy bugs, and it floods the context with raw responses.
2. Hand-writing a tool per endpoint is slow and inconsistent: every tool reimplements
   validation, auth, error handling and output trimming, each slightly differently.

We want developers in unrelated domains to define approved operations once and get
safe, token-efficient tools, without adopting a particular agent framework or provider.

## Decision

1. **The contract is the product.** A versioned, language-neutral contract (YAML/JSON,
   validated by a published meta-schema, with an equivalent typed Python API) describes
   one approved operation: input schema, trusted bindings, network policy, effect, limits
   and output shape.
2. **A Python engine executes contracts** through one pipeline for REST operations and
   trusted Python tools: validate → bind → scopes → `authorize()` → rate limit →
   approval → replay check → execute → shape → envelope.
3. **Narrow, generated tools.** Each contract becomes one model-visible tool with a closed
   schema. A compact `grouped` strategy merges related tools for larger catalogs. The
   execution engine is universal internally, but there is no unconstrained `execute_any_url`.
4. **Lightweight hexagonal architecture.** The core depends only on ports it defines
   (`Transport`, `CredentialProvider`, `Authorizer`, `Approver`, `TokenEstimator`,
   `Observer`, `StateStore`). Outbound adapters (httpx transport) and inbound adapters
   (Anthropic, OpenAI; MCP later) live outside. A CI test forbids HTTP-client or framework
   imports in the core. We do not add domain/application/infrastructure layers, DI
   containers or repositories: there is no database, and one implementation per port
   is common.
5. **Authorization belongs to the application.** The gateway refuses to start without an
   `authorize=` hook. It never decides business permissions itself.
6. **Security is enforced in code, never in prompts.** Model output is untrusted. Approval
   grants are HMAC-signed and approval requests and cursors are encrypted (AES-GCM, since
   0.2); all are bound to actor, tenant, tool and arguments. Grants and approval
   requests travel through host code only; cursors pass through the model but cannot be
   read or altered.

## Options considered

| Option | Why not (as the primary product) |
|---|---|
| **MCP server first** | Great reach for no-code clients, but weak for embedded apps (per-request trusted context, tests, tracing). MCP's auth story is still evolving, and the core logic would be tied to one protocol. → planned as an **adapter** (v0.2). |
| **Separate gateway service** | Strongest isolation (credentials outside the agent process), but every adopter pays to operate it. → the MCP-over-HTTP adapter will provide the same isolation without a separate product. |
| **Generate tools from OpenAPI** | Specs are untrusted, often inaccurate, and far too broad; auto-activation creates hundreds of tools. → planned as an importer that writes **draft** contracts (`status: draft` is refused at load time until reviewed). |
| **Code-only registration** | Excellent DX for Python, but not reviewable by non-Python teams and not portable to other runtimes. → kept as an equal authoring path. |
| **YAML-only configuration** | Portable and reviewable, but awkward for custom transforms and Python tools. → kept as an equal authoring path. |
| **Full hexagonal / clean architecture** | More layers than value for a library of this size. Contributors pay the cost and users see no benefit. |
| **JMESPath/JSONata for projection** | Powerful but larger and harder to audit. The output language must never evaluate code. → a tiny path language, plus trusted Python transforms for anything complex. |
| **Pydantic as the schema engine** | Common, but JSON Schema is what every LLM tool API consumes, and Pydantic v1/v2 conflicts hurt adoption. → `jsonschema` for validation; type-hint inference for Python tools. |

## Consequences

- Developers get one security model for every tool, REST or Python.
- Narrow tools cost more definition tokens than a single generic tool (measured in
  `docs/benchmarks.md`). This is the price of least privilege, partly offset by
  `grouped` exposure and per-user filtering.
- In-process execution means credentials live in the agent's process. Teams needing
  stronger isolation should wait for, or contribute, the MCP-over-HTTP gateway mode.
- Replay protection is per-process by default. Multi-worker deployments must plug in a
  shared `StateStore`.
- A TypeScript runtime can implement the same contract format later without
  breaking users' contracts.

## Follow-ups

- ADR 0002 (planned): MCP adapter design and the remote gateway trust model.
- ADR 0003 (planned): OpenAPI import and the review workflow.
