# Public API reference

Everything listed here is importable from `toolbound` unless another module is named.
Anything not listed is internal and may change without notice.

## Gateway

```python
Gateway(
    *,
    authorize,                    # required: (AuthorizationRequest) -> bool | Decision (sync/async)
    credentials=None,             # CredentialProvider
    approver=None,                # (PendingApproval) -> bool (sync/async); inline approval
    transport=None,               # Transport; default SecureTransport (created lazily)
    estimator=None,               # TokenEstimator; default ByteEstimator()
    observer=None,                # Observer; default no-op
    state=None,                   # StateStore; default MemoryStateStore()
    secret=None,                  # bytes|str >= 32 bytes; signs cursors and approvals
    visibility=None,              # (ctx, tool) -> bool; hidden == unknown
    transforms=None,              # {"name": callable} for declarative shapes
    approval_ttl=600, cursor_ttl=3600, call_id_ttl=86400,
    max_argument_bytes=65536,
)
```

| Method | Purpose |
|---|---|
| `register(*tools) -> Gateway` | add `Operation`s / `PythonTool`s; raises `ConfigurationError` on invalid contracts |
| `tool(fn=None, /, *, name, description, input, effect, output, bind, required_scopes, tags, group, requires_approval, timeout)` | decorator registering a Python function |
| `load(path) -> Gateway` | load YAML/JSON contracts from a file or directory |
| `definitions(ctx, *, tags=None, names=None, strategy="direct") -> list[ToolDefinition]` | model-visible tools for this context; `strategy="grouped"` merges tools sharing a `group` |
| `await call(name, arguments, *, ctx, call_id=None, approval=None) -> ToolResult` | execute one tool call; never raises for expected failures |
| `grant(pending, *, approved_by) -> str` | issue a single-use approval token (host code only) |
| `await resume(pending, *, ctx, approved_by, call_id=None) -> ToolResult` | grant + execute |
| `tool_names`, `get_tool(name)` | introspection |
| `await aclose()` / `async with Gateway(...)` | close the transport if the gateway created it |

`call()` raises only `TypeError` (if `ctx` is not an `ExecutionContext`) and
`asyncio.CancelledError` (cancellation propagates). One gateway should be used from one
event loop. For blocking code, use `toolbound.sync.SyncGateway(gateway)`, which provides
`.call()`, `.resume()` and `.close()`.

Policy helpers: `allow_all`, `deny_all`, `Decision.allow()`, `Decision.deny(reason)`.

## Context

`ExecutionContext(actor, tenant=None, scopes=frozenset(), attributes={}, request_id=auto)`.
It is immutable. Build it in trusted code after authentication. Its `repr` hides attribute
values.

## Contracts

| Type | Notes |
|---|---|
| `Service(name, base_url, auth, headers, network, limits, retry)` | see [contracts.md](contracts.md#service) |
| `Operation(name, description, service, method, path, effect, input, bind, required_scopes, tags, group, requires_approval, rate_limit, query, body, body_format, headers, idempotency_header, pagination, output)` | REST tool |
| `PythonTool(name, description, handler, timeout, input, effect, bind, ...)` | trusted Python tool |
| `Output(...)`, `Field(...)`, `Pagination(...)` | see [output.md](output.md) |
| `NetworkPolicy`, `Limits`, `RetryPolicy`, `RateLimit` | policies |
| `NoAuth`, `BearerAuth`, `ApiKeyAuth`, `BasicAuth` | auth by credential name |
| `Effect.READ / WRITE / DESTRUCTIVE` | string enum |
| `from_ctx(path)`, `FromContext`, `Const` | bindings (`"ctx.actor"` strings also work) |

## Results

`ToolResult(ok, tool, data, meta, error, approval, http_status, duration_ms, call_id)`

- `to_model() -> dict` / `to_json() -> str`: the only things to send to a model
- `meta: ResultMeta(truncated, omitted, redacted, warnings, next_cursor, items_returned, items_total, estimated_tokens, source)`
- `error: ToolError(code, message, retryable, details, retry_after)`
- `approval: PendingApproval(id, tool, effect, actor, tenant, arguments, bound, summary, digest, expires_at)`; show `summary` to a human

### Error codes

| Code | Meaning | Retryable |
|---|---|:---:|
| `unknown_tool` | not registered **or not visible** to this context | no |
| `invalid_arguments` | schema validation failed, unknown argument, bad path value, oversized | no |
| `invalid_cursor` | forged, expired or foreign cursor | no |
| `forbidden` | missing scope, `authorize()` denied, missing context value | no |
| `approval_required` | needs a human. `result.approval` holds the request; nothing was executed | no |
| `approval_denied` | the inline approver said no | no |
| `approval_invalid` | grant forged, expired, reused, or for a different call | no |
| `duplicate_call` | a write/destructive call id was already executed | no |
| `rate_limited` | local rate limit or upstream 429 (see `retry_after_seconds`) | yes |
| `network_blocked` | URL or IP policy violation | no |
| `timeout` | upstream or Python tool exceeded its deadline | yes |
| `upstream_unavailable` | DNS/connection/TLS failure | yes |
| `upstream_error` | upstream returned an error status (5xx retryable), or an unexpected redirect | depends |
| `upstream_schema_mismatch` | malformed JSON, schema mismatch, or missing required field (strict) | no |
| `unsupported_content_type` | non-JSON (and not `accept_text`) | no |
| `response_too_large` | body exceeded `max_response_bytes` | no |
| `result_too_large` | cannot fit the token budget (reject mode, or required fields too big) | no |
| `internal_error` | bug, missing credential, non-JSON handler result. Details are logged, not shown | no |

## Ports (extension points)

All are `typing.Protocol`s, so no subclassing is needed.

```python
class Transport:  # outbound HTTP; must NOT follow redirects
    async def send(self, request: HttpRequest) -> HttpResponse: ...
    async def aclose(self) -> None: ...


class CredentialProvider:
    def get(self, name: str, ctx: ExecutionContext) -> str | None | Awaitable[str | None]: ...


class TokenEstimator:
    def count(self, text: str) -> int: ...


class Observer:  # events carry no payloads
    def on_event(self, event: Event) -> None: ...


class StateStore:  # replay protection; shared store for >1 worker
    async def claim(self, key: str, ttl_seconds: float) -> bool: ...
```

`authorize` and `approver` are plain callables (sync or async). A custom `Transport` must
enforce IP policy with `toolbound.core.network.check_ip` on the address it connects to and
cap the decompressed body. See [security.md](security.md#what-toolbound-cannot-guarantee-residual-risk).

Implementations shipped: `SecureTransport` (httpx; `resolver=` injectable),
`MockTransport` + `MockResponse` (tests), `EnvCredentials`, `StaticCredentials`,
`ByteEstimator`, `toolbound.estimators.TiktokenEstimator`, `LoggingObserver`,
`MemoryStateStore`.

## Adapters

`toolbound.adapters.anthropic`: `tools(gateway, ctx, *, tags, names, strategy)`,
`tool_calls(message)`, and `await run_tool_calls(gateway, message, ctx, *, parallel=False)`,
which returns a batch with `.message` (one user message with all `tool_result` blocks),
`.blocks`, `.results` and `.pending_approvals`.

`toolbound.adapters.openai`: `tools(gateway, ctx, *, api="chat"|"responses", ...)`,
`tool_calls(obj)`, and `await run_tool_calls(gateway, obj, ctx)`, which returns `.blocks`:
`role="tool"` messages (Chat Completions) or `function_call_output` items (Responses).

## Loaders and CLI

`toolbound.loaders.load_contracts(path)`, `load_contract_file(path)`,
`parse_contract(document)`, `CONTRACT_SCHEMA`.

```text
toolbound validate PATH
toolbound tools PATH [--format neutral|anthropic|openai] [--strategy direct|grouped] [--scope S]...
toolbound schema
```
