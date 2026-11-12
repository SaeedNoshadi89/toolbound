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
| `tool(fn=None, /, *, effect, name, description, input, output, bind, required_scopes, tags, group, requires_approval, timeout)` | decorator registering a Python function; `effect` is **required** |
| `load(path) -> Gateway` | load YAML/JSON contracts from a file or directory |
| `definitions(ctx, *, tags=None, names=None, strategy="direct") -> list[ToolDefinition]` | model-visible tools for this context; `strategy="grouped"` merges tools sharing a `group` |
| `await call(name, arguments, *, ctx, call_id=None, approval=None, approval_ttl=None) -> ToolResult` | execute one tool call; never raises for expected failures. `approval_ttl` sets the lifetime of an approval request this call creates (overrides the tool's and the gateway's; 0 < ttl ≤ 7 days, else `ValueError`) |
| `pending_approval(token) -> PendingApproval` | verify an approval-request token (from storage, a browser, a workflow) and rebuild its display data; raises `ApprovalInvalid` |
| `grant(request, *, approved_by) -> str` | issue a single-use grant for a gateway-issued request (`PendingApproval` or its `token`); only the token is trusted; raises `ApprovalInvalid` |
| `await resume(request, *, ctx, approved_by, call_id=None, bound="live") -> ToolResult` | grant + execute under the live `ctx` (actor and tenant must match; scopes, `authorize` and visibility are checked again); returns `approval_invalid` instead of raising. `bound="live"`: bound values are resolved from `ctx` and must equal the sealed ones; a difference names them in `error.details["changed_bound"]` (names only). `bound="sealed"`: values bound from `attributes.<key>` come from the request token, so a value prepared for that one request (an operation id, the version the human saw) need not be kept by the host; actor, tenant, constants and callables stay live |
| `await deny(request) -> PendingApproval` | record a human's refusal; the request can never be granted afterwards |
| `tool_names`, `get_tool(name)` | introspection |
| `await aclose()` / `async with Gateway(...)` | close the transport if the gateway created it, and the private thread pool for sync Python tools |

`call()` raises only `TypeError` (if `ctx` is not an `ExecutionContext`) and
`asyncio.CancelledError` (cancellation propagates). A gateway may be shared by several
event loops and threads (for example FastAPI test clients, or `SyncGateway` in worker
threads): transport clients and concurrency limits are kept per event loop, and the
in-memory state is thread-safe. For blocking code, use `toolbound.sync.SyncGateway(gateway)`,
which provides `.call()`, `.resume()`, `.deny()` and `.close()`.

Without `secret=`, the gateway uses a random per-process key and emits a
`ToolboundWarning` the first time it issues a cursor or approval request.

Policy helpers: `allow_all`, `deny_all`, `Decision.allow()`, `Decision.deny(reason)`.

## Context

`ExecutionContext(actor, tenant=None, scopes=frozenset(), attributes={}, request_id=auto, principal=None)`.
It is immutable. Build it in trusted code after authentication. Its `repr` hides attribute
values. `principal` is any object for your own trusted code, typically the signed-in user:
Python tools (with a `ctx` parameter) and `authorize` read it as `ctx.principal`. It is
never bound, sealed into approvals or cursors, digested, logged or shown to the model, and
it does not take part in equality.

## Contracts

| Type | Notes |
|---|---|
| `Service(name, base_url, auth, headers, network, limits, retry)` | see [contracts.md](contracts.md#service) |
| `Operation(name, description, service, method, path, effect, input, bind, required_scopes, tags, group, requires_approval, rate_limit, query, body, body_format, headers, idempotency_header, pagination, output)` | REST tool. `effect` defaults from the method: GET/HEAD/OPTIONS → read, POST/PUT/PATCH → write, DELETE → destructive (and cannot be `read`) |
| `PythonTool(name, description, handler, effect, timeout, input, bind, ...)` | trusted Python tool; `effect` is **required**. A handler refuses a call with `raise ToolRefusal(reason, message, details=...)` |
| `approval_ttl` (on both) | lifetime in seconds of the approval requests the tool creates; `None` uses the gateway's |
| `Output(...)`, `Field(...)`, `Pagination(...)` | see [output.md](output.md) |
| `NetworkPolicy`, `Limits(timeout, connect_timeout, total_timeout, max_request_bytes, max_response_bytes, max_concurrency)`, `RetryPolicy`, `RateLimit` | policies; `total_timeout` (default 60 s) bounds a whole call including retries |
| `NoAuth`, `BearerAuth`, `ApiKeyAuth`, `BasicAuth` | auth by credential name |
| `Effect.READ / WRITE / DESTRUCTIVE` | string enum |
| `from_ctx(path)`, `FromContext`, `Const` | bindings (`"ctx.actor"` strings also work) |

## Results

`ToolResult(ok, tool, data, meta, error, approval, http_status, duration_ms, call_id)`

- `to_model() -> dict` / `to_json() -> str`: the only things to send to a model
- `meta: ResultMeta(truncated, omitted, redacted, warnings, next_cursor, items_returned, items_total, estimated_tokens, source)`
- `error: ToolError(code, message, retryable, details, retry_after)`
- `approval: PendingApproval(id, tool, effect, actor, tenant, arguments, bound, summary, digest, expires_at, token, target, summary_truncated, call_id)`. Show `target`, `arguments` and `bound` (or `summary`) to a human; persist or send `token` (encrypted and authenticated); `to_dict()` is JSON-safe. `call_id` is the id of the call that requested it: the approved action runs at most once per call id, even when the same call was sealed more than once, and hosts can use it to show one card per model tool call

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
| `timeout` | a read exceeded its deadline | yes |
| `upstream_unavailable` | DNS/connection/TLS failure (for writes: only when nothing was sent) | yes |
| `upstream_error` | upstream returned an error status (5xx retryable for reads only), or an unexpected redirect | depends |
| `upstream_schema_mismatch` | malformed JSON, schema mismatch, or missing required field (strict) | no |
| `unsupported_content_type` | non-JSON (and not `accept_text`) | no |
| `response_too_large` | body exceeded `max_response_bytes` | no |
| `result_too_large` | cannot fit the token budget (reject mode, required fields too big, or far too large to trim) | no |
| `refused` | a Python tool refused the call for a business reason (`raise ToolRefusal(...)`); `reason` and the tool's details are added to the error. For a write, nothing was applied and its approval is used up | no |
| `outcome_unknown` | a write may or may not have been applied (timeout or lost connection after sending, or a Python write tool timed out). Check state before calling again | no |
| `internal_error` | bug, missing credential, non-JSON handler result, replay store unavailable or full (call not executed). Details are logged, not shown | no |

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


class StateStore:  # replay protection; shared, durable store for >1 worker
    async def claim(self, key: str, ttl_seconds: float) -> bool: ...

    # True if newly claimed, False if already claimed and unexpired.
    # Raising makes the call fail closed. Never evict unexpired keys.
```

`authorize` and `approver` are plain callables (sync or async). A custom `Transport` must
enforce IP policy with `toolbound.core.network.check_ip` on the address it connects to and
cap the decompressed body. See [security.md](security.md#what-toolbound-cannot-guarantee-residual-risk).

Implementations shipped: `SecureTransport` (httpx; `resolver=` injectable),
`MockTransport` + `MockResponse` (tests), `EnvCredentials`, `StaticCredentials`,
`ByteEstimator`, `toolbound.estimators.TiktokenEstimator`, `LoggingObserver`,
`MemoryStateStore(max_entries=200_000, max_per_partition=10_000)` (thread-safe; partitioned per actor+tenant; raises `StateStoreError` instead of evicting live keys).

Exceptions and warnings: `ToolboundError` (base), `ConfigurationError`, `ApprovalInvalid`,
`StateStoreError`, `ToolboundWarning` (risky configuration; make it an error in CI with
`-W error::toolbound.ToolboundWarning`).

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
