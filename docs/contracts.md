# Contract reference

A contract describes one **service** (trusted base URL, credentials, policies) and the
**operations** the model may call on it. You can write contracts in YAML/JSON or in Python.
Both produce the same objects and go through the same validation.

- Print the file format's JSON Schema: `toolbound schema`
- Validate files: `toolbound validate contracts/`
- Preview what the model will see: `toolbound tools contracts/ --format anthropic`

## File layout (format version 1)

```yaml
version: 1                 # required; the contract format version
status: active             # optional; "draft" files are refused until reviewed
service: { ... }           # exactly one service per file
operations: [ ... ]        # one or more operations on that service
```

`Gateway.load(path)` accepts a file or a directory (all `*.yaml`, `*.yml`, `*.json`,
sorted by name). YAML needs `pip install 'toolbound[yaml]'`.

## Service

| YAML key | Python | Default | Meaning |
|---|---|---|---|
| `name` | `Service(name=)` | required | identifier, `[A-Za-z][A-Za-z0-9_-]{0,63}` |
| `base_url` | `base_url=` | required | `https://host[:port][/prefix]`; no userinfo, query or fragment. `http://` needs `network.allow_http` |
| `auth` | `auth=` | none | see [Auth](#auth) |
| `headers` | `headers=` | `{}` | static trusted headers (e.g. `Accept`). `Authorization`, `Cookie`, `Host`, hop-by-hop and proxy headers are refused |
| `network` | `NetworkPolicy(...)` | see below | where requests may go |
| `limits` | `Limits(...)` | see below | sizes and timeouts |
| `retry` | `RetryPolicy(...)` | see below | bounded retries |

### Auth

| YAML | Python | Sends |
|---|---|---|
| `{type: none}` | `NoAuth()` | nothing |
| `{type: bearer, credential: NAME}` | `BearerAuth("NAME")` | `Authorization: Bearer <value>` |
| `{type: api_key, credential: NAME, header: X-API-Key}` | `ApiKeyAuth("NAME", header="X-API-Key")` | header |
| `{type: api_key, credential: NAME, query: api_key}` | `ApiKeyAuth("NAME", header=None, query="api_key")` | query parameter (avoid if you can: query strings end up in logs) |
| `{type: basic, credential: NAME}` | `BasicAuth("NAME")` | `Authorization: Basic …`; the value must be `user:password` |

`credential` is a **name**. Values come from the `credentials=` provider passed to the
`Gateway`, such as `EnvCredentials`, `StaticCredentials`, or your own object with
`get(name, ctx) -> str | None` (sync or async). Because `ctx` is passed, per-user OAuth
tokens are easy.

### `network`

| Key | Default | Meaning |
|---|---|---|
| `allow_hosts` | `[host of base_url]` | exact host names, or `*.example.com` for subdomains |
| `allow_ports` | `[443]` (`[443, 80]` with `allow_http`) | allowed ports |
| `allow_http` | `false` | permit plain HTTP |
| `allow_networks` | `[]` | CIDRs trusted even though non-public (internal services). Keep narrow |
| `follow_redirects` | `false` | follow 3xx; every hop is re-checked, and credentials are dropped across origins |
| `max_redirects` | `3` | hop limit |

### `limits` and `retry`

| Key | Default | Meaning |
|---|---|---|
| `limits.timeout` | `15` s | total deadline per attempt (connect + send + full body) |
| `limits.connect_timeout` | `5` s | TCP/TLS connect |
| `limits.max_request_bytes` | `262144` | serialized body limit |
| `limits.max_response_bytes` | `5242880` | **decompressed** body limit |
| `limits.max_concurrency` | `8` | concurrent requests to this service per gateway |
| `retry.max_attempts` | `3` | only for GET/HEAD/OPTIONS, or operations with `idempotency_header` |
| `retry.backoff_base` / `backoff_max` | `0.25` / `4` s | exponential backoff with full jitter |
| `retry.retry_statuses` | `[429, 502, 503, 504]` | plus connection errors and timeouts |
| `retry.max_retry_after` | `30` s | a longer `Retry-After` returns `rate_limited` with `retry_after_seconds` instead of waiting |

## Operation

| YAML key | Python (`Operation(...)`) | Default | Meaning |
|---|---|---|---|
| `name` | `name=` | required | tool name the model sees |
| `description` | `description=` | required | ≤ 1024 chars; write it for the model: what it does and when to use it |
| `method` | `method=` | `GET` | GET, HEAD, POST, PUT, PATCH, DELETE, OPTIONS |
| `path` | `path=` | required | template like `/repos/{owner}/{repo}/issues/{number}`; no `..`, query or fragment |
| `effect` | `effect=` | from the method | `read`, `write` or `destructive`; drives approval, replay protection, retries and the cursor argument. Default: GET/HEAD/OPTIONS → `read`, POST/PUT/PATCH → `write`, DELETE → `destructive`. A read-only POST (search) must say `effect: read`; a DELETE can never be `read`. Python tools must always declare it |
| `input` | `input=` | `{}` | JSON Schema; see [Input](#input) |
| `bind` | `bind=` | `{}` | trusted values; see [Bindings](#bindings) |
| `required_scopes` | `required_scopes=` | `[]` | the context must have all of them, otherwise the tool is invisible |
| `tags` | `tags=` | `[]` | filter with `gateway.definitions(ctx, tags={...})` |
| `group` | `group=` | none | used by the `grouped` exposure strategy |
| `requires_approval` | `requires_approval=` | `true` for destructive, else `false` | override approval |
| `rate_limit` | `RateLimit(calls, per_seconds, scope)` | none | `scope`: `actor` (default), `tenant` or `global`; per process |
| `query` / `body` | `query=` / `body=` | automatic | explicit placement of argument names |
| `body_format` | `body_format=` | `json` | `json` or `form` |
| `headers` | `headers=` | `{}` | static headers for this operation |
| `idempotency_header` | `idempotency_header=` | none | e.g. `Idempotency-Key`; also enables safe retries |
| `pagination` | `Pagination(...)` | none | see [output.md](output.md#pagination) |
| `output` | `Output(...)` | defaults | see [output.md](output.md) |

### Input

Input is JSON Schema draft 2020-12. Two forms are accepted:

```yaml
# shorthand: a mapping of properties; every property without "default" is required
input:
  query: {type: string, minLength: 2, maxLength: 80}
  limit: {type: integer, minimum: 1, maximum: 50, default: 10}

# full schema
input:
  type: object
  required: [filter]
  properties:
    filter:
      type: object
      properties:
        status: {enum: [open, closed]}
        created_after: {type: string, format: date}
```

Rules enforced at registration:

- the top level must be `type: object`, and `additionalProperties` is forced to `false`
  (an explicit `true` is an error). Nested objects with `properties` also default to
  `additionalProperties: false`;
- only local `$ref` (`#/...`); no `$id`; maximum depth 16; maximum 64 KB;
- `fields` and `cursor` are reserved names (Toolbound adds them when enabled);
- every `{placeholder}` in `path` must be a **required** input or a binding;
- bound names must not appear in `input`.

At call time, arguments are validated, top-level defaults are applied, and serialized
arguments larger than `Gateway(max_argument_bytes=65536)` are rejected. Error messages
name the failing location and list the allowed arguments.

**Placement.** Path placeholders are filled from arguments and bindings, then strictly
encoded. Remaining values go to the query string for GET/HEAD/DELETE/OPTIONS and into the
body for POST/PUT/PATCH, unless `query`/`body` say otherwise. Parameters are emitted in
schema order, so URLs are deterministic.

### Bindings

```yaml
bind:
  tenant_id: ctx.tenant            # ExecutionContext.tenant (fails closed if missing)
  user_id: ctx.actor               # ExecutionContext.actor
  owner: ctx.attributes.repo_owner # ExecutionContext.attributes["repo_owner"]
  api_version: {const: "2024-01-01"}
```

In Python you can also bind a callable: `bind={"region": lambda ctx: lookup_region(ctx.tenant)}`.
Bound values are visible to your `authorize()` hook as `request.bound`, are part of the
approval digest, and are never shown to the model.

## Python tools

```python
@gateway.tool(
    bind={"tenant": "ctx.tenant"},
    effect="read",
    output=Output(shape={...}, max_tokens=500),
    required_scopes=("orders:read",),
    timeout=10,
)
def search_orders(
    tenant: str,
    status: Literal["paid", "refunded"] | None = None,
    limit: Annotated[int, "Max results", {"maximum": 100}] = 20,
) -> list[dict]:
    """Search orders of the current account."""  # first paragraph = description
```

- The schema is inferred from type hints (`str`, `int`, `float`, `bool`, `list[T]`,
  `set[T]`, `dict`, `Literal`, `Enum`, `Optional`/unions, and
  `Annotated[T, "description", {extra JSON Schema}]`), or given explicitly with `input=`.
- A parameter named `ctx` receives the `ExecutionContext`.
- Async handlers run on the event loop; sync handlers run in a worker thread.
- Return JSON-serializable data. Raise `ToolFailure(ErrorCode.X, "safe message")` to send
  a specific error; any other exception becomes a generic `internal_error`.
- **Handlers are trusted code and are not sandboxed.** A timeout stops waiting but cannot
  kill a running thread.

## Lifecycle and draft review

1. Generate or write the contract with `status: draft`.
2. Review it like code: hosts, bindings, effects, shapes, scopes.
3. Change it to `status: active` (or remove the line) and commit.

Changing an operation's method, path, base URL, effect, input schema, bindings or scopes
changes its **fingerprint**, which invalidates outstanding approval grants and cursors for
that tool.
