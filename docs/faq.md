# FAQ and troubleshooting

## Concepts

**Why not give the agent one `http_request` tool? It's simpler and smaller.**
It is smaller to *define* (see [benchmarks](benchmarks.md)), but the model then chooses
hosts, paths, headers and payloads, so every safety property depends on the model behaving.
It also returns raw bodies, which usually cost far more tokens than the definitions you
saved. Toolbound's tools are narrow so that policy is enforced by code.

**Is Toolbound an MCP server?**
Not yet. It is a library, and MCP is planned as an adapter (v0.3). Today you can expose a
gateway over MCP with the [recipe](integrations.md#mcp-recipe-until-the-packaged-server-ships).

**Does schema validation mean the data is correct?**
No. It means the data has the expected *shape*. Toolbound reports provenance
(`meta.source`) and omissions so your app can verify facts. It never claims to.

**Does Toolbound summarize long responses?**
No, by design. It selects, truncates and paginates, and it reports every cut.
Summaries cannot be checked and can silently change meaning.

**Are Python tools sandboxed?**
No. They are trusted code and run with your application's privileges. Toolbound gives
them the same validation, authorization, approval, rate limits, timeouts and output
shaping as REST tools.

**Who decides permissions?**
You do, in `authorize()`. Toolbound guarantees it runs, with trusted context and validated
arguments, before anything executes.

## Troubleshooting

| Symptom | Cause and fix |
|---|---|
| `ConfigurationError: Gateway(authorize=...) is required` | Pass your policy, or `toolbound.allow_all` explicitly for demos. |
| `network_blocked: address 127.0.0.1 is not a public address` | Local or internal service: add `allow_http=True` (if HTTP) and a narrow `allow_networks=("10.1.2.3/32",)`. For `localhost`, include `::1/128` too, because **every** resolved address must pass. |
| `network_blocked: host 'x' is not in the service allowlist` | A redirect or `Link` URL pointed elsewhere. Add the host to `allow_hosts` only if you trust it. |
| `network_blocked: plain HTTP is not allowed` | Set `network.allow_http=True` (internal services only). |
| `upstream redirected (HTTP 302) and redirects are disabled` | Set `network.follow_redirects=True`. Every hop is re-checked. |
| `invalid_arguments: unknown argument(s) ['x']` | The model sent an argument the contract does not declare. This is intended. Improve the description, or add the argument if it is legitimate. |
| `forbidden: the current session lacks context required by this tool` | A binding like `ctx.tenant` or `ctx.attributes.repo` has no value in the `ExecutionContext`. |
| `unknown_tool` for a tool you registered | The context lacks a `required_scopes` entry, or `visibility=` hid it. |
| `unsupported_content_type` | The API returned non-JSON. For text, set `Output(accept_text=True)`. Binary content is not supported. |
| `result_too_large` | The budget cannot fit even the `required` fields, or `overflow="reject"` is set. Raise `max_tokens`, shorten fields, or lower the page size. |
| `upstream_schema_mismatch: required field 'id' missing upstream` | The upstream changed or the path is wrong. Use `schema_mode="warn"` while investigating. |
| `approval_invalid: approval does not match this call` | The arguments, actor, tenant, tool or contract changed after approval, or a different gateway secret was used. Ask again. |
| Cursors/approvals stop working after restart or across workers | Set a persistent `Gateway(secret=...)`, and use a shared `StateStore` for single-use grants. Cursors from 0.1 (`tbc1.`) are not accepted by 0.2. |
| `ConfigurationError: Python tools must declare effect=...` | Since 0.2 Python tools need `effect="read"`, `"write"` or `"destructive"`: Toolbound cannot tell what a function does. |
| `ConfigurationError: a DELETE operation cannot be effect='read'` | Since 0.2 the effect follows the HTTP method. Remove `effect: read`, or use another method if the endpoint really only reads. |
| A POST tool suddenly needs `call_id` deduplication or no longer returns a cursor | Since 0.2 `POST`/`PUT`/`PATCH` default to `write`. For read-only POSTs (search), declare `effect="read"`. |
| `outcome_unknown` | A write may have reached the upstream but no answer came back (timeout, dropped connection). Check the current state before calling again, and prefer `idempotency_header` where the API supports it. |
| `internal_error: replay protection is unavailable` | Your `StateStore` raised, or `MemoryStateStore` is full of unexpired keys. Nothing was executed. Use a shared store (Redis) or raise `max_entries`. |
| `ToolboundWarning: Gateway has no secret=` | Set a persistent 32+ byte `secret=` so cursors and approvals survive restarts and work across workers. |
| `ToolboundWarning: JSON Schema format(s) [...] are not enforced` | jsonschema needs optional packages for some formats. Use `pattern`/`enum`, or install `jsonschema[format]`. |
| `approval_invalid: approval request is invalid, forged or expired` | The token was changed, expired (default 10 minutes), or was issued by a gateway with another secret. |
| Results smaller than the budget suggests | `ByteEstimator` is conservative (it over-counts by about 1.4–1.9× against `o200k`). Use `TiktokenEstimator` or your own. |
| `toolbound validate` says YAML needs PyYAML | `pip install 'toolbound[yaml]'`. |
