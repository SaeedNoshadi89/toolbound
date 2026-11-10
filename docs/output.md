# Output shaping, budgets and pagination

Three different things exist for every REST call:

| | Who sees it | Contents |
|---|---|---|
| **Transport response** | the engine only | status, headers, raw (decompressed, size-capped) body |
| **Normalized result** (`ToolResult`) | your host code | shaped `data`, `meta`, `error`, `approval`, `http_status`, `duration_ms`, `call_id` |
| **Model-visible result** (`ToolResult.to_model()` / `.to_json()`) | the model | `{"ok", "data", "meta"}` or `{"ok": false, "error"}` |

## Pipeline order

```text
decode (JSON; text only with accept_text)
 → select root            Output.root ("$" = whole document)
 → schema check           Output.schema, schema_mode strict|warn
 → skip cursor offset     continuation
 → project (shape)        allowlist, rename, nested shapes, defaults, per-field limits, transforms
 → final transform        Output.transform (trusted Python)
 → redact                 sensitive keys, secret patterns, echoed credentials, your redactors
 → limits                 max_items (every list), max_chars (every string)
 → budget                 max_tokens with overflow truncate|reject
 → envelope               data + meta (truncated, omitted, redacted, warnings, cursor, source)
```

Every step is deterministic: the same input always produces the same output and metadata.

## The path language

| Path | Selects |
|---|---|
| `$` | the whole value |
| `title` | key `title` |
| `user.login` | nested key |
| `labels[].name` | `name` of every element (elements without it are skipped) |
| `items[0].id` | an index |
| `[].id` | `id` of every element of a root array |
| `a[][].x` | nested arrays (structure preserved: `[[1], [2]]`) |

Names may contain letters, digits, `_`, `-`, `@` and `:`. There are no wildcards over keys,
no filters, and no function calls. Paths are parsed at registration and can never execute
code. For anything more complex, write a trusted transform.

## Shapes

```python
shape = {
    "id": "id",  # path string
    "author": "user.login",  # rename + nested
    "labels": Field("labels[].name", max_items=5),  # per-field list limit
    "body": Field("body", max_chars=500),  # per-field string limit
    "state": Field("state", transform="upper", default="unknown"),
    "first_label": Field("labels", transform="first", shape={"name": "name"}),
    "comments": Field("comments", shape={"by": "user.login", "text": Field("body", max_chars=200)}),
}
```

In YAML a field is either a path string or `{from, max_chars, max_items, transform, default, shape}`.

Built-in transforms: `lower`, `upper`, `strip`, `count` (length), `first`, `join`
(`", "`), `bool`, `str`. Register more with `Gateway(transforms={"cents": fn})` and use
them by name, or pass a callable in Python.

Missing source paths are **omitted** (never invented) and reported with reason `missing`,
unless the field has a `default`. A missing **required** field is an
`upstream_schema_mismatch` error in `strict` mode, and a warning in `warn` mode.

`shape=None` passes the selected value through. Limits and redaction still apply, but
prefer explicit shapes: allowlisting is the primary data-minimization control.

### Field selection by the model

`Output(selectable=True)` adds an optional `fields` argument whose items are an **enum of
your shape keys**. The model can narrow the result but cannot name arbitrary paths.
`required` keys are always included.

## Redaction

1. **Keys**, anywhere in the result, matched ignoring case, `-` and `_` (so `accessToken`,
   `ACCESS-TOKEN` and `access_token` are the same key). A shape field whose *source* key is
   sensitive is redacted even when renamed. Defaults: `password`, `passwd`, `secret`,
   `client_secret`, `token`, `access_token`, `refresh_token`, `id_token`, `api_key`,
   `apikey`, `authorization`, `cookie`, `set-cookie`, `private_key`, `session`, `session_id`,
   `x-api-key`, `client_assertion`. Customize with `redact_keys=`.
2. **Secret patterns** in strings (`redact_secrets=True`): PEM private keys, AWS access key
   ids, GitHub/Slack/Stripe tokens, `sk-…` style API keys, Google API keys, JWTs,
   `Bearer …` strings.
3. **Credentials used for this request**, if the upstream echoes them back: raw,
   URL-encoded, JSON-escaped, base64 and Basic-auth forms, in values and in object keys.
   Fragments or other transformations of a secret are not detected.
4. **Your hooks**: `redactors=(fn,)`, where `fn(path, value) -> value` is called for every
   scalar (useful for PII rules).

Every replacement increments `meta.redacted`. Redaction runs **before** truncation, so a
secret can't slip through by being cut in half. Secret patterns run in linear time, and
only over the part of each string that can still be returned (the longest `max_chars`
plus 4 KB), so a hostile response cannot make redaction slow.

## Limits and budgets

- `max_items` (default 50) applies to every list, and `max_chars` (default 4000) to every
  string. Per-field limits override them. These limits apply to `required` fields too:
  a cut is always reported in `meta.omitted`, but "required" protects a field from being
  *dropped*, not from being *shortened*. Raise the field's `max_chars` if it must stay
  whole.
- `max_tokens` (default 2000) is the budget for `data`. The envelope adds a small,
  roughly constant overhead (`meta`, about 30–150 tokens depending on omissions and
  cursors).
- Token counts come from the gateway's `TokenEstimator`. The default `ByteEstimator`
  (`ceil(utf8_bytes / 3)`) is deterministic and conservative: in our
  [measurements](benchmarks.md) it over-counted by 1.36–1.87× compared with the
  `o200k_base` tokenizer. Use `toolbound.estimators.TiktokenEstimator` or your own
  estimator for tighter budgets. Tokenizers differ between model families.

### When the budget is exceeded

`overflow="truncate"` (default):

1. If `data` is a list, keep the **longest prefix of whole items** that fits (binary
   search). Dropped items are reported as `{"path": "$", "reason": "budget", "count": n}`.
2. If it still does not fit, repeatedly halve the largest non-required list or string
   (deterministic order) and record each cut.
3. If it cannot fit without touching `required` fields, fail with `result_too_large`.
   Toolbound never returns a misleading result that silently lacks evidence.

`overflow="reject"`: if anything would need to be removed, fail with `result_too_large`
and a hint to narrow the request. Use it where partial data is dangerous (legal, finance,
medical), together with `required`.

**Truncate or reject?** Truncate when the model can usefully work with a partial view and
fetch more (search results, lists). Reject when a partial answer could be mistaken for a
complete one (a contract's clauses, a ledger, an audit trail).

Strings cut by `max_chars` end with `…` and are reported with reason `max_chars`. Cuts
happen on Unicode code points, so UTF-8 is never broken. Combining marks at the boundary
may be separated.

## Pagination

The model never sees upstream tokens or URLs, only `meta.next_cursor`: an opaque string
**encrypted and authenticated** (AES-256-GCM, so its contents cannot be read or changed), expiring after `Gateway(cursor_ttl=3600)` seconds, and bound to
the tool, its contract fingerprint, the actor/tenant and the other arguments. Pass it
back as the `cursor` argument to continue.

| Upstream style | Contract | How "next" is found |
|---|---|---|
| Cursor token in the body | `Pagination(type="cursor", param="page_token", next_path="meta.next")` | token at `next_path`, sent back as `?page_token=` |
| `Link: <…>; rel="next"` | `Pagination(type="link")` | URL from the header; must be same origin and same path, and is re-checked against network policy |
| Page numbers | `Pagination(type="page", param="page", start=1, page_size=50)` | increments while pages are non-empty (or full, when `page_size` is set) |

**Local continuation.** When `max_items` or the budget drops items from a list, a read
tool with `pagination` (or `Output(continuation=True)`) returns a cursor that resumes
**at the next item**, and moves to the next upstream page once the current page is
exhausted. No items are skipped. This re-runs the upstream request, so it assumes
stable ordering between calls.

## Result envelope

```json
{
  "ok": true,
  "data": [{"number": 1, "title": "…"}],
  "meta": {
    "truncated": true,
    "omitted": [{"path": "$", "reason": "budget", "count": 20},
                {"path": "[].body", "reason": "max_chars", "count": 3}],
    "redacted": 1,
    "warnings": ["response does not match schema at items.0.id"],
    "items_returned": 10,
    "items_in_upstream_page": 30,
    "next_cursor": "tbc2.…",
    "source": {"service": "github", "operation": "list_issues", "status": 200,
               "request_id": "ABCD:1234"}
  }
}
```

`omitted` reasons: `missing` (absent upstream; does not set `truncated`), `max_items`,
`max_chars`, `budget`. Errors look like
`{"ok": false, "error": {"code": "...", "message": "...", "retryable": true,
"retry_after_seconds": 2.0, "http_status": 503, "upstream": {...}}}`. See the
[error codes](api.md#error-codes).

Passing a schema check means the data has the expected **shape**, not that it is
**true**.
