# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/) (before 1.0, minor versions may break the API).

## [Unreleased]

### Added

- Gateway secret rotation: `Gateway(secret=[new, old, ...])` (at most 8 distinct keys of
  32+ bytes). The first key signs and encrypts new cursors, approval requests and grants;
  every listed key is accepted when one is checked. A single secret behaves as before.
  Changing the secret no longer has to invalidate every open approval at once.

## [0.3.0] - 2026-11-12

Security fix and host-integration additions. **Everyone using approvals with tool-call ids
should upgrade.** All additions are optional; no existing contract or call changes. One
behavior change, which is the fix: a second approval request for a call id that already
executed is refused with `duplicate_call`.

### Security

- **Medium:** a model tool call sealed for approval more than once (a retry, a re-run
  graph node) produced separate approval requests that **all executed** when approved: the
  call-id claim protected direct calls only. An approval request now carries the id of the
  call that requested it (`PendingApproval.call_id`), and that id is claimed when the
  approval executes, so the action runs at most once per call id. Requests sealed by
  earlier versions carry no call id and behave as before.

### Added

- `ToolRefusal(reason, message, details=...)`: a Python tool refuses a call for a
  business reason. The result is the new error code `refused` with `details["reason"]`;
  other exceptions are still `internal_error`.
- `Gateway.resume(..., bound="sealed")` uses the trusted values sealed in the request for
  `attributes.<key>` bindings; actor, tenant and scopes stay live. With the default
  `bound="live"`, a changed value is reported in `error.details["changed_bound"]` (names
  only) instead of a bare `approval_invalid`.
- `approval_ttl` per tool (`Operation`, `PythonTool`, YAML contracts) and per call
  (`Gateway.call(..., approval_ttl=...)`), each between 0 and 7 days.
- `ExecutionContext(principal=...)`: an object for trusted code (the signed-in user),
  never bound, sealed, digested, logged or compared.
- Docs: an out-of-band approval recipe for MCP servers.

## [0.2.2] - 2026-11-12

Security patch release. **Everyone on 0.2.x should upgrade.** One fix can reject contracts
that 0.2.1 accepted (see the first item).

### Security

- **Medium:** a trusted binding (`bind=`) that was not a path placeholder and was left out
  of explicit `query=`/`body=` lists was silently dropped from the request, while
  `authorize()` and the approval summary still saw it. A tenant filter could vanish this
  way. Such contracts now fail at registration with a `ConfigurationError`.
  **This can break contracts that relied on the old behavior; add the name to `query`
  or `body`.**
- **Low:** link-pagination cursors replayed the upstream's next URL verbatim, so the upstream
  decided the bound query values for later pages. Bound query values are now re-applied.
- **Low:** cross-origin redirects (only with `follow_redirects=True`) kept static
  `Service.headers` / `Operation.headers`. They are now dropped along with credentials.
- **Low:** `SecureTransport` decompressed each raw chunk in full before checking the size
  limit, so one compressed chunk could briefly inflate to tens of MiB. Decompression is now
  capped at every step. Only `gzip` and `deflate` (the encodings Toolbound requests) are
  accepted; other or stacked `Content-Encoding` values are `upstream_error`.

## [0.2.1] - 2026-11-11

Documentation-only release. **No code changes**; upgrading from 0.2.0 is optional.

### Changed

- The README on PyPI now shows the published status and `pip install toolbound` (the 0.2.0
  page still said "not yet published" and pointed to a GitHub install).
- CI and release workflows use newer major versions of `actions/checkout`,
  `astral-sh/setup-uv`, `actions/upload-artifact` and `actions/download-artifact`, still
  pinned by commit SHA.

## [0.2.0] - 2026-11-11

Security-hardening release after an independent production-readiness review of 0.1.0.
**Everyone on 0.1.0 should upgrade.** 0.1.0 was never published to PyPI.

### Security

- **Critical:** `SecureTransport` stored upstream cookies in a client shared by all users,
  so a `Set-Cookie` from one user's call was sent on later calls for other users and
  tenants. The transport no longer stores cookies.
- **High:** `Operation(method="DELETE")` without `effect` was treated as a read tool (no
  approval, no duplicate-call protection). The effect is now inferred from the method.
- **High:** `Gateway.grant()` signed any `PendingApproval` object, so a host that rebuilt
  one from client data could execute arguments the human never saw. Approval requests are
  now gateway-issued encrypted tokens, and only the token is trusted.
- **High:** trimming a large result to the token budget could block the event loop for
  seconds. Trimming work is bounded, and large bodies are processed in a worker thread.
- **Medium:** cursors were signed but readable (they exposed upstream tokens and trusted
  path values). They are now encrypted.
- **Medium:** a timed-out or interrupted write told the model `retryable: true`, inviting a
  duplicate write. Such failures are now `outcome_unknown` (not retryable), and 5xx after
  a write is not retryable.
- **Medium:** `MemoryStateStore` evicted unexpired replay keys when full, so an approval
  could be reused. It now refuses new claims (fail closed). Any `StateStore` error fails
  the call closed.
- **Medium:** approval summaries were truncated silently and hid trusted values and the
  target URL. They now show the method, resolved URL, all arguments and trusted values,
  escape control and bidi characters, and flag truncation.
- **Medium:** no warning for an ephemeral signing key. A `ToolboundWarning` is now emitted.
- **Low:** `HttpRequest`/`HttpResponse` reprs no longer print headers, bodies or query
  values. The rate limiter forgets idle callers and is thread-safe. A per-call
  `Limits.total_timeout` bounds retries and `Retry-After` waits. The transport falls back
  to the next checked address on connect failure. Key-based redaction applies to renamed
  fields. Non-object list items are reported and continuation offsets stay aligned. An
  explicit special-purpose IP blocklist no longer depends on the Python patch version.
  Unenforced JSON Schema `format`s produce a warning.

### Security (second, adversarial review of 0.2.0)

- **High:** a secret-detection regex was quadratic: an 800 KB response froze the process
  for 71 s (threads did not help, the regex holds the GIL). Patterns are now linear and
  only scan what can still be returned.
- **High:** when the last retry of a write failed before sending, an earlier attempt that
  had reached the upstream was hidden and the model saw a retryable error. Any attempt or
  redirect hop that may have landed now makes a write `outcome_unknown`; so does a 3xx.
- **High:** echoed credentials in URL-encoded, JSON-escaped or base64 form, or used as
  object keys, were not scrubbed, and `accessToken`-style keys escaped key redaction.
- **Medium-High:** automatic retries followed the HTTP method, so a destructive GET was
  retried. Only declared reads (or idempotency-keyed calls) are retried now.
- **Medium:** cursors were not bound to trusted bound values; nested schemas with
  `properties` but a non-`"object"` type stayed open (mass assignment); one actor could
  exhaust the replay store for everyone; the FastAPI example let the agent approve its own
  request and did not make rejections final.
- **Low:** the per-actor rate limit was not tenant-qualified; hidden group actions could
  be told apart from missing ones; a duplicate call id or a pre-send failure used up an
  approval; IPv4-translated (`::ffff:0:a.b.c.d`) addresses were allowed; concurrency limits
  were keyed by service name only; stuck sync tools could starve DNS resolution; missing
  provider call ids became the string `"None"`; release tooling was unpinned and releases
  were not restricted to commits on `main`.

### Breaking

- `PythonTool` and `@gateway.tool` require `effect=`.
- `POST`/`PUT`/`PATCH` operations default to `effect="write"` and `DELETE` to
  `"destructive"`. Declare `effect="read"` for read-only POSTs. `DELETE` + `read` is
  rejected.
- `Gateway.grant()`/`resume()` accept a gateway-issued `PendingApproval` or its `token`.
  Hand-built `PendingApproval` objects are rejected with `ApprovalInvalid`. Grant tokens
  changed prefix (`tba1` → `tba2`).
- Cursor format changed (`tbc1` → `tbc2`); 0.1 cursors are rejected.
- New runtime dependency: `cryptography>=42`.
- New error code `outcome_unknown`. Writes that may have reached the upstream are no longer
  marked retryable.

### Added

- `Gateway.pending_approval(token)`; `PendingApproval.token`, `.target`,
  `.summary_truncated`; `to_dict()` now includes the token and trusted values.
- `ApprovalInvalid`, `StateStoreError`, `ToolboundWarning`; `Limits.total_timeout`.
- `Gateway.deny()` / `SyncGateway.deny()`; `SyncGateway.resume(call_id=...)`;
  `MemoryStateStore(max_per_partition=...)`.
- Gateways can be shared across event loops and threads.
- FastAPI and LangGraph examples with automated tests (`tests/integrations`).
- Dedicated security regression suite (`tests/security`, `pytest -m security`), threat
  model (`docs/security/threat-model.md`), vulnerability process
  (`docs/security/vulnerability-process.md`).
- CI: separate security-suite job, `pip-audit`, dependency review, CodeQL, `zizmor`,
  actions pinned by commit SHA, and a single `required checks` gate. The release workflow
  refuses to build unless all of them pass.
- README: why Toolbound exists, a worked example with a comparison diagram, and a "how a
  tool call flows" diagram.

### Fixed

- `Gateway(state=...)`, `estimator=` and `observer=` were replaced by defaults when the
  given object was falsy (for example an empty store with `__len__`).
- Docs: removed the claim that the model cannot read cursor contents (true only from 0.2),
  corrected the LangChain recipe (it lost tool-call ids), and corrected the event-loop
  guidance.

## [0.1.0] - 2026-11-10

First public alpha.

### Added

- `Gateway`: one execution pipeline for REST operations and trusted Python tools
  (validation, trusted bindings, scopes, required `authorize` hook, rate limits, approval,
  replay protection, execution, output shaping, structured results).
- Contracts in Python (`Service`, `Operation`, `PythonTool`, `Output`, `Field`,
  `Pagination`, policies) and in YAML/JSON (format version 1, published meta-schema,
  `status: draft` review gate).
- `SecureTransport`: DNS resolution with every address checked, IP pinning with TLS host
  verification, non-public ranges blocked unless explicitly trusted, no proxies from the
  environment, decompressed size caps, total deadlines.
- Redirect policy (off by default; per-hop checks; credentials dropped across origins).
- Output pipeline: allowlist projection with a safe path language, nested shapes,
  transforms, defaults, limits, key/secret/credential redaction, PII hooks, output schema
  checks, token budgets with `truncate`/`reject`, required evidence fields, transparent
  omission metadata.
- Signed, expiring, argument-bound cursors for upstream cursor/link/page pagination and
  local continuation.
- Approval grants bound to actor, tenant, tool, contract fingerprint and arguments;
  single use; inline approver or two-step `grant`/`resume`.
- Duplicate call-id protection for writes; idempotency keys; retries only when safe.
- Exposure strategies `direct` and compact `grouped`; scope, visibility and tag filtering.
- Adapters for the Anthropic Messages API and OpenAI Chat Completions / Responses.
- `SyncGateway`, `TiktokenEstimator`, `LoggingObserver`, `MockTransport`, CLI
  (`validate`, `tools`, `schema`).
- Security regression suite, property-based tests, runnable examples, reproducible
  benchmarks, documentation.

[Unreleased]: https://github.com/SaeedNoshadi89/toolbound/compare/v0.1.0...HEAD
[0.1.0]: https://github.com/SaeedNoshadi89/toolbound/releases/tag/v0.1.0
