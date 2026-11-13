# Security guide: controls, tests and deployment

This document lists what Toolbound defends against, how, which tests guard each control,
and what it **cannot** guarantee. The STRIDE analysis, assets, attackers and assumptions
are in the **[threat model](security/threat-model.md)**. Report gaps privately (see
[SECURITY.md](../SECURITY.md)).

All tests named below live in `tests/security/` (run them with `uv run pytest -m security`)
or `tests/integrations/`.

## Trust boundaries

```text
 TRUSTED                                   UNTRUSTED
 ───────                                   ─────────
 contracts (YAML/Python), reviewed         model output: tool name, arguments, cursor
 your code: authorize(), approver,         upstream responses: bodies, headers, redirects,
   credential provider, Python tools         Link headers, error messages
 ExecutionContext built by your auth       tool descriptions in third-party/imported specs
   layer after authenticating the user       (until reviewed and activated)
```

The model can only choose **which registered, visible tool** to call and **which
arguments** to pass, and those arguments must satisfy a closed schema. Everything else is
fixed by trusted code.

## The four layers (do not confuse them)

1. **Structural validation:** JSON Schema on arguments (closed objects, bounds, enums,
   patterns, sizes) and optionally on upstream responses. It proves *shape* only.
2. **Authorization:** your `authorize(AuthorizationRequest)` hook receives the trusted
   context, the tool, the validated model arguments and the trusted bound values.
   Required scopes are checked first and also hide tools. **Toolbound does not own your
   business rules.** It guarantees the hook runs before anything executes.
3. **Network security:** URL construction, URL policy, IP policy, redirect policy, size
   and time limits (below).
4. **Factual verification:** out of scope. A response that passes schema checks may still
   be wrong, stale, or adversarial. Toolbound preserves provenance (`meta.source`) and
   reports omissions, so your application can verify facts where that matters.

## Threats and controls

| Threat | Controls | Tests |
|---|---|---|
| **Model picks an arbitrary URL, host, header or credential** | No such inputs exist: base URL, path template, headers and auth are contract fields. Unknown arguments are rejected (`additionalProperties: false`, also injected into nested objects). | `test_ssrf.py::test_model_cannot_supply_url_or_host` |
| **Path traversal / URL confusion via arguments** | Path values must be scalars. `/`, `\`, `?`, `#`, control chars, `.`/`..` and encoded separators (`%2e`, `%2f`, `%5c`) are rejected, then percent-encoded. The built URL is re-parsed and must stay under the base URL. Query values are form-encoded. | `test_path_parameter_injection_rejected`, `test_build_url_cannot_escape_base` |
| **SSRF to internal addresses** | URL policy: scheme (HTTPS only unless `allow_http`), no userinfo, IDNA-normalized host in allowlist, numeric/hex/octal host names refused, port allowlist. IP policy: loopback, private, link-local (incl. `169.254.169.254`), CGNAT, ULA (incl. `fd00:ec2::254`), multicast, reserved, unspecified, and IPv4 embedded in IPv6 (mapped, compatible, 6to4, Teredo, NAT64) are blocked unless inside an explicit `allow_networks` CIDR. | `test_check_url_blocks` (20 cases), `test_check_ip_blocks_non_public` (21 cases) |
| **DNS rebinding / resolution vs connection mismatch** | `SecureTransport` resolves the host itself, requires **every** address to pass, then connects only to checked addresses (falling back to the next checked address if one refuses). Nothing re-resolves the name. TLS still verifies the certificate for the original host name (SNI + `Host`). One connection pool per host name and event loop. | `test_dns_answer_is_pinned_no_second_lookup`, `test_rebinding_to_private_answer_is_blocked`, `test_transport_blocks_if_any_resolved_address_is_private`, `test_pinned_ip_still_verifies_certificate_hostname` (network) |
| **Special-purpose address ranges on older Pythons** | An explicit IANA special-purpose blocklist is applied in addition to `ipaddress.is_global`, whose answers changed across patch releases (CVE-2024-4032). | `test_hardening.py::test_l7_*` |
| **Session state shared between users** | The transport's HTTP clients use a cookie jar that stores nothing, so a `Set-Cookie` from one user's call is never sent on another's (fixed in 0.2). | `test_isolation.py::test_c1_*` |
| **Redirect-based SSRF and credential leaks** | Redirects are off by default. When enabled: bounded hops, every hop re-checked against URL policy and (by the transport) IP policy, and `Authorization`, `Cookie`, API-key headers and static `Service`/`Operation` headers are dropped on any change of origin. 303 (and 301/302 after POST) become GET without a body. | `test_redirect_to_private_address_blocked`, `test_cross_origin_redirect_drops_credentials`, end-to-end `test_redirect_to_metadata_blocked_end_to_end` |
| **Forged or readable pagination state** | The model only ever sees an opaque cursor **encrypted and authenticated with AES-256-GCM** (0.1 cursors were signed but readable), bound to tool, contract fingerprint, actor, tenant and arguments, with an expiry. `Link` URLs must be same-origin and same-path, and are re-checked at use. API-key query parameters are stripped before a URL is stored. | `test_cursors.py`, `test_forged_link_cursor_rejected`, `test_isolation.py::test_cursor_from_one_tenant_rejected_for_another` |
| **Proxy / environment hijack** | `trust_env=False`: `HTTP(S)_PROXY`, `.netrc` etc. are ignored. TLS verification cannot be disabled. | `test_tls_verification_cannot_be_disabled` |
| **Credential exposure** | Contracts hold credential *names*. Values come from your provider at call time, are never logged or put in events, and are scrubbed from results if the upstream echoes them (including the Basic-auth encoded form). Secret-looking values (AWS keys, GitHub/Slack/Stripe/OpenAI/Anthropic-style tokens, JWTs, PEM private keys, bearer strings) and sensitive keys (`password`, `token`, `authorization`, ...) are redacted. CR/LF in credentials is refused. Static `Authorization`/`Cookie`/`Host` headers cannot be configured. | `test_credentials.py` |
| **Confused deputy / tenant hopping** | Tenant, user and resource scoping come from `bind=` (trusted context) and are absent from the model schema. A missing context value fails closed. A contract whose binding would never reach the request (not in the path, and left out by explicit `query=`/`body=`) is refused at registration. Link-pagination cursors re-apply bound query values instead of trusting the upstream's next URL. Your hook can check resource ownership with the validated arguments. | `test_authz.py` |
| **Hidden-tool probing** | Tools hidden by scopes or `visibility=` return exactly the same `unknown_tool` error as non-existent tools. | `test_hidden_tool_indistinguishable_from_unknown` |
| **Write operations declared as reads** | The effect is inferred from the HTTP method (`DELETE` → destructive, `POST`/`PUT`/`PATCH` → write); `DELETE` cannot be declared `read`; Python tools must declare an effect (fixed in 0.2). | `test_effects.py` |
| **Destructive actions without consent** | `effect: destructive` requires approval by default. Without an inline approver the call returns `approval_required` and **sends nothing**. The approval request is a gateway-issued token, **encrypted and authenticated**, which can be stored or sent through a browser safely; `grant()` and `resume()` trust only that token, never the fields of a `PendingApproval` object (fixed in 0.2). Grants are signed, expiring and single-use (via `StateStore`), and bound to actor, tenant, tool, contract fingerprint, validated arguments and trusted values. They are passed by host code as a keyword argument, never through tool arguments. | `test_approval.py`, `test_approval_tokens.py`, `tests/integrations/test_fastapi.py`, `test_langgraph.py` |
| **Misleading approval prompts** | Summaries include the method and resolved URL (or Python tool), every argument and every trusted value. Control, format and bidi characters are escaped, and truncation is flagged (`summary_truncated`) instead of silent. | `test_approval_tokens.py::test_m4_*` |
| **Double execution** | Provider call ids are claimed once for write/destructive tools, **before** execution (`duplicate_call`). An approval request carries the id of the call that requested it, and that id is claimed when the approval executes, so a call sealed for approval twice (a model retry, a re-run graph node) still runs once. Non-idempotent requests are never retried automatically. With `idempotency_header`, the key is derived from the approval id or (actor, tenant, call id) and is stable across internal retries. | `test_duplicate_call_id_never_executes_twice`, `test_host_approvals.py::test_h1_*`, `test_effects.py`, `test_unsafe_retries.py` |
| **Unsafe retries after an unknown outcome** | Automatic retries only for declared reads over safe methods, or with `idempotency_header`. When **any** attempt or redirect hop of a write may have reached the upstream (read timeout, reset, total deadline, 5xx, 3xx, a blocked or refused later hop), the model gets `outcome_unknown` or a non-retryable error. Only failures that certainly happened before anything was sent stay retryable. Python write tools that time out report `outcome_unknown`. | `test_unsafe_retries.py`, `test_review2.py::test_r2_*`, `::test_r4_*`, `::test_r5_*` |
| **Replay store exhaustion or outage** | The in-memory store never evicts unexpired keys and keeps a quota per actor+tenant partition, so one actor cannot block others. When a partition or the store is full, or a custom store raises, the call is refused (fail closed). Approvals and call ids are claimed only immediately before execution. | `test_replay_store.py`, `test_review2.py::test_r7_*`, `::test_r12_*` |
| **Prompt injection in responses** | Results are structured JSON data; allowlist shaping reduces untrusted text; results cannot alter tool definitions, policy or approvals. | `test_tool_output_cannot_change_permissions` |
| **Process stalls from large or hostile results** | Secret patterns run in linear time and only over what can still be returned; budget trimming does bounded work; decoding and shaping of bodies over 256 KB run in a worker thread (fixed in 0.2). | `test_budget_dos.py`, `test_review2.py::test_r1_*` |
| **Mass assignment via nested objects** | Every nested schema with `properties` is closed, whatever its `type`; open objects warn. | `test_review2.py::test_r8_*` |
| **Resource exhaustion** | Per-call total deadline across retries and `Retry-After` waits (`Limits.total_timeout`), argument size cap, request body cap, response cap on the **decompressed** stream, with every inflate step capped so a single compressed chunk never expands past the limit (plus early `Content-Length` rejection), total per-attempt deadline (defeats slow-drip responses), per-service concurrency limit, per-tool rate limits, bounded retries with jittered backoff and a `Retry-After` ceiling, non-JSON content refused unless `accept_text`. | `test_transport_ssrf.py` (decompression bomb, slow drip, size), `test_budget_dos.py`, `test_unsafe_retries.py::test_l3_*` |
| **Malicious or sloppy contracts** | Contracts are validated at load: meta-schema, closed input schemas, only local `$ref`, no `$id`, size and depth limits, base URL host must be allowlisted, no userinfo/query in base URLs, path templates without `..`, bound names not visible, path parameters required. Imported specs must be `status: active` to load. | `test_adapters_and_loader.py`, registration tests |
| **Leaky errors** | Unexpected exceptions become a generic `internal_error`. Upstream errors return status-based messages plus an optional, shaped, redacted `error_shape`. No stack traces or raw bodies go to the model. | `test_handler_exceptions_do_not_leak`, `test_error_mapping` |

## What Toolbound cannot guarantee (residual risk)

- **Prompt injection cannot be prevented by a library.** A model may still be persuaded
  to call *allowed* tools with *allowed* arguments for the wrong reasons. Mitigate with
  narrow tools, per-user scopes, approvals for writes, and verification in your app.
- **The network beyond the process.** Toolbound cannot see sidecar proxies, service meshes,
  NAT rules, or what an upstream API does with your request (an upstream that fetches URLs
  is its own SSRF surface). **Run agents with egress firewall rules** when they sit near
  sensitive networks.
- **Custom transports.** IP-level checks live in the transport. A custom `Transport` must
  call `check_ip` on the address it connects to, or IP-level SSRF protection is lost.
  (`MockTransport` only checks IP literals and is meant for tests.)
- **Approved operations can still be harmful.** An approval proves a human consented to
  one exact call. It does not prove the call is wise. Show users `target`, `arguments` and
  `bound` (or at least `summary`, and check `summary_truncated`).
- **At most once, not exactly once.** A call id is claimed before the call runs. If the
  call then fails, the same call id will not run again: the model must call again with a
  new id, after checking the current state when the error is `outcome_unknown`. An approved
  write that times out may or may not have happened.
- **Python tools are not sandboxed.** They run with your application's full privileges,
  and their timeouts cannot forcibly stop a running thread (a timed-out write reports
  `outcome_unknown`). Toolbound validates their input and shapes their output. It does not
  contain their behavior.
- **Replay protection is only as shared as your `StateStore`.** The default in-memory store
  works per process (it is thread-safe and fails closed when full). Use a shared, durable
  store with several workers or processes. A store that raises makes calls fail closed.

  ```python
  class RedisStateStore:
      def __init__(self, redis):  # redis.asyncio.Redis
          self.redis = redis

      async def claim(self, key: str, ttl_seconds: float) -> bool:
          return bool(
              await self.redis.set(f"toolbound:{key}", 1, nx=True, ex=max(1, int(ttl_seconds)))
          )
  ```
- **Signing keys.** Without `secret=`, a random per-process key is used and a
  `ToolboundWarning` is emitted the first time a cursor or approval is issued. Cursors and
  approvals then fail (closed) after a restart and on other workers. Use a 32+ byte secret
  from your vault. **Rotation:** pass a list, `secret=[new, old]`. The first key signs and
  encrypts every new token; every listed key is accepted when a token is checked, so
  outstanding approvals and cursors keep working. Drop the old key once the longest-lived
  token it issued has expired (approval requests live at most 7 days); its tokens then stop
  working. After a leak, drop the leaked key at once, which invalidates everything it
  issued. Use the same list, in the same order, on every worker.
- **Token contents.** Cursors and approval requests are encrypted. Grants are signed but
  readable: they contain only an id, a digest and `approved_by`.
- **Rate limits are per process.** Use your API gateway or a shared limiter for global
  limits.
- **Redaction is a safety net, not a guarantee.** Pattern-based secret detection has false
  negatives. The primary control is the allowlist `shape`.
- **Token estimates are approximate** unless you plug in a tokenizer for your model.

## Deployment hardening checklist

1. Egress firewall: allow only the API hosts your contracts list.
2. `Gateway(secret=...)` from a secret manager; a shared `StateStore` with >1 worker.
3. Per-user credentials (OAuth) where the upstream supports it; least-privilege API tokens
   otherwise.
4. Explicit `shape` on every tool that returns user or business data; `required` for ids
   and citations; `overflow="reject"` where partial data is dangerous.
5. `required_scopes` and `visibility=` so each user sees only the tools they need.
6. `effect` declared on every Python tool and on read-only `POST`s; `idempotency_header`
   where the API supports it.
7. Keep `allow_networks` as narrow as possible (single hosts, `/32`).
8. Feed `Observer` events to your audit log. They contain no payloads, so they are safe to keep.
9. Review contracts (especially imported ones) like code: they *are* your security policy.
10. Run with `-W error::toolbound.ToolboundWarning` in CI so risky configuration
    (ephemeral keys, unenforced schema formats) fails loudly.
