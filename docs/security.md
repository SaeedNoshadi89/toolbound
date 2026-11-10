# Security model and threat analysis

This document states what Toolbound defends against, how, how it is tested, and what it
**cannot** guarantee. If you find a gap, please report it privately (see
[SECURITY.md](../SECURITY.md)).

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
| **Model picks an arbitrary URL, host, header or credential** | No such inputs exist: base URL, path template, headers and auth are contract fields. Unknown arguments are rejected (`additionalProperties: false`, also injected into nested objects). | `test_security_ssrf.py::test_model_cannot_supply_url_or_host` |
| **Path traversal / URL confusion via arguments** | Path values must be scalars. `/`, `\`, `?`, `#`, control chars, `.`/`..` and encoded separators (`%2e`, `%2f`, `%5c`) are rejected, then percent-encoded. The built URL is re-parsed and must stay under the base URL. Query values are form-encoded. | `test_path_parameter_injection_rejected`, `test_build_url_cannot_escape_base` |
| **SSRF to internal addresses** | URL policy: scheme (HTTPS only unless `allow_http`), no userinfo, IDNA-normalized host in allowlist, numeric/hex/octal host names refused, port allowlist. IP policy: loopback, private, link-local (incl. `169.254.169.254`), CGNAT, ULA (incl. `fd00:ec2::254`), multicast, reserved, unspecified, and IPv4 embedded in IPv6 (mapped, compatible, 6to4, Teredo, NAT64) are blocked unless inside an explicit `allow_networks` CIDR. | `test_check_url_blocks` (20 cases), `test_check_ip_blocks_non_public` (21 cases) |
| **DNS rebinding / resolution vs connection mismatch** | `SecureTransport` resolves the host itself, requires **every** address to pass, then connects to the checked IP. TLS still verifies the certificate for the original host name (SNI + `Host`). One connection pool per host name, so a TLS session is never reused for a different host behind the same IP. | `test_transport_blocks_if_any_resolved_address_is_private`, `test_pinned_ip_still_verifies_certificate_hostname` (network) |
| **Redirect-based SSRF and credential leaks** | Redirects are off by default. When enabled: bounded hops, every hop re-checked against URL policy and (by the transport) IP policy, and `Authorization`, `Cookie` and API-key headers are dropped on any change of origin. 303 (and 301/302 after POST) become GET without a body. | `test_redirect_to_private_address_blocked`, `test_cross_origin_redirect_drops_credentials`, end-to-end `test_redirect_to_metadata_blocked_end_to_end` |
| **Forged pagination targets** | The model only ever sees an opaque cursor signed with HMAC-SHA256 and bound to tool, contract fingerprint, actor, tenant and arguments, with an expiry. `Link` URLs must be same-origin and same-path, and are re-checked at use. API-key query parameters are stripped before storing a URL in a cursor. | `test_forged_link_cursor_rejected`, `test_link_pagination_rejects_foreign_origin` |
| **Proxy / environment hijack** | `trust_env=False`: `HTTP(S)_PROXY`, `.netrc` etc. are ignored. TLS verification cannot be disabled. | `test_tls_verification_cannot_be_disabled` |
| **Credential exposure** | Contracts hold credential *names*. Values come from your provider at call time, are never logged or put in events, and are scrubbed from results if the upstream echoes them (including the Basic-auth encoded form). Secret-looking values (AWS keys, GitHub/Slack/Stripe/OpenAI/Anthropic-style tokens, JWTs, PEM private keys, bearer strings) and sensitive keys (`password`, `token`, `authorization`, ...) are redacted. CR/LF in credentials is refused. Static `Authorization`/`Cookie`/`Host` headers cannot be configured. | `test_security_credentials.py` |
| **Confused deputy / tenant hopping** | Tenant, user and resource scoping come from `bind=` (trusted context) and are absent from the model schema. A missing context value fails closed. Your hook can check resource ownership with the validated arguments. | `test_security_authz.py` |
| **Hidden-tool probing** | Tools hidden by scopes or `visibility=` return exactly the same `unknown_tool` error as non-existent tools. | `test_hidden_tool_indistinguishable_from_unknown` |
| **Destructive actions without consent** | `effect: destructive` requires approval by default. Without an inline approver the call returns `approval_required` and **sends nothing**. Grants are signed, expiring and single-use (via `StateStore`), and bound to actor, tenant, tool, contract fingerprint and validated arguments. They are passed by host code as a keyword argument, never through tool arguments. | `test_security_approval.py` (15 tests) |
| **Double execution** | Provider call ids are claimed once for write/destructive tools (`duplicate_call`). Non-idempotent methods are never retried. With `idempotency_header`, the key is derived from the approval id or call id and is stable across retries. | `test_duplicate_call_id_never_executes_twice`, `test_post_is_never_retried_without_idempotency` |
| **Prompt injection in responses** | Results are structured JSON data; allowlist shaping reduces untrusted text; results cannot alter tool definitions, policy or approvals. | `test_tool_output_cannot_change_permissions` |
| **Resource exhaustion** | Argument size cap, request body cap, response cap on the **decompressed** stream (plus early `Content-Length` rejection), total per-attempt deadline (defeats slow-drip responses), per-service concurrency limit, per-tool rate limits, bounded retries with jittered backoff and a `Retry-After` ceiling, non-JSON content refused unless `accept_text`. | `test_transport.py` (decompression bomb, slow drip, size) |
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
  one exact call. It does not prove the call is wise. Show users a clear
  `PendingApproval.summary`.
- **Python tools are not sandboxed.** They run with your application's full privileges,
  and their timeouts cannot forcibly stop a running thread. Toolbound validates their
  input and shapes their output. It does not contain their behavior.
- **Replay protection is only as shared as your `StateStore`.** The default in-memory store
  works per process. Use a shared store with several workers:

  ```python
  class RedisStateStore:
      def __init__(self, redis):  # redis.asyncio.Redis
          self.redis = redis

      async def claim(self, key: str, ttl_seconds: float) -> bool:
          return bool(
              await self.redis.set(f"toolbound:{key}", 1, nx=True, ex=max(1, int(ttl_seconds)))
          )
  ```
- **Signing keys.** Without `secret=`, a random per-process key is used. Cursors and grants
  then break on restart and across workers. Use a 32+ byte secret from your vault, and
  rotate it like any HMAC key (rotation invalidates outstanding cursors and grants).
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
6. `effect` set honestly on every write; `idempotency_header` where the API supports it.
7. Keep `allow_networks` as narrow as possible (single hosts, `/32`).
8. Feed `Observer` events to your audit log. They contain no payloads, so they are safe to keep.
9. Review contracts (especially imported ones) like code: they *are* your security policy.
