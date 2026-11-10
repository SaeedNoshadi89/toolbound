# Changelog

All notable changes are documented here. The format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/), and the project uses
[Semantic Versioning](https://semver.org/) (before 1.0, minor versions may break the API).

## [Unreleased]

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
