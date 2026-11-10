# Security policy

Toolbound sits between AI models and real systems, so we treat security reports as our
highest priority.

## Supported versions

| Version | Supported | Notes |
|---|:---:|---|
| 0.2.x | ✅ | current; receives security fixes |
| 0.1.x | ❌ | **affected by issues fixed in 0.2.0**; upgrade (see the changelog) |
| < 0.1 | ❌ | never released |

Before 1.0, only the latest minor release line receives security fixes. After 1.0, the
latest two minor lines will.

## Reporting a vulnerability

**Do not open a public issue, pull request or discussion.** Report privately through
GitHub's [private vulnerability reporting](https://github.com/SaeedNoshadi89/toolbound/security/advisories/new).
If you cannot use GitHub, open an issue that says only "security contact requested" (no
details) and a maintainer will arrange a private channel.

Please include:

- the affected version or commit;
- a minimal contract and call that reproduces the problem (no real credentials or
  personal data);
- the impact you observed (for example SSRF to an internal address, credential exposure,
  cross-tenant data access, an authorization or approval bypass, a duplicate write).

## What happens next

| Step | Target time |
|---|---|
| Acknowledgement | 5 business days |
| Triage and severity (see below), shared with you | 10 business days |
| Fix for **critical/high** | 30 days |
| Fix for **medium** | 60 days |
| Fix for **low** | next regular release |

We keep you informed, credit you in the advisory and changelog if you wish, and agree on a
disclosure date with you. We ask that you do not disclose publicly before a fix is
released, or before 90 days have passed, whichever comes first. We will not take legal
action against good-faith research that respects this policy and avoids harming users or
their data.

The full process (severity rubric, fix and release steps, advisories) is in
[docs/security/vulnerability-process.md](docs/security/vulnerability-process.md).

## Severity

We use [CVSS v4.0](https://www.first.org/cvss/v4.0/) as an input and the impact on
Toolbound's documented guarantees as the deciding factor:

| Severity | Examples |
|---|---|
| **Critical** | data or session of one user/tenant reaching another; model-controlled requests to internal networks with default settings; credential disclosure to the model or a third party |
| **High** | bypass of `authorize`, scopes or approvals; a write executed twice despite a call id or idempotency key; denial of service of the host event loop from one response |
| **Medium** | a guarantee that holds only under conditions the docs do not state; information disclosure of trusted values to the model; fail-open behavior under resource pressure |
| **Low** | hardening gaps with no demonstrated exploit; misleading documentation |

## Scope

In scope: anything that lets **model output** or **upstream responses** bypass a control
documented in the [threat model](docs/security/threat-model.md), including network policy,
argument validation, trusted bindings, authorization, approvals, replay and idempotency
protection, retries, credential and cookie isolation, redaction of echoed credentials,
cursor and approval-token integrity, and size or time limits.

Out of scope (documented residual risks): prompt injection influencing *allowed* calls,
network paths outside the process, the behavior of trusted Python tools, custom
transports that skip IP checks, a non-shared `StateStore` in multi-worker deployments,
and vulnerabilities in upstream APIs themselves.

## Security advisories

Fixed vulnerabilities are published as
[GitHub Security Advisories](https://github.com/SaeedNoshadi89/toolbound/security/advisories)
(with a CVE when applicable), listing affected and fixed versions, and in the changelog
under **Security**. Advisories describe impact and mitigation; exploit details are only
published after a fixed release is available.
