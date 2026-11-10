# Security policy

## Reporting a vulnerability

**Please do not open a public issue.** Report privately through GitHub's
[private vulnerability reporting](https://github.com/SaeedNoshadi89/toolbound/security/advisories/new).

Please include:

- affected version or commit;
- a minimal contract and call that reproduces the problem (no real credentials);
- the impact you observed (for example SSRF to an internal address, credential exposure,
  an authorization or approval bypass).

What to expect:

- an acknowledgement within **5 business days**;
- an assessment and, for confirmed issues, a fix or mitigation plan, coordinated with you;
- credit in the advisory and changelog, if you want it.

We ask that you give us reasonable time to release a fix before any public disclosure.

## Supported versions

Security fixes are released for the latest minor version. Before 1.0 that means the
latest `0.x` release only.

## Scope

In scope: anything that lets model output or upstream responses bypass Toolbound's
documented controls (see [docs/security.md](docs/security.md)), such as network policy,
argument validation, bindings, authorization hooks, approvals, replay protection, credential
isolation, redaction of echoed credentials, and size or time limits.

Out of scope: the documented residual risks (prompt injection influencing *allowed* calls,
network paths outside the process, unsandboxed Python tools, custom transports that skip
IP checks), and vulnerabilities in upstream APIs themselves.
