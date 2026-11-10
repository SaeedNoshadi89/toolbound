# Contributing to Toolbound

Thanks for helping! Toolbound is a security-sensitive library, so we value small, focused
changes with tests over large rewrites.

## Setup

```bash
git clone https://github.com/SaeedNoshadi89/toolbound && cd toolbound
uv sync
uv run pytest
```

Before opening a pull request:

```bash
uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest
```

## Security regression suite

`tests/security/` holds a test for every vulnerability class Toolbound defends against
(SSRF, DNS rebinding, redirects, credential and cookie leakage, cross-tenant isolation,
authorization bypass, approval forgery and replay, duplicate writes, unsafe retries,
replay-store exhaustion, event-loop denial of service). Every test there is marked
`security` automatically, and the FastAPI/LangGraph isolation tests in
`tests/integrations/` are marked too.

```bash
uv run pytest -m security            # the whole suite (about 270 tests, ~10 s)
uv run pytest -m security -k approval   # one area
uv run pytest tests/security/test_isolation.py -v
```

CI runs it as a separate `security regression suite` job on Linux and Windows. The
`required checks` job fails if it (or lint, tests, the dependency audit or the package
build) fails. Pull requests cannot be merged while it is red.

Rules for the suite:

- a test name says which threat it guards (and the finding id, for example `c1`, when it
  comes from a review or report);
- its docstring describes the original failure;
- never weaken or delete a security test to make a change pass. If behavior changes on
  purpose, update the [threat model](docs/security/threat-model.md) in the same pull
  request and explain why in the description.

Dependency and workflow checks run in the same CI (`pip-audit`, dependency review, CodeQL,
`zizmor`). Run them locally with:

```bash
uv export --format requirements-txt --no-hashes --all-groups --no-emit-project > /tmp/req.txt
uvx pip-audit -r /tmp/req.txt --no-deps --disable-pip --strict
uvx zizmor --offline .github/workflows
```

## Ground rules

- **The core stays neutral.** `src/toolbound/core` must not import HTTP clients, AI
  frameworks, provider SDKs or YAML. `tests/test_architecture.py` enforces this.
- **Security logic lives in the core.** Adapters translate formats only.
- **Every security-relevant change needs a regression test** in `tests/security/` that
  fails without the change (revert your fix locally and watch it fail). See
  [Security regression suite](#security-regression-suite).
- **Docs must match behavior.** If you change behavior, update the README and `docs/`
  in the same pull request. Mark planned features as planned.
- **Measured numbers only.** Benchmarks come from `benchmarks/run.py`. Never hand-edit
  results.
- **No secrets or real personal data** in code, tests, fixtures or examples.
- Public API changes need a `CHANGELOG.md` entry under "Unreleased".

## Good first contributions

- adapters (with tests comparing their output with `gateway.definitions()`)
- new redaction patterns with low false-positive rates (include examples)
- documentation fixes and runnable examples

## Reporting issues

Use GitHub issues for bugs and ideas. **Report vulnerabilities privately:** see
[SECURITY.md](SECURITY.md).

## Conduct

Be respectful and constructive. Harassment or discrimination is not tolerated. Maintainers
may remove comments and contributors who violate this.

By contributing you agree that your contributions are licensed under the Apache-2.0
license of this project.
