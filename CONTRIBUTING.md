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

## Ground rules

- **The core stays neutral.** `src/toolbound/core` must not import HTTP clients, AI
  frameworks, provider SDKs or YAML. `tests/test_architecture.py` enforces this.
- **Security logic lives in the core.** Adapters translate formats only.
- **Every security-relevant change needs a regression test** in `tests/test_security_*.py`
  that fails without the change.
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
