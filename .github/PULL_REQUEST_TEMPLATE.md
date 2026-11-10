## What and why

## Checklist

- [ ] Tests added or updated (security-relevant changes need a regression test)
- [ ] `uv run ruff check . && uv run ruff format --check . && uv run mypy && uv run pytest` pass
- [ ] Docs updated (README / `docs/`) and they match the behavior
- [ ] `CHANGELOG.md` entry under "Unreleased"
- [ ] No credentials, private data or internal URLs in code, tests or fixtures
