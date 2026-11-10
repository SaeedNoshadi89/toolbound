# Release process

1. **Prepare.** Update `CHANGELOG.md` (move "Unreleased" items under the new version), bump
   `version` in `pyproject.toml` and `__version__` in `src/toolbound/__init__.py`.
2. **Verify locally.**
   ```bash
   uv run ruff check . && uv run ruff format --check . && uv run mypy
   uv run pytest
   TOOLBOUND_NETWORK_TESTS=1 uv run pytest -m network
   uv build && uv run --isolated --with dist/*.whl python -c "import toolbound"
   ```
3. **Benchmarks** (if behavior affecting size or latency changed):
   `uv run --with tiktoken python benchmarks/run.py`, then update `docs/benchmarks.md` and
   the README table with the new measured numbers and environment.
4. **Tag.** `git tag -s vX.Y.Z -m "vX.Y.Z" && git push --tags`.
5. **Publish.** The `release` workflow builds the sdist and wheel and publishes to PyPI
   with [trusted publishing](https://docs.pypi.org/trusted-publishers/) (no API tokens in
   the repository). It requires a PyPI project configured for this repository and a
   `pypi` GitHub environment, with manual approval recommended.
6. **Announce.** Create a GitHub release from the tag with the changelog section.

## Versioning policy

- Semantic Versioning. Before 1.0, a minor release (0.x → 0.y) may break the Python API,
  and every break is listed under **Breaking** in the changelog.
- The contract file format has its own version (`version: 1`). Releases keep loading
  existing versions, or ship an automated migration.
- Security fixes are released as patch versions for the latest minor release.

## Supported Python versions

| Python | Status |
|---|---|
| 3.11, 3.12, 3.13, 3.14, 3.15 | supported, tested in CI |
| 3.10 and older | not supported (3.10 reached end of life in October 2026) |

Support for a Python version is dropped in a minor release after it reaches end of life.
