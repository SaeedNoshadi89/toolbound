# Release process

1. **Prepare.** Update `CHANGELOG.md` (move "Unreleased" items under the new version), bump
   `version` in `pyproject.toml` and `__version__` in `src/toolbound/__init__.py`.
2. **Verify locally.**
   ```bash
   uv run ruff check . && uv run ruff format --check . && uv run mypy
   uv run pytest
   uv run pytest -m security            # must pass; never skip for a release
   TOOLBOUND_NETWORK_TESTS=1 uv run pytest -m network
   uv export --format requirements-txt --no-hashes --all-groups --no-emit-project > /tmp/req.txt
   uvx pip-audit -r /tmp/req.txt --no-deps --disable-pip --strict
   uvx zizmor --offline .github/workflows
   uv build && uvx twine check --strict dist/*
   ```
   CI on `main` must be green, including the `required checks` job, and CodeQL must show
   no open high-severity alerts.
3. **Benchmarks** (if behavior affecting size or latency changed):
   `uv run --with tiktoken python benchmarks/run.py`, then update `docs/benchmarks.md` and
   the README table with the new measured numbers and environment.
4. **Tag.** `git tag -s vX.Y.Z -m "vX.Y.Z" && git push --tags`.
5. **Publish.** The `release` workflow builds the sdist and wheel and publishes to PyPI
   with [trusted publishing](https://docs.pypi.org/trusted-publishers/) (no API tokens in
   the repository). It requires a PyPI project configured for this repository and a
   `pypi` GitHub environment, with manual approval recommended.
6. **Announce.** Create a GitHub release from the tag with the changelog section.

## Security releases

Security fixes follow [the vulnerability process](security/vulnerability-process.md):
fixed privately, released as a patch, announced with a GitHub Security Advisory. The
release workflow re-runs lint, the full suite, the security suite and the dependency
audit on the tagged commit and refuses to build if any fails.

## Branch protection

Protect `main` so that changes arrive through pull requests and cannot merge while the
security suite or the audit fail:

- require a pull request before merging;
- require the status check **`required checks`** (it fails if lint, tests, the security
  regression suite, the dependency audit, dependency review or the package build fails);
- require branches to be up to date; block force pushes and deletion.

With the GitHub CLI (repository admin):

```bash
gh api -X PUT repos/SaeedNoshadi89/toolbound/branches/main/protection --input - <<'JSON'
{"required_status_checks": {"strict": true, "contexts": ["required checks"]},
 "enforce_admins": false,
 "required_pull_request_reviews": {"required_approving_review_count": 0},
 "restrictions": null, "allow_force_pushes": false, "allow_deletions": false}
JSON
```

`enforce_admins: false` lets a sole maintainer merge their own pull request. Set it to
`true` once there are several maintainers.

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
