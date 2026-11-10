"""Credential providers. Secrets stay in trusted code and never reach the model."""

from __future__ import annotations

import os
from collections.abc import Mapping

from .context import ExecutionContext


class EnvCredentials:
    """Read credentials from environment variables.

    ``EnvCredentials({"github_token": "GITHUB_TOKEN"})`` maps names explicitly.
    With no mapping, the name is upper-cased (``github_token`` -> ``GITHUB_TOKEN``),
    optionally with a ``prefix``.
    """

    def __init__(self, mapping: Mapping[str, str] | None = None, *, prefix: str = "") -> None:
        self._mapping = dict(mapping or {})
        self._prefix = prefix

    def get(self, name: str, ctx: ExecutionContext) -> str | None:
        var = self._mapping.get(name) or (self._prefix + name.upper().replace(".", "_"))
        return os.environ.get(var) or None

    def __repr__(self) -> str:
        return f"EnvCredentials(names={sorted(self._mapping)!r}, prefix={self._prefix!r})"


class StaticCredentials:
    """Credentials from an in-memory mapping (tests, or values from your vault)."""

    def __init__(self, values: Mapping[str, str]) -> None:
        self._values = dict(values)

    def get(self, name: str, ctx: ExecutionContext) -> str | None:
        return self._values.get(name)

    def __repr__(self) -> str:  # never print secret values
        return f"StaticCredentials(names={sorted(self._values)!r})"
