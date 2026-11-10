"""A tiny, safe path language for selecting values from JSON.

Grammar (no evaluation, no functions, no wildcards over keys)::

    path     := "$" | step ( "." step )*
    step     := name suffix* | suffix+
    suffix   := "[]" | "[" integer "]"
    name     := [A-Za-z0-9_\\-@:]+

Examples: ``title``, ``user.login``, ``labels[].name``, ``items[0].id``,
``[].id`` (each element of a root array), ``$`` (the whole document).

Paths are parsed once at registration time. Evaluation is linear in the size of
the selected data and can never execute code or reach outside the document.
"""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Any, Final

from .errors import ConfigurationError


class _Missing:
    _instance: _Missing | None = None

    def __new__(cls) -> _Missing:
        if cls._instance is None:
            cls._instance = super().__new__(cls)
        return cls._instance

    def __repr__(self) -> str:
        return "MISSING"

    def __bool__(self) -> bool:
        return False


MISSING: Final = _Missing()
"""Sentinel returned when a path does not exist in the document."""


@dataclass(frozen=True, slots=True)
class Key:
    name: str


@dataclass(frozen=True, slots=True)
class Index:
    index: int


@dataclass(frozen=True, slots=True)
class Each:
    pass


Step = Key | Index | Each

_NAME = re.compile(r"[A-Za-z0-9_\-@:]+")
_SUFFIX = re.compile(r"\[(\d*)\]")
_MAX_PATH_LENGTH = 256
_MAX_STEPS = 32


@dataclass(frozen=True, slots=True)
class Path:
    """A parsed, immutable path."""

    text: str
    steps: tuple[Step, ...]

    @property
    def is_root(self) -> bool:
        return not self.steps

    def get(self, data: Any) -> Any:
        """Return the selected value, or :data:`MISSING`."""
        return _walk(data, self.steps)

    def __str__(self) -> str:
        return self.text


def parse_path(text: str) -> Path:
    """Parse ``text`` into a :class:`Path`, raising :class:`ConfigurationError`."""
    if not isinstance(text, str) or not text:
        raise ConfigurationError("path must be a non-empty string")
    if len(text) > _MAX_PATH_LENGTH:
        raise ConfigurationError(f"path is longer than {_MAX_PATH_LENGTH} characters")
    if text == "$":
        return Path(text, ())
    steps: list[Step] = []
    for raw in text.split("."):
        if not raw:
            raise ConfigurationError(f"invalid path {text!r}: empty segment")
        pos = 0
        match = _NAME.match(raw)
        if match:
            steps.append(Key(match.group(0)))
            pos = match.end()
        elif not raw.startswith("["):
            raise ConfigurationError(f"invalid path {text!r}: bad segment {raw!r}")
        while pos < len(raw):
            suffix = _SUFFIX.match(raw, pos)
            if not suffix:
                raise ConfigurationError(f"invalid path {text!r}: bad segment {raw!r}")
            steps.append(Each() if suffix.group(1) == "" else Index(int(suffix.group(1))))
            pos = suffix.end()
    if len(steps) > _MAX_STEPS:
        raise ConfigurationError(f"path {text!r} has more than {_MAX_STEPS} steps")
    return Path(text, tuple(steps))


def _walk(data: Any, steps: tuple[Step, ...]) -> Any:
    current = data
    for i, step in enumerate(steps):
        if isinstance(step, Key):
            if not isinstance(current, dict) or step.name not in current:
                return MISSING
            current = current[step.name]
        elif isinstance(step, Index):
            if not isinstance(current, list) or step.index >= len(current):
                return MISSING
            current = current[step.index]
        else:
            if not isinstance(current, list):
                return MISSING
            rest = steps[i + 1 :]
            out = []
            for item in current:
                value = _walk(item, rest)
                if value is not MISSING:
                    out.append(value)
            return out
    return current
