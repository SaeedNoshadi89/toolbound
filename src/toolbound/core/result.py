"""Tool results.

A :class:`ToolResult` has two audiences:

* **Host code** can read every attribute, including ``approval`` (a
  :class:`PendingApproval` to show a human) and diagnostics such as
  ``http_status`` and ``duration_ms``.
* **The model** only ever receives :meth:`ToolResult.to_model` (or
  :meth:`ToolResult.to_json`): the shaped data, transparent metadata about what
  was left out, and a safe error message.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .approval import PendingApproval
from .budget import to_json
from .errors import ErrorCode
from .shaping import Omission


@dataclass(frozen=True, slots=True)
class ToolError:
    code: ErrorCode
    message: str
    retryable: bool = False
    details: dict[str, Any] = field(default_factory=dict)
    retry_after: float | None = None

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"code": self.code.value, "message": self.message}
        if self.retryable:
            out["retryable"] = True
        if self.retry_after is not None:
            out["retry_after_seconds"] = round(self.retry_after, 1)
        out.update(self.details)
        return out


@dataclass(frozen=True, slots=True)
class ResultMeta:
    truncated: bool = False
    omitted: tuple[Omission, ...] = ()
    redacted: int = 0
    warnings: tuple[str, ...] = ()
    next_cursor: str | None = None
    items_returned: int | None = None
    items_total: int | None = None
    estimated_tokens: int | None = None
    source: dict[str, Any] = field(default_factory=dict)

    def to_dict(self) -> dict[str, Any]:
        out: dict[str, Any] = {"truncated": self.truncated}
        if self.omitted:
            out["omitted"] = [o.to_dict() for o in self.omitted]
        if self.redacted:
            out["redacted"] = self.redacted
        if self.warnings:
            out["warnings"] = list(self.warnings)
        if self.items_returned is not None:
            out["items_returned"] = self.items_returned
        if self.items_total is not None:
            out["items_in_upstream_page"] = self.items_total
        if self.next_cursor is not None:
            out["next_cursor"] = self.next_cursor
        if self.source:
            out["source"] = self.source
        return out


@dataclass(frozen=True, slots=True)
class ToolResult:
    """Outcome of one tool call."""

    ok: bool
    tool: str
    data: Any = None
    meta: ResultMeta = field(default_factory=ResultMeta)
    error: ToolError | None = None
    approval: PendingApproval | None = None
    http_status: int | None = None
    duration_ms: float | None = None
    call_id: str | None = None

    def to_model(self) -> dict[str, Any]:
        """The model-visible envelope. Contains no credentials or host-only data."""
        if self.ok:
            return {"ok": True, "data": self.data, "meta": self.meta.to_dict()}
        assert self.error is not None
        return {"ok": False, "error": self.error.to_dict()}

    def to_json(self) -> str:
        """Compact JSON of :meth:`to_model`, ready for a tool-result message."""
        return to_json(self.to_model())

    @property
    def needs_approval(self) -> bool:
        return self.approval is not None
