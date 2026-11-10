"""Shared helpers for provider adapters (no third-party imports)."""

from __future__ import annotations

import asyncio
import json
from collections.abc import Sequence
from dataclasses import dataclass, field
from typing import Any

from toolbound.core.approval import PendingApproval
from toolbound.core.context import ExecutionContext
from toolbound.core.errors import ErrorCode
from toolbound.core.gateway import Gateway
from toolbound.core.result import ToolError, ToolResult


def get(obj: Any, key: str, default: Any = None) -> Any:
    """Read ``key`` from a dict or an SDK object."""
    if isinstance(obj, dict):
        return obj.get(key, default)
    return getattr(obj, key, default)


@dataclass(slots=True)
class Call:
    id: str
    name: str
    arguments: Any
    parse_error: str | None = None


def parse_json_arguments(raw: Any) -> tuple[Any, str | None]:
    if isinstance(raw, dict):
        return raw, None
    if raw is None or raw == "":
        return {}, None
    if isinstance(raw, str):
        try:
            return json.loads(raw), None
        except ValueError:
            return None, "tool arguments were not valid JSON"
    return None, "tool arguments must be a JSON object"


@dataclass(slots=True)
class ToolCallBatch:
    """Results of executing one model turn's tool calls.

    ``messages`` (or ``blocks``) are ready to append to the conversation.
    ``results`` holds the full :class:`ToolResult` objects for host code, and
    ``pending_approvals`` lists calls waiting for a human decision.
    """

    results: list[ToolResult] = field(default_factory=list)
    blocks: list[dict[str, Any]] = field(default_factory=list)

    @property
    def pending_approvals(self) -> list[PendingApproval]:
        return [r.approval for r in self.results if r.approval is not None]


async def execute_calls(
    gateway: Gateway, calls: Sequence[Call], ctx: ExecutionContext, *, parallel: bool
) -> list[ToolResult]:
    async def one(call: Call) -> ToolResult:
        if call.parse_error is not None:
            return ToolResult(
                ok=False,
                tool=call.name,
                error=ToolError(ErrorCode.INVALID_ARGUMENTS, call.parse_error),
                call_id=call.id,
            )
        return await gateway.call(call.name, call.arguments, ctx=ctx, call_id=call.id)

    if parallel:
        return list(await asyncio.gather(*(one(c) for c in calls)))
    return [await one(c) for c in calls]
