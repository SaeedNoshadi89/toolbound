"""Blocking wrapper for code that is not async (scripts, sync frameworks)."""

from __future__ import annotations

import asyncio
import threading
from collections.abc import Coroutine, Mapping
from typing import Any, TypeVar

from toolbound.core.approval import PendingApproval
from toolbound.core.context import ExecutionContext
from toolbound.core.gateway import Gateway
from toolbound.core.result import ToolResult

T = TypeVar("T")


class SyncGateway:
    """Runs a :class:`Gateway` on a private event-loop thread.

    ``with SyncGateway(gateway) as gw: gw.call("get_issue", {...}, ctx=ctx)``.
    Do not use from inside a running event loop; use the async API there.
    """

    def __init__(self, gateway: Gateway) -> None:
        self.gateway = gateway
        self._loop = asyncio.new_event_loop()
        self._thread = threading.Thread(
            target=self._loop.run_forever, daemon=True, name="toolbound-sync"
        )
        self._thread.start()

    def _run(self, coro: Coroutine[Any, Any, T]) -> T:
        return asyncio.run_coroutine_threadsafe(coro, self._loop).result()

    def call(
        self,
        name: str,
        arguments: Mapping[str, Any] | None,
        *,
        ctx: ExecutionContext,
        call_id: str | None = None,
        approval: str | None = None,
    ) -> ToolResult:
        return self._run(
            self.gateway.call(name, arguments, ctx=ctx, call_id=call_id, approval=approval)
        )

    def resume(
        self, pending: PendingApproval, *, ctx: ExecutionContext, approved_by: str
    ) -> ToolResult:
        return self._run(self.gateway.resume(pending, ctx=ctx, approved_by=approved_by))

    def close(self) -> None:
        if self._loop.is_closed():
            return
        self._run(self.gateway.aclose())
        self._loop.call_soon_threadsafe(self._loop.stop)
        self._thread.join(timeout=5)
        self._loop.close()

    def __enter__(self) -> SyncGateway:
        return self

    def __exit__(self, *exc: object) -> None:
        self.close()
