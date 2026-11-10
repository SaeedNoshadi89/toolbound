"""In-memory sliding-window rate limiting (per process)."""

from __future__ import annotations

import time
from collections import deque

from .context import ExecutionContext
from .contracts import RateLimit
from .errors import ErrorCode, ToolFailure


class RateLimiter:
    def __init__(self) -> None:
        self._windows: dict[str, deque[float]] = {}

    def check(self, tool: str, limit: RateLimit, ctx: ExecutionContext) -> None:
        if limit.scope == "actor":
            scope = f"a:{ctx.actor}"
        elif limit.scope == "tenant":
            scope = f"t:{ctx.tenant}"
        else:
            scope = "g"
        key = f"{tool}|{scope}"
        now = time.monotonic()
        window = self._windows.setdefault(key, deque())
        while window and window[0] <= now - limit.per_seconds:
            window.popleft()
        if len(window) >= limit.calls:
            retry_after = max(0.0, window[0] + limit.per_seconds - now)
            raise ToolFailure(
                ErrorCode.RATE_LIMITED,
                f"rate limit reached for this tool ({limit.calls} calls per "
                f"{limit.per_seconds:g}s)",
                retry_after=retry_after,
            )
        window.append(now)
