"""In-memory sliding-window rate limiting (per process, thread-safe)."""

from __future__ import annotations

import json
import threading
import time
from collections import deque

from .context import ExecutionContext
from .contracts import RateLimit
from .errors import ErrorCode, ToolFailure

_SWEEP_EVERY = 1024


class RateLimiter:
    """Sliding windows keyed by tool and actor/tenant.

    Idle windows are removed, so memory stays proportional to the number of
    recently active callers rather than growing forever.
    """

    def __init__(self) -> None:
        self._windows: dict[str, tuple[float, deque[float]]] = {}
        self._lock = threading.Lock()
        self._checks = 0

    def __len__(self) -> int:
        return len(self._windows)

    def check(self, tool: str, limit: RateLimit, ctx: ExecutionContext) -> None:
        # JSON keeps None and "None" apart, and actors are qualified by tenant.
        if limit.scope == "actor":
            scope = "a:" + json.dumps([ctx.tenant, ctx.actor])
        elif limit.scope == "tenant":
            scope = "t:" + json.dumps(ctx.tenant)
        else:
            scope = "g"
        key = f"{tool}|{scope}"
        now = time.monotonic()
        with self._lock:
            self._checks += 1
            if self._checks % _SWEEP_EVERY == 0:
                self._sweep(now)
            entry = self._windows.get(key)
            window = entry[1] if entry is not None else deque()
            while window and window[0] <= now - limit.per_seconds:
                window.popleft()
            if len(window) >= limit.calls:
                retry_after = max(0.0, window[0] + limit.per_seconds - now)
                raise ToolFailure(
                    ErrorCode.RATE_LIMITED,
                    f"rate limit reached for this tool ({limit.calls} calls per "
                    f"{limit.per_seconds:g}s)",
                    retry_after=retry_after,
                    request_sent=False,
                )
            window.append(now)
            self._windows[key] = (limit.per_seconds, window)

    def _sweep(self, now: float) -> None:
        idle = [k for k, (period, w) in self._windows.items() if not w or w[-1] <= now - period]
        for key in idle:
            del self._windows[key]
