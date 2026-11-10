"""Default in-memory :class:`~toolbound.core.ports.StateStore`."""

from __future__ import annotations

import asyncio
import time
from collections import OrderedDict


class MemoryStateStore:
    """Per-process TTL set. Suitable for a single worker or for tests.

    With several processes, replay protection needs a shared store; see
    ``docs/security.md`` for a Redis recipe.
    """

    def __init__(self, *, max_entries: int = 100_000) -> None:
        self._entries: OrderedDict[str, float] = OrderedDict()
        self._max = max_entries
        self._lock = asyncio.Lock()

    async def claim(self, key: str, ttl_seconds: float) -> bool:
        async with self._lock:
            now = time.monotonic()
            self._evict(now)
            expiry = self._entries.get(key)
            if expiry is not None and expiry > now:
                return False
            self._entries[key] = now + ttl_seconds
            self._entries.move_to_end(key)
            while len(self._entries) > self._max:
                self._entries.popitem(last=False)
            return True

    def _evict(self, now: float) -> None:
        stale = [k for k, exp in self._entries.items() if exp <= now]
        for key in stale[:1000]:
            del self._entries[key]
