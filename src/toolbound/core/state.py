"""Default in-memory :class:`~toolbound.core.ports.StateStore`, and claim helpers."""

from __future__ import annotations

import heapq
import logging
import threading
import time

from .errors import ErrorCode, StateStoreError, ToolFailure
from .ports import StateStore

logger = logging.getLogger("toolbound")


class MemoryStateStore:
    """Per-process TTL set. Suitable for a single worker or for tests.

    It never forgets a key before its TTL expires: when ``max_entries`` live
    keys exist, new claims raise :class:`StateStoreError` and Toolbound refuses
    the call (fail closed) instead of evicting a live key, which would let an
    approval or call id be used twice.

    Keys are partitioned by their first two ``:``-separated segments. Toolbound's
    keys are ``call:<actor+tenant>:…`` and ``approval:<actor+tenant>:…``, so one
    actor filling its partition (``max_per_partition``) cannot block anyone else.
    ``max_entries`` bounds total memory.

    It is thread-safe and not bound to an event loop. With several processes,
    replay protection needs a shared store; see ``docs/security.md`` for a Redis
    recipe.
    """

    def __init__(self, *, max_entries: int = 200_000, max_per_partition: int = 10_000) -> None:
        if max_entries < 1 or max_per_partition < 1:
            raise ValueError("max_entries and max_per_partition must be at least 1")
        self._entries: dict[str, float] = {}
        self._expiry: list[tuple[float, str]] = []
        self._partitions: dict[str, int] = {}
        self._max = max_entries
        self._max_partition = max_per_partition
        self._lock = threading.Lock()

    async def claim(self, key: str, ttl_seconds: float) -> bool:
        with self._lock:
            now = time.monotonic()
            self._evict(now)
            expiry = self._entries.get(key)
            if expiry is not None and expiry > now:
                return False
            partition = _partition(key)
            if expiry is None and self._partitions.get(partition, 0) >= self._max_partition:
                raise StateStoreError(
                    f"MemoryStateStore partition is full ({self._max_partition} live keys); "
                    "refusing to evict unexpired replay-protection entries"
                )
            if expiry is None and len(self._entries) >= self._max:
                raise StateStoreError(
                    f"MemoryStateStore is full ({self._max} live keys); refusing to evict "
                    "unexpired replay-protection entries"
                )
            deadline = now + ttl_seconds
            if expiry is None:
                self._partitions[partition] = self._partitions.get(partition, 0) + 1
            self._entries[key] = deadline
            heapq.heappush(self._expiry, (deadline, key))
            return True

    def __len__(self) -> int:
        return len(self._entries)

    def _evict(self, now: float) -> None:
        while self._expiry and self._expiry[0][0] <= now:
            deadline, key = heapq.heappop(self._expiry)
            if self._entries.get(key) == deadline:
                del self._entries[key]
                partition = _partition(key)
                left = self._partitions.get(partition, 1) - 1
                if left:
                    self._partitions[partition] = left
                else:
                    self._partitions.pop(partition, None)


def _partition(key: str) -> str:
    return ":".join(key.split(":", 2)[:2])


async def claim_or_fail(store: StateStore, key: str, ttl_seconds: float) -> bool:
    """``store.claim`` that fails closed: any store error stops the call."""
    try:
        return bool(await store.claim(key, ttl_seconds))
    except Exception as exc:
        logger.error("state store claim failed: %s", type(exc).__name__)
        full = isinstance(exc, StateStoreError)
        raise ToolFailure(
            ErrorCode.INTERNAL_ERROR,
            "replay protection is unavailable, so the call was not executed"
            + (" (too many recent calls for this user)" if full else ""),
            retryable=not full,
            request_sent=False,
        ) from None
