"""M3: replay protection fails closed and never forgets a live key."""

from __future__ import annotations

import asyncio
import threading
import time

import pytest

from toolbound import (
    ErrorCode,
    MemoryStateStore,
    MockResponse,
    Operation,
    Service,
    StateStoreError,
)

SVC = Service(name="api", base_url="https://api.example.com")
WRITE = Operation(name="w", description="d", service=SVC, method="POST", path="/w")
DROP = Operation(
    name="drop",
    description="d",
    service=SVC,
    method="DELETE",
    path="/d/{id}",
    input={"id": {"type": "integer"}},
)


async def test_m3_full_store_refuses_instead_of_evicting_live_keys():
    """The original failure: a flood evicted approval:A, so it could be claimed again."""
    store = MemoryStateStore(max_entries=3)
    assert await store.claim("approval:A", 600)
    for i in range(2):
        assert await store.claim(f"call:{i}", 600)
    with pytest.raises(StateStoreError):
        await store.claim("call:flood", 600)
    assert await store.claim("approval:A", 600) is False  # still remembered


async def test_m3_expired_keys_are_reclaimed():
    store = MemoryStateStore(max_entries=2)
    assert await store.claim("a", 0.01)
    assert await store.claim("b", 0.01)
    await asyncio.sleep(0.03)
    assert await store.claim("c", 60)
    assert len(store) == 1


async def test_m3_full_store_blocks_the_call_not_the_check(make_gateway, mock, ctx):
    mock.route("POST", "https://api.example.com/w", {"ok": 1})
    gw = make_gateway(state=MemoryStateStore(max_entries=1)).register(WRITE)
    assert (await gw.call("w", {}, ctx=ctx, call_id="1")).ok
    blocked = await gw.call("w", {}, ctx=ctx, call_id="2")
    assert blocked.error.code is ErrorCode.INTERNAL_ERROR
    assert "not executed" in blocked.error.message
    assert len(mock.requests) == 1


class BrokenStore:
    async def claim(self, key: str, ttl_seconds: float) -> bool:
        raise ConnectionError("redis down")


async def test_m3_store_outage_fails_closed_for_call_ids(make_gateway, mock, ctx):
    mock.route("POST", "https://api.example.com/w", {"ok": 1})
    gw = make_gateway(state=BrokenStore()).register(WRITE)
    result = await gw.call("w", {}, ctx=ctx, call_id="1")
    assert not result.ok
    assert mock.requests == []


async def test_m3_store_outage_fails_closed_for_approvals(make_gateway, mock, ctx):
    mock.route("DELETE", "https://api.example.com/d/{id}", MockResponse(204))
    gw = make_gateway(state=BrokenStore()).register(DROP)
    pending = (await gw.call("drop", {"id": 1}, ctx=ctx)).approval
    result = await gw.resume(pending, ctx=ctx, approved_by="alice")
    assert not result.ok
    assert mock.requests == []


def test_m3_store_is_thread_safe():
    store = MemoryStateStore()
    wins: list[bool] = []
    barrier = threading.Barrier(16)

    def worker() -> None:
        barrier.wait()
        wins.append(asyncio.run(store.claim("same-key", 60)))

    threads = [threading.Thread(target=worker) for _ in range(16)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert wins.count(True) == 1


async def test_m3_eviction_is_not_quadratic():
    store = MemoryStateStore(max_entries=200_000)
    started = time.perf_counter()
    for i in range(50_000):
        await store.claim(f"k{i}", 600)
    assert time.perf_counter() - started < 5
