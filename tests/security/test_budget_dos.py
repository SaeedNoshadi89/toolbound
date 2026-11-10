"""H3: a large upstream response cannot stall the event loop."""

from __future__ import annotations

import asyncio
import time

import pytest

from toolbound import ByteEstimator, ErrorCode, MockResponse, Operation, Output, Service
from toolbound.core.errors import ToolFailure
from toolbound.core.shaping import compile_output, process

SVC = Service(name="api", base_url="https://api.example.com")
BIG = {f"k{i}": "x" * 3999 for i in range(1200)}  # ~4.8 MB, under the 5 MB response cap


def test_h3_trimming_large_passthrough_is_bounded():
    """The original failure took 8 s of CPU; it must now finish quickly."""
    started = time.perf_counter()
    with pytest.raises(ToolFailure) as info:  # nothing fits: fails fast instead of spinning
        process(compile_output(Output(max_tokens=2000)), BIG, estimator=ByteEstimator())
    assert info.value.code is ErrorCode.RESULT_TOO_LARGE
    assert time.perf_counter() - started < 2.0


def test_h3_single_huge_field_still_trims():
    out = process(
        compile_output(Output(max_tokens=200, max_chars=100_000)),
        {"id": "A-1", "text": "x" * 50_000},
        estimator=ByteEstimator(),
    )
    assert out.data["id"] == "A-1"
    assert out.estimated_tokens <= 200


async def test_h3_event_loop_keeps_running_during_large_result(make_gateway, mock, ctx):
    import json

    body = json.dumps(BIG).encode()
    mock.route(
        "GET",
        "https://api.example.com/big",
        MockResponse(200, body=body, headers={"Content-Type": "application/json"}),
    )
    op = Operation(
        name="big", description="d", service=SVC, path="/big", output=Output(max_tokens=2000)
    )
    gw = make_gateway().register(op)

    lag = 0.0
    stop = False

    async def ticker() -> None:
        nonlocal lag
        loop = asyncio.get_running_loop()
        while not stop:
            before = loop.time()
            await asyncio.sleep(0.005)
            lag = max(lag, loop.time() - before - 0.005)

    task = asyncio.create_task(ticker())
    await asyncio.sleep(0)
    await gw.call("big", {}, ctx=ctx)
    stop = True
    await task
    # Offloaded: ~16 ms on the reference machine; on the event loop: ~110 ms.
    assert lag < 0.06, f"event loop blocked for {lag:.3f}s"
