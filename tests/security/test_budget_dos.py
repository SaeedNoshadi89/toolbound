"""H3: a large upstream response cannot stall the event loop."""

from __future__ import annotations

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


async def test_h3_large_results_are_processed_off_the_event_loop(
    make_gateway, mock, ctx, monkeypatch
):
    """Deterministic: decoding and shaping of a large body run in a worker thread,
    small bodies stay inline. (A wall-clock lag threshold was flaky on slow CI.)"""
    import json
    import threading

    from toolbound.core import gateway as gateway_module

    threads: list[str] = []
    real_process, real_decode = gateway_module.process, gateway_module._decode_body

    def spy_process(*args, **kwargs):
        threads.append(f"process:{threading.current_thread() is threading.main_thread()}")
        return real_process(*args, **kwargs)

    def spy_decode(*args, **kwargs):
        threads.append(f"decode:{threading.current_thread() is threading.main_thread()}")
        return real_decode(*args, **kwargs)

    monkeypatch.setattr(gateway_module, "process", spy_process)
    monkeypatch.setattr(gateway_module, "_decode_body", spy_decode)
    mock.route(
        "GET",
        "https://api.example.com/big",
        MockResponse(
            200, body=json.dumps(BIG).encode(), headers={"Content-Type": "application/json"}
        ),
    )
    mock.route("GET", "https://api.example.com/small", {"ok": True})
    gw = make_gateway().register(
        Operation(
            name="big", description="d", service=SVC, path="/big", output=Output(max_tokens=2000)
        ),
        Operation(name="small", description="d", service=SVC, path="/small"),
    )
    await gw.call("big", {}, ctx=ctx)
    assert threads == ["decode:False", "process:False"]
    threads.clear()
    await gw.call("small", {}, ctx=ctx)
    assert threads == ["decode:True", "process:True"]
