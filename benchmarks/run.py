"""Reproducible local benchmarks. No model calls; nothing here is estimated by hand.

    uv run python benchmarks/run.py                    # byte-based token estimates only
    uv run --with tiktoken python benchmarks/run.py    # adds real tokenizer counts (o200k_base)

Writes benchmarks/results/latest.json and prints a Markdown report.
"""

from __future__ import annotations

import asyncio
import json
import os
import platform
import statistics
import sys
import threading
import time
import tracemalloc
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from typing import Any

sys.path.insert(0, str(Path(__file__).parent))

import httpx
from fixtures import github_issues, legal_documents

from toolbound import (
    ByteEstimator,
    ExecutionContext,
    Field,
    Gateway,
    MockTransport,
    NetworkPolicy,
    Operation,
    Output,
    Service,
    allow_all,
)
from toolbound.core.budget import to_json
from toolbound.core.errors import ToolFailure
from toolbound.core.shaping import compile_output, process
from toolbound.transport import SecureTransport

RESULTS = Path(__file__).parent / "results"
BYTE = ByteEstimator()
CTX = ExecutionContext(actor="bench")

try:
    import tiktoken

    _ENC = tiktoken.get_encoding("o200k_base")

    def real_tokens(text: str) -> int | None:
        return len(_ENC.encode(text, disallowed_special=()))

    TOKENIZER = f"tiktoken {tiktoken.__version__} o200k_base"
except Exception:

    def real_tokens(text: str) -> int | None:
        return None

    TOKENIZER = None


def tokens(text: str) -> dict[str, int | None]:
    return {
        "bytes": len(text.encode()),
        "byte_estimate": BYTE.count(text),
        "tokenizer": real_tokens(text),
    }


ISSUE_OUTPUT = Output(
    shape={
        "number": "number",
        "title": "title",
        "state": "state",
        "author": "user.login",
        "labels": "labels[].name",
        "comments": "comments",
        "body": Field("body", max_chars=280),
    },
    required=("number", "title", "state"),
    max_items=30,
    max_tokens=None,
)
ISSUE_OUTPUT_BUDGET = Output(
    shape=dict(ISSUE_OUTPUT.shape or {}),
    required=("number", "title", "state"),
    max_items=30,
    max_tokens=1500,
    continuation=True,
)
LEGAL_OUTPUT = Output(
    root="results",
    shape={
        "doc_id": "doc_id",
        "court": "court",
        "date": "date",
        "title": "title",
        "excerpt": Field("text", max_chars=600),
    },
    required=("doc_id", "date"),
    max_items=20,
    max_tokens=None,
)


def bench_payloads() -> list[dict[str, Any]]:
    rows = []
    cases = [
        (
            "GitHub-shaped issue list (30 items)",
            github_issues(30),
            ISSUE_OUTPUT,
            ("number", "title", "state"),
        ),
        (
            "same, with 1,500-token budget",
            github_issues(30),
            ISSUE_OUTPUT_BUDGET,
            ("number", "title", "state"),
        ),
        (
            "Persian legal search (20 rulings)",
            legal_documents(20),
            LEGAL_OUTPUT,
            ("doc_id", "date"),
        ),
    ]
    for label, raw, output, required in cases:
        raw_text = to_json(raw)
        shaped = process(compile_output(output), raw, estimator=BYTE)
        shaped_text = to_json(shaped.data)
        items = shaped.data if isinstance(shaped.data, list) else []
        upstream_items = raw if isinstance(raw, list) else raw["results"]
        retained = all(all(k in item for k in required) for item in items)
        rows.append(
            {
                "case": label,
                "raw": tokens(raw_text),
                "shaped": tokens(shaped_text),
                "items_upstream": len(upstream_items),
                "items_returned": len(items),
                "continuation_cursor": shaped.next_offset is not None,
                "required_fields_retained": retained,
                "omitted": [o.to_dict() for o in shaped.report.omissions()],
            }
        )
    return rows


def bench_estimator() -> list[dict[str, Any]]:
    if TOKENIZER is None:
        return []
    samples = {
        "English JSON (GitHub-shaped)": to_json(github_issues(30)),
        "Persian JSON (legal)": to_json(legal_documents(20)),
        "Shaped English result": to_json(
            process(compile_output(ISSUE_OUTPUT), github_issues(30), estimator=BYTE).data
        ),
    }
    out = []
    for label, text in samples.items():
        real = real_tokens(text) or 1
        est = BYTE.count(text)
        out.append(
            {
                "sample": label,
                "tokenizer": real,
                "byte_estimate": est,
                "estimate_over_real": round(est / real, 2),
                "bytes_per_token": round(len(text.encode()) / real, 2),
            }
        )
    return out


def _synthetic_ops(n: int) -> list[Operation]:
    service = Service(name="svc", base_url="https://api.example.com")
    ops = []
    for i in range(n):
        group = f"resource_{i // 5}"
        ops.append(
            Operation(
                name=f"op_{i}",
                description=f"Get or search records of kind {i} by id and filters.",
                service=service,
                path=f"/r{i}/{{id}}",
                group=group,
                input={
                    "id": {"type": "string", "maxLength": 64},
                    "status": {"enum": ["open", "closed"], "default": "open"},
                    "limit": {"type": "integer", "minimum": 1, "maximum": 100, "default": 20},
                },
            )
        )
    return ops


GENERIC_HTTP_TOOL = {
    "name": "http_request",
    "description": "Send an HTTP request to any URL and return the response body.",
    "input_schema": {
        "type": "object",
        "properties": {
            "method": {"type": "string"},
            "url": {"type": "string"},
            "headers": {"type": "object"},
            "body": {"type": "string"},
        },
        "required": ["method", "url"],
    },
}


def bench_definitions() -> list[dict[str, Any]]:
    rows = [
        {
            "tools_registered": 1,
            "strategy": "generic http_request tool (reference)",
            "definitions": 1,
            **tokens(to_json([GENERIC_HTTP_TOOL])),
        }
    ]
    for n in (10, 50, 200):
        gw = Gateway(authorize=allow_all, secret=b"b" * 32).register(*_synthetic_ops(n))
        for strategy in ("direct", "grouped"):
            defs = [d.to_dict() for d in gw.definitions(CTX, strategy=strategy)]  # type: ignore[arg-type]
            rows.append(
                {
                    "tools_registered": n,
                    "strategy": strategy,
                    "definitions": len(defs),
                    **tokens(to_json(defs)),
                }
            )
    return rows


def _percentiles(samples: list[float]) -> dict[str, float]:
    samples = sorted(samples)
    return {
        "median_ms": round(statistics.median(samples), 3),
        "p95_ms": round(samples[int(len(samples) * 0.95) - 1], 3),
    }


async def bench_pipeline(iterations: int = 500) -> dict[str, Any]:
    mock = MockTransport().route("GET", "https://api.example.com/issues", github_issues(30))
    service = Service(name="svc", base_url="https://api.example.com")
    op = Operation(
        name="list", description="d", service=service, path="/issues", output=ISSUE_OUTPUT
    )
    gw = Gateway(authorize=allow_all, transport=mock, secret=b"b" * 32).register(op)
    for _ in range(20):
        await gw.call("list", {}, ctx=CTX)
    samples = []
    for _ in range(iterations):
        start = time.perf_counter()
        result = await gw.call("list", {}, ctx=CTX)
        samples.append((time.perf_counter() - start) * 1000)
        assert result.ok
    return {
        "iterations": iterations,
        "payload_bytes": len(to_json(github_issues(30))),
        **_percentiles(samples),
    }


class _Handler(BaseHTTPRequestHandler):
    BODY = to_json(github_issues(30)).encode()

    def log_message(self, *args: object) -> None:
        pass

    def do_GET(self) -> None:
        self.send_response(200)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(self.BODY)))
        self.end_headers()
        self.wfile.write(self.BODY)


async def bench_end_to_end(iterations: int = 300) -> dict[str, Any]:
    server = ThreadingHTTPServer(("127.0.0.1", 0), _Handler)
    threading.Thread(target=server.serve_forever, daemon=True).start()
    port = server.server_address[1]
    url = f"http://127.0.0.1:{port}/issues"
    try:
        async with httpx.AsyncClient(trust_env=False) as client:
            raw = []
            for i in range(iterations + 20):
                start = time.perf_counter()
                response = await client.get(url)
                response.json()
                if i >= 20:
                    raw.append((time.perf_counter() - start) * 1000)
        service = Service(
            name="local",
            base_url=f"http://127.0.0.1:{port}",
            network=NetworkPolicy(
                allow_http=True,
                allow_hosts=("127.0.0.1",),
                allow_ports=(port,),
                allow_networks=("127.0.0.1/32",),
            ),
        )
        op = Operation(
            name="list", description="d", service=service, path="/issues", output=ISSUE_OUTPUT
        )
        async with Gateway(
            authorize=allow_all, transport=SecureTransport(), secret=b"b" * 32
        ).register(op) as gw:
            shaped = []
            for i in range(iterations + 20):
                start = time.perf_counter()
                result = await gw.call("list", {}, ctx=CTX)
                if i >= 20:
                    shaped.append((time.perf_counter() - start) * 1000)
                assert result.ok
    finally:
        server.shutdown()
    raw_p, tb_p = _percentiles(raw), _percentiles(shaped)
    return {
        "iterations": iterations,
        "raw_httpx_get_and_json": raw_p,
        "toolbound_call_with_shaping": tb_p,
        "median_overhead_ms": round(tb_p["median_ms"] - raw_p["median_ms"], 3),
    }


def bench_memory() -> dict[str, Any]:
    big = github_issues(2000)
    raw_bytes = len(to_json(big))
    compiled = compile_output(
        Output(shape=dict(ISSUE_OUTPUT.shape or {}), max_items=50, max_tokens=2000)
    )
    tracemalloc.start()
    process(compiled, big, estimator=BYTE)
    _, peak = tracemalloc.get_traced_memory()
    tracemalloc.stop()
    return {
        "input_items": len(big),
        "input_json_bytes": raw_bytes,
        "peak_traced_bytes_during_shaping": peak,
    }


def bench_worst_case_trim() -> dict[str, Any]:
    """Adversarial output: a ~4.8 MB pass-through object of 1,200 long strings.

    Before 0.2 this took about 8 s of event-loop CPU on the reference machine and then
    failed anyway. It is now bounded, and large results are shaped off the event loop.
    """
    big = {f"k{i}": "x" * 3999 for i in range(1200)}
    compiled = compile_output(Output(max_tokens=2000))
    started = time.perf_counter()
    outcome = "ok"
    try:
        process(compiled, big, estimator=BYTE)
    except ToolFailure as failure:
        outcome = failure.code.value
    return {
        "input_json_bytes": len(to_json(big)),
        "seconds": round(time.perf_counter() - started, 3),
        "outcome": outcome,
    }


def environment() -> dict[str, Any]:
    import toolbound

    return {
        "toolbound": toolbound.__version__,
        "python": platform.python_version(),
        "implementation": platform.python_implementation(),
        "machine": platform.machine(),
        "system": platform.system(),
        "cpu_count": os.cpu_count(),
        "tokenizer": TOKENIZER or "not installed (byte estimates only)",
        "date": time.strftime("%Y-%m-%d"),
    }


def report(results: dict[str, Any]) -> str:
    lines = [
        f"Environment: {json.dumps(results['environment'])}",
        "",
        "### Payload size: raw upstream JSON vs shaped result",
        "",
        "| Case | Raw bytes | Raw tokens* | Shaped bytes | Shaped tokens* | Items returned "
        "| Required fields kept | More via cursor |",
        "|---|---:|---:|---:|---:|---:|:---:|:---:|",
    ]
    for row in results["payloads"]:
        raw, shaped = row["raw"], row["shaped"]
        rt = raw["tokenizer"] or raw["byte_estimate"]
        st = shaped["tokenizer"] or shaped["byte_estimate"]
        lines.append(
            f"| {row['case']} | {raw['bytes']:,} | {rt:,} | {shaped['bytes']:,} | {st:,} "
            f"({(1 - st / rt) * 100:.0f}% fewer) | {row['items_returned']}/{row['items_upstream']} "
            f"| {'yes' if row['required_fields_retained'] else 'NO'} "
            f"| {'yes' if row['continuation_cursor'] else 'n/a'} |"
        )
    unit = "tokenizer tokens" if TOKENIZER else "byte-estimated tokens"
    lines += ["", f"*{unit}.", ""]
    if results["estimator"]:
        lines += [
            "### Default ByteEstimator vs real tokenizer",
            "",
            "| Sample | Tokenizer | ByteEstimator | Estimate / real | Bytes per token |",
            "|---|---:|---:|---:|---:|",
        ]
        for row in results["estimator"]:
            lines.append(
                f"| {row['sample']} | {row['tokenizer']:,} | {row['byte_estimate']:,} "
                f"| {row['estimate_over_real']} | {row['bytes_per_token']} |"
            )
        lines.append("")
    lines += [
        "### Tool-definition size",
        "",
        "| Tools registered | Strategy | Definitions sent | Bytes | Tokens* |",
        "|---:|---|---:|---:|---:|",
    ]
    for row in results["definitions"]:
        t = row["tokenizer"] or row["byte_estimate"]
        lines.append(
            f"| {row['tools_registered']} | {row['strategy']} | {row['definitions']} "
            f"| {row['bytes']:,} | {t:,} |"
        )
    p, e = results["pipeline"], results["end_to_end"]
    lines += [
        "",
        "### Overhead",
        "",
        f"- Pipeline only (mock transport, 30-item payload, {p['iterations']} calls): "
        f"median {p['median_ms']} ms, p95 {p['p95_ms']} ms",
        f"- Local HTTP, {e['iterations']} calls: raw httpx GET+json median "
        f"{e['raw_httpx_get_and_json']['median_ms']} ms (p95 "
        f"{e['raw_httpx_get_and_json']['p95_ms']}); Toolbound call median "
        f"{e['toolbound_call_with_shaping']['median_ms']} ms (p95 "
        f"{e['toolbound_call_with_shaping']['p95_ms']}); median overhead "
        f"{e['median_overhead_ms']} ms",
        f"- Peak traced memory shaping {results['memory']['input_items']:,} issues "
        f"({results['memory']['input_json_bytes']:,} bytes JSON): "
        f"{results['memory']['peak_traced_bytes_during_shaping']:,} bytes",
        f"- Worst-case budget trimming ({results['worst_case_trim']['input_json_bytes']:,} bytes, "
        f"1,200 long strings, 2,000-token budget): {results['worst_case_trim']['seconds']} s, "
        f"outcome `{results['worst_case_trim']['outcome']}`",
    ]
    return "\n".join(lines)


async def main() -> None:
    results = {
        "environment": environment(),
        "payloads": bench_payloads(),
        "estimator": bench_estimator(),
        "definitions": bench_definitions(),
        "pipeline": await bench_pipeline(),
        "end_to_end": await bench_end_to_end(),
        "memory": bench_memory(),
        "worst_case_trim": bench_worst_case_trim(),
    }
    RESULTS.mkdir(exist_ok=True)
    (RESULTS / "latest.json").write_text(json.dumps(results, indent=2, ensure_ascii=False))
    print(report(results))


if __name__ == "__main__":
    asyncio.run(main())
