# Benchmarks

All numbers on this page were produced by [`benchmarks/run.py`](../benchmarks/run.py) and
are stored in [`benchmarks/results/latest.json`](../benchmarks/results/latest.json).
**No language model was called.** Nothing was estimated by hand.

```bash
uv run python benchmarks/run.py                   # byte estimates only
uv run --with tiktoken python benchmarks/run.py   # adds tokenizer counts (o200k_base)
```

**Environment of the published run:** Apple M4 Pro (12 cores), macOS, CPython 3.13.15,
toolbound 0.2.0, tiktoken 0.14.0 with `o200k_base`, 2026-11-10.

## Method and caveats

- **Fixtures are synthetic** (`benchmarks/fixtures.py`, fixed random seeds). The issue list
  uses the field names and nesting of the GitHub REST issue object, with generated values.
  The legal fixture is generated Persian text. Real payloads will differ.
- **Token counts use `o200k_base`**, an OpenAI tokenizer. Other model families (including
  Claude) tokenize differently, so treat the counts as relative, not exact. Run the script
  with your own tokenizer for your model.
- **Shaping is lossy by design.** Each row reports whether the `required` (evidence)
  fields survived and whether more data is reachable through a cursor. Fewer tokens are
  only better when the dropped fields were not needed for the task. We did not measure
  answer quality with a model.
- Latency is measured on loopback, so it shows Toolbound's own overhead, not network time.
- Not measured (would need model calls): end-to-end agent token usage, tool-selection
  accuracy by exposure strategy, and comparison with an equivalent third-party MCP server.

## Results

### Payload size: raw upstream JSON vs shaped result

| Case | Raw bytes | Raw tokens | Shaped bytes | Shaped tokens | Items returned | Required fields kept | More via cursor |
|---|---:|---:|---:|---:|---:|:---:|:---:|
| GitHub-shaped issue list (30 items) | 105,902 | 25,936 | 12,898 | 2,717 (90% fewer) | 30/30 | yes | n/a |
| same, with 1,500-token budget | 105,902 | 25,936 | 4,212 | 894 (97% fewer) | 10/30 | yes | yes |
| Persian legal search (20 rulings) | 132,276 | 23,587 | 26,583 | 4,910 (79% fewer) | 20/20 | yes | n/a |

Shapes used: issues keep `number, title, state, author, labels, comments` and the first
280 characters of `body`. Rulings keep `doc_id, court, date, title` and a 600-character
excerpt.

"Shaped tokens" counts the `data` the model receives. The **full envelope** sent to the
model (`ToolResult.to_json()`, data + `meta`) measured 2,778, 1,124 and 4,971 tokens for the
three rows. The middle row is larger because it includes an encrypted `next_cursor`
(154 tokens on its own).

**Independent check.** These counts were reproduced with a separate script that goes
through the public `Gateway` API with a mock upstream and counts with `tiktoken`
directly, not with the benchmark's helpers. Both give identical numbers. The fixtures use
fixed seeds, so re-running `benchmarks/run.py` reproduces the token counts exactly.

### Default `ByteEstimator` vs a real tokenizer

| Sample | Tokenizer | ByteEstimator | Estimate / real | Bytes per token |
|---|---:|---:|---:|---:|
| English JSON (GitHub-shaped) | 25,936 | 35,301 | 1.36 | 4.08 |
| Persian JSON (legal) | 23,587 | 44,092 | 1.87 | 5.61 |
| Shaped English result | 2,717 | 4,300 | 1.58 | 4.75 |

The default estimator **over-counts** (by design), so budgets are conservative: a
2,000-token budget typically yields about 1,100–1,500 real `o200k` tokens. If you need
tighter packing, use `TiktokenEstimator` or an estimator for your model.

### Tool-definition size

| Tools registered | Strategy | Definitions sent | Bytes | Tokens |
|---:|---|---:|---:|---:|
| 1 | generic `http_request` tool (reference) | 1 | 283 | 67 |
| 10 | direct | 10 | 3,351 | 852 |
| 10 | grouped | 2 | 1,893 | 558 |
| 50 | direct | 50 | 16,831 | 4,252 |
| 50 | grouped | 10 | 9,581 | 2,782 |
| 200 | direct | 200 | 67,581 | 17,002 |
| 200 | grouped | 40 | 38,771 | 11,122 |

Synthetic operations have three arguments each, and groups have five operations.
Observations:

- Narrow tools cost more definition tokens than one generic tool. That is the price of
  least privilege. The generic tool lets the model pick any URL and returns raw bodies,
  which typically costs far more in result tokens (see the payload table).
- `grouped` cuts definition tokens by about 35% here. The trade-off: the model sees each
  action's arguments as a one-line summary instead of a full schema (the gateway still
  validates against the full schema). Whether that changes tool-selection accuracy for
  your model has **not** been measured.
- Filtering by user and task (`required_scopes`, `visibility=`, `tags=`) reduces
  definitions further and is usually the bigger lever.

### Overhead

| Measurement | Median | p95 |
|---|---:|---:|
| Pipeline only: mock transport, 30-issue payload (105 KB), 500 calls | 0.911 ms | 1.024 ms |
| Raw `httpx` GET + `json()` against a local server, 300 calls | 0.864 ms | 1.046 ms |
| Toolbound call (validation, policy, DNS check, IP pinning, shaping), same server | 1.442 ms | 1.687 ms |

Median added latency over raw httpx: **0.578 ms** per call for this payload. Most of it
is JSON decoding plus shaping of a 105 KB body, so the cost grows with payload size.

**Memory:** shaping 2,000 issues (7.1 MB of JSON, already in memory) to a 50-item,
2,000-token result peaked at **178 KB** of additional traced allocations
(`tracemalloc`). This excludes the input itself. The transport buffers up to
`max_response_bytes` per response.

**Worst-case trimming (added in 0.2):** a hostile 4.8 MB pass-through object (1,200 strings
of 4,000 characters) against a 2,000-token budget is rejected with `result_too_large` in
**0.118 s**. In 0.1 the same input took about 8 s of CPU **on the event loop** before
failing. Bodies over 256 KB are now also decoded and shaped in a worker thread.

**0.1 → 0.2 comparison** (same machine and fixtures): payload, estimator and
tool-definition numbers are unchanged. Pipeline-only median 1.173 → 0.911 ms and
end-to-end added latency 0.864 → 0.578 ms: 0.2 is *faster*, because the
secret-detection regex was rewritten (one shared lookbehind instead of per-branch anchors)
while fixing its quadratic worst case. An intermediate fix without that rewrite measured
1.45 ms.
