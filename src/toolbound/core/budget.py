"""Token estimation.

The default estimator is deterministic and dependency-free. It is an
*approximation*, deliberately conservative (it tends to over-count) so budgets
are rarely exceeded. Plug in a real tokenizer through the
:class:`~toolbound.core.ports.TokenEstimator` port when exact counts matter
(see :class:`toolbound.estimators.TiktokenEstimator`).

Measured accuracy against a real tokenizer is published in ``docs/benchmarks.md``.
"""

from __future__ import annotations

import json
import math
from typing import Any


class ByteEstimator:
    """Estimate tokens as ``ceil(utf8_bytes / bytes_per_token)``.

    The default of 3.0 bytes per token over-estimates typical English JSON
    (closer to ~3.5-4.5 bytes/token for modern tokenizers) and stays
    conservative for non-Latin scripts such as Persian or Arabic, which use 2
    bytes per character in UTF-8 and often tokenize less efficiently.
    """

    def __init__(self, bytes_per_token: float = 3.0) -> None:
        if bytes_per_token <= 0:
            raise ValueError("bytes_per_token must be positive")
        self.bytes_per_token = bytes_per_token

    def count(self, text: str) -> int:
        return math.ceil(len(text.encode("utf-8")) / self.bytes_per_token)

    def __repr__(self) -> str:
        return f"ByteEstimator(bytes_per_token={self.bytes_per_token})"


def to_json(value: Any) -> str:
    """Compact, deterministic JSON used for both budgeting and model output."""
    return json.dumps(value, ensure_ascii=False, separators=(",", ":"), sort_keys=False)
