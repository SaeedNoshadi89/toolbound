"""Optional tokenizer-backed estimators (install ``toolbound[tiktoken]``)."""

from __future__ import annotations

from typing import Any


class TiktokenEstimator:
    """Counts tokens with a tiktoken encoding (default ``o200k_base``).

    tiktoken implements OpenAI tokenizers. For other model families it is still
    a closer approximation than byte counting, but it is not exact.
    """

    def __init__(self, encoding: str = "o200k_base") -> None:
        try:
            import tiktoken
        except ImportError as exc:  # pragma: no cover - environment dependent
            raise ImportError("pip install 'toolbound[tiktoken]'") from exc
        self._encoding: Any = tiktoken.get_encoding(encoding)
        self.name = encoding

    def count(self, text: str) -> int:
        return len(self._encoding.encode(text, disallowed_special=()))
